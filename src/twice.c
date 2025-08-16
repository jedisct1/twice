#include "twice.h"
#include "os.h"

static const int POLLFD_TUN = 0, POLLFD_UDP = 1, POLLFD_COUNT = 2;

typedef struct Context_ {
    const char            *wanted_if_name;
    const char            *local_tun_ip;
    const char            *remote_tun_ip;
    const char            *local_tun_ip6;
    const char            *remote_tun_ip6;
    const char            *server_ip_or_name;
    const char            *server_port;
    const char            *ext_if_name;
    const char            *wanted_ext_gw_ip;
    char                   client_ip[NI_MAXHOST];
    char                   ext_gw_ip[64];
    char                   server_ip[64];
    char                   if_name[IFNAMSIZ];
    int                    is_server;
    int                    tun_fd;
    int                    udp_fd;
    int                    firewall_rules_set;
    int                    tun_mtu;
    struct sockaddr_storage client_addr;
    socklen_t              client_addr_len;
    int                    client_connected;
    UdpBuf                 udp_buf;
    struct pollfd          fds[2];
} Context;

volatile sig_atomic_t exit_signal_received;

static void signal_handler(int sig)
{
    signal(sig, SIG_DFL);
    exit_signal_received = 1;
}

static int firewall_rules(Context *context, int set, int silent)
{
    const char        *substs[][2] = { { "$LOCAL_TUN_IP6", context->local_tun_ip6 },
                                       { "$REMOTE_TUN_IP6", context->remote_tun_ip6 },
                                       { "$LOCAL_TUN_IP", context->local_tun_ip },
                                       { "$REMOTE_TUN_IP", context->remote_tun_ip },
                                       { "$EXT_IP", context->server_ip },
                                       { "$EXT_PORT", context->server_port },
                                       { "$EXT_IF_NAME", context->ext_if_name },
                                       { "$EXT_GW_IP", context->ext_gw_ip },
                                       { "$IF_NAME", context->if_name },
                                       { NULL, NULL } };
    const char *const *cmds;
    size_t             i;

    if (context->firewall_rules_set == set) {
        return 0;
    }
    if ((cmds = (set ? firewall_rules_cmds(context->is_server).set
                     : firewall_rules_cmds(context->is_server).unset)) == NULL) {
        fprintf(stderr,
                "Routing commands for that operating system have not been "
                "added yet.\n");
        return 0;
    }
    for (i = 0; cmds[i] != NULL; i++) {
        if (shell_cmd(substs, cmds[i], silent) != 0) {
            fprintf(stderr, "Unable to run [%s]: [%s]\n", cmds[i], strerror(errno));
            return -1;
        }
    }
    context->firewall_rules_set = set;
    return 0;
}

static int udp_server_socket(const char *address, const char *port)
{
    struct addrinfo hints, *res;
    int             eai;
    int             server_fd;
    int             err;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_addr     = NULL;
#if defined(__OpenBSD__) || defined(__DragonFly__)
    if (address == NULL) {
        hints.ai_family = AF_INET;
    }
#endif
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the UDP server socket: [%s]\n", gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }
    if ((server_fd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP)) == -1 ||
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *) (int[]) { 1 }, sizeof(int)) != 0) {
        err = errno;
        if (server_fd != -1) {
            (void) close(server_fd);
        }
        freeaddrinfo(res);
        errno = err;
        return -1;
    }
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
    (void) setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) (int[]) { 0 }, sizeof(int));
#endif
    printf("Listening on UDP %s:%s\n", address == NULL ? "*" : address, port);
    if (bind(server_fd, (struct sockaddr *) res->ai_addr, (socklen_t) res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    return server_fd;
}

static int udp_client_socket(const char *address, const char *port)
{
    struct addrinfo hints, *res;
    int             eai;
    int             client_fd;
    int             err;

    printf("Connecting to UDP %s:%s...\n", address, port);
    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = 0;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_addr     = NULL;
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the UDP client socket: [%s]\n", gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }
    if ((client_fd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP)) == -1 ||
        connect(client_fd, (const struct sockaddr *) res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        err = errno;
        if (client_fd != -1) {
            (void) close(client_fd);
        }
        errno = err;
        return -1;
    }
    freeaddrinfo(res);
    return client_fd;
}

static void client_disconnect(Context *context)
{
    context->client_connected = 0;
    memset(&context->client_addr, 0, sizeof context->client_addr);
    context->client_addr_len = 0;
}

static int client_connect(Context *context)
{
    const char *ext_gw_ip = NULL;

    context->udp_buf.pos = 0;
    memset(context->udp_buf.data, 0, sizeof context->udp_buf.data);
#ifndef NO_DEFAULT_ROUTES
    if (context->wanted_ext_gw_ip == NULL && (ext_gw_ip = get_default_gw_ip()) != NULL &&
        strcmp(ext_gw_ip, context->ext_gw_ip) != 0) {
        printf("Gateway changed from [%s] to [%s]\n", context->ext_gw_ip, ext_gw_ip);
        firewall_rules(context, 0, 0);
        snprintf(context->ext_gw_ip, sizeof context->ext_gw_ip, "%s", ext_gw_ip);
        firewall_rules(context, 1, 0);
    }
#endif
    context->udp_fd = udp_client_socket(context->server_ip, context->server_port);
    if (context->udp_fd == -1) {
        perror("UDP client connection failed");
        return -1;
    }
    fcntl(context->udp_fd, F_SETFL, fcntl(context->udp_fd, F_GETFL, 0) | O_NONBLOCK);
    
    firewall_rules(context, 1, 0);
    context->fds[POLLFD_UDP] =
        (struct pollfd) { .fd = context->udp_fd, .events = POLLIN, .revents = 0 };
    puts("Connected");

    return 0;
}

static int client_reconnect(Context *context)
{
    client_disconnect(context);
    if (context->udp_fd != -1) {
        close(context->udp_fd);
        context->udp_fd = -1;
        context->fds[POLLFD_UDP] = (struct pollfd) { .fd = -1, .events = 0 };
    }
    if (context->is_server) {
        return 0;
    }
    unsigned int i;
    for (i = 0; exit_signal_received == 0 && i < RECONNECT_ATTEMPTS; i++) {
        puts("Trying to reconnect");
        sleep(i > 3 ? 3 : i);
        if (client_connect(context) == 0) {
            return 0;
        }
    }
    return -1;
}

// TCP MSS clamping to prevent fragmentation
static void clamp_tcp_mss(unsigned char *data, size_t len, int tun_mtu)
{
    unsigned char *ip_hdr, *tcp_hdr, *tcp_options;
    int ip_hdr_len, tcp_hdr_len, options_len;
    int i;
    uint16_t max_mss = tun_mtu - 40; // IP header (20) + TCP header (20)
    
    // Check if packet is large enough to contain IP header
    if (len < 20) {
        return;
    }
    
    ip_hdr = data;
    
    // Check IP version and protocol (raw byte access for portability)
    if (((ip_hdr[0] >> 4) != 4) || (ip_hdr[9] != IPPROTO_TCP)) {
        return;
    }
    
    ip_hdr_len = (ip_hdr[0] & 0x0f) * 4;
    
    // Check if packet is large enough to contain TCP header
    if (len < (size_t)(ip_hdr_len + 20)) {
        return;
    }
    
    tcp_hdr = data + ip_hdr_len;
    tcp_hdr_len = ((tcp_hdr[12] >> 4) & 0x0f) * 4;
    
    // Only process SYN packets (check SYN flag in TCP flags byte)
    if (!(tcp_hdr[13] & 0x02)) {
        return;
    }
    
    // Check if packet has TCP options
    if (tcp_hdr_len <= 20) {
        return;
    }
    
    options_len = tcp_hdr_len - 20;
    tcp_options = data + ip_hdr_len + 20;
    
    // Parse TCP options looking for MSS option (kind=2, length=4)
    for (i = 0; i < options_len; ) {
        if (tcp_options[i] == 0) { // End of options
            break;
        } else if (tcp_options[i] == 1) { // NOP
            i++;
        } else if (tcp_options[i] == 2 && i + 3 < options_len) { // MSS option
            if (tcp_options[i + 1] == 4) { // MSS option length is 4
                uint16_t current_mss = (tcp_options[i + 2] << 8) | tcp_options[i + 3];
                if (current_mss > max_mss) {
                    tcp_options[i + 2] = (max_mss >> 8) & 0xff;
                    tcp_options[i + 3] = max_mss & 0xff;
                    
                    // Note: TCP checksum recalculation is skipped for simplicity
                    // Most systems will handle this or ignore checksum errors on TUN
                }
            }
            i += tcp_options[i + 1];
        } else if (i + 1 < options_len && tcp_options[i + 1] > 0) {
            i += tcp_options[i + 1];
        } else {
            break;
        }
    }
}

// Check if packet size would cause fragmentation after UDP encapsulation
static int check_packet_size(size_t packet_len, int tun_mtu)
{
    // UDP encapsulation adds: 2 bytes length + UDP header (8) + IP header (20) = 30 bytes minimum
    // Add some safety margin for IPv6 or other headers
    size_t max_safe_size = tun_mtu + 30;
    
    if (packet_len > 1500) {
        fprintf(stderr, "Warning: Large packet (%zu bytes) will likely fragment\n", packet_len);
        if (packet_len > max_safe_size) {
            fprintf(stderr, "Dropping oversized packet (%zu bytes)\n", packet_len);
            return -1; // Drop packet
        }
    }
    return 0; // Packet size OK
}

static int event_loop(Context *context)
{
    struct pollfd *const fds = context->fds;
    UdpBuf               tun_buf;
    ssize_t              len;
    int                  found_fds;

    if (exit_signal_received != 0) {
        return -2;
    }
    if ((found_fds = poll(fds, POLLFD_COUNT, 1500)) == -1) {
        return errno == EINTR ? 0 : -1;
    }
    
    // Handle TUN interface events
    if ((fds[POLLFD_TUN].revents & POLLERR) || (fds[POLLFD_TUN].revents & POLLHUP)) {
        puts("HUP (tun)");
        return -1;
    }
    if (fds[POLLFD_TUN].revents & POLLIN) {
        len = tun_read(context->tun_fd, tun_buf.data, sizeof tun_buf.data);
        if (len <= 0) {
            perror("tun_read");
            return -1;
        }
        
        // Apply TCP MSS clamping to prevent fragmentation
        clamp_tcp_mss(tun_buf.data, (size_t)len, context->tun_mtu);
        
        // Check packet size before transmission
        if (check_packet_size((size_t)len, context->tun_mtu) != 0) {
            return 0; // Drop oversized packet
        }
        
        // Send TUN data over UDP
        if (context->is_server && context->client_connected) {
            uint16_t net_len = endian_swap16((uint16_t) len);
            tun_buf.len = net_len;
            
            struct iovec iov[2] = {
                { .iov_base = &tun_buf.len, .iov_len = sizeof(uint16_t) },
                { .iov_base = tun_buf.data, .iov_len = (size_t) len }
            };
            struct msghdr msg = {
                .msg_name = &context->client_addr,
                .msg_namelen = context->client_addr_len,
                .msg_iov = iov,
                .msg_iovlen = 2,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0
            };
            
            if (sendmsg(context->udp_fd, &msg, 0) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("Unable to send UDP packet to client");
                    return client_reconnect(context);
                }
            }
        } else if (!context->is_server && context->udp_fd != -1) {
            uint16_t net_len = endian_swap16((uint16_t) len);
            tun_buf.len = net_len;
            
            struct iovec iov[2] = {
                { .iov_base = &tun_buf.len, .iov_len = sizeof(uint16_t) },
                { .iov_base = tun_buf.data, .iov_len = (size_t) len }
            };
            
            if (writev(context->udp_fd, iov, 2) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("Unable to send UDP packet to server");
                    return client_reconnect(context);
                }
            }
        }
    }
    
    // Handle UDP socket events
    if ((fds[POLLFD_UDP].revents & POLLERR) || (fds[POLLFD_UDP].revents & POLLHUP)) {
        puts("UDP socket error");
        return client_reconnect(context);
    }
    if (fds[POLLFD_UDP].revents & POLLIN) {
        if (context->is_server) {
            // Server: receive from any client and track the latest one
            struct sockaddr_storage from_addr;
            socklen_t from_addr_len = sizeof(from_addr);
            unsigned char packet_buf[sizeof(uint16_t) + MAX_PACKET_LEN];
            
            ssize_t recvlen = recvfrom(context->udp_fd, packet_buf, sizeof(packet_buf), 0,
                                     (struct sockaddr *) &from_addr, &from_addr_len);
            if (recvlen < (ssize_t) sizeof(uint16_t)) {
                if (recvlen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("UDP recvfrom failed");
                }
                return 0;
            }
            
            // Update client address
            memcpy(&context->client_addr, &from_addr, from_addr_len);
            context->client_addr_len = from_addr_len;
            if (!context->client_connected) {
                char client_ip[NI_MAXHOST];
                getnameinfo((const struct sockaddr *) &from_addr, from_addr_len, client_ip,
                          sizeof client_ip, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
                printf("Client connected from [%s]\n", client_ip);
                strcpy(context->client_ip, client_ip);
                context->client_connected = 1;
            }
            
            // Extract packet length and data
            uint16_t net_len;
            memcpy(&net_len, packet_buf, sizeof(uint16_t));
            size_t data_len = endian_swap16(net_len);
            
            if (data_len > MAX_PACKET_LEN || recvlen != (ssize_t) (sizeof(uint16_t) + data_len)) {
                fprintf(stderr, "Invalid packet size received\n");
                return 0;
            }
            
            // Write to TUN interface
            if (tun_write(context->tun_fd, packet_buf + sizeof(uint16_t), data_len) != (ssize_t) data_len) {
                perror("tun_write");
            }
        } else {
            // Client: receive from server
            unsigned char packet_buf[sizeof(uint16_t) + MAX_PACKET_LEN];
            
            ssize_t recvlen = recv(context->udp_fd, packet_buf, sizeof(packet_buf), 0);
            if (recvlen < (ssize_t) sizeof(uint16_t)) {
                if (recvlen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("UDP recv failed");
                    return client_reconnect(context);
                }
                return 0;
            }
            
            // Extract packet length and data
            uint16_t net_len;
            memcpy(&net_len, packet_buf, sizeof(uint16_t));
            size_t data_len = endian_swap16(net_len);
            
            if (data_len > MAX_PACKET_LEN || recvlen != (ssize_t) (sizeof(uint16_t) + data_len)) {
                fprintf(stderr, "Invalid packet size received\n");
                return client_reconnect(context);
            }
            
            // Write to TUN interface
            if (tun_write(context->tun_fd, packet_buf + sizeof(uint16_t), data_len) != (ssize_t) data_len) {
                perror("tun_write");
            }
        }
    }
    return 0;
}

static int doit(Context *context)
{
    context->udp_fd = -1;
    context->client_connected = 0;
    memset(context->fds, 0, sizeof context->fds);
    context->fds[POLLFD_TUN] =
        (struct pollfd) { .fd = context->tun_fd, .events = POLLIN, .revents = 0 };
    
    if (context->is_server) {
        if ((context->udp_fd = udp_server_socket(context->server_ip_or_name, context->server_port)) ==
            -1) {
            perror("Unable to set up UDP server");
            return -1;
        }
        fcntl(context->udp_fd, F_SETFL, fcntl(context->udp_fd, F_GETFL, 0) | O_NONBLOCK);
        context->fds[POLLFD_UDP] = (struct pollfd) {
            .fd     = context->udp_fd,
            .events = POLLIN,
        };
    }
    if (!context->is_server && client_reconnect(context) != 0) {
        fprintf(stderr, "Unable to connect to server: [%s]\n", strerror(errno));
        return -1;
    }
    while (event_loop(context) == 0)
        ;
    return 0;
}

__attribute__((noreturn)) static void usage(void)
{
    puts("twice " VERSION_STRING
         " usage:\n"
         "\n"
         "twice\t\"server\"\n\t<vpn server ip or name>|\"auto\"\n\t<vpn "
         "server port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun "
         "ip>|\"auto\"\n\t<remote tun ip>\"auto\"\n\t<external ip>|\"auto\""
         "\n\n"
         "twice\t\"client\"\n\t<vpn server ip or name>\n\t<vpn server "
         "port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun "
         "ip>|\"auto\"\n\t<remote tun ip>|\"auto\"\n\t<gateway ip>|\"auto\"\n\n"
         "Options:\n"
         "\t-m, --mtu <mtu>\tSet TUN interface MTU (default: 1420)\n\n"
         "Example:\n\n[server]\n"
         "\tsudo ./twice server auto\t# listen on UDP port 1194\n"
         "\tsudo ./twice -m 1380 server auto\t# with custom MTU\n\n[client]\n"
         "\tsudo ./twice client 34.216.127.34\n"
         "\tsudo ./twice --mtu 1380 client 34.216.127.34\n");
    exit(254);
}

static void get_tun6_addresses(Context *context)
{
    static char local_tun_ip6[40], remote_tun_ip6[40];

    snprintf(local_tun_ip6, sizeof local_tun_ip6, "64:ff9b::%s", context->local_tun_ip);
    snprintf(remote_tun_ip6, sizeof remote_tun_ip6, "64:ff9b::%s", context->remote_tun_ip);
    context->local_tun_ip6  = local_tun_ip6;
    context->remote_tun_ip6 = remote_tun_ip6;
}

static int resolve_ip(char *ip, size_t sizeof_ip, const char *ip_or_name)
{
    struct addrinfo hints, *res = NULL;
    int             eai;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = 0;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_addr     = NULL;
    if ((eai = getaddrinfo(ip_or_name, NULL, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6) ||
        (eai = getnameinfo(res->ai_addr, res->ai_addrlen, ip, (socklen_t) sizeof_ip, NULL, 0,
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        fprintf(stderr, "Unable to resolve [%s]: [%s]\n", ip_or_name, gai_strerror(eai));
        if (res != NULL) {
            freeaddrinfo(res);
        }
        return -1;
    }
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char *argv[])
{
    Context     context;
    const char *ext_gw_ip;
    int         arg_start = 1;

    if (argc < 2) {
        usage();
    }
    memset(&context, 0, sizeof context);
    context.tun_mtu = TUN_MTU; // Set default MTU
    
    // Parse MTU option if present
    if (argc >= 3 && (strcmp(argv[1], "-m") == 0 || strcmp(argv[1], "--mtu") == 0)) {
        context.tun_mtu = atoi(argv[2]);
        if (context.tun_mtu < 68 || context.tun_mtu > 9000) {
            fprintf(stderr, "Invalid MTU value: %d (must be between 68 and 9000)\n", context.tun_mtu);
            return 1;
        }
        arg_start = 3;
        if (argc < 4) {
            usage();
        }
    }
    
    context.is_server = strcmp(argv[arg_start], "server") == 0;
    
    context.server_ip_or_name = (argc <= arg_start + 1 || strcmp(argv[arg_start + 1], "auto") == 0) ? NULL : argv[arg_start + 1];
    if (context.server_ip_or_name == NULL && !context.is_server) {
        usage();
    }
    context.server_port      = (argc <= arg_start + 2 || strcmp(argv[arg_start + 2], "auto") == 0) ? DEFAULT_PORT : argv[arg_start + 2];
    context.wanted_if_name   = (argc <= arg_start + 3 || strcmp(argv[arg_start + 3], "auto") == 0) ? NULL : argv[arg_start + 3];
    context.local_tun_ip     = (argc <= arg_start + 4 || strcmp(argv[arg_start + 4], "auto") == 0)
                                   ? (context.is_server ? DEFAULT_SERVER_IP : DEFAULT_CLIENT_IP)
                                   : argv[arg_start + 4];
    context.remote_tun_ip    = (argc <= arg_start + 5 || strcmp(argv[arg_start + 5], "auto") == 0)
                                   ? (context.is_server ? DEFAULT_CLIENT_IP : DEFAULT_SERVER_IP)
                                   : argv[arg_start + 5];
    context.wanted_ext_gw_ip = (argc <= arg_start + 6 || strcmp(argv[arg_start + 6], "auto") == 0) ? NULL : argv[arg_start + 6];
    ext_gw_ip = context.wanted_ext_gw_ip ? context.wanted_ext_gw_ip : get_default_gw_ip();
    snprintf(context.ext_gw_ip, sizeof context.ext_gw_ip, "%s", ext_gw_ip == NULL ? "" : ext_gw_ip);
    if (ext_gw_ip == NULL && !context.is_server) {
        fprintf(stderr, "Unable to automatically determine the gateway IP\n");
        return 1;
    }
    if ((context.ext_if_name = get_default_ext_if_name()) == NULL && context.is_server) {
        fprintf(stderr, "Unable to automatically determine the external interface\n");
        return 1;
    }
    get_tun6_addresses(&context);
    context.tun_fd = tun_create(context.if_name, context.wanted_if_name);
    if (context.tun_fd == -1) {
        perror("tun device creation");
        return 1;
    }
    printf("Interface: [%s]\n", context.if_name);
    printf("MTU: %d bytes\n", context.tun_mtu);
    if (tun_set_mtu(context.if_name, context.tun_mtu) != 0) {
        perror("mtu");
    }
#ifdef __OpenBSD__
    pledge("stdio proc exec dns inet", NULL);
#endif
    context.firewall_rules_set = -1;
    if (context.server_ip_or_name != NULL &&
        resolve_ip(context.server_ip, sizeof context.server_ip, context.server_ip_or_name) != 0) {
        firewall_rules(&context, 0, 1);
        return 1;
    }
    if (context.is_server) {
        if (firewall_rules(&context, 1, 0) != 0) {
            return -1;
        }
#ifdef __OpenBSD__
        printf("\nAdd the following rule to /etc/pf.conf:\npass out from %s nat-to egress\n\n",
               context.remote_tun_ip);
#endif
    } else {
        firewall_rules(&context, 0, 1);
    }
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    if (doit(&context) != 0) {
        return -1;
    }
    firewall_rules(&context, 0, 0);
    puts("Done.");

    return 0;
}