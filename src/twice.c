#include "twice.h"
#include "os.h"
#include <sys/stat.h>

// HiAE function declarations
int HiAE_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                 size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);
int HiAE_decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                 size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);
int HiAE_mac(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
             uint8_t *tag);

static const int POLLFD_TUN = 0, POLLFD_UDP = 1, POLLFD_COUNT = 2;

typedef struct Context_ {
    const char             *wanted_if_name;
    const char             *local_tun_ip;
    const char             *remote_tun_ip;
    const char             *local_tun_ip6;
    const char             *remote_tun_ip6;
    const char             *server_ip_or_name;
    const char             *server_port;
    const char             *ext_if_name;
    const char             *wanted_ext_gw_ip;
    const char             *key_file; // Path to key file
    char                    client_ip[NI_MAXHOST];
    char                    ext_gw_ip[64];
    char                    server_ip[64];
    char                    if_name[IFNAMSIZ];
    int                     is_server;
    int                     tun_fd;
    int                     udp_fd;
    int                     firewall_rules_set;
    int                     tun_mtu;
    int                     mtu_discovery; // Enable MTU discovery
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    int                     client_connected;
    uint64_t                packet_random;      // Random value for packet header
    uint64_t                packet_counter;     // Counter for packet header
    uint8_t                 key[HIAE_KEYBYTES]; // Encryption key (all-zero if no key file)
    int                     key_loaded;         // Whether encryption key has been loaded
    ReorderState            reorder;            // Packet reordering state
    struct timespec         last_reorder_check; // Last time we checked for timeouts
    UdpBuf                  udp_buf;
    struct pollfd           fds[2];
} Context;

volatile sig_atomic_t exit_signal_received;

// Forward declarations
static void reorder_init(ReorderState *state);
static void reorder_cleanup(ReorderState *state);
static void reorder_check_timeouts(Context *context);
static int  reorder_deliver_buffered(Context *context);
static int  reorder_process_packet(Context *context, uint64_t random_value, uint64_t counter,
                                   const unsigned char *data, size_t len);
static int  discover_mtu(Context *context);
static int  get_effective_tun_mtu(int base_mtu, int key_loaded);

// Read secure random bytes from /dev/urandom
static int get_random_bytes(void *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (uint8_t *) buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total += n;
    }

    close(fd);
    return 0;
}

// Load encryption key from file
static int load_key(Context *context)
{
    // Initialize with all-zero key for authentication-only mode
    memset(context->key, 0, HIAE_KEYBYTES);

    if (!context->key_file) {
        // No key file specified - use all-zero key for MAC only
        printf("Running in authentication-only mode (no encryption)\n");
        return 0;
    }

    FILE *fp = fopen(context->key_file, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open key file: %s\n", context->key_file);
        return -1;
    }

    size_t n = fread(context->key, 1, HIAE_KEYBYTES, fp);
    fclose(fp);

    if (n != HIAE_KEYBYTES) {
        fprintf(stderr, "Key file must contain exactly %d bytes\n", HIAE_KEYBYTES);
        return -1;
    }

    context->key_loaded = 1;
    printf("Running in encrypted mode with authentication\n");
    return 0;
}

// Cleanup sensitive data before exit
static void cleanup_context(Context *context)
{
    if (context) {
        // Clear sensitive key material
        if (context->key_loaded) {
            memset(context->key, 0, HIAE_KEYBYTES);
        }

        // Cleanup reordering state
        reorder_cleanup(&context->reorder);
    }
}

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

    // Set larger socket buffers to handle burst traffic
    int rcvbuf = 4 * 1024 * 1024; // 4MB receive buffer
    int sndbuf = 4 * 1024 * 1024; // 4MB send buffer
    setsockopt(server_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(server_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
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

    // Set larger socket buffers to handle burst traffic
    int rcvbuf = 4 * 1024 * 1024; // 4MB receive buffer
    int sndbuf = 4 * 1024 * 1024; // 4MB send buffer
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

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

    // Perform MTU discovery if enabled
    if (context->mtu_discovery) {
        int discovered_mtu = discover_mtu(context);
        if (discovered_mtu > 0 && discovered_mtu != context->tun_mtu) {
            context->tun_mtu  = discovered_mtu;
            int effective_mtu = get_effective_tun_mtu(context->tun_mtu, context->key_loaded);
            printf(
                "Setting TUN MTU to discovered value: %d bytes (effective: %d bytes, with "
                "authentication)\n",
                context->tun_mtu, effective_mtu);
            if (tun_set_mtu(context->if_name, effective_mtu) != 0) {
                perror("Failed to set discovered MTU");
            }
        }
    }

    return 0;
}

static int client_reconnect(Context *context)
{
    client_disconnect(context);
    if (context->udp_fd != -1) {
        close(context->udp_fd);
        context->udp_fd          = -1;
        context->fds[POLLFD_UDP] = (struct pollfd) { .fd = -1, .events = 0 };
    }

    // Reset reorder state on reconnect
    reorder_cleanup(&context->reorder);
    reorder_init(&context->reorder);

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

// Initialize reorder state
static void reorder_init(ReorderState *state)
{
    memset(state, 0, sizeof(*state));
    state->expected_counter = 1; // Start expecting counter 1 (first packet has ++counter = 1)
    state->window_base      = 1;

    // Mark all buffer slots as unoccupied
    for (int i = 0; i < REORDER_WINDOW_SIZE; i++) {
        state->buffer[i].occupied = 0;
    }
}

// Clean up reorder state
static void reorder_cleanup(ReorderState *state)
{
    // Just mark all slots as unoccupied - no need to free since it's preallocated
    for (int i = 0; i < REORDER_WINDOW_SIZE; i++) {
        state->buffer[i].occupied = 0;
    }
}

// Get current time in milliseconds
static uint64_t get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Check if we should process buffered packets due to timeout
static void reorder_check_timeouts(Context *context)
{
    ReorderState *state    = &context->reorder;
    uint64_t      now_ms   = get_time_ms();
    int           advanced = 0;

    for (int i = 0; i < REORDER_WINDOW_SIZE; i++) {
        BufferedPacket *pkt = &state->buffer[i];
        if (pkt->occupied) {
            uint64_t pkt_age_ms =
                now_ms - (pkt->timestamp.tv_sec * 1000 + pkt->timestamp.tv_nsec / 1000000);
            if (pkt_age_ms > REORDER_TIMEOUT_MS) {
                // This packet is too old, we need to skip ahead
                if (pkt->counter > state->expected_counter) {
                    fprintf(stderr,
                            "Timeout: skipping from counter %llu to %llu (lost %llu packets)\n",
                            (unsigned long long) state->expected_counter,
                            (unsigned long long) pkt->counter,
                            (unsigned long long) (pkt->counter - state->expected_counter));
                    state->packets_lost += (pkt->counter - state->expected_counter);

                    // Deliver the timed-out packet
                    if (tun_write(context->tun_fd, pkt->data, pkt->len) != (ssize_t) pkt->len) {
                        perror("tun_write (timeout)");
                    }
                    pkt->occupied = 0;

                    state->expected_counter  = pkt->counter + 1;
                    state->window_base       = state->expected_counter;
                    state->highest_processed = pkt->counter;
                    advanced                 = 1;
                    break;
                }
            }
        }
    }

    // If we advanced, try to deliver any buffered packets that are now in sequence
    if (advanced) {
        reorder_deliver_buffered(context);
    }
}

// Buffer a packet for later delivery
static int reorder_buffer_packet(ReorderState *state, uint64_t counter, const unsigned char *data,
                                 size_t len)
{
    int             slot = counter % REORDER_WINDOW_SIZE;
    BufferedPacket *pkt  = &state->buffer[slot];

    // Check if slot is already occupied with same counter (duplicate)
    if (pkt->occupied && pkt->counter == counter) {
        state->packets_duplicated++;
        return -1;
    }

    // Check if slot is occupied by a different packet (collision)
    if (pkt->occupied && pkt->counter != counter) {
        // This shouldn't happen if window size is enforced correctly
        fprintf(stderr, "Buffer slot collision: slot %d has counter %llu, trying to store %llu\n",
                slot, (unsigned long long) pkt->counter, (unsigned long long) counter);
        return -1; // Drop the packet rather than overwrite
    }

    // Store packet in preallocated slot
    pkt->occupied = 1;
    pkt->counter  = counter;
    pkt->len      = len;
    memcpy(pkt->data, data, len);
    clock_gettime(CLOCK_MONOTONIC, &pkt->timestamp);

    state->packets_reordered++;

    return 0;
}

// Try to deliver buffered packets that are now in sequence
static int reorder_deliver_buffered(Context *context)
{
    ReorderState *state     = &context->reorder;
    int           delivered = 0;

    while (1) {
        int             slot = state->expected_counter % REORDER_WINDOW_SIZE;
        BufferedPacket *pkt  = &state->buffer[slot];

        if (!pkt->occupied || pkt->counter != state->expected_counter) {
            break;
        }

        // Deliver this packet
        if (tun_write(context->tun_fd, pkt->data, pkt->len) != (ssize_t) pkt->len) {
            perror("tun_write (buffered)");
        }

        // Mark slot as unoccupied
        pkt->occupied = 0;

        state->expected_counter++;
        state->highest_processed = state->expected_counter - 1;
        delivered++;
    }

    return delivered;
}

// Process a received packet through the reordering system
// Returns: 1 if packet should be delivered immediately, 0 if buffered, -1 if dropped
static int reorder_process_packet(Context *context, uint64_t random_value, uint64_t counter,
                                  const unsigned char *data, size_t len)
{
    ReorderState *state = &context->reorder;

    state->packets_received++;

    // First packet - initialize random value
    if (!state->random_initialized) {
        state->random_value       = random_value;
        state->random_initialized = 1;
        state->expected_counter   = counter;
        state->window_base        = counter;
    }

    // Check random value (detect peer restart)
    if (random_value != state->random_value) {
        fprintf(stderr, "Random value mismatch - peer restarted. Resetting reorder state.\n");
        reorder_cleanup(state);
        reorder_init(state);
        state->random_value       = random_value;
        state->random_initialized = 1;
        state->expected_counter   = counter;
        state->window_base        = counter;
    }

    // Check for duplicate
    if (counter < state->expected_counter) {
        state->packets_duplicated++;
        return -1; // Drop duplicate/old packet
    }

    // Check if this is the expected packet
    if (counter == state->expected_counter) {
        state->expected_counter++;
        state->highest_processed = counter;

        // Write to TUN immediately
        if (tun_write(context->tun_fd, data, len) != (ssize_t) len) {
            perror("tun_write");
        }

        // Try to deliver any buffered packets that are now in sequence
        reorder_deliver_buffered(context);

        // Update window base
        state->window_base = state->expected_counter;

        return 1; // Delivered
    }

    // Packet is in the future
    if (counter >= state->expected_counter + REORDER_WINDOW_SIZE) {
        // Too far ahead - we've likely lost many packets
        fprintf(stderr, "Packet too far ahead: expected %llu, got %llu. Advancing window.\n",
                (unsigned long long) state->expected_counter, (unsigned long long) counter);

        // Record lost packets
        state->packets_lost += (counter - state->expected_counter);

        // Advance window
        state->expected_counter = counter;
        state->window_base      = counter;

        // Clear old buffer entries
        reorder_cleanup(state);
        reorder_init(state);
        state->random_value       = random_value;
        state->random_initialized = 1;
        state->expected_counter   = counter + 1;
        state->highest_processed  = counter;

        // Deliver this packet
        if (tun_write(context->tun_fd, data, len) != (ssize_t) len) {
            perror("tun_write");
        }

        return 1;
    }

    // Packet is within window but out of order - buffer it
    reorder_buffer_packet(state, counter, data, len);

    return 0; // Buffered
}

// Get effective TUN MTU accounting for authentication tag overhead
static int get_effective_tun_mtu(int base_mtu, int key_loaded)
{
    (void) key_loaded; // No longer used - always account for auth tag
    // Always account for authentication tag (used even without encryption)
    return base_mtu - HIAE_MACBYTES;
}

// Check if packet size would cause fragmentation after UDP encapsulation
static int check_packet_size(size_t packet_len, int tun_mtu, int key_loaded)
{
    (void) key_loaded; // No longer used - always account for auth tag
    // UDP encapsulation adds: 2 bytes length + 16 bytes header + UDP header (8) + IP header (20) =
    // 46 bytes minimum. Always add 16 bytes for authentication tag. Add some safety margin
    // for IPv6 or other headers
    size_t overhead      = 46 + HIAE_MACBYTES;
    size_t max_safe_size = tun_mtu + overhead;

    if (packet_len > max_safe_size) {
        fprintf(stderr, "Dropping oversized packet (%zu bytes)\n", packet_len);
        return -1; // Drop packet
    }
    return 0; // Packet size OK
}

// Send an MTU probe packet of specified size
static int send_mtu_probe(Context *context, int probe_size)
{
    unsigned char probe_data[MAX_PACKET_LEN];
    unsigned char encrypted_data[MAX_PACKET_LEN];
    unsigned char auth_tag[HIAE_MACBYTES];
    PacketHeader  probe_header;

    // Set magic values to identify as MTU probe
    probe_header.random_value = endian_swap64(MTU_PROBE_MAGIC);
    probe_header.counter      = endian_swap64(MTU_PROBE_MAGIC);

    // Fill probe data with pattern
    memset(probe_data, 0xAA, probe_size);

    // Process data based on encryption mode
    void  *data_to_send = probe_data;
    size_t data_len     = probe_size;

    if (context->key_loaded) {
        // Full encryption with authentication
        if (HiAE_encrypt(context->key, (uint8_t *) &probe_header, probe_data, encrypted_data,
                         probe_size, NULL, 0, auth_tag) != 0) {
            fprintf(stderr, "MTU probe encryption failed\n");
            return -1;
        }
        data_to_send = encrypted_data;
    } else {
        // Authentication only (no encryption) with all-zero key
        if (HiAE_mac(context->key, (uint8_t *) &probe_header, probe_data, probe_size, auth_tag) !=
            0) {
            fprintf(stderr, "MTU probe MAC generation failed\n");
            return -1;
        }
    }

    // Always send header, data, and tag (just like normal packets)
    struct iovec iov[3] = { { .iov_base = &probe_header, .iov_len = sizeof(PacketHeader) },
                            { .iov_base = data_to_send, .iov_len = data_len },
                            { .iov_base = auth_tag, .iov_len = HIAE_MACBYTES } };

    if (writev(context->udp_fd, iov, 3) < 0) {
        return -1;
    }

    return 0;
}

// Wait for MTU probe response
static int recv_mtu_probe(Context *context, int expected_size, int timeout_ms)
{
    struct pollfd pfd = { .fd = context->udp_fd, .events = POLLIN };
    unsigned char packet_buf[sizeof(PacketHeader) + MAX_PACKET_LEN + HIAE_MACBYTES];

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) {
        return 0; // Timeout or error
    }

    ssize_t recvlen = recv(context->udp_fd, packet_buf, sizeof(packet_buf), 0);
    if (recvlen < (ssize_t) (sizeof(PacketHeader) + HIAE_MACBYTES)) {
        return 0; // Too small to be a valid authenticated packet
    }

    PacketHeader header;
    memcpy(&header, packet_buf, sizeof(PacketHeader));

    // Check if this is an MTU probe response
    if (endian_swap64(header.random_value) == MTU_PROBE_MAGIC &&
        endian_swap64(header.counter) == MTU_PROBE_MAGIC) {
        // Calculate data length (excluding header and auth tag)
        size_t data_len = recvlen - sizeof(PacketHeader) - HIAE_MACBYTES;

        // Verify the authentication tag
        unsigned char *data_ptr = packet_buf + sizeof(PacketHeader);
        unsigned char *tag_ptr  = packet_buf + sizeof(PacketHeader) + data_len;
        unsigned char  decrypted_data[MAX_PACKET_LEN];

        if (context->key_loaded) {
            // Full decryption with authentication verification
            if (HiAE_decrypt(context->key, (uint8_t *) &header, decrypted_data, data_ptr, data_len,
                             NULL, 0, tag_ptr) != 0) {
                return 0; // Authentication failed
            }
        } else {
            // Verify MAC only (no decryption)
            unsigned char computed_tag[HIAE_MACBYTES];
            if (HiAE_mac(context->key, (uint8_t *) &header, data_ptr, data_len, computed_tag) !=
                0) {
                return 0; // MAC computation failed
            }
            // Compare tags
            if (memcmp(tag_ptr, computed_tag, HIAE_MACBYTES) != 0) {
                return 0; // Authentication failed
            }
        }

        // Check if data length matches expected size
        if (data_len == (size_t) expected_size) {
            return 1; // Success
        }
    }

    return 0;
}

// Test if a specific MTU size works
static int test_mtu_size(Context *context, int test_size)
{
    for (int retry = 0; retry < MTU_PROBE_RETRIES; retry++) {
        if (send_mtu_probe(context, test_size) < 0) {
            continue;
        }

        if (recv_mtu_probe(context, test_size, MTU_PROBE_TIMEOUT_MS)) {
            return 1; // Size works
        }
    }

    return 0; // Size doesn't work
}

// Perform MTU discovery using binary search
static int discover_mtu(Context *context)
{
    if (context->is_server) {
        return DEFAULT_MTU; // Server doesn't initiate MTU discovery
    }

    printf("Starting MTU discovery...\n");

    int min_mtu  = MTU_MIN;
    int max_mtu  = MTU_MAX;
    int best_mtu = MTU_MIN;

    // Binary search for optimal MTU
    while (min_mtu <= max_mtu) {
        int test_mtu = (min_mtu + max_mtu) / 2;

        printf("Testing MTU %d... ", test_mtu);
        fflush(stdout);

        // Calculate probe data size: test_mtu minus all overheads
        // MTU_OVERHEAD (46) = UDP(8) + IP(20) + packet header(16) + 2 bytes for length
        // Also subtract HIAE_MACBYTES (16) since auth tag is always added
        int probe_data_size = test_mtu - MTU_OVERHEAD - HIAE_MACBYTES;

        if (probe_data_size > 0 && test_mtu_size(context, probe_data_size)) {
            printf("OK\n");
            best_mtu = test_mtu;
            min_mtu  = test_mtu + 1;
        } else {
            printf("Failed\n");
            max_mtu = test_mtu - 1;
        }
    }

    // Calculate TUN MTU from best discovered MTU
    // best_mtu includes: UDP + IP + packet header + auth tag
    // TUN MTU = best_mtu - MTU_OVERHEAD - HIAE_MACBYTES
    int tun_mtu = best_mtu - MTU_OVERHEAD - HIAE_MACBYTES;

    // Ensure it's at least the minimum
    if (tun_mtu < MTU_MIN) {
        tun_mtu = MTU_MIN;
    }

    printf("MTU discovery complete: %d bytes (TUN MTU: %d)\n", best_mtu, tun_mtu);

    return tun_mtu;
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

    // Check for timeout on buffered packets periodically
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t ms_since_check = (now.tv_sec - context->last_reorder_check.tv_sec) * 1000 +
                              (now.tv_nsec - context->last_reorder_check.tv_nsec) / 1000000;
    if (ms_since_check >= REORDER_CHECK_INTERVAL_MS) {
        reorder_check_timeouts(context);
        context->last_reorder_check = now;
    }

    if ((found_fds = poll(fds, POLLFD_COUNT, REORDER_CHECK_INTERVAL_MS)) == -1) {
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

        // Check packet size before transmission
        if (check_packet_size((size_t) len, context->tun_mtu, context->key_loaded) != 0) {
            return 0; // Drop oversized packet
        }

        // Send TUN data over UDP with 128-bit header
        if (context->is_server && context->client_connected) {
            // Check for counter wrap and increment random value
            if (context->packet_counter == UINT64_MAX) {
                context->packet_random++;
                context->packet_counter = 0;
            } else {
                context->packet_counter++;
            }

            // Set up packet header with random value and counter
            tun_buf.header.random_value = endian_swap64(context->packet_random);
            tun_buf.header.counter      = endian_swap64(context->packet_counter);

            // Process data based on encryption mode
            unsigned char encrypted_data[MAX_PACKET_LEN];
            void         *data_to_send = tun_buf.data;
            size_t        data_len     = (size_t) len;

            if (context->key_loaded) {
                // Full encryption with authentication
                if (HiAE_encrypt(context->key, (uint8_t *) &tun_buf.header, tun_buf.data,
                                 encrypted_data, len, NULL, 0, tun_buf.tag) != 0) {
                    fprintf(stderr, "Encryption failed\n");
                    return -1;
                }
                data_to_send = encrypted_data;
            } else {
                // Authentication only (no encryption) with all-zero key
                if (HiAE_mac(context->key, (uint8_t *) &tun_buf.header, tun_buf.data, len,
                             tun_buf.tag) != 0) {
                    fprintf(stderr, "MAC generation failed\n");
                    return -1;
                }
            }

            // Always send header, data, and tag
            struct iovec iov[3] = { { .iov_base = &tun_buf.header,
                                      .iov_len  = sizeof(PacketHeader) },
                                    { .iov_base = data_to_send, .iov_len = data_len },
                                    { .iov_base = tun_buf.tag, .iov_len = HIAE_MACBYTES } };

            struct msghdr msg = { .msg_name       = &context->client_addr,
                                  .msg_namelen    = context->client_addr_len,
                                  .msg_iov        = iov,
                                  .msg_iovlen     = 3,
                                  .msg_control    = NULL,
                                  .msg_controllen = 0,
                                  .msg_flags      = 0 };

            if (sendmsg(context->udp_fd, &msg, 0) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    // A server send error must not tear down the listening socket.
                    perror("Unable to send UDP packet to client");
                }
            }
        } else if (!context->is_server && context->udp_fd != -1) {
            // Check for counter wrap and increment random value
            if (context->packet_counter == UINT64_MAX) {
                context->packet_random++;
                context->packet_counter = 0;
            } else {
                context->packet_counter++;
            }

            // Set up packet header with random value and counter
            tun_buf.header.random_value = endian_swap64(context->packet_random);
            tun_buf.header.counter      = endian_swap64(context->packet_counter);

            // Process data based on encryption mode
            unsigned char encrypted_data[MAX_PACKET_LEN];
            void         *data_to_send = tun_buf.data;
            size_t        data_len     = (size_t) len;

            if (context->key_loaded) {
                // Full encryption with authentication
                if (HiAE_encrypt(context->key, (uint8_t *) &tun_buf.header, tun_buf.data,
                                 encrypted_data, len, NULL, 0, tun_buf.tag) != 0) {
                    fprintf(stderr, "Encryption failed\n");
                    return -1;
                }
                data_to_send = encrypted_data;
            } else {
                // Authentication only (no encryption) with all-zero key
                if (HiAE_mac(context->key, (uint8_t *) &tun_buf.header, tun_buf.data, len,
                             tun_buf.tag) != 0) {
                    fprintf(stderr, "MAC generation failed\n");
                    return -1;
                }
            }

            // Always send header, data, and tag
            struct iovec iov[3] = { { .iov_base = &tun_buf.header,
                                      .iov_len  = sizeof(PacketHeader) },
                                    { .iov_base = data_to_send, .iov_len = data_len },
                                    { .iov_base = tun_buf.tag, .iov_len = HIAE_MACBYTES } };

            if (writev(context->udp_fd, iov, 3) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("Unable to send UDP packet to server");
                    return client_reconnect(context);
                }
            }
        }
    }

    // Handle UDP socket events
    if ((fds[POLLFD_UDP].revents & POLLERR) || (fds[POLLFD_UDP].revents & POLLHUP)) {
        // Only the client reconnects; the server keeps its listening socket and
        // drains the error through recvfrom below.
        if (!context->is_server) {
            puts("UDP socket error");
            return client_reconnect(context);
        }
    }
    if (fds[POLLFD_UDP].revents & (POLLIN | POLLERR | POLLHUP)) {
        if (context->is_server) {
            // Server: receive from any client and track the latest one
            struct sockaddr_storage from_addr;
            socklen_t               from_addr_len = sizeof(from_addr);
            unsigned char packet_buf[sizeof(PacketHeader) + MAX_PACKET_LEN + HIAE_MACBYTES];

            ssize_t recvlen = recvfrom(context->udp_fd, packet_buf, sizeof(packet_buf), 0,
                                       (struct sockaddr *) &from_addr, &from_addr_len);
            if (recvlen < (ssize_t) sizeof(PacketHeader)) {
                if (recvlen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("UDP recvfrom failed");
                }
                return 0;
            }

            // Extract header
            PacketHeader header;
            memcpy(&header, packet_buf, sizeof(PacketHeader));

            // Extract header values for MTU probe check
            uint64_t recv_random  = endian_swap64(header.random_value);
            uint64_t recv_counter = endian_swap64(header.counter);

            // Check if this is an MTU probe packet (not encrypted)
            if (recv_random == MTU_PROBE_MAGIC && recv_counter == MTU_PROBE_MAGIC) {
                // Echo the probe packet back to the client
                if (sendto(context->udp_fd, packet_buf, recvlen, 0, (struct sockaddr *) &from_addr,
                           from_addr_len) < 0) {
                    perror("Failed to echo MTU probe");
                }
                return 0; // Don't process probe packets as normal data
            }

            // Calculate data and tag positions (tag is always present)
            if (recvlen < (ssize_t) (sizeof(PacketHeader) + HIAE_MACBYTES)) {
                fprintf(stderr, "Packet too small (missing authentication tag)\n");
                return 0;
            }

            unsigned char *encrypted_data = packet_buf + sizeof(PacketHeader);
            size_t         data_len       = recvlen - sizeof(PacketHeader) - HIAE_MACBYTES;
            unsigned char *tag            = packet_buf + sizeof(PacketHeader) + data_len;
            unsigned char  decrypted_data[MAX_PACKET_LEN];
            unsigned char *final_data = encrypted_data;

            if (context->key_loaded) {
                // Decrypt and verify with encryption key
                if (HiAE_decrypt(context->key, (uint8_t *) &header, decrypted_data, encrypted_data,
                                 data_len, NULL, 0, tag) != 0) {
                    fprintf(stderr, "Decryption or authentication failed\n");
                    return 0;
                }
                final_data = decrypted_data;
            } else {
                // Verify MAC only (no decryption) with all-zero key
                unsigned char expected_tag[HIAE_MACBYTES];
                if (HiAE_mac(context->key, (uint8_t *) &header, encrypted_data, data_len,
                             expected_tag) != 0) {
                    fprintf(stderr, "MAC verification failed\n");
                    return 0;
                }
                // Compare tags
                if (memcmp(tag, expected_tag, HIAE_MACBYTES) != 0) {
                    fprintf(stderr, "Authentication tag mismatch - packet rejected\n");
                    return 0;
                }
                // Data is not encrypted, use as-is
                final_data = encrypted_data;
            }

            // Update client address only after successful authentication
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

            if (data_len > MAX_PACKET_LEN) {
                fprintf(stderr, "Invalid packet size received\n");
                return 0;
            }

            // Process packet through reordering system
            reorder_process_packet(context, recv_random, recv_counter, final_data, data_len);
        } else {
            // Client: receive from server
            unsigned char packet_buf[sizeof(PacketHeader) + MAX_PACKET_LEN + HIAE_MACBYTES];

            ssize_t recvlen = recv(context->udp_fd, packet_buf, sizeof(packet_buf), 0);
            if (recvlen < (ssize_t) sizeof(PacketHeader)) {
                if (recvlen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("UDP recv failed");
                    return client_reconnect(context);
                }
                return 0;
            }

            // Extract header
            PacketHeader header;
            memcpy(&header, packet_buf, sizeof(PacketHeader));

            // Extract header values
            uint64_t recv_random  = endian_swap64(header.random_value);
            uint64_t recv_counter = endian_swap64(header.counter);

            // Calculate data and tag positions (tag is always present)
            if (recvlen < (ssize_t) (sizeof(PacketHeader) + HIAE_MACBYTES)) {
                fprintf(stderr, "Packet too small (missing authentication tag)\n");
                return client_reconnect(context);
            }

            unsigned char *encrypted_data = packet_buf + sizeof(PacketHeader);
            size_t         data_len       = recvlen - sizeof(PacketHeader) - HIAE_MACBYTES;
            unsigned char *tag            = packet_buf + sizeof(PacketHeader) + data_len;
            unsigned char  decrypted_data[MAX_PACKET_LEN];
            unsigned char *final_data = encrypted_data;

            if (context->key_loaded) {
                // Decrypt and verify with encryption key
                if (HiAE_decrypt(context->key, (uint8_t *) &header, decrypted_data, encrypted_data,
                                 data_len, NULL, 0, tag) != 0) {
                    fprintf(stderr, "Decryption or authentication failed\n");
                    return client_reconnect(context);
                }
                final_data = decrypted_data;
            } else {
                // Verify MAC only (no decryption) with all-zero key
                unsigned char expected_tag[HIAE_MACBYTES];
                if (HiAE_mac(context->key, (uint8_t *) &header, encrypted_data, data_len,
                             expected_tag) != 0) {
                    fprintf(stderr, "MAC verification failed\n");
                    return client_reconnect(context);
                }
                // Compare tags
                if (memcmp(tag, expected_tag, HIAE_MACBYTES) != 0) {
                    fprintf(stderr, "Authentication tag mismatch - packet rejected\n");
                    return client_reconnect(context);
                }
                // Data is not encrypted, use as-is
                final_data = encrypted_data;
            }

            if (data_len > MAX_PACKET_LEN) {
                fprintf(stderr, "Invalid packet size received\n");
                return client_reconnect(context);
            }

            // Process packet through reordering system
            reorder_process_packet(context, recv_random, recv_counter, final_data, data_len);
        }
    }
    return 0;
}

static int doit(Context *context)
{
    context->udp_fd           = -1;
    context->client_connected = 0;
    memset(context->fds, 0, sizeof context->fds);
    context->fds[POLLFD_TUN] =
        (struct pollfd) { .fd = context->tun_fd, .events = POLLIN, .revents = 0 };

    // Initialize reorder state
    reorder_init(&context->reorder);
    clock_gettime(CLOCK_MONOTONIC, &context->last_reorder_check);

    if (context->is_server) {
        if ((context->udp_fd =
                 udp_server_socket(context->server_ip_or_name, context->server_port)) == -1) {
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

    // Clean up reorder state
    reorder_cleanup(&context->reorder);

    return 0;
}

__attribute__((noreturn)) static void usage(void)
{
    puts("twice " VERSION_STRING
         " usage:\n"
         "\n"
         "twice genkey [keyfile]\t# Generate encryption key (default: vpn.key)\n"
         "\n"
         "twice\t\"server\"\n\t<vpn server ip or name>|\"auto\"\n\t<vpn "
         "server port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun "
         "ip>|\"auto\"\n\t<remote tun ip>\"auto\"\n\t<external ip>|\"auto\""
         "\n\n"
         "twice\t\"client\"\n\t<vpn server ip or name>\n\t<vpn server "
         "port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun "
         "ip>|\"auto\"\n\t<remote tun ip>|\"auto\"\n\t<gateway ip>|\"auto\"\n\n"
         "Options:\n"
         "\t-k, --key <file>\tPath to 256-bit key file for encryption\n"
         "\t-m, --mtu <mtu>\t\tSet TUN interface MTU (default: 1420)\n"
         "\t-d, --discover-mtu\tAutomatically discover optimal MTU (client only)\n\n"
         "Example:\n\n[server]\n"
         "\tsudo ./twice server auto\t# listen on UDP port 41194\n"
         "\tsudo ./twice -k vpn.key server auto\t# with encryption\n"
         "\tsudo ./twice -m 1380 server auto\t# with custom MTU\n\n[client]\n"
         "\tsudo ./twice client 34.216.127.34\n"
         "\tsudo ./twice -k vpn.key client 34.216.127.34\t# with encryption\n"
         "\tsudo ./twice -d client 34.216.127.34\t# with MTU discovery\n"
         "\tsudo ./twice --mtu 1380 client 34.216.127.34\n\n"
         "Generate encryption key:\n"
         "\t./twice genkey\t\t# creates vpn.key\n"
         "\t./twice genkey mykey.key\t# creates mykey.key\n");
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
    Context    *context;
    const char *ext_gw_ip;
    int         arg_start = 1;

    if (argc < 2) {
        usage();
    }

    // Handle key generation command
    if (strcmp(argv[1], "genkey") == 0 || strcmp(argv[1], "generate-key") == 0) {
        const char *keyfile = (argc > 2) ? argv[2] : "vpn.key";

        // Check if file already exists
        if (access(keyfile, F_OK) == 0) {
            fprintf(stderr, "Error: Key file '%s' already exists\n", keyfile);
            fprintf(stderr, "Please specify a different filename or remove the existing file\n");
            return 1;
        }

        // Generate 32 random bytes
        uint8_t keybuf[HIAE_KEYBYTES];
        if (get_random_bytes(keybuf, HIAE_KEYBYTES) < 0) {
            fprintf(stderr, "Error: Failed to generate random key\n");
            return 1;
        }

        // Write to file
        FILE *fp = fopen(keyfile, "wb");
        if (!fp) {
            fprintf(stderr, "Error: Failed to create key file '%s'\n", keyfile);
            return 1;
        }

        if (fwrite(keybuf, 1, HIAE_KEYBYTES, fp) != HIAE_KEYBYTES) {
            fprintf(stderr, "Error: Failed to write key file\n");
            fclose(fp);
            unlink(keyfile);
            return 1;
        }

        fclose(fp);

        // Set restrictive permissions (owner read/write only)
        if (chmod(keyfile, 0600) != 0) {
            fprintf(stderr, "Warning: Failed to set restrictive permissions on key file\n");
        }

        // Clear key from memory
        memset(keybuf, 0, HIAE_KEYBYTES);

        printf("Successfully generated 256-bit key file: %s\n\n", keyfile);
        printf("Usage:\n");
        printf("  Server: sudo ./twice -k %s server auto\n", keyfile);
        printf("  Client: sudo ./twice -k %s client <server-ip>\n\n", keyfile);
        printf("Important: Copy this key file securely to both server and client\n");

        return 0;
    }

    // Allocate Context on heap to avoid stack overflow
    context = calloc(1, sizeof(Context));
    if (context == NULL) {
        perror("malloc");
        return 1;
    }
    context->tun_mtu       = TUN_MTU; // Set default MTU
    context->mtu_discovery = 0;       // MTU discovery disabled by default

    // Initialize packet counter
    context->packet_counter = 0;

    // Parse command-line options
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if ((strcmp(argv[arg_start], "-k") == 0 || strcmp(argv[arg_start], "--key") == 0)) {
            if (arg_start + 1 >= argc) {
                fprintf(stderr, "Key option requires a file path\n");
                cleanup_context(context);
                free(context);
                return 1;
            }
            context->key_file = argv[arg_start + 1];
            arg_start += 2;
        } else if ((strcmp(argv[arg_start], "-m") == 0 || strcmp(argv[arg_start], "--mtu") == 0)) {
            if (arg_start + 1 >= argc) {
                fprintf(stderr, "MTU option requires a value\n");
                cleanup_context(context);
                free(context);
                return 1;
            }
            context->tun_mtu = atoi(argv[arg_start + 1]);
            if (context->tun_mtu < 68 || context->tun_mtu > 9000) {
                fprintf(stderr, "Invalid MTU value: %d (must be between 68 and 9000)\n",
                        context->tun_mtu);
                cleanup_context(context);
                free(context);
                return 1;
            }
            context->mtu_discovery = 0; // Disable discovery if MTU is manually set
            arg_start += 2;
        } else if ((strcmp(argv[arg_start], "-d") == 0 ||
                    strcmp(argv[arg_start], "--discover-mtu") == 0)) {
            context->mtu_discovery = 1;
            arg_start++;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[arg_start]);
            usage();
        }
    }

    if (argc - arg_start < 1) {
        usage();
    }

    context->is_server = strcmp(argv[arg_start], "server") == 0;

    context->server_ip_or_name = (argc <= arg_start + 1 || strcmp(argv[arg_start + 1], "auto") == 0)
                                     ? NULL
                                     : argv[arg_start + 1];
    if (context->server_ip_or_name == NULL && !context->is_server) {
        usage();
    }
    context->server_port      = (argc <= arg_start + 2 || strcmp(argv[arg_start + 2], "auto") == 0)
                                    ? DEFAULT_PORT
                                    : argv[arg_start + 2];
    context->wanted_if_name   = (argc <= arg_start + 3 || strcmp(argv[arg_start + 3], "auto") == 0)
                                    ? NULL
                                    : argv[arg_start + 3];
    context->local_tun_ip     = (argc <= arg_start + 4 || strcmp(argv[arg_start + 4], "auto") == 0)
                                    ? (context->is_server ? DEFAULT_SERVER_IP : DEFAULT_CLIENT_IP)
                                    : argv[arg_start + 4];
    context->remote_tun_ip    = (argc <= arg_start + 5 || strcmp(argv[arg_start + 5], "auto") == 0)
                                    ? (context->is_server ? DEFAULT_CLIENT_IP : DEFAULT_SERVER_IP)
                                    : argv[arg_start + 5];
    context->wanted_ext_gw_ip = (argc <= arg_start + 6 || strcmp(argv[arg_start + 6], "auto") == 0)
                                    ? NULL
                                    : argv[arg_start + 6];
    ext_gw_ip = context->wanted_ext_gw_ip ? context->wanted_ext_gw_ip : get_default_gw_ip();
    snprintf(context->ext_gw_ip, sizeof context->ext_gw_ip, "%s",
             ext_gw_ip == NULL ? "" : ext_gw_ip);
    if (ext_gw_ip == NULL && !context->is_server) {
        fprintf(stderr, "Unable to automatically determine the gateway IP\n");
        cleanup_context(context);
        free(context);
        return 1;
    }
    if ((context->ext_if_name = get_default_ext_if_name()) == NULL && context->is_server) {
        fprintf(stderr, "Unable to automatically determine the external interface\n");
        cleanup_context(context);
        free(context);
        return 1;
    }
    get_tun6_addresses(context);

    // Load encryption key if provided
    if (load_key(context) < 0) {
        cleanup_context(context);
        free(context);
        return 1;
    }

    // Initialize random value for packet header using /dev/urandom
    if (get_random_bytes(&context->packet_random, sizeof(context->packet_random)) < 0) {
        perror("Failed to read from /dev/urandom");
        cleanup_context(context);
        free(context);
        return 1;
    }

    context->tun_fd = tun_create(context->if_name, context->wanted_if_name);
    if (context->tun_fd == -1) {
        perror("tun device creation");
        cleanup_context(context);
        free(context);
        return 1;
    }
    printf("Interface: [%s]\n", context->if_name);

    // Adjust MTU for encryption overhead
    int effective_mtu = get_effective_tun_mtu(context->tun_mtu, context->key_loaded);
    printf("MTU: %d bytes (effective: %d bytes, with authentication)\n", context->tun_mtu,
           effective_mtu);

    if (tun_set_mtu(context->if_name, effective_mtu) != 0) {
        perror("mtu");
    }
#ifdef __OpenBSD__
    pledge("stdio proc exec dns inet", NULL);
#endif
    context->firewall_rules_set = -1;
    if (context->server_ip_or_name != NULL &&
        resolve_ip(context->server_ip, sizeof context->server_ip, context->server_ip_or_name) !=
            0) {
        firewall_rules(context, 0, 1);
        cleanup_context(context);
        free(context);
        return 1;
    }
    if (context->is_server) {
        if (firewall_rules(context, 1, 0) != 0) {
            cleanup_context(context);
            free(context);
            return -1;
        }
#ifdef __OpenBSD__
        printf("\nAdd the following rule to /etc/pf.conf:\npass out from %s nat-to egress\n\n",
               context->remote_tun_ip);
#endif
    } else {
        firewall_rules(context, 0, 1);
    }
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    if (doit(context) != 0) {
        cleanup_context(context);
        free(context);
        return -1;
    }
    firewall_rules(context, 0, 0);
    puts("Done.");

    cleanup_context(context);
    free(context);
    return 0;
}