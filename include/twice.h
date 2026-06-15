#ifndef TWICE_H
#define TWICE_H 1

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#define VERSION_STRING "0.1.0"

// HiAE constants
#define HIAE_KEYBYTES 32   // 256-bit key
#define HIAE_NONCEBYTES 16 // 128-bit nonce (using our packet header)
#define HIAE_MACBYTES 16   // 128-bit authentication tag

#ifdef __NetBSD__
#define DEFAULT_MTU 1420
#else
#define DEFAULT_MTU 1420
#endif
#define TUN_MTU DEFAULT_MTU
#define RECONNECT_ATTEMPTS 100
#define MAX_PACKET_LEN 65536
#define TIMEOUT (60 * 1000)
#define ACCEPT_TIMEOUT (10 * 1000)
#define DEFAULT_CLIENT_IP "192.168.192.1"
#define DEFAULT_SERVER_IP "192.168.192.254"
#define DEFAULT_PORT "41194"

// MTU Discovery parameters
#define MTU_PROBE_MAGIC 0xFFFFFFFFFFFFFFFFULL // Magic value for MTU probe packets
#define MTU_MIN 576                           // Minimum MTU (IPv4 minimum)
#define MTU_MAX 9000                          // Maximum MTU to probe
#define MTU_PROBE_TIMEOUT_MS 500              // Timeout for each probe
#define MTU_PROBE_RETRIES 2                   // Number of retries per size
#define MTU_OVERHEAD 46                       // UDP + IP + encapsulation overhead

// Reordering parameters
#define REORDER_WINDOW_SIZE 1024     // Large buffer for severe reordering
#define REORDER_TIMEOUT_MS 2000      // 2 seconds for satellite/poor networks
#define REORDER_CHECK_INTERVAL_MS 50 // Check every 50ms to reduce overhead

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && !defined(NATIVE_BIG_ENDIAN)
#define NATIVE_BIG_ENDIAN
#endif

#ifdef NATIVE_BIG_ENDIAN
#define endian_swap16(x) __builtin_bswap16(x)
#define endian_swap32(x) __builtin_bswap32(x)
#define endian_swap64(x) __builtin_bswap64(x)
#else
#define endian_swap16(x) (x)
#define endian_swap32(x) (x)
#define endian_swap64(x) (x)
#endif

extern volatile sig_atomic_t exit_signal_received;

// 128-bit packet header: 64-bit random value + 64-bit counter
typedef struct __attribute__((packed)) PacketHeader_ {
    uint64_t random_value; // Random value initialized once at startup
    uint64_t counter;      // Counter incremented for each packet
} PacketHeader;

// UDP packet structure with header and tag
typedef struct __attribute__((aligned(16))) UdpBuf_ {
    PacketHeader  header;               // 128-bit header/nonce (16 bytes)
    unsigned char data[MAX_PACKET_LEN]; // TUN frame data (will be encrypted)
    unsigned char tag[HIAE_MACBYTES];   // Authentication tag (16 bytes)
    size_t        pos;                  // Position for partial reads/writes
} UdpBuf;

// Buffered packet for reordering - preallocated
typedef struct BufferedPacket_ {
    int             occupied;             // Whether this slot is in use
    uint64_t        counter;              // Packet counter value
    size_t          len;                  // Data length
    struct timespec timestamp;            // When packet was buffered
    unsigned char   data[MAX_PACKET_LEN]; // Packet data (preallocated)
} BufferedPacket;

// Reordering state for a connection
typedef struct ReorderState_ {
    uint64_t expected_counter;   // Next expected packet counter
    uint64_t highest_processed;  // Highest counter we've processed
    uint64_t random_value;       // Expected random value from peer
    int      random_initialized; // Whether we've seen first packet

    // Sliding window parameters
    uint64_t window_base; // Lowest acceptable counter

    // Preallocated packet buffer - indexed by (counter % WINDOW_SIZE)
    BufferedPacket buffer[REORDER_WINDOW_SIZE];

    // Statistics
    uint64_t packets_received;
    uint64_t packets_duplicated;
    uint64_t packets_reordered;
    uint64_t packets_lost;
} ReorderState;

#endif