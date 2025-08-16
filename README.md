# twice - UDP-based VPN

A simple, fast UDP-based VPN software based on dsvpn. twice provides basic VPN functionality using UDP transport with optional HiAE authenticated encryption - suitable for both secure and insecure networks depending on configuration.

## Features

- UDP-based transport (no TCP overhead)
- Optional HiAE authenticated encryption
- Automatic MTU discovery for optimal performance
- Packet deduplication and reordering handling
- Non-blocking I/O everywhere
- Cross-platform support (Linux, macOS, BSD variants)
- Simple client/server architecture
- Automatic routing and firewall configuration

## Security

### Without Encryption (Default)

By default, **twice provides NO encryption or authentication.** All traffic is sent in plaintext over UDP. Only use this mode:
- On trusted internal networks
- Behind other security measures (like IPsec)
- For testing or development purposes
- As a foundation for building more secure solutions

### With HiAE Encryption (Optional)

When configured with a key file, twice uses HiAE (High-Throughput Authenticated Encryption):
- **AES-based AEAD cipher** with 256-bit keys
- **128-bit authentication tags** prevent tampering and replay attacks
- **Unique nonce per packet** ensures security
- **Hardware acceleration** on modern CPUs (AES-NI, ARM Crypto Extensions)

## Building

```bash
make
```

## Usage

### Server Mode

Start a UDP VPN server listening on all interfaces, port 1194:

```bash
sudo ./twice server auto
```

Or specify a specific interface and port:

```bash
sudo ./twice server 0.0.0.0 1194
```

### Client Mode

Connect to a UDP VPN server:

```bash
sudo ./twice client <server-ip>
```

Or specify a custom port:

```bash
sudo ./twice client <server-ip> 1194
```

### Command Line Arguments

```
twice genkey [keyfile]                  # Generate 256-bit encryption key
twice [-k <keyfile>] [-m <mtu>] [-d] server [bind-ip|auto] [port|auto] [tun-interface|auto] [local-tun-ip|auto] [remote-tun-ip|auto] [external-ip|auto]
twice [-k <keyfile>] [-m <mtu>] [-d] client <server-ip> [port|auto] [tun-interface|auto] [local-tun-ip|auto] [remote-tun-ip|auto] [gateway-ip|auto]
```

**Options:**
- `-k, --key <file>`: Path to 256-bit key file for encryption
- `-m, --mtu <mtu>`: Set TUN interface MTU in bytes (default: 1420, range: 68-9000)
- `-d, --discover-mtu`: Automatically discover optimal MTU (client only)

**Arguments:**
- `bind-ip` (server only): IP address to bind to (default: all interfaces)
- `server-ip` (client only): VPN server IP address
- `port`: UDP port number (default: 1194)
- `tun-interface`: TUN interface name (default: auto-assigned)
- `local-tun-ip`: Local tunnel IP address (default: 192.168.192.254 for server, 192.168.192.1 for client)
- `remote-tun-ip`: Remote tunnel IP address (default: 192.168.192.1 for server, 192.168.192.254 for client)
- `external-ip`: External interface IP (server) or gateway IP (client) for routing

Use "auto" for any parameter to use default values.

## Encryption Setup

### Generating a Key File

Create a 256-bit (32-byte) random key file that both server and client will use:

```bash
# Method 1: Use the built-in command (recommended)
./twice genkey                  # Creates vpn.key
./twice genkey mykey.key        # Creates mykey.key with custom name

# Method 2: Generate manually with dd
dd if=/dev/urandom of=vpn.key bs=32 count=1

# Method 3: Generate with openssl
openssl rand -out vpn.key 32

# Verify key size (should be exactly 32 bytes)
ls -l vpn.key
wc -c vpn.key  # Should output: 32 vpn.key
```

**Important:** 
- The key file must be **exactly 32 bytes** (256 bits)
- Use the **same key file** on both server and client
- Keep the key file **secure** - anyone with this file can decrypt your traffic
- Transfer the key file **securely** to the client (use SSH, not email or unencrypted methods)

### Using Encryption

**Server with encryption:**
```bash
sudo ./twice -k vpn.key server auto
```

**Client with encryption:**
```bash
sudo ./twice -k vpn.key client <server-ip>
```

### Encryption Examples

**Basic encrypted VPN:**
```bash
# Server
sudo ./twice --key /path/to/vpn.key server auto

# Client
sudo ./twice --key /path/to/vpn.key client 10.0.1.100
```

**Encrypted VPN with custom MTU:**
```bash
# Server (MTU adjusted for encryption overhead)
sudo ./twice -k vpn.key -m 1404 server auto

# Client
sudo ./twice -k vpn.key -m 1404 client 10.0.1.100
```

**Encrypted VPN with MTU discovery:**
```bash
# Client with automatic MTU discovery (accounts for encryption overhead)
sudo ./twice -k vpn.key -d client 10.0.1.100
```

### Encryption Notes

- **Overhead:** Encryption adds 16 bytes per packet for the authentication tag
- **MTU:** When using encryption, the effective TUN MTU is automatically reduced by 16 bytes
- **Performance:** HiAE uses hardware AES acceleration when available (AES-NI on x86, ARM Crypto Extensions on ARM)
- **Compatibility:** Both server and client must use the same key file, or both must run without encryption

## Examples

### Basic Setup (No Encryption)

**Server:**

```bash
sudo ./twice server
```

**Client:**

```bash
sudo ./twice client 10.0.1.100
```

### Custom Configuration

**Server with custom settings:**

```bash
sudo ./twice server 10.0.1.100 2194 tun0 10.8.0.1 10.8.0.2
```

**Client with custom settings:**

```bash
sudo ./twice client 10.0.1.100 2194 tun1 10.8.0.2 10.8.0.1
```

### MTU Examples

**Automatic MTU discovery:**

```bash
# Client automatically discovers optimal MTU
sudo ./twice -d client 10.0.1.100
```

**Conservative MTU for problematic networks:**

```bash
# Server
sudo ./twice -m 1380 server auto

# Client  
sudo ./twice -m 1380 client 10.0.1.100
```

**PPPoE-friendly MTU:**

```bash
# Server
sudo ./twice --mtu 1412 server auto

# Client
sudo ./twice --mtu 1412 client 10.0.1.100
```

## How It Works

1. **TUN Interface**: Creates a virtual network interface for routing packets
2. **UDP Encapsulation**: Wraps TUN frames in UDP packets with 16-byte header
3. **Packet Management**: Handles packet reordering, deduplication, and buffering
4. **MTU Discovery**: Automatically finds optimal MTU using binary search probing
5. **Non-blocking I/O**: Uses poll() for efficient event handling
6. **Server**: Listens on UDP port and tracks the latest client address
7. **Client**: Connects to server and maintains the connection
8. **Routing**: Automatically configures system routing tables and firewall rules

## Packet Format

### Without Encryption
UDP packets contain:
```
+--------+--------+--------+--------+
| Random Value (8 bytes)            |
+--------+--------+--------+--------+
| Counter (8 bytes)                 |
+--------+--------+--------+--------+
| TUN frame data                    |
| (variable length, plaintext)      |
+--------+--------+--------+--------+
```

### With Encryption (HiAE)
UDP packets contain:
```
+--------+--------+--------+--------+
| Random Value (8 bytes)            |
+--------+--------+--------+--------+
| Counter (8 bytes)                 |
+--------+--------+--------+--------+
| Encrypted TUN frame data          |
| (variable length, ciphertext)     |
+--------+--------+--------+--------+
| Authentication Tag (16 bytes)     |
+--------+--------+--------+--------+
```

The packet header (16 bytes) serves dual purposes:

- **Packet identification**: Random value (64-bit) + Counter (64-bit)
- **Encryption nonce**: The entire 128-bit header is used as the nonce for HiAE

When encryption is enabled:

- **Data is encrypted** using HiAE with the provided 256-bit key
- **Authentication tag** (16 bytes) is appended to verify integrity and authenticity
- **Invalid packets** (failed authentication) are silently dropped

Note: No explicit length field is needed since UDP provides the packet length.

## Automatic MTU Discovery

twice includes an automatic MTU discovery feature that finds the optimal Maximum Transmission Unit for your network path. This ensures maximum performance without packet fragmentation.

### How It Works

When enabled with the `-d` flag, the client:

1. **Sends probe packets** of various sizes to the server
2. **Uses binary search** between 576 (minimum) and 9000 (maximum) bytes
3. **Identifies probe packets** using a special magic header (0xFFFFFFFFFFFFFFFF)
4. **Server echoes** probe packets back unchanged
5. **Determines optimal MTU** based on successful round-trips
6. **Automatically configures** the TUN interface with the discovered MTU

### Usage

```bash
# Enable automatic MTU discovery on client
sudo ./twice -d client <server-ip>
```

The discovery process typically takes 5-10 seconds and happens during initial connection. When encryption is enabled, the discovery automatically accounts for the 16-byte authentication tag overhead.

## Packet Deduplication and Reordering

twice implements sophisticated packet management to handle unreliable network conditions:

### Deduplication

- **Duplicate Detection**: Uses 64-bit packet counters to identify and drop duplicate packets
- **Statistics Tracking**: Monitors duplicate packet rates for diagnostics
- **Zero Overhead**: No additional memory or CPU cost for normal operation

### Reordering Handling

- **Sliding Window**: Maintains a 1024-packet reordering buffer
- **Out-of-Order Buffering**: Temporarily stores future packets until missing ones arrive
- **Timeout Recovery**: Delivers buffered packets after 2-second timeout to prevent stalls
- **Automatic Recovery**: Handles peer restarts by detecting random value changes

### Benefits

- **Resilient to packet loss**: Continues operating smoothly even with 5-10% packet loss
- **Handles burst reordering**: Can reorder up to 1024 out-of-sequence packets
- **No performance impact**: Preallocated buffers ensure consistent memory usage
- **Automatic recovery**: Self-heals from network disruptions without manual intervention

## MTU Handling and Fragmentation Prevention

twice implements comprehensive MTU handling to prevent packet fragmentation, which can severely impact VPN performance.

### Default MTU

The default TUN interface MTU is **1420 bytes**, which provides:
- 80 bytes headroom for encapsulation overhead
- Compatibility with most internet paths (even PPPoE links with 1492 MTU)
- Prevention of fragmentation on standard Ethernet networks (1500 MTU)

### MTU Override

You can customize the TUN MTU using the `-m` or `--mtu` option:

```bash
# Set custom MTU for both server and client
sudo ./twice -m 1380 server auto
sudo ./twice --mtu 1380 client 10.0.1.100
```

### Fragmentation Prevention Features

1. **TCP MSS Clamping**: Automatically modifies TCP SYN packets to clamp the Maximum Segment Size (MSS) to `MTU - 40` bytes, preventing TCP from generating oversized segments.

2. **Packet Size Monitoring**: Logs warnings for packets larger than 1500 bytes and drops packets that would definitely cause fragmentation.

3. **Encapsulation Overhead Calculation**: Accounts for UDP (8 bytes) + IP (20+ bytes) + packet header (16 bytes) + optional authentication tag (16 bytes when encryption is enabled).

### MTU Testing and Optimization

To find the optimal MTU for your network path:

1. **Test with ping and DF (Don't Fragment) flag**:
   ```bash
   # Test from client side through the VPN tunnel
   ping -M do -s 1372 <remote-ip>  # 1372 + 28 (IP+ICMP) = 1400
   ping -M do -s 1392 <remote-ip>  # 1392 + 28 = 1420
   ```

2. **Gradually increase packet size** until fragmentation occurs:
   ```bash
   # If this works, try larger sizes
   ping -M do -s 1432 <remote-ip>  # 1460 total
   ping -M do -s 1452 <remote-ip>  # 1480 total
   ```

3. **Set MTU based on largest successful ping**:
   - If 1392-byte ping works: use MTU 1420
   - If 1372-byte ping works but 1392 fails: use MTU 1400
   - If 1352-byte ping works but 1372 fails: use MTU 1380

### MTU Troubleshooting

**Symptoms of MTU issues:**
- Slow file transfers or web browsing
- Some websites load partially or not at all
- SSH/HTTPS connections hang during authentication
- Large ping packets fail

**Solutions:**
1. **Reduce TUN MTU**:
   ```bash
   sudo ./twice -m 1380 client <server-ip>
   ```

2. **Check path MTU**:
   ```bash
   # Test path to VPN server
   ping -M do -s 1472 <vpn-server-ip>  # 1500 total
   ping -M do -s 1452 <vpn-server-ip>  # 1480 total
   ```

3. **Common MTU values for different scenarios**:
   - **1420**: Default, safe for most networks
   - **1400**: Conservative, good for problematic links
   - **1380**: Very conservative, for heavily encapsulated networks
   - **1280**: Minimum IPv6 MTU, maximum compatibility

**Network-specific considerations:**
- **PPPoE connections**: Use 1412 or lower (1492 - 80 overhead)
- **Mobile/cellular**: Use 1400 or lower
- **Corporate networks**: May require 1380 or lower due to additional encapsulation
- **Cloud providers**: Check documentation for recommended values

## Platform Support

- **Linux**: Full support with iptables integration
- **macOS**: Full support with route command integration  
- **BSD variants**: Full support (OpenBSD, FreeBSD, NetBSD, DragonFly)

## Differences from DSVPN

- Uses UDP instead of TCP transport
- Optional HiAE encryption instead of mandatory XChaCha20-Poly1305
- Simplified packet format when encryption is disabled
- No key exchange - uses pre-shared keys when encryption is enabled
- Single client per server (latest client wins)
- Default port changed to 1194 (OpenVPN standard)

## Installation

```bash
make install
```

This installs `twice` to `/usr/local/sbin/`. You can change the prefix:

```bash
make install PREFIX=/usr
```

## Troubleshooting

### Permission Issues
twice requires root privileges to create TUN interfaces and modify routing tables:

```bash
sudo ./twice server
```

### TUN Interface Creation
If TUN interface creation fails on Linux, ensure the TUN module is loaded:

```bash
sudo modprobe tun
```

### Firewall Issues

twice automatically configures firewall rules. If connection fails:
1. Check if iptables/pf is blocking UDP traffic
2. Verify the server is listening: `netstat -un | grep 1194`
3. Test UDP connectivity: `nc -u server-ip 1194`

### Routing Issues

If packets aren't routed correctly:
1. Check routing table: `ip route` (Linux) or `route -n get default` (macOS/BSD)
2. Verify TUN interface is up: `ip link show` (Linux) or `ifconfig` (macOS/BSD)
3. Check if IP forwarding is enabled on server: `sysctl net.ipv4.ip_forward`

### MTU and Fragmentation Issues

If experiencing slow connections or partial website loading:

1. **Check current MTU**:
   ```bash
   # Linux
   ip link show <tun-interface>
   
   # macOS/BSD
   ifconfig <tun-interface>
   ```

2. **Test with smaller MTU**:
   ```bash
   sudo ./twice -m 1380 client <server-ip>
   ```

3. **Verify no fragmentation**:
   ```bash
   # Test through tunnel with DF flag
   ping -M do -s 1372 <remote-ip>
   ```

4. **Check for MSS clamping**:
   ```bash
   # Monitor TCP SYN packets to verify MSS is being clamped
   tcpdump -i <tun-interface> -n tcp[tcpflags] \& 0x02 != 0
