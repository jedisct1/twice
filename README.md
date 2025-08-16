# twice - UDP-based VPN

A simple, fast UDP-based VPN software based on dsvpn. twice provides basic VPN functionality using UDP transport without encryption or authentication - suitable for secure internal networks or as a building block for other tools.

## Features

- UDP-based transport (no TCP overhead)
- No encryption or authentication (raw TUN frame encapsulation)
- Non-blocking I/O everywhere
- Cross-platform support (Linux, macOS, BSD variants)
- Simple client/server architecture
- Automatic routing and firewall configuration

## Security Warning

**twice provides NO encryption or authentication.** All traffic is sent in plaintext over UDP. Only use this:
- On trusted internal networks
- Behind other security measures (like IPsec)
- For testing or development purposes
- As a foundation for building more secure solutions

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

Both server and client accept these optional arguments:

```
twice [-m|--mtu <mtu>] server [bind-ip|auto] [port|auto] [tun-interface|auto] [local-tun-ip|auto] [remote-tun-ip|auto] [external-ip|auto]
twice [-m|--mtu <mtu>] client <server-ip> [port|auto] [tun-interface|auto] [local-tun-ip|auto] [remote-tun-ip|auto] [gateway-ip|auto]
```

**Options:**
- `-m, --mtu <mtu>`: Set TUN interface MTU in bytes (default: 1420, range: 68-9000)

**Arguments:**
- `bind-ip` (server only): IP address to bind to (default: all interfaces)
- `server-ip` (client only): VPN server IP address
- `port`: UDP port number (default: 1194)
- `tun-interface`: TUN interface name (default: auto-assigned)
- `local-tun-ip`: Local tunnel IP address (default: 192.168.192.254 for server, 192.168.192.1 for client)
- `remote-tun-ip`: Remote tunnel IP address (default: 192.168.192.1 for server, 192.168.192.254 for client)
- `external-ip`: External interface IP (server) or gateway IP (client) for routing

Use "auto" for any parameter to use default values.

## Examples

### Basic Setup

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
2. **UDP Encapsulation**: Wraps TUN frames in simple UDP packets (2-byte length + data)
3. **Non-blocking I/O**: Uses poll() for efficient event handling
4. **Server**: Listens on UDP port and tracks the latest client address
5. **Client**: Connects to server and maintains the connection
6. **Routing**: Automatically configures system routing tables and firewall rules

## Packet Format

UDP packets contain:
```
+--------+--------+--------+--------+
| Length (2 bytes, network order)   |
+--------+--------+--------+--------+
| TUN frame data                    |
| (variable length)                 |
+--------+--------+--------+--------+
```

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

3. **Encapsulation Overhead Calculation**: Accounts for UDP (8 bytes) + IP (20+ bytes) + length header (2 bytes) when checking packet sizes.

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
- Removes all encryption and authentication
- Simplified packet format (no authentication tags)
- No key exchange or cryptographic operations
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
   ```

## License

Based on dsvpn by Frank Denis. See original dsvpn license for details.