# Networking Fundamentals - Hints

Reference hints for networking exercises. Use when stuck, but try solving problems yourself first.

## IP Address and Interface Hints

### Hint: Finding your IP address
- Use `ip addr show` (modern) or `ifconfig` (legacy)
- Quick method: `hostname -I`
- Look for `inet` entries (IPv4) or `inet6` (IPv6)

### Hint: Identifying your gateway
- `ip route | grep default` shows default gateway
- Gateway is the IP after "via"
- Usually ends in .1 (e.g., 192.168.1.1)

### Hint: Understanding interface names
- `eth0`, `eth1`: Wired Ethernet
- `wlan0`: Wireless
- `lo`: Loopback (127.0.0.1)
- `docker0`, `br-*`: Docker networks
- `tun0`, `tap0`: VPN tunnels

### Hint: No IP address showing
- Interface might be down: `sudo ip link set eth0 up`
- Need DHCP: `sudo dhclient eth0`
- Check cable/WiFi connection

---

## DNS Hints

### Hint: dig command not working
- Install with: `sudo apt install dnsutils`
- Alternative: use `nslookup` or `host`

### Hint: Understanding dig output
```
;; QUESTION SECTION:
;example.com.                   IN      A

;; ANSWER SECTION:
example.com.            300     IN      A       93.184.216.34
```
- Question: What you asked for
- Answer: The result
- 300: TTL (time to live) in seconds

### Hint: DNS not resolving
- Check `/etc/resolv.conf` for nameserver entries
- Try public DNS: `dig @8.8.8.8 example.com`
- Check if DNS port is blocked: `nc -zv 8.8.8.8 53`

### Hint: Common DNS record types
- A: IPv4 address
- AAAA: IPv6 address
- MX: Mail server (priority number)
- NS: Authoritative name server
- CNAME: Alias to another domain
- TXT: Text records (SPF, DKIM, verification)

---

## Port and Service Hints

### Hint: Understanding ss output
```
LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
```
- LISTEN: State (listening for connections)
- 0.0.0.0:22: Listening on all interfaces, port 22
- sshd: Process name

### Hint: Port numbers to remember
```
22   = SSH
80   = HTTP
443  = HTTPS
25   = SMTP
53   = DNS
3306 = MySQL
5432 = PostgreSQL
```

### Hint: Finding what's using a port
```bash
sudo lsof -i :80      # What's on port 80
sudo ss -tlnp | grep :80
sudo netstat -tlnp | grep :80
```

### Hint: Testing if a port is open
```bash
nc -zv hostname 80    # Check port 80
telnet hostname 80    # Interactive test
curl http://hostname  # HTTP test
```

---

## Connectivity Hints

### Hint: ping not working
- Target might block ICMP
- Try with sudo: `sudo ping -c 4 target`
- Check firewall rules
- Try traceroute instead

### Hint: Understanding ping output
```
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=15.2 ms
```
- 64 bytes: Packet size
- icmp_seq: Sequence number
- ttl: Time to live (hops remaining)
- time: Round-trip time

### Hint: High ping times
- Normal: < 50ms local, < 100ms internet
- High: 200ms+ indicates congestion or distance
- Packet loss: Check for `DUP!` or missing sequences

### Hint: traceroute interpretation
```
 1  192.168.1.1 (192.168.1.1)  1.234 ms
 2  * * *
 3  core-router.isp.com (10.0.0.1)  15.234 ms
```
- Line 1: Your gateway (fast, local)
- Line 2: Asterisks = router doesn't respond to ICMP
- Line 3: ISP router (look at hostname for clues)

---

## ARP Hints

### Hint: ARP cache empty or incomplete
- Need to communicate with device first
- Ping devices to populate: `ping -c 1 192.168.1.1`
- Entries expire after timeout

### Hint: Understanding ARP states
- REACHABLE: Recently confirmed
- STALE: Not recently used
- DELAY: Waiting for reconfirmation
- FAILED: No response received

### Hint: MAC address format
```
AA:BB:CC:DD:EE:FF  or  AA-BB-CC-DD-EE-FF
```
- First 3 octets: Manufacturer (OUI)
- Last 3 octets: Device-specific
- Lookup: https://macvendors.com/

### Hint: Suspicious ARP entries
- Same MAC for multiple IPs: Possible ARP spoofing
- Different MACs for same IP over time: Attack indicator

---

## Subnetting Hints

### Hint: Quick subnet calculations
```
/24 = 256 addresses = 254 hosts
/25 = 128 addresses = 126 hosts
/26 = 64 addresses = 62 hosts
/27 = 32 addresses = 30 hosts
/28 = 16 addresses = 14 hosts
/29 = 8 addresses = 6 hosts
/30 = 4 addresses = 2 hosts
/32 = 1 address = single host
```

### Hint: Finding network address
- Convert to binary, AND with mask
- Or use: `ipcalc IP/CIDR`

### Hint: Common private ranges
```
10.0.0.0/8       = 10.x.x.x
172.16.0.0/12    = 172.16.x.x - 172.31.x.x
192.168.0.0/16   = 192.168.x.x
```

### Hint: Is this IP routable?
- Private ranges (above) = NOT routable on internet
- 127.x.x.x = Loopback, local only
- 169.254.x.x = Link-local, no DHCP
- Everything else = Routable

---

## Protocol Hints

### Hint: TCP vs UDP quick reference
**TCP** (Connection-oriented, reliable):
- HTTP/HTTPS, SSH, FTP, SMTP
- Three-way handshake required
- Guaranteed delivery

**UDP** (Connectionless, fast):
- DNS, DHCP, SNMP, streaming
- No handshake
- No guarantee

### Hint: TCP flags
```
SYN     = Start connection
SYN-ACK = Acknowledge SYN
ACK     = Acknowledge data
FIN     = End connection
RST     = Reset/abort
PSH     = Push data immediately
```

### Hint: Identifying protocols by port
- See well-known ports: `/etc/services`
- `grep "80/tcp" /etc/services`

---

## Troubleshooting Hints

### Hint: No network connectivity
1. Check interface status: `ip link show`
2. Check IP assignment: `ip addr show`
3. Check gateway: `ip route show`
4. Ping gateway: `ping -c 1 GATEWAY_IP`
5. Ping external IP: `ping -c 1 8.8.8.8`
6. Test DNS: `dig google.com`

### Hint: Can reach by IP but not hostname
- DNS issue
- Check `/etc/resolv.conf`
- Try: `dig @8.8.8.8 hostname`

### Hint: Intermittent connectivity
- Check for packet loss: `ping -c 100 target`
- Look for routing changes: `mtr target`
- Check interface errors: `ip -s link show eth0`

### Hint: Slow network
- Check latency: `ping target`
- Check bandwidth: `speedtest-cli`
- Check for congestion: `iftop`

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| Show IP addresses | `ip addr show` |
| Show routing table | `ip route show` |
| Show ARP cache | `ip neigh show` |
| DNS lookup | `dig domain.com` |
| Listening ports | `ss -tulnp` |
| Ping test | `ping -c 4 target` |
| Trace route | `traceroute target` |
| Check port open | `nc -zv host port` |
| Capture packets | `sudo tcpdump -i eth0` |
| Subnet calc | `ipcalc IP/CIDR` |

---

## Still Stuck?

1. Check if you need sudo/root privileges
2. Verify the target is reachable (might be down/blocked)
3. Check your firewall isn't blocking traffic
4. Try alternative tools (nslookup vs dig, netstat vs ss)
5. Read error messages carefully - they often tell you exactly what's wrong
6. Consult man pages: `man command`

Remember: Network troubleshooting is systematic - always start from Layer 1 (physical) and work up!
