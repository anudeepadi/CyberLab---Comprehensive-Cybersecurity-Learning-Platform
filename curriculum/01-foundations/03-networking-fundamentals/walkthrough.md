# Networking Fundamentals - Walkthrough

This walkthrough provides hands-on exercises to reinforce networking concepts. Complete each exercise in your terminal.

## Exercise 1: Interface Investigation

### Step 1: List All Network Interfaces

Using the modern `ip` command:

```bash
ip addr show
```

Sample output explanation:

```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 00:0c:29:ab:cd:ef brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
```

- `eth0`: Interface name
- `UP`: Interface is active
- `link/ether`: MAC address
- `inet`: IPv4 address with CIDR notation
- `brd`: Broadcast address

### Step 2: Identify Your IP Configuration

Extract just the IP addresses:

```bash
ip -4 addr show | grep inet
```

Find your primary IP:

```bash
hostname -I
```

### Step 3: View the Routing Table

```bash
ip route show
```

Look for:
- `default via X.X.X.X` - Your gateway
- Routes to local networks

Alternative:

```bash
route -n
```

### Step 4: Identify Your Gateway

```bash
ip route | grep default
```

The gateway IP is after "via".

### Step 5: Find Your DNS Servers

```bash
cat /etc/resolv.conf
```

Look for `nameserver` lines.

---

## Exercise 2: DNS Exploration

### Step 1: Query A Record

Find the IP address for google.com:

```bash
dig google.com A
```

Look in the "ANSWER SECTION" for the IP address.

Shorter output:

```bash
dig +short google.com
```

### Step 2: Query MX Records

Find mail servers:

```bash
dig google.com MX
```

The numbers indicate priority (lower = preferred).

### Step 3: Query NS Records

Find authoritative name servers:

```bash
dig google.com NS
```

### Step 4: Query All Records

Get comprehensive DNS information:

```bash
dig google.com ANY
```

### Step 5: Reverse DNS Lookup

Find hostname from IP:

```bash
dig -x 8.8.8.8
```

### Step 6: Using a Specific DNS Server

Query using Google's DNS:

```bash
dig @8.8.8.8 example.com
```

Query using Cloudflare's DNS:

```bash
dig @1.1.1.1 example.com
```

### Step 7: Trace DNS Resolution

See the full resolution path:

```bash
dig +trace example.com
```

---

## Exercise 3: Port Discovery

### Step 1: List Listening TCP Ports

```bash
ss -tlnp
```

Flags explained:
- `-t`: TCP only
- `-l`: Listening sockets
- `-n`: Numeric (don't resolve names)
- `-p`: Show process (needs root for all processes)

With sudo for process info:

```bash
sudo ss -tlnp
```

### Step 2: List Listening UDP Ports

```bash
ss -ulnp
```

### Step 3: List All Listening Ports (TCP and UDP)

```bash
ss -tulnp
```

### Step 4: Find a Specific Port

Check if SSH is listening:

```bash
ss -tlnp | grep :22
```

Check if a web server is running:

```bash
ss -tlnp | grep -E ':80|:443'
```

### Step 5: View Established Connections

```bash
ss -tunp | grep ESTABLISHED
```

### Step 6: Count Connections by State

```bash
ss -t | awk '{print $1}' | sort | uniq -c
```

### Step 7: Using netstat (Legacy)

If netstat is available:

```bash
netstat -tulnp
```

---

## Exercise 4: Connectivity Testing

### Step 1: Basic Ping Test

Test connectivity to your gateway:

```bash
ping -c 4 $(ip route | grep default | awk '{print $3}')
```

### Step 2: Test Internet Connectivity

```bash
ping -c 4 8.8.8.8
```

### Step 3: Test DNS Resolution

```bash
ping -c 4 google.com
```

If this fails but 8.8.8.8 works, you have a DNS issue.

### Step 4: Traceroute to a Website

```bash
traceroute google.com
```

Or using tracepath (no root needed):

```bash
tracepath google.com
```

### Step 5: Analyze the Hops

Each line in traceroute shows:
- Hop number
- Router IP/hostname
- Round-trip times (3 measurements)

```
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.456 ms  1.678 ms
 2  10.0.0.1 (10.0.0.1)  5.123 ms  5.234 ms  5.345 ms
```

Look for:
- Large jumps in latency (bottlenecks)
- `* * *` (filtered/unresponsive routers)
- Hostnames revealing network ownership

### Step 6: TCP Traceroute

Some networks block ICMP. Use TCP:

```bash
sudo traceroute -T -p 80 google.com
```

---

## Exercise 5: ARP Analysis

### Step 1: View ARP Cache

```bash
ip neigh show
```

Or legacy command:

```bash
arp -a
```

### Step 2: Understanding ARP Output

```
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
```

- IP address of neighbor
- Interface used to reach it
- MAC address (lladdr = link layer address)
- State: REACHABLE, STALE, DELAY, etc.

### Step 3: Clear ARP Cache (Optional)

```bash
sudo ip neigh flush all
```

### Step 4: Ping Local Network to Populate ARP

Ping your gateway to add it to ARP cache:

```bash
ping -c 1 192.168.1.1
ip neigh show
```

### Step 5: Find Devices on Local Network

Ping broadcast address:

```bash
ping -c 1 -b 192.168.1.255 2>/dev/null
ip neigh show
```

Or use a simple scan:

```bash
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i is up" &
done
wait
```

---

## Exercise 6: Protocol Analysis

### Step 1: Capture DNS Traffic

Open two terminals.

Terminal 1 - Start capture (requires tcpdump):

```bash
sudo tcpdump -i any port 53 -n
```

Terminal 2 - Generate DNS query:

```bash
dig example.com
```

Observe the DNS request and response in Terminal 1.

### Step 2: Capture HTTP Traffic

Terminal 1:

```bash
sudo tcpdump -i any port 80 -A
```

Terminal 2:

```bash
curl http://example.com
```

You'll see the HTTP request headers in plain text.

### Step 3: Observe TCP Handshake

Terminal 1:

```bash
sudo tcpdump -i any port 80 -n
```

Terminal 2:

```bash
curl http://example.com
```

Look for the SYN, SYN-ACK, ACK sequence:

```
IP 192.168.1.100.54321 > 93.184.216.34.80: Flags [S], ...
IP 93.184.216.34.80 > 192.168.1.100.54321: Flags [S.], ...
IP 192.168.1.100.54321 > 93.184.216.34.80: Flags [.], ...
```

Flags: `[S]` = SYN, `[S.]` = SYN-ACK, `[.]` = ACK

---

## Exercise 7: Subnetting Practice

### Step 1: Calculate Network Address

Given: `192.168.1.100/24`

Network address = IP AND subnet mask

```bash
# Using ipcalc (install if needed: apt install ipcalc)
ipcalc 192.168.1.100/24
```

Output shows:
- Network address
- Broadcast address
- Usable host range

### Step 2: Manual Calculation

For `192.168.1.100/24`:
- Subnet mask: 255.255.255.0
- Network: 192.168.1.0
- Broadcast: 192.168.1.255
- First host: 192.168.1.1
- Last host: 192.168.1.254
- Total hosts: 254

### Step 3: Practice Different CIDR

Calculate for `/26`:

```bash
ipcalc 192.168.1.100/26
```

How many hosts per subnet?
/26 = 64 addresses - 2 = 62 usable hosts

---

## Challenge Exercises

### Challenge 1: Network Mapping

Without using nmap, discover all active hosts on your local /24 network using only ping and ARP.

### Challenge 2: Service Identification

For each listening port on your system, identify:
1. Port number
2. Protocol (TCP/UDP)
3. Service name
4. Process running it

### Challenge 3: DNS Investigation

For a domain of your choice, find:
1. All IP addresses (A records)
2. Mail servers (MX records)
3. Name servers (NS records)
4. Any TXT records

Create a report of your findings.

### Challenge 4: Trace Analysis

Run traceroute to three different websites and compare:
- Number of hops
- Geographic routing (if hostnames reveal location)
- Latency patterns

---

## Verification Checklist

Before proceeding, ensure you can:

- [ ] Find your IP address, subnet mask, and gateway
- [ ] Query DNS records using dig
- [ ] List listening ports and identify services
- [ ] Trace the route to a remote host
- [ ] View and interpret ARP cache entries
- [ ] Capture basic network traffic with tcpdump
- [ ] Calculate network addresses from CIDR notation

## Common Issues

### "Network is unreachable"
- Check if interface is up: `ip link show`
- Verify IP configuration: `ip addr show`
- Check routing: `ip route show`

### DNS not resolving
- Check `/etc/resolv.conf` for valid nameservers
- Try using a public DNS: `dig @8.8.8.8 example.com`

### Can ping IP but not hostname
- DNS issue - check resolver configuration
- Try `nslookup` or `dig` to diagnose

### traceroute shows all asterisks
- Firewall blocking ICMP
- Try TCP traceroute: `sudo traceroute -T destination`

## Next Steps

Continue to [Security Tools Introduction](../04-security-tools-intro/README.md) to start using professional security tools.
