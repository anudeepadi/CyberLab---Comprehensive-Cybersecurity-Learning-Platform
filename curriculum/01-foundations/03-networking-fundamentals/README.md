# Lab 03: Networking Fundamentals

## Introduction

Networks are the battlefield of cybersecurity. Every attack traverses a network; every defense monitors one. Understanding how data flows from one system to another - through layers of protocols, across ports, and via various addressing schemes - is essential knowledge for any security professional.

This lab covers the foundational networking concepts you'll use daily: the OSI and TCP/IP models, IP addressing, common protocols, and the ports they use. You'll learn to think like a packet, understanding its journey through the network.

## Learning Objectives

- Understand the OSI and TCP/IP networking models
- Master IP addressing and subnetting basics
- Identify common protocols and their purposes
- Know essential ports and services
- Analyze network traffic conceptually
- Use basic network diagnostic commands

## The OSI Model

The Open Systems Interconnection (OSI) model describes how data moves through a network in seven layers. Understanding this model helps you pinpoint where security issues occur.

```
Layer 7: Application    - HTTP, FTP, DNS, SMTP (user-facing protocols)
Layer 6: Presentation   - SSL/TLS, encryption, data formatting
Layer 5: Session        - Session management, authentication
Layer 4: Transport      - TCP, UDP (reliable/unreliable delivery)
Layer 3: Network        - IP, ICMP, routing (logical addressing)
Layer 2: Data Link      - MAC addresses, switches (physical addressing)
Layer 1: Physical       - Cables, signals, hardware
```

### Security Relevance by Layer

| Layer | Security Considerations |
|-------|------------------------|
| 7 - Application | SQL injection, XSS, application vulnerabilities |
| 6 - Presentation | SSL/TLS attacks, encryption weaknesses |
| 5 - Session | Session hijacking, authentication bypass |
| 4 - Transport | Port scanning, SYN floods, connection hijacking |
| 3 - Network | IP spoofing, routing attacks, ICMP abuse |
| 2 - Data Link | ARP spoofing, MAC flooding, VLAN hopping |
| 1 - Physical | Cable tapping, hardware keyloggers |

### Data Encapsulation

As data descends through layers, each adds its header:

```
Application Data
    ↓
[TCP Header][Data]                    → Segment
    ↓
[IP Header][TCP Header][Data]         → Packet
    ↓
[Frame Header][IP][TCP][Data][FCS]    → Frame
```

## The TCP/IP Model

The practical model used in real networks has four layers:

```
Application Layer   - HTTP, FTP, DNS, SSH (combines OSI 5-7)
Transport Layer     - TCP, UDP (OSI Layer 4)
Internet Layer      - IP, ICMP (OSI Layer 3)
Network Access      - Ethernet, WiFi (OSI Layers 1-2)
```

## IP Addressing

### IPv4 Addresses

IPv4 uses 32-bit addresses written in dotted decimal notation:

```
192.168.1.100
```

Each octet ranges from 0-255. Total possible addresses: ~4.3 billion.

### Address Classes (Historical)

| Class | Range | Default Mask | Purpose |
|-------|-------|--------------|---------|
| A | 1.0.0.0 - 126.255.255.255 | 255.0.0.0 | Large networks |
| B | 128.0.0.0 - 191.255.255.255 | 255.255.0.0 | Medium networks |
| C | 192.0.0.0 - 223.255.255.255 | 255.255.255.0 | Small networks |

### Private IP Ranges (RFC 1918)

These addresses are not routable on the internet:

```
10.0.0.0    - 10.255.255.255    (10.0.0.0/8)
172.16.0.0  - 172.31.255.255    (172.16.0.0/12)
192.168.0.0 - 192.168.255.255   (192.168.0.0/16)
```

### Special Addresses

| Address | Purpose |
|---------|---------|
| 127.0.0.1 | Localhost (loopback) |
| 0.0.0.0 | All interfaces / default route |
| 255.255.255.255 | Broadcast |
| 169.254.x.x | Link-local (APIPA) - no DHCP |

### Subnet Masks and CIDR

Subnet masks separate the network portion from the host portion:

```
IP:      192.168.1.100
Mask:    255.255.255.0
Network: 192.168.1.0
Host:    .100

CIDR Notation: 192.168.1.100/24
```

Common CIDR blocks:

| CIDR | Mask | Usable Hosts |
|------|------|--------------|
| /8 | 255.0.0.0 | 16,777,214 |
| /16 | 255.255.0.0 | 65,534 |
| /24 | 255.255.255.0 | 254 |
| /25 | 255.255.255.128 | 126 |
| /26 | 255.255.255.192 | 62 |
| /27 | 255.255.255.224 | 30 |
| /28 | 255.255.255.240 | 14 |
| /30 | 255.255.255.252 | 2 |
| /32 | 255.255.255.255 | 1 (single host) |

## TCP vs UDP

### TCP (Transmission Control Protocol)

- **Connection-oriented**: Establishes connection before data transfer
- **Reliable**: Guarantees delivery, order, and integrity
- **Flow control**: Adjusts speed to prevent overwhelming receiver
- **Use cases**: HTTP, SSH, FTP, email

**TCP Three-Way Handshake:**

```
Client              Server
   |    SYN --->      |
   |   <--- SYN-ACK   |
   |    ACK --->      |
   |   Connection     |
   |   Established    |
```

**TCP Flags:**

| Flag | Name | Purpose |
|------|------|---------|
| SYN | Synchronize | Initiate connection |
| ACK | Acknowledge | Confirm receipt |
| FIN | Finish | Close connection |
| RST | Reset | Abort connection |
| PSH | Push | Send immediately |
| URG | Urgent | Priority data |

### UDP (User Datagram Protocol)

- **Connectionless**: No handshake required
- **Unreliable**: No delivery guarantee
- **Fast**: Lower overhead than TCP
- **Use cases**: DNS, DHCP, streaming, gaming

## Essential Ports and Services

Memorize these common port numbers:

### Well-Known Ports (0-1023)

| Port | Protocol | Service |
|------|----------|---------|
| 20, 21 | TCP | FTP (data, control) |
| 22 | TCP | SSH |
| 23 | TCP | Telnet (insecure!) |
| 25 | TCP | SMTP (email) |
| 53 | TCP/UDP | DNS |
| 67, 68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 (email) |
| 111 | TCP/UDP | RPC |
| 135 | TCP | Windows RPC |
| 139 | TCP | NetBIOS |
| 143 | TCP | IMAP |
| 161, 162 | UDP | SNMP |
| 389 | TCP | LDAP |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB |
| 636 | TCP | LDAPS |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |

### High Ports (Security Tools)

| Port | Service |
|------|---------|
| 1433 | MSSQL |
| 1521 | Oracle |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 5900 | VNC |
| 6379 | Redis |
| 8080 | HTTP Proxy/Alt |
| 8443 | HTTPS Alt |
| 27017 | MongoDB |

## Common Protocols

### DNS (Domain Name System)

Translates domain names to IP addresses:

```
www.example.com → 93.184.216.34
```

**DNS Record Types:**

| Type | Purpose |
|------|---------|
| A | IPv4 address |
| AAAA | IPv6 address |
| CNAME | Alias to another name |
| MX | Mail server |
| NS | Name server |
| TXT | Text records (SPF, DKIM) |
| PTR | Reverse DNS |
| SOA | Zone authority |

### DHCP (Dynamic Host Configuration Protocol)

Automatically assigns network configuration:

1. **Discover**: Client broadcasts request
2. **Offer**: Server offers IP address
3. **Request**: Client accepts offer
4. **Acknowledge**: Server confirms assignment

### ARP (Address Resolution Protocol)

Maps IP addresses to MAC addresses on local network:

```
Who has 192.168.1.1? Tell 192.168.1.100
192.168.1.1 is at AA:BB:CC:DD:EE:FF
```

**Security Note**: ARP has no authentication, enabling ARP spoofing attacks.

### ICMP (Internet Control Message Protocol)

Network diagnostics and error reporting:

| Type | Description |
|------|-------------|
| 0 | Echo Reply (ping response) |
| 3 | Destination Unreachable |
| 8 | Echo Request (ping) |
| 11 | Time Exceeded (traceroute) |

## Network Diagnostic Commands

### ip / ifconfig

View and configure network interfaces:

```bash
ip addr show              # Show all interfaces
ip route show             # Show routing table
ip neigh show             # Show ARP cache

# Legacy commands
ifconfig                  # Show interfaces
route -n                  # Show routes
arp -a                    # Show ARP cache
```

### ping

Test connectivity to a host:

```bash
ping -c 4 192.168.1.1     # Send 4 ICMP echo requests
ping -c 4 google.com      # Test DNS and connectivity
```

### traceroute / tracepath

Show the path packets take:

```bash
traceroute google.com
tracepath google.com
```

### netstat / ss

View network connections:

```bash
ss -tuln                  # TCP/UDP listening ports
ss -tunp                  # Include process names
netstat -an               # All connections
```

### dig / nslookup

DNS queries:

```bash
dig example.com           # Query DNS
dig example.com MX        # Query MX records
dig @8.8.8.8 example.com  # Use specific DNS server
nslookup example.com      # Alternative DNS lookup
```

### curl / wget

HTTP requests:

```bash
curl http://example.com              # GET request
curl -I http://example.com           # Headers only
curl -X POST -d "data" http://url    # POST request
wget http://example.com/file         # Download file
```

## Network Security Concepts

### Firewalls

Filter traffic based on rules:
- **Allow/Deny** by IP, port, protocol
- **Stateful** vs **Stateless** inspection
- Host-based vs Network-based

### NAT (Network Address Translation)

Translates private IPs to public IPs:
- Hides internal network structure
- Conserves public IP addresses
- Can complicate some attacks/defenses

### VPN (Virtual Private Network)

Creates encrypted tunnel over public network:
- Protects traffic confidentiality
- Used for remote access and site-to-site connections

## Hands-On Exercises

1. **Interface Investigation**: List all network interfaces and identify your IP address, subnet mask, and gateway

2. **DNS Exploration**: Query DNS for google.com's A, MX, and NS records

3. **Port Discovery**: List all listening ports on your system and identify the services

4. **Connectivity Testing**: Trace the route to a public website and analyze the hops

5. **ARP Analysis**: View your ARP cache and identify devices on your local network

## Summary

You've learned the foundational networking concepts:

- The OSI and TCP/IP models for understanding network layers
- IP addressing, subnetting, and private vs public addresses
- TCP (reliable) vs UDP (fast) transport protocols
- Essential ports and the services they represent
- Common protocols: DNS, DHCP, ARP, ICMP
- Diagnostic commands: ip, ping, traceroute, ss, dig

This knowledge is essential for network scanning, traffic analysis, and understanding how attacks propagate through networks.

## Next Steps

Continue to [Security Tools Introduction](../04-security-tools-intro/README.md) to start using practical security tools like nmap and Wireshark.
