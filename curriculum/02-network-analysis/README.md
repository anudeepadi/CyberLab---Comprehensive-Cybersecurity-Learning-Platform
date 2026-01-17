# Module 02: Network Analysis

Master network packet analysis, traffic inspection, and forensic investigation techniques essential for cybersecurity professionals.

## Module Overview

Network analysis is a fundamental skill in cybersecurity. Whether you're detecting intrusions, investigating incidents, or performing penetration tests, understanding what happens at the packet level is crucial.

```
                    Network Analysis Skills
                           |
    ┌──────────┬───────────┼───────────┬──────────┐
    |          |           |           |          |
 Capture    Traffic    Protocol   Forensics   Scanning
    |       Analysis    Analysis      |          |
 tcpdump   Patterns     HTTP      PCAP        nmap
Wireshark  Anomalies    DNS       Evidence    ports
 Scapy     Baselines   TCP/UDP    Timeline   services
```

## Learning Objectives

By completing this module, you will be able to:

- Capture network traffic using tcpdump and Wireshark
- Analyze traffic patterns to identify suspicious activity
- Understand common protocols at the packet level (HTTP, DNS, TCP, UDP)
- Perform network forensics on PCAP files
- Understand and demonstrate Man-in-the-Middle attacks
- Conduct comprehensive network reconnaissance with scanning tools
- Craft custom packets using Scapy

## Labs in This Module

| Lab | Name | Duration | Difficulty |
|-----|------|----------|------------|
| 01 | Packet Capture Basics | 1 hr | Beginner |
| 02 | Traffic Analysis | 1.5 hrs | Intermediate |
| 03 | Protocol Analysis | 1.5 hrs | Intermediate |
| 04 | Network Forensics CTF | 2 hrs | Intermediate |
| 05 | Man-in-the-Middle Attacks | 1.5 hrs | Advanced |
| 06 | Network Scanning | 1.5 hrs | Intermediate |
| 07 | Packet Crafting with Scapy | 1 hr | Intermediate |
| 08 | Intrusion Detection | 1.5 hrs | Advanced |
| 09 | Network Defense & Firewalls | 1 hr | Intermediate |

**Total Duration:** ~12 hours

## Prerequisites

Before starting this module, you should have:

- Basic understanding of the OSI/TCP-IP model
- Familiarity with command-line operations
- Completed Module 01 (Foundations) or equivalent knowledge
- Docker environment running (for lab targets)

## Key Concepts

### The OSI Model and TCP/IP Stack

```
OSI Model          TCP/IP          Common Protocols
─────────         ────────         ────────────────
7. Application    Application      HTTP, HTTPS, FTP, DNS, SSH
6. Presentation       ↑
5. Session            |
4. Transport      Transport        TCP, UDP
3. Network        Internet         IP, ICMP, ARP
2. Data Link      Network Access   Ethernet, Wi-Fi
1. Physical           ↓            Cables, Signals
```

### Network Analysis Categories

| Category | Purpose | Tools |
|----------|---------|-------|
| **Passive** | Monitor without interfering | Wireshark, tcpdump, tshark |
| **Active** | Interact with targets | nmap, Scapy, netcat |
| **Forensic** | Post-incident investigation | Wireshark, Zeek, NetworkMiner |
| **Defensive** | Detection and prevention | Snort, Suricata, iptables |

## Tools Overview

### Packet Capture Tools

```bash
# tcpdump - Command-line packet analyzer
sudo tcpdump -i eth0 -w capture.pcap

# Wireshark - GUI packet analyzer
wireshark capture.pcap

# tshark - Terminal version of Wireshark
tshark -r capture.pcap -Y "http"
```

### Network Scanning Tools

```bash
# nmap - Network mapper and port scanner
nmap -sV -sC target.com

# netcat - Network utility knife
nc -zv target.com 20-100
```

### Packet Crafting

```python
# Scapy - Python packet manipulation
from scapy.all import *
pkt = IP(dst="target")/TCP(dport=80, flags="S")
send(pkt)
```

## Lab Environment

### Docker Services Used

| Service | Port | Purpose |
|---------|------|---------|
| Apache (Lab Dashboard) | 80 | Web interface for labs |
| DVWA | 8081 | Web vulnerability testing |
| Network Labs Web | - | Login capture demo |
| MITM Namespace | 10.0.0.x | Isolated network for MITM |

### Starting the Environment

```bash
# Start Docker services
cd /path/to/cyberlab/docker
docker-compose up -d

# Start MITM isolated network (for Lab 05)
sudo /opt/network-labs/mitm/setup-mitm-env.sh start

# Verify services
curl -s http://localhost/network-labs/ | head -5
```

## Directory Structure

```
02-network-analysis/
├── README.md                    # This file
├── 01-packet-capture-basics/
│   ├── README.md               # Lab overview
│   ├── walkthrough.md          # Step-by-step guide
│   └── hints.md                # Progressive hints
├── 02-traffic-analysis/
│   ├── README.md
│   ├── walkthrough.md
│   └── hints.md
├── 03-protocol-analysis/
│   ├── README.md
│   ├── walkthrough.md
│   └── hints.md
├── 04-network-forensics/
│   ├── README.md
│   ├── walkthrough.md
│   └── hints.md
├── 05-mitm-attacks/
│   ├── README.md
│   ├── walkthrough.md
│   └── hints.md
└── 06-network-scanning/
    ├── README.md
    ├── walkthrough.md
    └── hints.md
```

## Flags and Challenges

Several labs contain CTF-style challenges with flags:

| Challenge | Source | Format |
|-----------|--------|--------|
| PCAP Challenge 1-8 | Network Forensics Lab | `FLAG{...}` |
| Scapy Exercises | Packet Crafting Lab | Verification scripts |
| MITM Captures | MITM Lab | Captured credentials |

## Progression Path

```
Week 1: Labs 01-02
  Packet Capture → Traffic Analysis

Week 2: Labs 03-04
  Protocol Deep-Dive → Forensics CTF

Week 3: Labs 05-06
  MITM Attacks → Network Scanning

Week 4: Advanced Topics
  Packet Crafting → IDS → Defense
```

## Assessment Criteria

- [ ] Successfully capture and save network traffic
- [ ] Identify protocols and traffic patterns in PCAP files
- [ ] Complete at least 5 forensics challenges
- [ ] Demonstrate ARP spoofing in isolated environment
- [ ] Perform comprehensive port/service scan
- [ ] Write basic Snort detection rules

## Additional Resources

- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [tcpdump Manual](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [SANS Network Forensics Poster](https://www.sans.org/posters/)
- [Zeek (Bro) Documentation](https://docs.zeek.org/)

## Common Wireshark Filters Quick Reference

```
# Protocol filters
tcp                     # All TCP traffic
udp                     # All UDP traffic
http                    # HTTP traffic
dns                     # DNS queries and responses
icmp                    # ICMP (ping) traffic
arp                     # ARP requests/replies

# Host filters
ip.addr == 192.168.1.1      # Traffic to/from IP
ip.src == 192.168.1.1       # Traffic from IP
ip.dst == 192.168.1.1       # Traffic to IP

# Port filters
tcp.port == 80              # TCP port 80
udp.port == 53              # UDP port 53
tcp.dstport == 443          # Destination port 443

# Content filters
http.request.method == "POST"   # HTTP POST requests
http.host contains "example"    # Hostname contains text
tcp.flags.syn == 1              # TCP SYN packets
```

---

**Next:** Start with [Lab 01: Packet Capture Basics](./01-packet-capture-basics/README.md)
