# Lab 01: Packet Capture Basics

Learn the fundamentals of network packet capture using industry-standard tools: Wireshark and tcpdump.

## Lab Overview

| Attribute | Value |
|-----------|-------|
| **Difficulty** | Beginner |
| **Duration** | 1 hour |
| **Prerequisites** | Basic networking knowledge |
| **Tools** | Wireshark, tcpdump, tshark |
| **Target** | localhost / Docker services |

## Introduction

Packet capture is the foundation of network analysis. Every network security investigation starts with collecting and examining network traffic. In this lab, you'll learn to:

- Capture live network traffic
- Save captures to PCAP files
- Open and navigate PCAP files
- Apply basic capture and display filters
- Understand packet structure

## What is Packet Capture?

Packet capture (or packet sniffing) is the process of intercepting and logging network traffic. Tools like Wireshark and tcpdump can see all packets traveling across a network interface.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────>│   Network   │────>│   Server    │
│             │<────│   (Packets) │<────│             │
└─────────────┘     └──────┬──────┘     └─────────────┘
                          │
                    ┌─────▼─────┐
                    │  Packet   │
                    │  Capture  │
                    │   Tool    │
                    └───────────┘
```

## Why Packet Capture Matters

| Use Case | Description |
|----------|-------------|
| **Incident Response** | Investigate security breaches |
| **Network Troubleshooting** | Diagnose connectivity issues |
| **Forensics** | Gather evidence for legal proceedings |
| **Penetration Testing** | Understand target network behavior |
| **Malware Analysis** | Identify command-and-control traffic |
| **Performance Analysis** | Find bandwidth bottlenecks |

## Tools Introduction

### tcpdump

The classic command-line packet analyzer. Lightweight and available on most Unix/Linux systems.

```bash
# Basic syntax
tcpdump [options] [filter expression]

# Key options
-i <interface>    # Specify interface (eth0, lo, any)
-w <file>         # Write to PCAP file
-r <file>         # Read from PCAP file
-c <count>        # Capture only n packets
-n                # Don't resolve hostnames
-v, -vv, -vvv     # Verbosity levels
-A                # Print ASCII content
-X                # Print hex and ASCII
```

### Wireshark

The industry-standard GUI packet analyzer with powerful filtering and analysis features.

**Key Features:**
- Visual packet inspection
- Protocol dissection
- Follow TCP/HTTP streams
- Export objects from traffic
- Statistical analysis
- Color-coded protocols

### tshark

The command-line version of Wireshark. Useful for scripting and headless systems.

```bash
# Basic syntax
tshark [options] [filter]

# Key options
-i <interface>    # Capture interface
-r <file>         # Read PCAP file
-w <file>         # Write PCAP file
-Y <filter>       # Display filter
-T fields         # Field output format
-e <field>        # Specify field to extract
```

## Lab Exercises

### Exercise 1: Your First Capture with tcpdump

Capture packets on the loopback interface while generating HTTP traffic.

**Objective:** Understand basic tcpdump usage and packet output.

### Exercise 2: Save and Read PCAP Files

Learn to save captures for later analysis and read existing PCAP files.

**Objective:** Master PCAP file operations.

### Exercise 3: Introduction to Wireshark

Open a capture in Wireshark and explore the interface.

**Objective:** Navigate the Wireshark GUI effectively.

### Exercise 4: Capture Filters vs Display Filters

Understand the difference between capture-time and display-time filtering.

**Objective:** Apply appropriate filters for different scenarios.

### Exercise 5: Following Streams

Reconstruct complete conversations from captured packets.

**Objective:** Use Wireshark's stream following feature.

### Exercise 6: Capturing Credentials

Capture cleartext credentials from HTTP traffic.

**Objective:** Understand why encryption is critical.

## Capture Filter Syntax (BPF)

Capture filters use Berkeley Packet Filter (BPF) syntax and reduce the amount of data captured:

```bash
# Host filters
host 192.168.1.1          # Traffic to/from host
src host 192.168.1.1      # Traffic from host
dst host 192.168.1.1      # Traffic to host

# Port filters
port 80                   # Traffic on port 80
src port 443              # Traffic from port 443
dst port 22               # Traffic to port 22

# Protocol filters
tcp                       # TCP traffic only
udp                       # UDP traffic only
icmp                      # ICMP traffic only
arp                       # ARP traffic only

# Combining filters
tcp port 80               # TCP port 80
host 192.168.1.1 and port 80
not port 22               # Exclude SSH
```

## Display Filter Syntax (Wireshark)

Display filters are applied after capture and use Wireshark's own syntax:

```
# Protocol filters
http                      # HTTP traffic
dns                       # DNS traffic
tcp                       # TCP traffic

# Field-based filters
ip.addr == 192.168.1.1
tcp.port == 80
http.request.method == "GET"
dns.qry.name contains "google"

# Comparison operators
== (equal)
!= (not equal)
> < >= <= (numeric comparison)
contains (substring match)
matches (regex match)

# Logical operators
and, or, not, &&, ||, !
```

## Understanding Packet Structure

Each packet contains multiple layers of information:

```
┌─────────────────────────────────────────┐
│ Frame (Layer 2 - Ethernet)              │
│  - Source MAC Address                   │
│  - Destination MAC Address              │
│  - EtherType (0x0800 = IPv4)            │
├─────────────────────────────────────────┤
│ Internet Protocol (Layer 3 - IP)        │
│  - Source IP Address                    │
│  - Destination IP Address               │
│  - Protocol (6=TCP, 17=UDP, 1=ICMP)     │
│  - TTL, Length, Checksum                │
├─────────────────────────────────────────┤
│ Transport (Layer 4 - TCP/UDP)           │
│  - Source Port                          │
│  - Destination Port                     │
│  - Sequence/Acknowledgment Numbers      │
│  - Flags (SYN, ACK, FIN, RST)           │
├─────────────────────────────────────────┤
│ Application Data (Layer 7)              │
│  - HTTP Request/Response                │
│  - DNS Query/Response                   │
│  - Actual payload data                  │
└─────────────────────────────────────────┘
```

## Key Takeaways

1. **tcpdump** is ideal for quick captures and scripting
2. **Wireshark** provides powerful visual analysis
3. **Capture filters** reduce data volume during collection
4. **Display filters** help analyze after capture
5. **PCAP files** are the standard format for packet data
6. **Cleartext protocols** expose sensitive data

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Permission denied | Run with `sudo` |
| No packets captured | Check interface name with `ip a` |
| Wireshark won't capture | Add user to `wireshark` group |
| Can't see all traffic | May need promiscuous mode |
| Interface not found | Use `-i any` for all interfaces |

## Further Reading

- [tcpdump Manual Page](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)

---

**Next Steps:**
- Complete the [Walkthrough](./walkthrough.md) for hands-on practice
- Use [Hints](./hints.md) if you get stuck
- Proceed to [Lab 02: Traffic Analysis](../02-traffic-analysis/README.md)
