# Lab 02: Traffic Analysis

Learn to analyze network traffic patterns to identify normal behavior, anomalies, and suspicious activity.

## Lab Overview

| Attribute | Value |
|-----------|-------|
| **Difficulty** | Intermediate |
| **Duration** | 1.5 hours |
| **Prerequisites** | Lab 01 - Packet Capture Basics |
| **Tools** | Wireshark, tshark, Zeek, netstat |
| **Target** | PCAP files, Live traffic |

## Introduction

Traffic analysis goes beyond capturing packets - it's about understanding what the traffic means. Security professionals use traffic analysis to:

- Establish baseline network behavior
- Detect anomalies and suspicious patterns
- Identify data exfiltration attempts
- Discover unauthorized services
- Investigate security incidents

## Learning Objectives

By the end of this lab, you will be able to:

- Analyze traffic volume and patterns
- Identify protocol distributions
- Detect unusual port usage
- Recognize beaconing behavior (C2 traffic)
- Find data exfiltration indicators
- Use Wireshark statistics features

## Key Concepts

### Normal vs Abnormal Traffic

| Characteristic | Normal | Suspicious |
|----------------|--------|------------|
| **Ports** | Standard (80, 443, 22) | Unusual (4444, high random) |
| **Timing** | Business hours, variable | Regular intervals (beaconing) |
| **Volume** | Consistent with baseline | Sudden spikes |
| **Destinations** | Known services/CDNs | Unknown IPs, foreign hosts |
| **Protocols** | Expected (HTTP, DNS) | Unusual for environment |

### Traffic Analysis Categories

```
┌──────────────────────────────────────────────────────────────┐
│                    Traffic Analysis                           │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Volume    │  │   Pattern   │  │   Content   │           │
│  │  Analysis   │  │  Analysis   │  │  Analysis   │           │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤           │
│  │ • Bandwidth │  │ • Timing    │  │ • Payloads  │           │
│  │ • Packet    │  │ • Beaconing │  │ • Protocols │           │
│  │   counts    │  │ • Flows     │  │ • Anomalies │           │
│  │ • Trends    │  │ • Sessions  │  │ • Encoding  │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Common Attack Indicators

| Indicator | What It Might Mean |
|-----------|-------------------|
| Regular interval connections | C2 beaconing |
| Large outbound transfers | Data exfiltration |
| DNS to unusual domains | DNS tunneling |
| Connections on port 4444 | Metasploit default shell |
| Base64 in HTTP headers | Encoded commands |
| ICMP with large payloads | ICMP tunneling |
| Multiple failed connections | Scanning/Recon |

## Lab Exercises

### Exercise 1: Traffic Statistics in Wireshark

Use Wireshark's built-in statistics to understand traffic composition.

**Key Statistics Views:**
- Statistics -> Capture File Properties
- Statistics -> Protocol Hierarchy
- Statistics -> Conversations
- Statistics -> Endpoints
- Statistics -> I/O Graphs

### Exercise 2: Identifying Top Talkers

Find which hosts generate the most traffic - useful for detecting compromised systems.

### Exercise 3: Protocol Distribution Analysis

Understand what protocols are in use and identify unexpected ones.

### Exercise 4: Detecting Beaconing Behavior

Find regular, periodic connections that may indicate C2 communication.

### Exercise 5: Identifying Data Exfiltration

Look for signs of data being stolen from the network.

### Exercise 6: Anomaly Detection

Identify traffic that doesn't fit expected patterns.

## Wireshark Statistics Features

### Protocol Hierarchy
```
Statistics -> Protocol Hierarchy

Shows breakdown of all protocols:
├── Ethernet (100%)
│   └── IPv4 (98%)
│       ├── TCP (85%)
│       │   ├── HTTP (60%)
│       │   └── TLS (20%)
│       └── UDP (13%)
│           └── DNS (12%)
```

### Conversations
```
Statistics -> Conversations

Shows all network conversations:
- Ethernet (MAC to MAC)
- IPv4 (IP to IP)
- TCP (connection pairs)
- UDP (connection pairs)
```

### Endpoints
```
Statistics -> Endpoints

Lists all unique hosts:
- Total packets sent/received
- Total bytes
- Geographic location (if GeoIP enabled)
```

### I/O Graphs
```
Statistics -> I/O Graphs

Visual representation of:
- Packets over time
- Bytes over time
- Filtered traffic trends
```

## Traffic Analysis Tools

### Wireshark/tshark
The primary analysis tool with rich protocol support.

### Zeek (formerly Bro)
Network analysis framework that generates structured logs.

```bash
# Run Zeek on a PCAP
zeek -r capture.pcap

# Generated logs:
# conn.log - Connection records
# dns.log  - DNS queries
# http.log - HTTP requests
# ssl.log  - SSL/TLS connections
```

### Netstat/ss
View current network connections.

```bash
# All connections
netstat -an

# Using ss (modern replacement)
ss -tuln
```

### NetworkMiner
Windows tool for host-based network forensics.

## Suspicious Traffic Patterns

### Beaconing (C2 Communication)
```
Time      Source        Destination     Interval
09:00:00  10.0.0.5  ->  45.33.32.156   -
09:05:00  10.0.0.5  ->  45.33.32.156   5 min
09:10:00  10.0.0.5  ->  45.33.32.156   5 min
09:15:00  10.0.0.5  ->  45.33.32.156   5 min
                                        ^ Regular interval!
```

### Data Exfiltration
```
Normal:   POST /api/login   (200 bytes)
Normal:   POST /api/query   (500 bytes)
Abnormal: POST /api/update  (50 MB)  <- Unusual size!
```

### Port Scanning
```
10.0.0.5:4321 -> 10.0.0.1:21 [SYN] -> [RST]
10.0.0.5:4321 -> 10.0.0.1:22 [SYN] -> [SYN-ACK]
10.0.0.5:4321 -> 10.0.0.1:23 [SYN] -> [RST]
10.0.0.5:4321 -> 10.0.0.1:25 [SYN] -> [RST]
                ^ Sequential port testing
```

## Analysis Methodology

### Step 1: Get the Big Picture
- How much data? How long a timespan?
- What protocols are present?
- Who are the main communicators?

### Step 2: Identify Anomalies
- Unusual protocols for the environment
- Unexpected destinations
- Strange timing patterns
- Large data transfers

### Step 3: Deep Dive
- Follow suspicious streams
- Examine payloads
- Check for encoding/obfuscation
- Correlate with known IOCs

### Step 4: Document Findings
- Timeline of events
- Hosts involved
- Data transferred
- Evidence of compromise

## Key Takeaways

1. **Baseline First** - Know normal before finding abnormal
2. **Statistics Matter** - Volume and patterns reveal much
3. **Timing is Key** - Beaconing indicates automation
4. **Context Matters** - DNS at midnight is more suspicious than at noon
5. **Multiple Indicators** - One anomaly isn't proof; look for patterns

## References

- [SANS Network Traffic Analysis Cheat Sheet](https://www.sans.org/posters/)
- [Zeek Documentation](https://docs.zeek.org/)
- [Wireshark Statistics Guide](https://www.wireshark.org/docs/wsug_html/)

---

**Next Steps:**
- Complete the [Walkthrough](./walkthrough.md) for hands-on practice
- Use [Hints](./hints.md) if you get stuck
- Proceed to [Lab 03: Protocol Analysis](../03-protocol-analysis/README.md)
