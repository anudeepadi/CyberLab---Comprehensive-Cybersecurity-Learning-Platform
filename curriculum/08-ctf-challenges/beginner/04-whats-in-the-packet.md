# Challenge 04 - What's in the Packet?

**Category:** Forensics
**Difficulty:** Beginner
**Points:** 100
**Target:** PCAP Analysis (Local)

## Challenge Description

Our security team captured network traffic from a suspicious workstation. Hidden somewhere in this packet capture is a flag being transmitted in clear text.

Your mission is to analyze the PCAP file and extract the hidden flag.

## Challenge Files

Create the challenge PCAP file with this Python script:

```python
#!/usr/bin/env python3
"""Generate challenge PCAP with hidden flag"""

from scapy.all import *

packets = []

# Normal HTTP traffic
packets.append(IP(dst="192.168.1.100")/TCP(dport=80)/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
packets.append(IP(dst="192.168.1.100")/TCP(dport=80)/"HTTP/1.1 200 OK\r\n\r\nWelcome!")

# FTP traffic with flag
packets.append(IP(dst="192.168.1.50")/TCP(dport=21)/"220 FTP Server Ready\r\n")
packets.append(IP(dst="192.168.1.50")/TCP(dport=21)/"USER admin\r\n")
packets.append(IP(dst="192.168.1.50")/TCP(dport=21)/"331 Password required\r\n")
packets.append(IP(dst="192.168.1.50")/TCP(dport=21)/"PASS FLAG{p4ck3t_sn1ff1ng_101}\r\n")
packets.append(IP(dst="192.168.1.50")/TCP(dport=21)/"230 Login successful\r\n")

# More noise
packets.append(IP(dst="192.168.1.1")/ICMP())
packets.append(IP(dst="8.8.8.8")/UDP(dport=53)/"DNS Query")

wrpcap("/tmp/challenge04.pcap", packets)
print("PCAP created: /tmp/challenge04.pcap")
```

Or download from: `curriculum/08-ctf-challenges/files/challenge04.pcap`

## Objectives

- Open and analyze PCAP files
- Use Wireshark filters effectively
- Identify interesting protocols
- Extract clear-text credentials/data

---

## Hints

<details>
<summary>Hint 1 (Cost: -10 points)</summary>

Start by opening the PCAP in Wireshark and looking at the protocol hierarchy (Statistics > Protocol Hierarchy). What protocols are being used?

</details>

<details>
<summary>Hint 2 (Cost: -20 points)</summary>

FTP transmits data in clear text, including passwords. Filter for FTP traffic using the filter: `ftp`

</details>

<details>
<summary>Hint 3 (Cost: -30 points)</summary>

Look for FTP PASS commands. Use the filter: `ftp.request.command == "PASS"`
The password field contains the flag.

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Open the PCAP in Wireshark

```bash
wireshark /tmp/challenge04.pcap
```

Or use tshark for command-line analysis.

### Step 2: View Protocol Hierarchy

Go to Statistics > Protocol Hierarchy to see what protocols are present:
- TCP
- HTTP
- FTP
- ICMP
- UDP/DNS

### Step 3: Filter for FTP Traffic

In the filter bar, type: `ftp`

This shows all FTP-related packets.

### Step 4: Look for Credentials

FTP commands of interest:
- `USER` - Username
- `PASS` - Password

Filter more specifically: `ftp.request.command == "PASS"`

### Step 5: Extract the Flag

In the PASS command packet, you'll see:
```
PASS FLAG{p4ck3t_sn1ff1ng_101}
```

### Using tshark (Command Line)

```bash
# Show all FTP traffic
tshark -r /tmp/challenge04.pcap -Y "ftp"

# Extract FTP passwords
tshark -r /tmp/challenge04.pcap -Y "ftp.request.command == PASS" -T fields -e ftp.request.arg
```

### Using strings

Quick and dirty method:
```bash
strings /tmp/challenge04.pcap | grep FLAG
```

### Understanding the Vulnerability

This demonstrates why **unencrypted protocols are dangerous**:

| Protocol | Encrypted | Safe for Credentials |
|----------|-----------|---------------------|
| FTP | No | No |
| FTPS | Yes | Yes |
| Telnet | No | No |
| SSH | Yes | Yes |
| HTTP | No | No |
| HTTPS | Yes | Yes |

### Key Wireshark Filters

```
# FTP traffic
ftp

# FTP commands only
ftp.request.command

# Specific FTP command
ftp.request.command == "PASS"
ftp.request.command == "USER"

# HTTP traffic
http

# Follow TCP stream (right-click on packet)
tcp.stream eq 0
```

</details>

---

## Flag

```
FLAG{p4ck3t_sn1ff1ng_101}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- PCAP file analysis
- Wireshark navigation and filtering
- Protocol identification
- Clear-text credential extraction
- Command-line packet analysis (tshark)

## Tools Used

- Wireshark
- tshark
- strings
- Python/Scapy (optional)

## Related Challenges

- [Stealthy Transfer (Intermediate)](../intermediate/04-stealthy-transfer.md) - Advanced PCAP analysis
- [DNS Tunneling (Intermediate)](../intermediate/06-dns-tunneling.md) - Covert channels

## References

- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
- [Packet Analysis Tutorial](https://www.varonis.com/blog/how-to-use-wireshark)
