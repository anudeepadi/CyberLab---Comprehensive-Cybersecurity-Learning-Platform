# Lab 02: Traffic Analysis - Hints

Progressive hints for traffic analysis exercises.

---

## Exercise 1: Traffic Statistics in Wireshark

### Hint 1: Finding Statistics Menu
<details>
<summary>Click to reveal</summary>

All statistics features are under the **Statistics** menu at the top of Wireshark:
- Statistics -> Capture File Properties
- Statistics -> Protocol Hierarchy
- Statistics -> Conversations
- Statistics -> Endpoints
- Statistics -> I/O Graphs
</details>

### Hint 2: Understanding Protocol Hierarchy
<details>
<summary>Click to reveal</summary>

Protocol Hierarchy shows a tree structure:
- Top level is always "Frame" (100%)
- Percentages show relative amount of that protocol
- Expand to see sub-protocols
- Look for unexpected protocols at any level

Example suspicious findings:
- IRC protocol in corporate network
- Custom/unknown protocols
- High percentage of encrypted traffic to unknown destinations
</details>

### Hint 3: Using I/O Graphs Effectively
<details>
<summary>Click to reveal</summary>

In I/O Graphs:
1. Click "+" to add new graph
2. Enter a display filter (e.g., `http`, `dns`)
3. Change Y axis to "Bytes" for bandwidth view
4. Change interval for finer/coarser granularity
5. Click on peaks to jump to those packets

Compare multiple protocols by adding multiple graphs with different colors.
</details>

---

## Exercise 2: Identifying Top Talkers

### Hint 1: Finding Conversations View
<details>
<summary>Click to reveal</summary>

**Statistics -> Conversations**

The tabs at bottom show different layers:
- **Ethernet** - MAC address pairs
- **IPv4** - IP address pairs
- **TCP** - TCP connection pairs
- **UDP** - UDP connection pairs

Click column headers to sort.
</details>

### Hint 2: Understanding Columns
<details>
<summary>Click to reveal</summary>

| Column | Meaning |
|--------|---------|
| Address A | First endpoint |
| Address B | Second endpoint |
| Packets A->B | Packets sent A to B |
| Bytes A->B | Data sent A to B |
| Packets B->A | Response packets |
| Bytes B->A | Response data |
| Duration | How long conversation lasted |

Sort by "Bytes" columns to find heavy traffic.
</details>

### Hint 3: Command Line Alternative
<details>
<summary>Click to reveal</summary>

```bash
# List conversations by bytes
tshark -r capture.pcap -q -z conv,ip

# List unique destination IPs
tshark -r capture.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn

# Show who's talking to whom
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn
```
</details>

---

## Exercise 3: Protocol Distribution Analysis

### Hint 1: Getting Protocol Breakdown
<details>
<summary>Click to reveal</summary>

In Wireshark: **Statistics -> Protocol Hierarchy**

With tshark:
```bash
tshark -r capture.pcap -q -z io,phs
```

This shows every protocol and its packet/byte count.
</details>

### Hint 2: Analyzing Port Distribution
<details>
<summary>Click to reveal</summary>

```bash
# Most common destination ports
tshark -r capture.pcap -T fields -e tcp.dstport | sort | uniq -c | sort -rn | head

# Common port meanings:
# 80   - HTTP
# 443  - HTTPS
# 22   - SSH
# 53   - DNS
# 25   - SMTP
# 3389 - RDP
# 4444 - Metasploit default
```
</details>

### Hint 3: Finding Unusual Protocols
<details>
<summary>Click to reveal</summary>

Wireshark filters for suspicious traffic:

```
# IRC (possible botnet)
irc

# Non-standard ports
tcp.port > 10000 and tcp.port < 65000

# Unknown TCP (no recognized protocol)
tcp and not http and not tls and not ssh

# Telnet (cleartext - security concern)
telnet
```
</details>

---

## Exercise 4: Detecting Beaconing Behavior

### Hint 1: What is Beaconing?
<details>
<summary>Click to reveal</summary>

Beaconing is when malware connects to its C2 server at regular intervals:
- Check-in every 60 seconds
- Phone home every 5 minutes
- Heartbeat every hour

The regularity is the key indicator - humans don't click at exactly 60-second intervals, but malware does.
</details>

### Hint 2: Finding Interval Patterns
<details>
<summary>Click to reveal</summary>

1. In Wireshark, change Time Display:
   - View -> Time Display Format -> Seconds Since Beginning

2. Filter for suspicious destination:
   ```
   ip.dst == suspicious.ip.address
   ```

3. Look at timestamp column - calculate differences between connections

4. Regular intervals (60s, 300s, 600s) suggest beaconing
</details>

### Hint 3: Automated Detection
<details>
<summary>Click to reveal</summary>

```bash
# Extract timestamps for specific destination
tshark -r capture.pcap \
    -Y "ip.dst == X.X.X.X and tcp.flags.syn==1" \
    -T fields -e frame.time_epoch

# Calculate intervals between connections
# If intervals are consistently the same (+/- jitter), it's beaconing

# Look for connection patterns
tshark -r capture.pcap -q -z conv,tcp | grep "suspicious.ip"
```
</details>

---

## Exercise 5: Identifying Data Exfiltration

### Hint 1: Signs of Exfiltration
<details>
<summary>Click to reveal</summary>

Data exfiltration indicators:
- **Large outbound transfers** - More data going out than expected
- **Unusual protocols** - Using DNS or ICMP for data
- **Off-hours activity** - Transfers at 3 AM
- **Encrypted to unknown hosts** - TLS to non-CDN IPs
- **Unusual encoding** - Base64 in HTTP headers
</details>

### Hint 2: Finding Large Transfers
<details>
<summary>Click to reveal</summary>

```bash
# Large HTTP POST requests
tshark -r capture.pcap \
    -Y "http.request.method==POST and http.content_length > 10000" \
    -T fields -e ip.src -e ip.dst -e http.content_length

# Conversations sorted by bytes
tshark -r capture.pcap -q -z conv,tcp

# Look at bytes "from source" vs "from dest"
# Exfiltration: source sends much more than it receives
```
</details>

### Hint 3: DNS Tunneling Detection
<details>
<summary>Click to reveal</summary>

DNS tunneling hides data in query names:

Normal: `www.google.com` (15 characters)
Tunnel: `dGhpcyBpcyBzZWNyZXQgZGF0YQ.evil.com` (35+ characters)

```bash
# Find long DNS queries
tshark -r capture.pcap \
    -Y "dns.qry.name" \
    -T fields -e dns.qry.name \
    | awk '{if(length($0) > 50) print}'

# Look for:
# - Many queries to same domain
# - Base64/hex-like subdomains
# - Non-standard TXT record queries
```
</details>

---

## Exercise 6: Anomaly Detection

### Hint 1: Establishing Baseline
<details>
<summary>Click to reveal</summary>

To find anomalies, you need to know what's normal:

1. Capture "normal" traffic for comparison
2. Note typical:
   - Protocols used
   - Common ports
   - Traffic volume
   - Peak hours
3. Anomaly = deviation from baseline

```bash
# Traffic rate over time
tshark -r capture.pcap -q -z io,stat,10  # 10-second intervals
```
</details>

### Hint 2: Detecting Scans
<details>
<summary>Click to reveal</summary>

Port scanning patterns:
- Many SYN packets to one host
- Sequential or common ports
- Many RST responses (closed ports)

```bash
# Find SYN-only packets (connection attempts)
tshark -r capture.pcap \
    -Y "tcp.flags.syn==1 and tcp.flags.ack==0" \
    -T fields -e ip.src -e tcp.dstport

# Count by source (scanner has many connections)
tshark -r capture.pcap \
    -Y "tcp.flags.syn==1 and tcp.flags.ack==0" \
    -T fields -e ip.src | sort | uniq -c | sort -rn
```
</details>

### Hint 3: Finding Failed Connections
<details>
<summary>Click to reveal</summary>

RST (reset) packets indicate:
- Closed ports (scan detected)
- Firewall blocks
- Application errors

```bash
# Find RST packets
tshark -r capture.pcap -Y "tcp.flags.reset==1" \
    -T fields -e ip.src -e ip.dst -e tcp.dstport

# Many RSTs to different ports = scan response
# Many RSTs from one server = service issue
```
</details>

---

## General Analysis Hints

### Using Zeek
<details>
<summary>Click to reveal</summary>

Zeek generates structured logs from PCAPs:

```bash
# Run Zeek
zeek -r capture.pcap

# Key log files:
# conn.log     - All connections
# http.log     - HTTP requests
# dns.log      - DNS queries
# ssl.log      - SSL/TLS info
# notice.log   - Detected anomalies

# View connection log
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service
```
</details>

### Time-Based Analysis
<details>
<summary>Click to reveal</summary>

```bash
# Extract timestamps
tshark -r capture.pcap -T fields -e frame.time

# Filter by time in Wireshark
frame.time >= "2024-01-01 09:00:00" and frame.time <= "2024-01-01 17:00:00"

# Show traffic by hour (requires processing)
tshark -r capture.pcap -T fields -e frame.time | cut -d' ' -f2 | cut -d':' -f1 | sort | uniq -c
```
</details>

### Correlation Tips
<details>
<summary>Click to reveal</summary>

Correlate multiple indicators:
1. Find suspicious IP
2. Check all traffic to/from that IP
3. Look for timing patterns
4. Examine payload content
5. Cross-reference with threat intel

```bash
# All traffic to suspicious IP
tshark -r capture.pcap -Y "ip.addr == X.X.X.X"

# Just TCP connections
tshark -r capture.pcap -Y "ip.addr == X.X.X.X and tcp"
```
</details>

---

## Quick Reference

### Common tshark Statistics
```bash
# Protocol hierarchy
tshark -r file.pcap -q -z io,phs

# Conversations
tshark -r file.pcap -q -z conv,ip
tshark -r file.pcap -q -z conv,tcp

# Endpoints
tshark -r file.pcap -q -z endpoints,ip

# HTTP requests
tshark -r file.pcap -q -z http,tree

# DNS queries
tshark -r file.pcap -q -z dns,tree
```

### Wireshark Display Filters for Analysis
```
# Traffic volume
tcp.len > 1000           # Large TCP segments
http.content_length > 10000   # Large HTTP

# Timing
frame.time_delta > 0.5   # Slow responses

# Errors
tcp.analysis.flags       # TCP problems
http.response.code >= 400    # HTTP errors
```

---

**Still stuck?** Review the full [Walkthrough](./walkthrough.md) for complete solutions.
