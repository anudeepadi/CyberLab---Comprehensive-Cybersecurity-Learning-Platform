# Lab 02: Traffic Analysis - Walkthrough

Hands-on exercises for analyzing network traffic patterns and identifying anomalies.

## Setup

```bash
# Ensure Apache is running for traffic generation
sudo systemctl start apache2

# Location of sample PCAP files
PCAP_DIR="/var/www/html/network-labs/forensics-lab/pcaps"
ls -la $PCAP_DIR

# Generate fresh traffic for analysis
sudo python3 /opt/network-labs/traffic/traffic-generator.py --all 2>/dev/null &
```

---

## Exercise 1: Traffic Statistics in Wireshark

### Step 1: Capture Fresh Traffic

```bash
# Capture 5 minutes of varied traffic
sudo tcpdump -i lo -w /tmp/traffic_sample.pcap &
TCPDUMP_PID=$!

# Generate mixed traffic
for i in {1..10}; do
    curl -s http://localhost/network-labs/ > /dev/null
    ping -c 1 127.0.0.1 > /dev/null
    sleep 2
done

# Stop capture
sudo kill $TCPDUMP_PID
```

### Step 2: Open in Wireshark

```bash
wireshark /tmp/traffic_sample.pcap &
```

### Step 3: Capture File Properties

Go to **Statistics -> Capture File Properties**

Note these key metrics:
- **File size** - Total capture size
- **Packet count** - Number of packets
- **Time span** - Duration of capture
- **Average packet rate** - Packets per second
- **Average bit rate** - Bandwidth used

### Step 4: Protocol Hierarchy

Go to **Statistics -> Protocol Hierarchy**

This shows a tree view of all protocols:
```
Frame (100%)
└── Ethernet (100%)
    └── IPv4 (98%)
        ├── TCP (75%)
        │   ├── HTTP (50%)
        │   └── [other TCP] (25%)
        ├── UDP (20%)
        │   └── DNS (15%)
        └── ICMP (5%)
```

**Analysis Questions:**
- What percentage is HTTP traffic?
- Is there any unexpected protocol?
- What's the TCP vs UDP ratio?

### Step 5: I/O Graphs

Go to **Statistics -> I/O Graphs**

This shows traffic over time:
1. Click "+" to add graphs
2. Add filters like `http` or `dns`
3. Look for traffic spikes or patterns

---

## Exercise 2: Identifying Top Talkers

### Step 1: View Conversations

In Wireshark: **Statistics -> Conversations**

Click the **IPv4** tab to see IP-to-IP conversations:
- **Address A** - First host
- **Address B** - Second host
- **Packets** - Total packets exchanged
- **Bytes** - Total data transferred
- **Duration** - How long the conversation lasted

### Step 2: Sort by Traffic Volume

Click the "Bytes A->B" column to sort by most data transferred.

The top entries are your "top talkers" - hosts with the most activity.

### Step 3: Command Line Analysis with tshark

```bash
# Show top conversations by bytes
tshark -r /tmp/traffic_sample.pcap -q -z conv,ip

# Output example:
#                                             <-      | ->      | Total
# Address A        Address B                 Frames   | Frames  | Bytes
# 127.0.0.1       127.0.0.1                    50     |   50    | 15000
```

### Step 4: Identify Unusual Communications

Look for:
- Unknown IP addresses
- Excessive traffic from single host
- Traffic to suspicious destinations

```bash
# List all unique destination IPs
tshark -r /tmp/traffic_sample.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn | head -20
```

---

## Exercise 3: Protocol Distribution Analysis

### Step 1: Protocol Statistics

```bash
# Get protocol breakdown with tshark
tshark -r /tmp/traffic_sample.pcap -q -z io,phs
```

Output shows packet counts per protocol:
```
===================================================================
Protocol Hierarchy Statistics
===================================================================
eth                                frames:1000 bytes:500000
  ip                               frames:980  bytes:490000
    tcp                            frames:800  bytes:400000
      http                         frames:500  bytes:250000
    udp                            frames:150  bytes:75000
      dns                          frames:120  bytes:60000
    icmp                           frames:30   bytes:15000
```

### Step 2: Port Distribution

```bash
# Show which ports have most traffic
tshark -r /tmp/traffic_sample.pcap -T fields -e tcp.dstport | sort | uniq -c | sort -rn | head -10

# Example output:
# 500 80       <- HTTP
# 200 443      <- HTTPS
# 50  22       <- SSH
# 10  4444     <- Suspicious? (Metasploit default)
```

### Step 3: Identify Unexpected Protocols

In Wireshark, filter for unusual protocols:
```
# Look for IRC (might indicate botnet)
irc

# Look for unusual ports
tcp.port == 4444 or tcp.port == 31337

# Look for raw TCP (no recognized protocol)
tcp and not http and not ssl and not ssh
```

### Step 4: Compare to Baseline

Normal corporate network might have:
- 60% HTTPS (443)
- 20% HTTP (80)
- 10% DNS (53)
- 5% SSH (22)
- 5% Other

Deviations could indicate:
- New applications
- Compromised systems
- Data exfiltration

---

## Exercise 4: Detecting Beaconing Behavior

Beaconing is when malware checks in with its C2 server at regular intervals.

### Step 1: Open C2 Beacon Challenge

```bash
wireshark /var/www/html/network-labs/forensics-lab/pcaps/challenge2_c2beacon.pcap &
```

### Step 2: Look at Conversation Timing

**Statistics -> Conversations -> TCP tab**

Look for:
- Repeated connections to same destination
- Similar packet sizes
- Regular time intervals

### Step 3: Create Time-Based Analysis

Use Wireshark's Time column:
1. View -> Time Display Format -> Seconds Since Beginning of Capture
2. Sort by destination IP
3. Calculate time between similar connections

### Step 4: Command Line Beacon Detection

```bash
# Extract timestamps and destinations
tshark -r /var/www/html/network-labs/forensics-lab/pcaps/challenge2_c2beacon.pcap \
    -T fields -e frame.time_relative -e ip.dst \
    | grep -v "127.0.0.1" | head -30

# Look for patterns like:
# 0.000000    185.123.45.67
# 60.001234   185.123.45.67   <- ~60 second interval
# 120.002345  185.123.45.67   <- ~60 second interval
```

### Step 5: Calculate Intervals

```bash
# Advanced: Calculate connection intervals
tshark -r /var/www/html/network-labs/forensics-lab/pcaps/challenge2_c2beacon.pcap \
    -Y "ip.dst == 185.123.45.67" \
    -T fields -e frame.time_relative \
    | awk 'NR>1{print $1-prev} {prev=$1}'
```

Regular intervals (60s, 300s, etc.) strongly suggest beaconing.

---

## Exercise 5: Identifying Data Exfiltration

### Step 1: Find Large Outbound Transfers

```bash
# Look for conversations with large byte counts
tshark -r /tmp/traffic_sample.pcap -q -z conv,tcp | sort -t'|' -k5 -rn | head -10
```

### Step 2: Check for Large POST Requests

HTTP POST is commonly used for data exfiltration:

```bash
# Find large HTTP POST requests
tshark -r /tmp/traffic_sample.pcap \
    -Y "http.request.method == POST" \
    -T fields -e ip.src -e ip.dst -e http.content_length \
    | sort -t$'\t' -k3 -rn
```

### Step 3: Examine DNS for Data Exfiltration

DNS can be used to tunnel data in query names:

```bash
# Look for unusually long DNS queries
tshark -r /var/www/html/network-labs/forensics-lab/pcaps/challenge4_dns_tunnel.pcap \
    -Y "dns.qry.name" \
    -T fields -e dns.qry.name \
    | awk '{print length, $0}' | sort -rn | head -10
```

Normal DNS: `www.google.com` (14 chars)
Exfil DNS: `dGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl.evil.com` (40+ chars)

### Step 4: Check ICMP Payloads

ICMP can hide data in the payload:

```bash
# Look at ICMP data field sizes
tshark -r /var/www/html/network-labs/forensics-lab/pcaps/challenge6_icmp_tunnel.pcap \
    -Y "icmp" \
    -T fields -e data.len \
    | sort | uniq -c
```

Normal ping: 48-64 bytes
Tunneling: Variable, often larger

---

## Exercise 6: Anomaly Detection

### Step 1: Establish Baseline Statistics

```bash
# Generate baseline traffic statistics
tshark -r /tmp/traffic_sample.pcap -q -z io,stat,1
```

This shows packets per second - note the normal range.

### Step 2: Identify Traffic Spikes

In Wireshark I/O Graphs:
1. Set interval to 1 second
2. Look for unusual spikes
3. Click on spike to see packets at that time

### Step 3: Find Failed Connections

Failed connections might indicate scanning:

```bash
# Find RST packets (connection rejections)
tshark -r /tmp/traffic_sample.pcap -Y "tcp.flags.reset==1" \
    -T fields -e ip.src -e ip.dst -e tcp.dstport \
    | sort | uniq -c | sort -rn | head -10
```

Many RSTs to sequential ports = port scan

### Step 4: Detect Scanning Patterns

```bash
# Find hosts connecting to many different ports
tshark -r /tmp/traffic_sample.pcap \
    -Y "tcp.flags.syn==1 and tcp.flags.ack==0" \
    -T fields -e ip.src -e tcp.dstport \
    | sort | uniq | cut -f1 | sort | uniq -c | sort -rn
```

A host hitting many ports is likely scanning.

### Step 5: Check for After-Hours Activity

```bash
# Filter by time (if timestamps are real)
tshark -r /tmp/traffic_sample.pcap \
    -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport \
    | grep -E "0[0-5]:" # Early morning hours
```

---

## Exercise 7: Using Zeek for Analysis

### Step 1: Generate Zeek Logs

```bash
# Create working directory
cd /tmp
mkdir zeek_analysis
cd zeek_analysis

# Run Zeek on a capture file
zeek -r /var/www/html/network-labs/forensics-lab/pcaps/challenge2_c2beacon.pcap

# List generated logs
ls -la *.log
```

### Step 2: Analyze Connection Log

```bash
# View connection log fields
head -20 conn.log

# Extract key fields (using zeek-cut if available)
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes

# Or with awk
awk '/^[^#]/ {print $1, $3, $5, $6, $8, $10, $11}' conn.log
```

### Step 3: Find Long-Duration Connections

```bash
# Sort by duration to find persistent connections
cat conn.log | zeek-cut ts id.orig_h id.resp_h duration | sort -t$'\t' -k4 -rn | head -10
```

### Step 4: Identify Beacons with Zeek

```bash
# Find repeated connections to same destination
cat conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10
```

---

## Verification Checklist

After completing this lab, verify you can:

- [ ] Use Wireshark Statistics -> Protocol Hierarchy
- [ ] Identify top talkers in Conversations view
- [ ] Analyze port distribution in traffic
- [ ] Detect beaconing patterns by timing analysis
- [ ] Find large data transfers (exfiltration indicators)
- [ ] Recognize port scanning patterns
- [ ] Generate and analyze Zeek logs
- [ ] Calculate connection intervals for beacon detection

---

## Command Reference

```bash
# Protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# Conversations
tshark -r capture.pcap -q -z conv,ip
tshark -r capture.pcap -q -z conv,tcp

# Endpoints
tshark -r capture.pcap -q -z endpoints,ip

# Top destination ports
tshark -r capture.pcap -T fields -e tcp.dstport | sort | uniq -c | sort -rn

# I/O statistics (1 second intervals)
tshark -r capture.pcap -q -z io,stat,1

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# Filter with display filter
tshark -r capture.pcap -Y "http.request.method==POST"
```

---

**Next:** [Lab 03: Protocol Analysis](../03-protocol-analysis/README.md)
