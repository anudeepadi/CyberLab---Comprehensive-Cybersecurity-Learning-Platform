# Protocol Analysis - Walkthrough

This walkthrough provides detailed, step-by-step guidance for analyzing network protocols at the packet level. Follow along in your terminal and Wireshark.

## Prerequisites

Ensure your lab environment is running:

```bash
# Verify Apache is running (for generating HTTP traffic)
sudo systemctl status apache2
# If not running:
sudo systemctl start apache2

# Verify the network labs are accessible
curl -s http://localhost/network-labs/ | head -5
```

---

## Exercise 1: TCP Three-Way Handshake Analysis

### Objective
Capture and analyze a complete TCP connection establishment.

### Step 1: Start Packet Capture

Open a terminal and start capturing on the loopback interface:

```bash
# Create a directory for captures
mkdir -p /tmp/protocol-lab

# Start tcpdump capturing only TCP SYN/ACK/FIN packets
sudo tcpdump -i lo -w /tmp/protocol-lab/tcp_handshake.pcap "tcp port 80"
```

### Step 2: Generate a TCP Connection

In another terminal, make an HTTP request:

```bash
curl http://localhost/network-labs/
```

### Step 3: Stop Capture

Return to the first terminal and press `Ctrl+C` to stop tcpdump.

### Step 4: Analyze in Wireshark

```bash
wireshark /tmp/protocol-lab/tcp_handshake.pcap &
```

### Step 5: Identify the Handshake

Apply this display filter to see only the handshake:

```
tcp.flags.syn == 1 || tcp.flags.fin == 1
```

You should see:
1. **Packet 1**: SYN from client (flags: S)
2. **Packet 2**: SYN-ACK from server (flags: SA)
3. **Packet 3**: ACK from client (flags: A)

### Step 6: Examine Packet Details

Click on the first SYN packet and expand the TCP layer:

**Key fields to observe:**
- Source Port (ephemeral port, e.g., 45678)
- Destination Port (80 for HTTP)
- Sequence Number (initial sequence number)
- Flags: SYN = 1, ACK = 0

Click on the SYN-ACK packet:
- Acknowledgment Number = Client's Seq + 1
- Flags: SYN = 1, ACK = 1

### Step 7: Verify with tshark

```bash
# Show TCP flags for all packets
tshark -r /tmp/protocol-lab/tcp_handshake.pcap -T fields \
    -e frame.number -e ip.src -e ip.dst \
    -e tcp.srcport -e tcp.dstport -e tcp.flags.str

# Filter for SYN packets only
tshark -r /tmp/protocol-lab/tcp_handshake.pcap -Y "tcp.flags.syn == 1"
```

### Expected Output Analysis

```
Frame 1: 127.0.0.1:45678 -> 127.0.0.1:80  [SYN] Seq=0
Frame 2: 127.0.0.1:80 -> 127.0.0.1:45678  [SYN, ACK] Seq=0 Ack=1
Frame 3: 127.0.0.1:45678 -> 127.0.0.1:80  [ACK] Seq=1 Ack=1
Frame 4+: HTTP Data Exchange
Last frames: [FIN, ACK] connection teardown
```

---

## Exercise 2: HTTP Request/Response Analysis

### Objective
Examine HTTP protocol structure in detail.

### Step 1: Capture HTTP Traffic

```bash
sudo tcpdump -i lo -w /tmp/protocol-lab/http_traffic.pcap "tcp port 80" &

# Generate various HTTP requests
curl http://localhost/network-labs/
curl -X POST http://localhost/network-labs/login.php \
    -d "username=testuser&password=testpass"
curl -I http://localhost/network-labs/  # HEAD request

# Stop capture
sudo pkill tcpdump
```

### Step 2: Open in Wireshark

```bash
wireshark /tmp/protocol-lab/http_traffic.pcap &
```

### Step 3: Filter for HTTP Only

Apply display filter:

```
http
```

### Step 4: Analyze GET Request

Find a GET request and examine:

**Request Line:**
```
GET /network-labs/ HTTP/1.1
```

**Headers to note:**
- `Host`: Target hostname
- `User-Agent`: Client identification
- `Accept`: Content types accepted
- `Connection`: Keep-alive or close

### Step 5: Follow HTTP Stream

Right-click on an HTTP packet and select:
**Follow > HTTP Stream**

This shows the complete request/response conversation in a readable format.

### Step 6: Analyze POST Request

Filter for POST requests:

```
http.request.method == "POST"
```

Expand the packet and look at:
- **HTTP > HTML Form URL Encoded**
- You'll see form field names and values

**Security Note:** This is why HTTPS is critical - form data is visible!

### Step 7: Export with tshark

```bash
# Extract all HTTP hosts
tshark -r /tmp/protocol-lab/http_traffic.pcap -Y "http.request" \
    -T fields -e http.host

# Extract request URIs
tshark -r /tmp/protocol-lab/http_traffic.pcap -Y "http.request" \
    -T fields -e http.request.uri

# Extract POST data
tshark -r /tmp/protocol-lab/http_traffic.pcap \
    -Y "http.request.method == POST" \
    -T fields -e http.file_data
```

---

## Exercise 3: DNS Query Analysis

### Objective
Trace DNS resolution from query to answer.

### Step 1: Capture DNS Traffic

```bash
# DNS uses UDP port 53
sudo tcpdump -i any -w /tmp/protocol-lab/dns_traffic.pcap "udp port 53" &

# Generate DNS queries
nslookup google.com
dig facebook.com
host github.com
dig -t MX gmail.com        # Mail exchange record
dig -t NS example.com      # Name server record
dig -t TXT example.com     # TXT record

# Stop capture
sudo pkill tcpdump
```

### Step 2: Open in Wireshark

```bash
wireshark /tmp/protocol-lab/dns_traffic.pcap &
```

### Step 3: Filter DNS Traffic

```
dns
```

### Step 4: Identify Query vs Response

- **Queries** have flag `QR = 0` (Question)
- **Responses** have flag `QR = 1` (Response)

Filter for queries only:
```
dns.flags.response == 0
```

### Step 5: Examine DNS Query Structure

Click on a DNS query packet and expand:

**DNS Layer:**
- Transaction ID (matches query to response)
- Flags
- Questions: 1
- Query Name (e.g., google.com)
- Query Type (A, AAAA, MX, etc.)

### Step 6: Examine DNS Response

Find the corresponding response (same Transaction ID):

**Answer Section:**
- Name: google.com
- Type: A
- Class: IN
- Time to live: (TTL in seconds)
- Data: 142.250.xxx.xxx (IP address)

### Step 7: Extract DNS Data with tshark

```bash
# List all queried domains
tshark -r /tmp/protocol-lab/dns_traffic.pcap \
    -Y "dns.flags.response == 0" \
    -T fields -e dns.qry.name

# List queries and answers together
tshark -r /tmp/protocol-lab/dns_traffic.pcap \
    -Y "dns" \
    -T fields -e dns.qry.name -e dns.a -e dns.aaaa

# Find MX records
tshark -r /tmp/protocol-lab/dns_traffic.pcap \
    -Y "dns.qry.type == 15" \
    -T fields -e dns.qry.name -e dns.mx.mail_exchange
```

---

## Exercise 4: UDP Communication Analysis

### Objective
Compare UDP's simplicity with TCP's complexity.

### Step 1: Capture UDP Traffic

```bash
# Capture DNS (UDP 53) and NTP (UDP 123) traffic
sudo tcpdump -i any -w /tmp/protocol-lab/udp_traffic.pcap \
    "udp port 53 or udp port 123" &

# Generate traffic
nslookup example.com
# If NTP is running
ntpdate -q pool.ntp.org 2>/dev/null || echo "NTP not available"

sudo pkill tcpdump
```

### Step 2: Compare UDP Header to TCP

Open in Wireshark and examine a UDP packet:

**UDP Header (8 bytes only):**
- Source Port
- Destination Port
- Length
- Checksum

Compare to TCP's 20+ byte header with:
- Sequence numbers
- Acknowledgment numbers
- Flags
- Window size
- Options

### Step 3: Note Key Differences

**UDP:**
- No connection setup (no handshake)
- No delivery confirmation
- No ordering guarantee
- Much faster for simple requests

```bash
# Compare packet counts
tshark -r /tmp/protocol-lab/dns_traffic.pcap -q -z conv,udp
# Typically 2 packets per DNS query (request + response)

tshark -r /tmp/protocol-lab/tcp_handshake.pcap -q -z conv,tcp
# Many more packets for equivalent data transfer
```

---

## Exercise 5: Protocol Anomalies Detection

### Objective
Identify malformed or suspicious protocol behavior.

### Step 1: Look for TCP Anomalies

Using your existing captures or the lab PCAP files:

```bash
# Find retransmissions (network issues or attacks)
tshark -r /tmp/protocol-lab/tcp_handshake.pcap \
    -Y "tcp.analysis.retransmission"

# Find RST packets (connection aborts)
tshark -r /tmp/protocol-lab/tcp_handshake.pcap \
    -Y "tcp.flags.rst == 1"

# Find out-of-order packets
tshark -r /tmp/protocol-lab/tcp_handshake.pcap \
    -Y "tcp.analysis.out_of_order"
```

### Step 2: DNS Anomaly Detection

```bash
# Unusually long DNS queries (potential tunneling)
tshark -r /tmp/protocol-lab/dns_traffic.pcap \
    -Y "dns.qry.name" \
    -T fields -e dns.qry.name | awk 'length > 50'

# DNS responses with errors
tshark -r /tmp/protocol-lab/dns_traffic.pcap \
    -Y "dns.flags.rcode != 0" \
    -T fields -e dns.qry.name -e dns.flags.rcode
```

### Step 3: HTTP Anomaly Detection

```bash
# Large number of requests to same endpoint (potential attack)
tshark -r /tmp/protocol-lab/http_traffic.pcap \
    -Y "http.request" \
    -T fields -e http.request.uri | sort | uniq -c | sort -rn

# Suspicious User-Agents
tshark -r /tmp/protocol-lab/http_traffic.pcap \
    -Y "http.request" \
    -T fields -e http.user_agent | sort | uniq -c

# Large response sizes
tshark -r /tmp/protocol-lab/http_traffic.pcap \
    -Y "http.response" \
    -T fields -e http.content_length | sort -rn | head
```

### Step 4: Using Wireshark Expert Info

In Wireshark, go to:
**Analyze > Expert Information**

This shows:
- Errors (malformed packets)
- Warnings (retransmissions, out-of-order)
- Notes (unusual but valid behavior)
- Chats (normal protocol events)

---

## Exercise 6: Protocol Analysis with Scapy

### Objective
Use Python Scapy for programmatic protocol analysis.

### Step 1: Start Scapy

```bash
sudo scapy
```

### Step 2: Read and Analyze PCAP

```python
# Read a PCAP file
>>> packets = rdpcap('/tmp/protocol-lab/http_traffic.pcap')
>>> print(f"Loaded {len(packets)} packets")

# Examine first packet
>>> packets[0].show()

# Filter TCP packets
>>> tcp_packets = [p for p in packets if TCP in p]
>>> print(f"TCP packets: {len(tcp_packets)}")

# Find SYN packets
>>> syn_packets = [p for p in packets if TCP in p and p[TCP].flags == 'S']
>>> print(f"SYN packets: {len(syn_packets)}")

# Examine TCP flags
>>> for p in packets[:10]:
...     if TCP in p:
...         print(f"{p[IP].src}:{p[TCP].sport} -> {p[IP].dst}:{p[TCP].dport} Flags:{p[TCP].flags}")
```

### Step 3: Extract Protocol Information

```python
# Extract all destination ports
>>> dports = [p[TCP].dport for p in packets if TCP in p]
>>> from collections import Counter
>>> Counter(dports).most_common(5)

# Find packets with specific content
>>> http_packets = [p for p in packets if p.haslayer(Raw) and b'HTTP' in bytes(p[Raw])]
>>> print(f"HTTP packets: {len(http_packets)}")

# Show HTTP content
>>> if http_packets:
...     print(bytes(http_packets[0][Raw]).decode('utf-8', errors='ignore')[:500])
```

### Step 4: Build Analysis Functions

```python
# Function to summarize conversations
>>> def summarize_tcp_streams(packets):
...     streams = {}
...     for p in packets:
...         if TCP in p:
...             key = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
...             streams[key] = streams.get(key, 0) + 1
...     return sorted(streams.items(), key=lambda x: x[1], reverse=True)
...
>>> for stream, count in summarize_tcp_streams(packets)[:5]:
...     print(f"{stream}: {count} packets")
```

---

## Verification Checklist

After completing this lab, ensure you can:

- [ ] Identify all three packets in a TCP handshake
- [ ] Explain the purpose of SYN, ACK, and FIN flags
- [ ] Extract HTTP request methods and URIs from a capture
- [ ] Follow an HTTP stream in Wireshark
- [ ] Identify DNS queries and their responses
- [ ] Distinguish between UDP and TCP traffic patterns
- [ ] Find protocol anomalies using Wireshark filters
- [ ] Use tshark to extract specific protocol fields

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| No traffic captured | Verify correct interface (`-i lo` for localhost) |
| Can't see HTTP content | Check if HTTPS is being used (encrypted) |
| DNS queries not visible | Ensure UDP port 53 is in capture filter |
| Wireshark filter syntax error | Use Wireshark filter syntax, not BPF |

## Key Commands Reference

```bash
# TCP handshake packets
tshark -r file.pcap -Y "tcp.flags.syn == 1"

# HTTP requests
tshark -r file.pcap -Y "http.request" -T fields -e http.request.uri

# DNS queries
tshark -r file.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Follow TCP stream
tshark -r file.pcap -q -z follow,tcp,ascii,0

# Protocol hierarchy
tshark -r file.pcap -q -z io,phs
```

---

**Next Steps:**
- Practice with the [PCAP challenges](../04-network-forensics/) in the forensics lab
- Use [Hints](./hints.md) if you encounter difficulties
- Proceed to [Lab 04: Network Forensics](../04-network-forensics/README.md)
