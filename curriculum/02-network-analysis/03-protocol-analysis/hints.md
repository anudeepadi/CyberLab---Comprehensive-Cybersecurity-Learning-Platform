# Protocol Analysis - Hints

Use these hints progressively when you're stuck. Try to solve problems yourself first - the struggle reinforces learning!

---

## General Protocol Analysis Hints

### Hint: I can't identify the protocol
- Check the port number - common protocols use well-known ports
- Look at the packet payload for protocol signatures
- Use Wireshark's "Decode As" feature for non-standard ports
- Check the IP protocol field (6=TCP, 17=UDP, 1=ICMP)

### Hint: Packets look encrypted/garbled
- HTTPS traffic (port 443) is encrypted - you won't see HTTP headers
- Look for TLS/SSL handshake packets instead
- Some applications use custom encryption
- Use `strings` on PCAP to find any cleartext

### Hint: I don't understand the packet structure
- Expand all layers in Wireshark's packet details pane
- Right-click on fields to add as columns for comparison
- Use Wireshark's built-in help (right-click > Wiki Protocol Page)
- Reference RFC documents for protocol specifications

---

## TCP Analysis Hints

### Hint: I can't find the TCP handshake
- Filter: `tcp.flags.syn == 1`
- Look at the very beginning of a TCP stream
- The first three packets should be: SYN, SYN-ACK, ACK
- Use: `tcp.stream eq 0` to isolate the first conversation

### Hint: What do the TCP flags mean?
```
S = SYN (synchronize) - Start connection
A = ACK (acknowledge) - Confirm receipt
F = FIN (finish) - Close connection
R = RST (reset) - Abort connection
P = PSH (push) - Send data immediately
U = URG (urgent) - Urgent data
```

### Hint: I see strange sequence numbers
- Wireshark shows "relative" sequence numbers by default
- Edit > Preferences > Protocols > TCP > "Relative sequence numbers"
- Uncheck this to see actual sequence numbers
- Sequence numbers wrap around after 2^32

### Hint: What are retransmissions?
- TCP retransmits when ACK is not received
- Filter: `tcp.analysis.retransmission`
- Could indicate network problems or packet loss
- In attacks, may indicate SYN flood

### Hint: Connection closed unexpectedly
- Look for RST packets: `tcp.flags.rst == 1`
- RST means connection was aborted, not gracefully closed
- Normal close uses FIN-ACK sequence
- RST can indicate firewall blocking or application crash

---

## HTTP Analysis Hints

### Hint: I can't see HTTP traffic
- Verify you're capturing on the right interface
- Check if traffic is HTTPS (encrypted)
- Use filter: `http` not `tcp.port == 80`
- Some HTTP traffic uses non-standard ports

### Hint: How do I see the full HTTP request?
- Right-click on HTTP packet > Follow > HTTP Stream
- This reconstructs the entire conversation
- Shows request and response together
- Color-coded: client = red, server = blue

### Hint: Where is the POST data?
- Expand: HTTP > HTML Form URL Encoded
- Or look in the packet bytes at the bottom
- Filter: `http.request.method == "POST"`
- Use tshark: `-T fields -e http.file_data`

### Hint: I need to extract files from HTTP
- File > Export Objects > HTTP
- Select the files you want to save
- Works for images, documents, executables
- Only works for complete transfers

### Hint: How do I find specific HTTP content?
- Filter by URI: `http.request.uri contains "login"`
- Filter by host: `http.host contains "example"`
- Filter by cookie: `http.cookie contains "session"`
- Filter by response code: `http.response.code == 200`

---

## DNS Analysis Hints

### Hint: I can't see DNS traffic
- DNS uses UDP port 53 (usually)
- Capture filter: `udp port 53`
- Display filter: `dns`
- Some DNS uses TCP for large responses

### Hint: How do I tell query from response?
- Query: `dns.flags.response == 0`
- Response: `dns.flags.response == 1`
- Queries have question section only
- Responses have answer section

### Hint: What are the DNS record types?
```
A     = IPv4 address (type 1)
AAAA  = IPv6 address (type 28)
CNAME = Canonical name (type 5)
MX    = Mail exchanger (type 15)
NS    = Name server (type 2)
TXT   = Text record (type 16)
PTR   = Reverse lookup (type 12)
SOA   = Start of authority (type 6)
```

### Hint: DNS query name looks strange
- DNS names are length-encoded, not dot-separated internally
- Wireshark decodes this for you
- Very long query names may indicate DNS tunneling
- Check for encoded data in subdomains

### Hint: I need to find DNS errors
- Filter: `dns.flags.rcode != 0`
- NXDOMAIN (code 3) = domain doesn't exist
- SERVFAIL (code 2) = server error
- REFUSED (code 5) = query refused

---

## UDP Analysis Hints

### Hint: UDP packets seem incomplete
- UDP doesn't guarantee delivery
- No retransmission mechanism
- Response might be missing
- Check both directions of traffic

### Hint: I don't see UDP streams in Wireshark
- UDP doesn't have "connections" like TCP
- Use: Follow > UDP Stream
- Based on IP addresses and ports
- May combine unrelated packets

### Hint: What protocols use UDP?
```
DNS     = Port 53
DHCP    = Ports 67, 68
NTP     = Port 123
SNMP    = Port 161
TFTP    = Port 69
VoIP    = Various (SIP: 5060)
Gaming  = Various
```

---

## ICMP Analysis Hints

### Hint: I need to find ping traffic
- Filter: `icmp.type == 8` for echo request (ping)
- Filter: `icmp.type == 0` for echo reply
- Or simply: `icmp`

### Hint: What do ICMP codes mean?
```
Type 0  = Echo Reply
Type 3  = Destination Unreachable
Type 5  = Redirect
Type 8  = Echo Request
Type 11 = Time Exceeded (TTL expired)
```

### Hint: ICMP packet has unusual data
- Normal ping has pattern data or zeros
- Custom data in ICMP payload = suspicious
- Could indicate ICMP tunneling
- Check payload: expand ICMP > Data

---

## Protocol Anomaly Hints

### Hint: How do I detect SYN flood?
- Many SYN packets from one source
- No completing handshakes (no SYN-ACK)
- Filter: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
- Count: `tshark -r file.pcap -Y "tcp.flags.syn==1" | wc -l`

### Hint: How do I detect port scanning?
- Many connection attempts to different ports
- Mostly RST or no response
- Filter: `tcp.flags.rst == 1`
- Look for sequential port numbers

### Hint: How do I detect DNS tunneling?
- Unusually long domain names
- Base64 or hex patterns in subdomains
- High volume of DNS to same domain
- TXT record queries for data exfiltration

### Hint: How do I detect data exfiltration?
- Large outbound data transfers
- Connections to unusual destinations
- Data in protocol fields (DNS, ICMP)
- Encoded payloads

---

## tshark Quick Reference

```bash
# Count packets by protocol
tshark -r file.pcap -q -z io,phs

# List all conversations
tshark -r file.pcap -q -z conv,tcp
tshark -r file.pcap -q -z conv,udp

# Extract specific fields
tshark -r file.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# Follow a stream
tshark -r file.pcap -q -z follow,tcp,ascii,0

# Apply display filter
tshark -r file.pcap -Y "http.request"

# Statistics
tshark -r file.pcap -q -z endpoints,ip
```

---

## Wireshark Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+F | Find packet |
| Ctrl+G | Go to packet number |
| Ctrl+R | Reload capture |
| Ctrl+E | Expert Info |
| Ctrl+Shift+E | Export packet dissection |

---

## Still Stuck?

1. **Read the protocol RFC** - Official specifications explain everything
2. **Use Wireshark Wiki** - Right-click > Wiki Protocol Page
3. **Check packet bytes** - Sometimes the hex reveals what's hidden
4. **Compare with known good** - Capture normal traffic to compare
5. **Ask specific questions** - "Why is this TCP flag set?" not "It doesn't work"

---

## Common Mistakes

| Mistake | Correction |
|---------|------------|
| Using BPF syntax in display filter | Use Wireshark syntax (e.g., `tcp.port` not `port`) |
| Looking for HTTP in HTTPS traffic | Encrypted traffic won't show HTTP fields |
| Expecting TCP data in handshake | Data comes after the 3-way handshake |
| Confusing query and response | Check the QR flag in DNS |
| Ignoring packet timestamps | Time differences reveal patterns |

Remember: Protocol analysis is about understanding the conversation between systems. Think about what each side is trying to communicate!
