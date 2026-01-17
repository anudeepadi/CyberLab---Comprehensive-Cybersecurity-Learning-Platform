# Lab 03: Protocol Analysis

Deep dive into network protocols at the packet level - HTTP, DNS, TCP, UDP, and more.

## Lab Overview

| Attribute | Value |
|-----------|-------|
| **Difficulty** | Intermediate |
| **Duration** | 1.5 hours |
| **Prerequisites** | Lab 01 & 02 |
| **Tools** | Wireshark, tshark, Scapy |
| **Target** | PCAP files, Live traffic |

## Introduction

Understanding protocols at the packet level is essential for:
- Debugging network applications
- Identifying attack signatures
- Performing forensic investigations
- Building security tools
- Recognizing malicious traffic

This lab examines the most common protocols you'll encounter in network security.

## Learning Objectives

By the end of this lab, you will be able to:

- Analyze TCP three-way handshakes and connection states
- Decode HTTP requests and responses
- Understand DNS query/response structure
- Examine UDP communication patterns
- Identify protocol anomalies
- Extract data from protocol fields

## Protocol Overview

### The TCP/IP Stack

```
┌─────────────────────────────────────────────────────────────┐
│ Application Layer                                            │
│   HTTP, HTTPS, DNS, FTP, SSH, SMTP, POP3, IMAP              │
├─────────────────────────────────────────────────────────────┤
│ Transport Layer                                              │
│   TCP (reliable, ordered, connection-oriented)              │
│   UDP (unreliable, fast, connectionless)                    │
├─────────────────────────────────────────────────────────────┤
│ Internet Layer                                               │
│   IP (addressing, routing)                                  │
│   ICMP (diagnostics, errors)                                │
│   ARP (address resolution)                                  │
├─────────────────────────────────────────────────────────────┤
│ Network Access Layer                                         │
│   Ethernet, Wi-Fi, PPP                                      │
└─────────────────────────────────────────────────────────────┘
```

## TCP Protocol Deep Dive

### TCP Header Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┤
│          Source Port          │       Destination Port        │
├───────────────────────────────┴───────────────────────────────┤
│                        Sequence Number                        │
├───────────────────────────────────────────────────────────────┤
│                    Acknowledgment Number                      │
├───────┬───────┬─┬─┬─┬─┬─┬─┬───────────────────────────────────┤
│  Data │       │U│A│P│R│S│F│                                   │
│ Offset│ Rsrvd │R│C│S│S│Y│I│            Window                 │
│       │       │G│K│H│T│N│N│                                   │
├───────┴───────┴─┴─┴─┴─┴─┴─┴───────────────────────────────────┤
│           Checksum            │         Urgent Pointer        │
├───────────────────────────────┴───────────────────────────────┤
│                    Options (if any)                           │
└───────────────────────────────────────────────────────────────┘
```

### TCP Flags

| Flag | Name | Purpose |
|------|------|---------|
| SYN | Synchronize | Initiate connection |
| ACK | Acknowledge | Confirm receipt |
| FIN | Finish | Close connection |
| RST | Reset | Abort connection |
| PSH | Push | Send data immediately |
| URG | Urgent | Urgent data present |

### TCP Three-Way Handshake

```
Client                          Server
  │                                │
  │──────── SYN (seq=x) ──────────>│  Step 1: Client initiates
  │                                │
  │<─── SYN-ACK (seq=y, ack=x+1) ──│  Step 2: Server responds
  │                                │
  │──────── ACK (ack=y+1) ─────────>│  Step 3: Client confirms
  │                                │
  │      [Connection Established]   │
```

### TCP Connection Termination

```
Client                          Server
  │                                │
  │──────── FIN ──────────────────>│  Step 1: Client wants to close
  │                                │
  │<─────── ACK ───────────────────│  Step 2: Server acknowledges
  │                                │
  │<─────── FIN ───────────────────│  Step 3: Server ready to close
  │                                │
  │──────── ACK ──────────────────>│  Step 4: Client confirms
  │                                │
  │      [Connection Closed]        │
```

## HTTP Protocol Deep Dive

### HTTP Request Structure

```
GET /path/page.html HTTP/1.1          <- Request Line
Host: www.example.com                 <- Headers
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: session=abc123
                                      <- Empty line
[Request Body - for POST/PUT]         <- Body (optional)
```

### HTTP Response Structure

```
HTTP/1.1 200 OK                       <- Status Line
Date: Mon, 15 Jan 2024 10:30:00 GMT   <- Headers
Server: Apache/2.4.41
Content-Type: text/html; charset=UTF-8
Content-Length: 1234
Set-Cookie: session=xyz789
Connection: keep-alive
                                      <- Empty line
<!DOCTYPE html>                       <- Body
<html>...
```

### HTTP Methods

| Method | Purpose | Has Body |
|--------|---------|----------|
| GET | Retrieve resource | No |
| POST | Submit data | Yes |
| PUT | Update resource | Yes |
| DELETE | Remove resource | No |
| HEAD | Get headers only | No |
| OPTIONS | Get allowed methods | No |

### HTTP Status Codes

| Code | Category | Examples |
|------|----------|----------|
| 1xx | Informational | 100 Continue |
| 2xx | Success | 200 OK, 201 Created |
| 3xx | Redirection | 301 Moved, 302 Found |
| 4xx | Client Error | 400 Bad Request, 404 Not Found |
| 5xx | Server Error | 500 Internal Error, 503 Unavailable |

## DNS Protocol Deep Dive

### DNS Query Structure

```
┌──────────────────────────────────────────┐
│                Header                     │
│  ID, Flags, Question/Answer Counts       │
├──────────────────────────────────────────┤
│                Question                   │
│  QNAME: www.example.com                  │
│  QTYPE: A (IPv4 address)                 │
│  QCLASS: IN (Internet)                   │
├──────────────────────────────────────────┤
│                Answer (in response)       │
│  NAME: www.example.com                   │
│  TYPE: A                                 │
│  CLASS: IN                               │
│  TTL: 3600                               │
│  RDATA: 93.184.216.34                    │
└──────────────────────────────────────────┘
```

### DNS Record Types

| Type | Purpose | Example |
|------|---------|---------|
| A | IPv4 address | 192.168.1.1 |
| AAAA | IPv6 address | 2001:db8::1 |
| CNAME | Canonical name (alias) | www -> server1 |
| MX | Mail exchanger | mail.example.com |
| NS | Name server | ns1.example.com |
| TXT | Text record | SPF, DKIM |
| PTR | Reverse lookup | IP -> hostname |
| SOA | Start of authority | Zone info |

## UDP Protocol

### UDP Header Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┤
│          Source Port          │       Destination Port        │
├───────────────────────────────┴───────────────────────────────┤
│            Length             │           Checksum            │
├───────────────────────────────┴───────────────────────────────┤
│                             Data                              │
└───────────────────────────────────────────────────────────────┘
```

### TCP vs UDP

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Required | None |
| Reliability | Guaranteed delivery | Best effort |
| Ordering | Preserved | Not guaranteed |
| Speed | Slower (overhead) | Faster |
| Use Cases | HTTP, SSH, FTP | DNS, VoIP, Gaming |
| Header Size | 20+ bytes | 8 bytes |

## ICMP Protocol

### Common ICMP Types

| Type | Name | Purpose |
|------|------|---------|
| 0 | Echo Reply | Ping response |
| 3 | Destination Unreachable | Routing failure |
| 5 | Redirect | Route change |
| 8 | Echo Request | Ping request |
| 11 | Time Exceeded | TTL expired |

## Lab Exercises

### Exercise 1: TCP Handshake Analysis
Capture and analyze a complete TCP connection lifecycle.

### Exercise 2: HTTP Request/Response Analysis
Examine HTTP headers, methods, and status codes.

### Exercise 3: DNS Query Analysis
Trace DNS resolution from query to answer.

### Exercise 4: UDP Communication
Compare UDP's simplicity with TCP's complexity.

### Exercise 5: Protocol Anomalies
Identify malformed or suspicious protocol behavior.

## Key Wireshark Filters

### TCP Filters
```
tcp.flags.syn == 1 && tcp.flags.ack == 0    # SYN only (new connection)
tcp.flags.syn == 1 && tcp.flags.ack == 1    # SYN-ACK
tcp.flags.fin == 1                          # Connection close
tcp.flags.rst == 1                          # Connection reset
tcp.analysis.retransmission                 # Retransmissions
tcp.analysis.duplicate_ack                  # Duplicate ACKs
tcp.stream eq 0                             # First TCP stream
```

### HTTP Filters
```
http.request                                # All HTTP requests
http.response                               # All HTTP responses
http.request.method == "GET"                # GET requests
http.request.method == "POST"               # POST requests
http.response.code == 200                   # OK responses
http.response.code >= 400                   # Error responses
http.host contains "example"                # Specific host
http.request.uri contains "login"           # URI pattern
```

### DNS Filters
```
dns                                         # All DNS
dns.flags.response == 0                     # Queries only
dns.flags.response == 1                     # Responses only
dns.qry.type == 1                           # A record queries
dns.qry.name contains "google"              # Specific domain
dns.flags.rcode != 0                        # Error responses
```

## Security Considerations

### Protocol-Based Attacks

| Protocol | Attack | Indicator |
|----------|--------|-----------|
| TCP | SYN Flood | Many SYN, no ACK |
| TCP | RST Injection | Unexpected RST packets |
| HTTP | SQL Injection | SQLi patterns in URI |
| HTTP | XSS | Script tags in parameters |
| DNS | DNS Tunneling | Long query names |
| DNS | DNS Amplification | Large responses to small queries |
| ICMP | Ping of Death | Oversized ICMP packets |
| ICMP | ICMP Tunneling | Data in ICMP payload |

---

**Next Steps:**
- Complete the [Walkthrough](./walkthrough.md) for hands-on practice
- Use [Hints](./hints.md) if you get stuck
- Proceed to [Lab 04: Network Forensics](../04-network-forensics/README.md)
