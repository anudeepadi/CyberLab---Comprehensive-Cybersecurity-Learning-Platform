# Lab 01: Packet Capture Basics - Walkthrough

Step-by-step guide to master packet capture with tcpdump and Wireshark.

## Setup

Before starting, ensure your environment is ready:

```bash
# Verify tcpdump is installed
which tcpdump

# Verify Wireshark/tshark is installed
which wireshark
which tshark

# Start Apache for HTTP traffic generation
sudo systemctl start apache2

# Verify web server is running
curl -s http://localhost/network-labs/ | head -3
```

---

## Exercise 1: Your First Capture with tcpdump

### Step 1: View Available Interfaces

```bash
# List all network interfaces
ip addr show

# Or use tcpdump to list interfaces
sudo tcpdump -D
```

You should see interfaces like:
- `lo` - Loopback (localhost traffic)
- `eth0` or `ens33` - Primary network interface
- `docker0` - Docker bridge (if Docker is running)

### Step 2: Start a Basic Capture

```bash
# Capture on loopback interface (for localhost traffic)
sudo tcpdump -i lo

# Let it run and observe the output format
# Press Ctrl+C to stop
```

### Step 3: Generate Traffic While Capturing

Open two terminal windows:

**Terminal 1 - Capture:**
```bash
sudo tcpdump -i lo -n
```

**Terminal 2 - Generate traffic:**
```bash
# Simple ping
ping -c 3 127.0.0.1

# HTTP request
curl http://localhost/network-labs/
```

### Step 4: Understand the Output

tcpdump output format:
```
timestamp protocol source > destination: info
```

Example TCP packet:
```
14:23:45.123456 IP 127.0.0.1.54321 > 127.0.0.1.80: Flags [S], seq 1234567890
```

Breaking it down:
- `14:23:45.123456` - Timestamp
- `IP` - Protocol (Internet Protocol)
- `127.0.0.1.54321` - Source IP and port
- `127.0.0.1.80` - Destination IP and port
- `Flags [S]` - TCP SYN flag (connection initiation)
- `seq 1234567890` - Sequence number

### Step 5: Apply a Capture Filter

```bash
# Capture only HTTP traffic (port 80)
sudo tcpdump -i lo port 80

# Generate HTTP traffic in another terminal
curl http://localhost/network-labs/
```

You should only see TCP traffic on port 80, not the ping packets.

---

## Exercise 2: Save and Read PCAP Files

### Step 1: Capture to a File

```bash
# Create a capture file
sudo tcpdump -i lo -w /tmp/capture1.pcap -c 50

# Generate some traffic in another terminal
curl http://localhost/network-labs/
ping -c 3 127.0.0.1
```

The `-c 50` option captures only 50 packets then stops.

### Step 2: Read the PCAP File

```bash
# Read with tcpdump
sudo tcpdump -r /tmp/capture1.pcap

# Read with more detail
sudo tcpdump -r /tmp/capture1.pcap -n -vv

# Read only HTTP traffic
sudo tcpdump -r /tmp/capture1.pcap port 80
```

### Step 3: Use tshark for Analysis

```bash
# Read with tshark
tshark -r /tmp/capture1.pcap

# Show only HTTP requests
tshark -r /tmp/capture1.pcap -Y "http.request"

# Extract specific fields
tshark -r /tmp/capture1.pcap -Y "http" -T fields -e ip.src -e ip.dst -e http.request.uri
```

---

## Exercise 3: Introduction to Wireshark

### Step 1: Open Wireshark

```bash
# Start Wireshark (may need sudo)
wireshark &

# Or open a specific file
wireshark /tmp/capture1.pcap &
```

### Step 2: Explore the Interface

Wireshark has three main panels:

```
┌──────────────────────────────────────────────────────┐
│ Packet List (top)                                     │
│ - All captured packets with summary info              │
│ - Click to select a packet                            │
├──────────────────────────────────────────────────────┤
│ Packet Details (middle)                               │
│ - Expandable protocol layers                          │
│ - Click + to expand layers                            │
├──────────────────────────────────────────────────────┤
│ Packet Bytes (bottom)                                 │
│ - Raw hex and ASCII representation                    │
└──────────────────────────────────────────────────────┘
```

### Step 3: Navigate Packets

- **Click** on a packet in the list to view details
- **Double-click** to open in new window
- **Ctrl+F** to find packets
- **Arrow keys** to move between packets

### Step 4: Expand Protocol Layers

In the Packet Details pane:
1. Click `+` next to "Frame" to see frame info
2. Click `+` next to "Ethernet" to see MAC addresses
3. Click `+` next to "Internet Protocol" to see IP info
4. Click `+` next to "Transmission Control Protocol" to see TCP details

### Step 5: Color Coding

Wireshark uses colors to identify traffic:
- **Light purple** - TCP
- **Light blue** - UDP
- **Light green** - HTTP
- **Light yellow** - DNS
- **Black/Red** - Errors/Problems

---

## Exercise 4: Capture Filters vs Display Filters

### Understanding the Difference

| Capture Filter | Display Filter |
|---------------|----------------|
| Applied during capture | Applied after capture |
| Reduces file size | Only changes view |
| BPF syntax | Wireshark syntax |
| Set before starting | Can change anytime |
| Efficient for large captures | Better for analysis |

### Step 1: Capture with a Capture Filter

```bash
# Only capture TCP port 80
sudo tcpdump -i lo -w /tmp/http_only.pcap "tcp port 80"

# Generate mixed traffic
curl http://localhost/network-labs/
ping -c 3 127.0.0.1  # This won't be captured

# Verify - should only show HTTP
tcpdump -r /tmp/http_only.pcap
```

### Step 2: Use Display Filters in Wireshark

1. Open `/tmp/capture1.pcap` in Wireshark
2. In the filter bar at top, type: `http`
3. Press Enter or click Apply
4. Only HTTP packets are now shown

Try other display filters:
```
tcp                         # All TCP traffic
icmp                        # ICMP only (ping)
tcp.port == 80              # TCP port 80
ip.addr == 127.0.0.1        # Specific IP
http.request.method == GET  # HTTP GET requests
```

### Step 3: Clear and Combine Filters

- Click the **X** button to clear filter
- Combine with `and` / `or`:
  ```
  http and ip.src == 127.0.0.1
  tcp.port == 80 or tcp.port == 443
  dns or icmp
  ```

---

## Exercise 5: Following Streams

### Step 1: Capture HTTP Traffic

```bash
# Start capture
sudo tcpdump -i lo -w /tmp/http_stream.pcap port 80 &

# Generate HTTP traffic
curl http://localhost/network-labs/
curl -X POST http://localhost/network-labs/login.php -d "username=test&password=secret"

# Stop capture
sudo pkill tcpdump
```

### Step 2: Follow TCP Stream in Wireshark

1. Open `/tmp/http_stream.pcap` in Wireshark
2. Find an HTTP packet (look for green packets or filter `http`)
3. Right-click on the packet
4. Select **Follow** -> **TCP Stream**

A new window shows the complete conversation:
- **Red text** - Client to server (requests)
- **Blue text** - Server to client (responses)

### Step 3: Follow HTTP Stream

For HTTP-specific following:
1. Find an HTTP packet
2. Right-click -> **Follow** -> **HTTP Stream**

This shows the HTTP request and response more cleanly.

### Step 4: Export Stream Content

In the stream window:
- Use "Show and save data as" dropdown
- Options: ASCII, Hex Dump, C Arrays, Raw
- Click "Save as..." to save content

---

## Exercise 6: Capturing Credentials

### Step 1: Set Up the Capture

```bash
# Start capturing on loopback
sudo tcpdump -i lo -w /tmp/credentials.pcap port 80
```

### Step 2: Send Login Request

In another terminal:
```bash
# Simulate login with credentials
curl -X POST http://localhost/network-labs/login.php \
    -d "username=admin&password=P@ssw0rd123"
```

### Step 3: Stop and Analyze

```bash
# Stop tcpdump
sudo pkill tcpdump

# Quick analysis with tshark
tshark -r /tmp/credentials.pcap -Y "http.request.method==POST" \
    -T fields -e http.file_data
```

Output should show:
```
username=admin&password=P@ssw0rd123
```

### Step 4: Analyze in Wireshark

1. Open `/tmp/credentials.pcap`
2. Filter: `http.request.method == POST`
3. Click on the POST packet
4. Expand "Hypertext Transfer Protocol"
5. Look for "HTML Form URL Encoded"
6. See the username and password in clear text!

### Security Lesson

This demonstrates why **HTTPS is critical**:
- HTTP transmits data in cleartext
- Anyone on the network path can see credentials
- HTTPS encrypts the connection
- Modern sites should always use HTTPS for sensitive data

---

## Exercise 7: Advanced tcpdump Options

### Verbose Output

```bash
# Increasing verbosity levels
sudo tcpdump -i lo -v      # Verbose
sudo tcpdump -i lo -vv     # More verbose
sudo tcpdump -i lo -vvv    # Maximum verbosity
```

### Display Content

```bash
# ASCII output (readable text)
sudo tcpdump -i lo -A port 80

# Hex and ASCII
sudo tcpdump -i lo -X port 80

# Hex only
sudo tcpdump -i lo -x port 80
```

### Practical Examples

```bash
# Capture first 100 packets, don't resolve names
sudo tcpdump -i lo -c 100 -n -w /tmp/quick.pcap

# Capture with timestamp for each packet
sudo tcpdump -i lo -tttt

# Rotate capture files (new file every 1MB)
sudo tcpdump -i lo -w /tmp/capture -C 1 -W 5

# Capture with packet size limit (snap length)
sudo tcpdump -i lo -s 96  # Only first 96 bytes
```

---

## Verification Checklist

After completing this lab, verify you can:

- [ ] List network interfaces with `ip addr` or `tcpdump -D`
- [ ] Capture live traffic with `tcpdump -i <interface>`
- [ ] Save captures to PCAP files with `-w`
- [ ] Read PCAP files with `tcpdump -r` and `tshark -r`
- [ ] Apply capture filters (BPF syntax)
- [ ] Apply display filters in Wireshark
- [ ] Navigate Wireshark's three-panel interface
- [ ] Follow TCP/HTTP streams
- [ ] Extract credentials from HTTP traffic
- [ ] Explain why HTTPS is important

---

## Common Commands Summary

```bash
# tcpdump essentials
sudo tcpdump -i lo                    # Capture on loopback
sudo tcpdump -i any                   # All interfaces
sudo tcpdump -w file.pcap             # Write to file
sudo tcpdump -r file.pcap             # Read from file
sudo tcpdump -n                       # Don't resolve names
sudo tcpdump port 80                  # Filter port 80
sudo tcpdump host 192.168.1.1         # Filter by host
sudo tcpdump -A                       # ASCII output
sudo tcpdump -c 100                   # Capture 100 packets

# tshark essentials
tshark -i eth0                        # Capture live
tshark -r file.pcap                   # Read file
tshark -Y "http"                      # Display filter
tshark -T fields -e ip.src            # Extract fields

# Wireshark
wireshark file.pcap                   # Open file
# Display filters:
http                                  # HTTP traffic
tcp.port == 80                        # Port 80
ip.addr == 192.168.1.1                # Specific IP
http.request.method == POST           # POST requests
```

---

**Next:** [Lab 02: Traffic Analysis](../02-traffic-analysis/README.md)
