# Lab 01: Packet Capture Basics - Hints

Progressive hints for each exercise. Try to solve on your own first!

---

## Exercise 1: Your First Capture with tcpdump

### Hint 1: Permission Issues
<details>
<summary>Click to reveal</summary>

If you get "permission denied", you need root privileges:
```bash
sudo tcpdump -i lo
```
Packet capture requires elevated permissions to access raw network interfaces.
</details>

### Hint 2: Finding the Right Interface
<details>
<summary>Click to reveal</summary>

Not sure which interface to use?
```bash
# List all interfaces
ip addr show

# Or let tcpdump list them
sudo tcpdump -D
```
Common interfaces:
- `lo` - Loopback (localhost traffic)
- `eth0` or `enp0s3` - Ethernet
- `wlan0` - Wireless
- `any` - Capture on all interfaces
</details>

### Hint 3: Understanding Output
<details>
<summary>Click to reveal</summary>

tcpdump output format:
```
timestamp proto source.port > dest.port: flags, seq, ack, options
```

Example:
```
12:34:56.789 IP 192.168.1.10.54321 > 192.168.1.1.80: Flags [S], seq 123
```
- `12:34:56.789` - Time of packet
- `IP` - Internet Protocol
- `192.168.1.10.54321` - Source IP and port
- `192.168.1.1.80` - Destination IP and port 80
- `Flags [S]` - TCP SYN flag
</details>

---

## Exercise 2: Save and Read PCAP Files

### Hint 1: Writing to File
<details>
<summary>Click to reveal</summary>

Use the `-w` flag to write to a file:
```bash
sudo tcpdump -i lo -w /tmp/capture.pcap
```
The file won't be readable as text - it's in PCAP binary format.
</details>

### Hint 2: Reading PCAP Files
<details>
<summary>Click to reveal</summary>

Use `-r` to read:
```bash
tcpdump -r /tmp/capture.pcap
```
No `sudo` needed for reading files you own.

Add `-n` to skip DNS lookups (faster):
```bash
tcpdump -r /tmp/capture.pcap -n
```
</details>

### Hint 3: Using tshark
<details>
<summary>Click to reveal</summary>

tshark is Wireshark's command-line version:
```bash
# Basic read
tshark -r /tmp/capture.pcap

# With display filter
tshark -r /tmp/capture.pcap -Y "http"

# Extract specific fields
tshark -r /tmp/capture.pcap -T fields -e ip.src -e ip.dst
```
</details>

---

## Exercise 3: Introduction to Wireshark

### Hint 1: Starting Wireshark
<details>
<summary>Click to reveal</summary>

```bash
# GUI method
wireshark &

# Open specific file
wireshark /tmp/capture.pcap &

# If you get permission errors
sudo wireshark &  # Not recommended for security
```

Better solution for permissions:
```bash
sudo usermod -aG wireshark $USER
# Then log out and back in
```
</details>

### Hint 2: Navigating the Interface
<details>
<summary>Click to reveal</summary>

Three main panes:
1. **Packet List** (top) - List of all packets
2. **Packet Details** (middle) - Protocol layers
3. **Packet Bytes** (bottom) - Raw hex data

To customize:
- Drag the dividers between panes
- View menu -> customize layout
- Click column headers to sort
</details>

### Hint 3: Finding Specific Packets
<details>
<summary>Click to reveal</summary>

Use `Ctrl+F` to open Find dialog:
- **Display filter** - Filter syntax
- **Hex value** - Search for hex pattern
- **String** - Search for text

Jump to packet number: `Ctrl+G`
</details>

---

## Exercise 4: Capture Filters vs Display Filters

### Hint 1: Capture Filter Syntax
<details>
<summary>Click to reveal</summary>

Capture filters use BPF (Berkeley Packet Filter) syntax:
```bash
# In tcpdump
sudo tcpdump -i lo "port 80"
sudo tcpdump -i lo "host 192.168.1.1 and tcp"
sudo tcpdump -i lo "not port 22"

# In Wireshark (Capture menu -> Options -> Capture filter)
```
Set BEFORE starting capture - can't change during capture.
</details>

### Hint 2: Display Filter Syntax
<details>
<summary>Click to reveal</summary>

Display filters use Wireshark syntax:
```
http                           # Protocol
ip.addr == 192.168.1.1         # IP address
tcp.port == 80                 # Port number
http.request.method == "GET"   # HTTP method
```

Type in the filter bar at top of Wireshark.
Green background = valid filter
Red background = syntax error
</details>

### Hint 3: When to Use Which
<details>
<summary>Click to reveal</summary>

**Use Capture Filters when:**
- You know exactly what you want
- Capturing for a long time
- Limited disk space
- High-traffic networks

**Use Display Filters when:**
- Exploring unknown traffic
- Need to see everything first
- Switching between different views
- Already have a PCAP file
</details>

---

## Exercise 5: Following Streams

### Hint 1: Finding the Right Packet
<details>
<summary>Click to reveal</summary>

First, filter to find relevant packets:
```
http           # All HTTP traffic
tcp.port == 80 # TCP on port 80
http.request   # HTTP requests only
```
Then right-click on any packet in the conversation.
</details>

### Hint 2: Follow Menu Options
<details>
<summary>Click to reveal</summary>

Right-click -> Follow:
- **TCP Stream** - Raw TCP data
- **UDP Stream** - Raw UDP data
- **HTTP Stream** - HTTP request/response
- **TLS Stream** - Decrypted TLS (if keys available)

TCP Stream is most commonly used.
</details>

### Hint 3: Understanding Stream Colors
<details>
<summary>Click to reveal</summary>

In the stream window:
- **Red text** - Data sent from client to server
- **Blue text** - Data sent from server to client

This helps identify request vs response.
</details>

---

## Exercise 6: Capturing Credentials

### Hint 1: Setting Up the Capture
<details>
<summary>Click to reveal</summary>

```bash
# Capture HTTP traffic
sudo tcpdump -i lo -w /tmp/creds.pcap port 80

# In another terminal, send login
curl -X POST http://localhost/network-labs/login.php \
    -d "username=testuser&password=testpass"

# Stop capture with Ctrl+C
```
</details>

### Hint 2: Finding POST Data
<details>
<summary>Click to reveal</summary>

With tshark:
```bash
tshark -r /tmp/creds.pcap -Y "http.request.method==POST" -T fields -e http.file_data
```

With Wireshark:
1. Filter: `http.request.method == POST`
2. Click on POST packet
3. Expand "HTML Form URL Encoded" in details
</details>

### Hint 3: What This Demonstrates
<details>
<summary>Click to reveal</summary>

This shows why HTTPS matters:
- HTTP sends data in cleartext
- Anyone on the network can see passwords
- HTTPS encrypts the entire conversation
- You'd only see encrypted gibberish with HTTPS

Modern applications should NEVER use HTTP for sensitive data.
</details>

---

## General Troubleshooting Hints

### tcpdump Shows Nothing
<details>
<summary>Click to reveal</summary>

Check these:
1. Are you on the right interface? (`-i lo` for localhost, `-i eth0` for network)
2. Is there actually traffic? (Try `ping` in another terminal)
3. Is the filter too restrictive? (Remove filter temporarily)
4. Running as root? (`sudo`)
</details>

### Wireshark Won't Start
<details>
<summary>Click to reveal</summary>

Try:
```bash
# Run with sudo (not ideal)
sudo wireshark

# Better: Add yourself to wireshark group
sudo usermod -aG wireshark $USER
# Then log out and log back in

# Check if running
ps aux | grep wireshark
```
</details>

### PCAP File Won't Open
<details>
<summary>Click to reveal</summary>

Verify it's a valid PCAP:
```bash
file /tmp/capture.pcap
# Should show: pcap capture file

# Check if it has data
ls -la /tmp/capture.pcap
# Size should be > 24 bytes
```
</details>

### Filter Syntax Errors
<details>
<summary>Click to reveal</summary>

Common mistakes:
```
# Wrong:
ip.addr = 192.168.1.1     # Should use ==
tcp.port eq 80            # Use == not eq
http.method == GET        # Should be http.request.method
host == 192.168.1.1       # This is tcpdump syntax, not Wireshark

# Correct:
ip.addr == 192.168.1.1
tcp.port == 80
http.request.method == "GET"
ip.addr == 192.168.1.1    # Wireshark syntax
```
</details>

---

## Quick Reference

### tcpdump Cheat Sheet
```bash
sudo tcpdump -i lo            # Capture on loopback
sudo tcpdump -w file.pcap     # Save to file
tcpdump -r file.pcap          # Read from file
sudo tcpdump port 80          # Capture port 80
sudo tcpdump host 10.0.0.1    # Capture specific host
sudo tcpdump -n               # No name resolution
sudo tcpdump -c 100           # Capture 100 packets
sudo tcpdump -A               # ASCII output
```

### Wireshark Display Filters
```
http                          # HTTP traffic
tcp.port == 80                # TCP port 80
ip.addr == 10.0.0.1           # Specific IP
http.request.method == POST   # POST requests
dns                           # DNS traffic
tcp.flags.syn == 1            # SYN packets
```

---

**Still stuck?** Check the full [Walkthrough](./walkthrough.md) for complete solutions.
