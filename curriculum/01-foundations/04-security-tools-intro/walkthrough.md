# Security Tools Introduction - Walkthrough

This walkthrough guides you through practical exercises with Nmap, Netcat, and Wireshark. Follow along step-by-step, typing each command yourself.

## Prerequisites

Ensure you have the following tools installed:

```bash
# Check if tools are installed
which nmap
which nc
which wireshark

# Install if needed (Kali Linux)
sudo apt update
sudo apt install nmap netcat-openbsd wireshark -y
```

## Exercise 1: Network Discovery with Nmap

We'll discover hosts on your local network.

### Step 1: Identify Your Network

First, find your IP address and network range:

```bash
ip addr show
```

Look for your main interface (eth0, wlan0, or similar). Note your IP address and subnet. For example: `192.168.1.105/24`

### Step 2: Perform Host Discovery

Scan your network for live hosts (replace with your network range):

```bash
sudo nmap -sn 192.168.1.0/24
```

**Expected Output:**
```
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0012s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Router Manufacturer)
Nmap scan report for 192.168.1.105
Host is up.
...
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.34 seconds
```

### Step 3: Identify MAC Addresses

The `-sn` scan shows MAC addresses for local hosts. Note these for later identification:

```bash
sudo nmap -sn 192.168.1.0/24 | grep -E "Nmap scan|MAC"
```

### Step 4: Try ARP Ping (Most Reliable for Local Networks)

```bash
sudo nmap -PR 192.168.1.0/24
```

ARP scanning is more reliable on local networks because devices must respond to ARP requests.

---

## Exercise 2: Port Scanning

Now let's scan for open ports. We'll use `scanme.nmap.org` - a legal target provided by Nmap for testing.

### Step 1: Basic Port Scan

```bash
nmap scanme.nmap.org
```

**Expected Output:**
```
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.052s latency).
Not shown: 996 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
9929/tcp  open     nping-echo
31337/tcp open     Elite

Nmap done: 1 IP address (1 host up) scanned in 1.44 seconds
```

### Step 2: Scan Specific Ports

```bash
nmap -p 22,80,443,8080 scanme.nmap.org
```

### Step 3: Version Detection

Identify what services and versions are running:

```bash
nmap -sV scanme.nmap.org
```

**Expected Output:**
```
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp    open  http       Apache httpd 2.4.7 ((Ubuntu))
...
```

### Step 4: OS Detection

Attempt to identify the operating system:

```bash
sudo nmap -O scanme.nmap.org
```

Note: OS detection requires root privileges and needs at least one open and one closed port.

### Step 5: Comprehensive Scan

Combine scan techniques:

```bash
sudo nmap -sS -sV -O -sC scanme.nmap.org
```

This runs:
- `-sS`: SYN scan
- `-sV`: Version detection
- `-O`: OS detection
- `-sC`: Default scripts

### Step 6: Save Results

```bash
nmap -oA scanme_results scanme.nmap.org
```

This creates three files:
- `scanme_results.nmap` (normal)
- `scanme_results.gnmap` (grepable)
- `scanme_results.xml` (XML)

View each:

```bash
cat scanme_results.nmap
cat scanme_results.gnmap
head -50 scanme_results.xml
```

---

## Exercise 3: NSE Scripting

Explore Nmap's Scripting Engine.

### Step 1: Run Default Scripts

```bash
nmap -sC scanme.nmap.org
```

### Step 2: HTTP Scripts

```bash
nmap --script=http-headers scanme.nmap.org -p 80
```

**Output shows HTTP server headers:**
```
PORT   STATE SERVICE
80/tcp open  http
| http-headers:
|   Date: Thu, 15 Jan 2024 10:30:00 GMT
|   Server: Apache/2.4.7 (Ubuntu)
|   ...
```

### Step 3: HTTP Methods Detection

```bash
nmap --script=http-methods scanme.nmap.org -p 80
```

### Step 4: Explore Available Scripts

```bash
ls /usr/share/nmap/scripts/ | head -20

# Search for specific scripts
ls /usr/share/nmap/scripts/ | grep http | head -10

# Get script help
nmap --script-help=http-headers
```

---

## Exercise 4: Netcat Basics

### Step 1: Port Scanning with Netcat

Scan a range of ports:

```bash
nc -zv scanme.nmap.org 20-25
```

**Output:**
```
Connection to scanme.nmap.org 22 port [tcp/ssh] succeeded!
```

The `-z` flag scans without sending data, `-v` provides verbose output.

### Step 2: Single Port Check

```bash
nc -zv scanme.nmap.org 80
```

### Step 3: Banner Grabbing

Connect to SSH and see the banner:

```bash
nc -v scanme.nmap.org 22
```

You'll see something like:
```
Connection to scanme.nmap.org 22 port [tcp/ssh] succeeded!
SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
```

Press Ctrl+C to disconnect.

### Step 4: HTTP Banner Grab

```bash
echo -e "HEAD / HTTP/1.1\r\nHost: scanme.nmap.org\r\n\r\n" | nc scanme.nmap.org 80
```

**Output:**
```
HTTP/1.1 200 OK
Date: Thu, 15 Jan 2024 10:30:00 GMT
Server: Apache/2.4.7 (Ubuntu)
...
```

### Step 5: Full HTTP Request

```bash
echo -e "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\n\r\n" | nc scanme.nmap.org 80 | head -50
```

---

## Exercise 5: Netcat Listener and Client

This exercise requires two terminal windows.

### Step 1: Set Up Listener (Terminal 1)

```bash
nc -l -p 4444
```

The terminal will wait for connections.

### Step 2: Connect as Client (Terminal 2)

```bash
nc localhost 4444
```

### Step 3: Exchange Messages

Type in Terminal 2:
```
Hello from client!
```

You'll see the message appear in Terminal 1.

Type in Terminal 1:
```
Hello from server!
```

The message appears in Terminal 2.

Press Ctrl+C in either terminal to close the connection.

---

## Exercise 6: File Transfer with Netcat

### Step 1: Create a Test File

```bash
echo "This is a secret message for testing file transfer." > /tmp/testfile.txt
cat /tmp/testfile.txt
```

### Step 2: Set Up Receiver (Terminal 1)

```bash
nc -l -p 4444 > /tmp/received.txt
```

### Step 3: Send File (Terminal 2)

```bash
nc localhost 4444 < /tmp/testfile.txt
```

The connection closes automatically after transfer.

### Step 4: Verify Transfer

```bash
cat /tmp/received.txt
diff /tmp/testfile.txt /tmp/received.txt && echo "Files are identical!"
```

---

## Exercise 7: Wireshark Packet Capture

### Step 1: Start Wireshark

```bash
sudo wireshark &
```

Or use the command-line version:
```bash
sudo tshark -i lo -c 10
```

### Step 2: Select Interface

In Wireshark GUI:
1. Double-click on `lo` (loopback) for local testing
2. Or select your main interface (eth0, wlan0) for real traffic

### Step 3: Generate Traffic

While Wireshark captures, generate some traffic:

```bash
ping -c 3 localhost
curl http://example.com
```

### Step 4: Stop Capture

Click the red square button to stop capturing.

### Step 5: Apply Basic Filters

Try these display filters in the filter bar:

```
# Show only ICMP (ping) traffic
icmp

# Show only HTTP traffic
http

# Show traffic to/from specific IP
ip.addr == 93.184.216.34

# Show only TCP SYN packets
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

---

## Exercise 8: Capturing and Analyzing Nmap Traffic

This exercise shows how Nmap works at the packet level.

### Step 1: Start Wireshark Capture

Open Wireshark and start capturing on your main interface.

### Step 2: Run Nmap Scan

In a terminal:

```bash
nmap -sS scanme.nmap.org -p 22,80
```

### Step 3: Stop Capture and Filter

Stop the capture and apply filter:

```
ip.addr == 45.33.32.156
```

(Use the actual IP of scanme.nmap.org from your scan)

### Step 4: Analyze the Packets

Look for the TCP handshake pattern:

1. **SYN packet** (flags: 0x002): Nmap sends to test port
2. **SYN-ACK** (flags: 0x012): Open port responds
3. **RST** (flags: 0x004): Nmap resets without completing connection

For closed ports:
1. **SYN packet**: Nmap sends
2. **RST-ACK**: Server rejects immediately

### Step 5: Color Coding

Notice Wireshark's color coding:
- Light purple: TCP
- Light blue: UDP
- Light green: HTTP
- Pink/red: Errors or RST packets

---

## Exercise 9: Following TCP Streams

### Step 1: Generate HTTP Traffic

Start a capture, then:

```bash
curl http://example.com
```

### Step 2: Find HTTP Packets

Apply filter:
```
http
```

### Step 3: Follow Stream

1. Right-click on an HTTP packet
2. Select "Follow" > "TCP Stream"
3. View the complete HTTP conversation

You'll see:
- Red text: Client request (your curl command)
- Blue text: Server response (the HTML page)

### Step 4: Analyze the Stream

Notice:
- HTTP request headers
- Host header
- Server response headers
- HTML content

---

## Exercise 10: Using tshark (Command-Line Wireshark)

### Step 1: Capture to File

```bash
sudo tshark -i eth0 -c 50 -w /tmp/capture.pcap
```

Generate some traffic (ping, curl) while it captures.

### Step 2: Read Capture File

```bash
tshark -r /tmp/capture.pcap | head -20
```

### Step 3: Apply Display Filter

```bash
tshark -r /tmp/capture.pcap -Y "tcp.port == 80"
```

### Step 4: Extract Specific Fields

```bash
tshark -r /tmp/capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port
```

### Step 5: Count Protocols

```bash
tshark -r /tmp/capture.pcap -q -z io,phs
```

---

## Exercise 11: Integration Challenge

Combine all three tools in a realistic workflow.

### Step 1: Discover Target

```bash
nmap -sn 192.168.1.0/24 | grep "Nmap scan"
```

Pick a target (your router at 192.168.1.1 works well).

### Step 2: Start Wireshark

Begin capturing on your main interface.

### Step 3: Run Port Scan

```bash
nmap -sS -sV 192.168.1.1 -p 1-1000
```

### Step 4: Verify with Netcat

For each open port found, verify:

```bash
nc -zv 192.168.1.1 80
nc -zv 192.168.1.1 443
```

### Step 5: Analyze in Wireshark

1. Stop capture
2. Filter: `ip.addr == 192.168.1.1`
3. Look at the SYN scan pattern
4. Identify open vs closed port responses

### Step 6: Document Findings

Create a simple report:

```bash
cat << EOF > /tmp/scan_report.txt
Target: 192.168.1.1
Date: $(date)

Open Ports:
$(nmap -p 1-1000 192.168.1.1 | grep open)

Banner Information:
- Port 80: $(echo "" | nc -w 2 192.168.1.1 80 2>/dev/null | head -1)
EOF

cat /tmp/scan_report.txt
```

---

## Verification Checklist

Before moving on, ensure you can:

- [ ] Discover live hosts with Nmap ping scan
- [ ] Perform TCP SYN and TCP Connect scans
- [ ] Use version detection to identify services
- [ ] Run NSE scripts for additional information
- [ ] Save Nmap results in multiple formats
- [ ] Use Netcat for port scanning and banner grabbing
- [ ] Transfer files with Netcat
- [ ] Capture traffic with Wireshark
- [ ] Apply display filters effectively
- [ ] Follow TCP streams to see conversations
- [ ] Use tshark for command-line packet analysis

## Common Issues and Solutions

**Nmap permission errors:**
- SYN scans require root: use `sudo nmap -sS`
- Or use TCP Connect scan: `nmap -sT` (no sudo needed)

**Netcat connection refused:**
- Ensure the target port is actually open
- Check if a firewall is blocking connections

**Wireshark no interfaces:**
- Run with sudo: `sudo wireshark`
- Add your user to wireshark group: `sudo usermod -aG wireshark $USER` (logout/login)

**Capture filter errors:**
- Capture filters use BPF syntax (different from display filters)
- Example: `host 192.168.1.1` (capture) vs `ip.addr == 192.168.1.1` (display)

## Next Steps

Continue to the [Lab Environment Setup](../05-lab-environment-setup/README.md) walkthrough to configure your complete CyberLab practice environment.
