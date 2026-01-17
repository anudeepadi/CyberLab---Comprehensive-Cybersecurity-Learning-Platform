# Lab 01: Wireless Fundamentals

Understanding the foundation of 802.11 wireless networks, frequencies, channels, and network architecture.

```
╔═══════════════════════════════════════════════════════════════╗
║                   WIRELESS FUNDAMENTALS                        ║
╠═══════════════════════════════════════════════════════════════╣
║  Difficulty: Beginner        Duration: 1 hour                 ║
║  Hardware: None Required     Type: Theory                     ║
╚═══════════════════════════════════════════════════════════════╝
```

## Learning Objectives

By the end of this lab, you will:

1. Understand the IEEE 802.11 standard family
2. Know the differences between frequency bands (2.4GHz vs 5GHz vs 6GHz)
3. Understand wireless channels and their overlap
4. Identify different wireless network types and topologies
5. Recognize key components of wireless infrastructure

## Legal Notice

This lab is purely theoretical and does not require any wireless testing. The concepts learned here form the foundation for understanding wireless security vulnerabilities covered in subsequent labs.

## IEEE 802.11 Standards Overview

### Evolution of WiFi Standards

```
Timeline of 802.11 Standards:

1997 ──► 802.11    (Legacy)     2 Mbps      2.4 GHz
  │
1999 ──► 802.11a   (WiFi 1)    54 Mbps      5 GHz
  │
1999 ──► 802.11b   (WiFi 2)    11 Mbps      2.4 GHz
  │
2003 ──► 802.11g   (WiFi 3)    54 Mbps      2.4 GHz
  │
2009 ──► 802.11n   (WiFi 4)   600 Mbps      2.4/5 GHz
  │
2013 ──► 802.11ac  (WiFi 5)   6.9 Gbps      5 GHz
  │
2019 ──► 802.11ax  (WiFi 6)   9.6 Gbps      2.4/5/6 GHz
  │
2024 ──► 802.11be  (WiFi 7)   46 Gbps       2.4/5/6 GHz
```

### Standard Comparison Table

| Standard | WiFi Gen | Max Speed | Frequency | Channel Width | MIMO |
|----------|----------|-----------|-----------|---------------|------|
| 802.11a | 1 | 54 Mbps | 5 GHz | 20 MHz | No |
| 802.11b | 2 | 11 Mbps | 2.4 GHz | 22 MHz | No |
| 802.11g | 3 | 54 Mbps | 2.4 GHz | 20 MHz | No |
| 802.11n | 4 | 600 Mbps | 2.4/5 GHz | 20/40 MHz | 4x4 |
| 802.11ac | 5 | 6.9 Gbps | 5 GHz | 20-160 MHz | 8x8 |
| 802.11ax | 6/6E | 9.6 Gbps | 2.4/5/6 GHz | 20-160 MHz | 8x8 |

### Key Technologies by Generation

**802.11n (WiFi 4) Introduced:**
- MIMO (Multiple Input Multiple Output)
- Channel bonding (40 MHz)
- Frame aggregation
- Dual-band operation

**802.11ac (WiFi 5) Introduced:**
- MU-MIMO (Multi-User MIMO)
- Wider channels (80/160 MHz)
- Beamforming
- 256-QAM modulation

**802.11ax (WiFi 6) Introduced:**
- OFDMA (Orthogonal Frequency Division Multiple Access)
- 1024-QAM modulation
- Target Wake Time (TWT)
- BSS Coloring
- WPA3 mandatory

## Radio Frequencies and Spectrum

### 2.4 GHz Band (ISM Band)

```
2.4 GHz Spectrum (2400 - 2500 MHz):

Channel:  1    2    3    4    5    6    7    8    9   10   11  12  13  14
         ┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬───┬───┬───┬──┐
MHz:   2412 2417 2422 2427 2432 2437 2442 2447 2452 2457 2462 2467 2472 2484
         └────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴───┴───┴───┴──┘

Non-overlapping channels: 1, 6, 11 (US/Canada)
                         1, 5, 9, 13 (Europe - 4 channels)

Channel Width: 22 MHz (overlaps adjacent channels)

       Ch 1          Ch 6          Ch 11
    ┌───────┐     ┌───────┐     ┌───────┐
    │       │     │       │     │       │
────┴───────┴─────┴───────┴─────┴───────┴────
   2401   2423   2426   2448   2451   2473
```

**2.4 GHz Characteristics:**
- Better wall penetration
- Longer range
- More interference (microwaves, Bluetooth, baby monitors)
- Only 3 non-overlapping channels (US)
- Crowded spectrum

### 5 GHz Band (U-NII Bands)

```
5 GHz Spectrum Overview:

U-NII-1 (Indoor)     U-NII-2A (Low)      U-NII-2C (Extended)    U-NII-3
5150-5250 MHz        5250-5350 MHz       5470-5725 MHz          5725-5850 MHz
    │                    │                    │                     │
    ▼                    ▼                    ▼                     ▼
┌─────────────┐    ┌─────────────┐    ┌──────────────────┐   ┌─────────────┐
│ Ch 36-48    │    │ Ch 52-64    │    │ Ch 100-144       │   │ Ch 149-165  │
│ 4 channels  │    │ 4 channels  │    │ 12 channels      │   │ 5 channels  │
│ Indoor only │    │ DFS/TPC     │    │ DFS/TPC          │   │ Outdoor OK  │
└─────────────┘    └─────────────┘    └──────────────────┘   └─────────────┘

DFS = Dynamic Frequency Selection (must avoid radar)
TPC = Transmit Power Control

Total: 25 non-overlapping 20 MHz channels in 5 GHz
```

**5 GHz Channels:**
```
Channel  Center Freq   Usage Notes
--------------------------------------
36       5180 MHz      Indoor, no DFS
40       5200 MHz      Indoor, no DFS
44       5220 MHz      Indoor, no DFS
48       5240 MHz      Indoor, no DFS
52       5260 MHz      DFS required
56       5280 MHz      DFS required
60       5300 MHz      DFS required
64       5320 MHz      DFS required
100      5500 MHz      DFS required
104      5520 MHz      DFS required
108      5540 MHz      DFS required
112      5560 MHz      DFS required
116      5580 MHz      DFS required
120      5600 MHz      DFS required
124      5620 MHz      DFS required
128      5640 MHz      DFS required
132      5660 MHz      DFS required
136      5680 MHz      DFS required
140      5700 MHz      DFS required
144      5720 MHz      DFS required
149      5745 MHz      No DFS
153      5765 MHz      No DFS
157      5785 MHz      No DFS
161      5805 MHz      No DFS
165      5825 MHz      No DFS
```

### 6 GHz Band (WiFi 6E/7)

```
6 GHz Spectrum (5925 - 7125 MHz):

┌───────────────────────────────────────────────────────────────┐
│                    1200 MHz of Spectrum                       │
│                                                               │
│  59 new 20 MHz channels                                       │
│  14 new 80 MHz channels                                       │
│  7 new 160 MHz channels                                       │
│                                                               │
│  Less congestion (new spectrum)                               │
│  Requires WiFi 6E/7 compatible devices                        │
│  WPA3 mandatory                                               │
└───────────────────────────────────────────────────────────────┘
```

## Wireless Network Architecture

### Network Types

```
1. INFRASTRUCTURE MODE (Most Common)
   ═══════════════════════════════

   ┌──────────────────────────────────────┐
   │              INTERNET                │
   └──────────────────────────────────────┘
                    │
                    ▼
            ┌───────────────┐
            │    Router     │
            │  (Gateway)    │
            └───────────────┘
                    │
                    ▼
            ┌───────────────┐
            │ Access Point  │──── BSSID (AP MAC)
            │    (AP)       │──── ESSID (Network Name)
            └───────────────┘
               ╱    │    ╲
              ╱     │     ╲
             ▼      ▼      ▼
          ┌───┐  ┌───┐  ┌───┐
          │STA│  │STA│  │STA│  (Stations/Clients)
          └───┘  └───┘  └───┘


2. AD-HOC MODE (Peer-to-Peer)
   ══════════════════════════

          ┌───┐         ┌───┐
          │STA│◄───────►│STA│
          └───┘         └───┘
             ╲           ╱
              ╲         ╱
               ╲       ╱
                ┌───┐
                │STA│
                └───┘

   - No central AP
   - Direct device-to-device
   - IBSS (Independent Basic Service Set)


3. MESH NETWORK
   ═════════════

   ┌────┐     ┌────┐     ┌────┐
   │ AP │◄───►│ AP │◄───►│ AP │
   └────┘     └────┘     └────┘
      │          │          │
      ▼          ▼          ▼
   ┌────┐     ┌────┐     ┌────┐
   │STA │     │STA │     │STA │
   └────┘     └────┘     └────┘

   - Self-healing network
   - Multiple paths
   - 802.11s standard
```

### Key Terminology

| Term | Definition |
|------|------------|
| **SSID** | Service Set Identifier - Network name (e.g., "HomeNetwork") |
| **BSSID** | Basic Service Set Identifier - MAC address of AP |
| **ESSID** | Extended Service Set Identifier - Network name across multiple APs |
| **BSS** | Basic Service Set - Single AP and its clients |
| **ESS** | Extended Service Set - Multiple APs with same SSID |
| **STA** | Station - Any device that connects to WiFi |
| **AP** | Access Point - Device that broadcasts wireless signal |

### Frame Types

```
802.11 Frame Types:

1. MANAGEMENT FRAMES (Control network)
   ├── Beacon          - AP announces its presence
   ├── Probe Request   - Client searches for networks
   ├── Probe Response  - AP responds to probe
   ├── Authentication  - Begin connection process
   ├── Association     - Complete connection
   ├── Deauthentication- Disconnect (used in attacks!)
   └── Disassociation  - Clean disconnect

2. CONTROL FRAMES (Coordinate access)
   ├── RTS (Request to Send)
   ├── CTS (Clear to Send)
   └── ACK (Acknowledgment)

3. DATA FRAMES (Carry payload)
   └── Actual network traffic
```

### Connection Process

```
Client-to-AP Connection Sequence:

CLIENT                                         ACCESS POINT
   │                                                │
   │     1. Probe Request (Looking for SSIDs)       │
   │───────────────────────────────────────────────►│
   │                                                │
   │     2. Probe Response (SSID, capabilities)     │
   │◄───────────────────────────────────────────────│
   │                                                │
   │     3. Authentication Request                  │
   │───────────────────────────────────────────────►│
   │                                                │
   │     4. Authentication Response                 │
   │◄───────────────────────────────────────────────│
   │                                                │
   │     5. Association Request                     │
   │───────────────────────────────────────────────►│
   │                                                │
   │     6. Association Response                    │
   │◄───────────────────────────────────────────────│
   │                                                │
   │     [If WPA/WPA2: 4-Way Handshake follows]     │
   │                                                │
   │     7. Connected - Data transfer begins        │
   │◄──────────────────────────────────────────────►│
```

## Wireless Signal Characteristics

### Signal Strength (RSSI)

```
RSSI (Received Signal Strength Indicator):

dBm Value    Quality       Description
─────────────────────────────────────────────────
-30 dBm      Excellent     Maximum achievable
-50 dBm      Excellent     Close to AP
-60 dBm      Good          Reliable connection
-70 dBm      Fair          Minimum for reliable
-80 dBm      Poor          Connectivity issues
-90 dBm      Very Poor     Nearly unusable
-100 dBm     No signal     Disconnected

Visual representation:
█████████████████████  -30 dBm (Excellent)
█████████████████      -50 dBm (Excellent)
█████████████          -60 dBm (Good)
█████████              -70 dBm (Fair)
█████                  -80 dBm (Poor)
██                     -90 dBm (Very Poor)
```

### Factors Affecting Signal

1. **Distance** - Signal weakens with distance (inverse square law)
2. **Obstacles** - Walls, floors, furniture
3. **Interference** - Other devices on same frequency
4. **Antenna** - Type, gain, orientation

**Material Signal Loss:**
| Material | Signal Loss |
|----------|-------------|
| Drywall | 3-4 dB |
| Brick | 6-8 dB |
| Concrete | 10-15 dB |
| Metal | 20+ dB |
| Water | Variable, high |

## Lab Exercises (Theory)

### Exercise 1: Identify Standards

Given a device specification, identify which 802.11 standard it uses:
- Device A: 5 GHz only, 433 Mbps max, single antenna
- Device B: 2.4 GHz and 5 GHz, 150 Mbps on each band
- Device C: 2.4/5/6 GHz, OFDMA, 1024-QAM

<details>
<summary>Answers</summary>

- Device A: 802.11ac (WiFi 5) - 5 GHz, speed indicates single-stream AC
- Device B: 802.11n (WiFi 4) - Dual-band, speeds match WiFi 4 single stream
- Device C: 802.11ax (WiFi 6E) - Tri-band with 6 GHz, OFDMA, 1024-QAM

</details>

### Exercise 2: Channel Planning

You're setting up a network with 3 APs in the 2.4 GHz band. Which channels should you assign to minimize interference?

<details>
<summary>Answer</summary>

Assign channels 1, 6, and 11 (in the US) as these are the only non-overlapping channels in 2.4 GHz. Each AP should use a different channel to avoid co-channel interference.

</details>

### Exercise 3: Signal Analysis

An AP shows the following client connections:
- Client A: -45 dBm, Channel 6
- Client B: -72 dBm, Channel 6
- Client C: -88 dBm, Channel 6

Analyze the connection quality for each client.

<details>
<summary>Answer</summary>

- Client A: Excellent signal, very close to AP, optimal performance
- Client B: Fair signal, usable but may experience slower speeds
- Client C: Very poor signal, likely experiencing packet loss, slow speeds, frequent disconnections

</details>

## Knowledge Check

1. What is the maximum theoretical speed of 802.11ac (WiFi 5)?
2. How many non-overlapping channels exist in the 2.4 GHz band (US)?
3. What does DFS stand for and why is it required?
4. What is the difference between SSID and BSSID?
5. Which frame type is exploited in deauthentication attacks?

<details>
<summary>Answers</summary>

1. 6.9 Gbps (with 8x8 MIMO and 160 MHz channel)
2. 3 (Channels 1, 6, and 11)
3. Dynamic Frequency Selection - required to avoid interference with radar systems
4. SSID is the network name, BSSID is the MAC address of the access point
5. Management frames (specifically Deauthentication frames)

</details>

## Summary

Key takeaways from this lab:

1. **802.11 Evolution**: Standards have evolved from 2 Mbps to multi-gigabit speeds
2. **Frequency Bands**: 2.4 GHz for range, 5 GHz for speed, 6 GHz for capacity
3. **Channel Planning**: Use non-overlapping channels to avoid interference
4. **Network Architecture**: Infrastructure mode with APs is most common
5. **Frame Types**: Management, Control, and Data frames each serve specific purposes

## Next Lab

Proceed to [Lab 02: WiFi Security Protocols](../02-wifi-security-protocols/) to learn about WEP, WPA, WPA2, and WPA3 security mechanisms.

## References

- IEEE 802.11 Standard: https://standards.ieee.org/standard/802_11.html
- WiFi Alliance: https://www.wi-fi.org/
- Aircrack-ng Theory: https://www.aircrack-ng.org/doku.php?id=theory

---

**Flag:** `FLAG{802_11_fund4m3nt4ls}`
