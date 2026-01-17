# Lab 08: Bluetooth Security

Understanding Bluetooth vulnerabilities, attack techniques, and security measures.

```
+===============================================================+
|                    BLUETOOTH SECURITY                          |
+===============================================================+
|  Difficulty: Intermediate    Duration: 1 hour                 |
|  Hardware: Bluetooth Adapter Type: Theory + Demo              |
+===============================================================+
```

## Legal Disclaimer

```
+=====================================================================+
|                         LEGAL WARNING                                |
+=====================================================================+
|  Bluetooth attacks without explicit authorization are ILLEGAL.      |
|                                                                      |
|  - Only test on devices you OWN or have WRITTEN PERMISSION         |
|  - Intercepting Bluetooth communications may violate wiretap laws   |
|  - Unauthorized access to Bluetooth devices is a criminal offense   |
|                                                                      |
|  Many Bluetooth attacks require specialized hardware (Ubertooth)    |
|  that is not commonly available. This lab focuses on theory and     |
|  demonstrations with standard equipment where possible.              |
+=====================================================================+
```

## Learning Objectives

By the end of this lab, you will:

1. Understand Bluetooth technology and protocols
2. Know common Bluetooth vulnerabilities
3. Perform basic Bluetooth reconnaissance
4. Understand Bluetooth Low Energy (BLE) security
5. Learn about BlueBorne and other major vulnerabilities
6. Implement Bluetooth security best practices

## Prerequisites

- Basic understanding of wireless communication
- Familiarity with Linux command line
- Kali Linux or similar security distribution

## Hardware Requirements

| Hardware | Purpose | Required? |
|----------|---------|-----------|
| Built-in Bluetooth | Basic scanning | Sufficient for basics |
| USB Bluetooth Adapter | Extended features | Recommended |
| Ubertooth One | Advanced attacks | Optional (expensive) |
| Parani UD100 | Long-range scanning | Optional |

## Theory: Bluetooth Technology Overview

### Bluetooth Versions

```
Bluetooth Version Timeline:

1999 ──► Bluetooth 1.0
         │ ├── 1 Mbps data rate
         │ └── Basic Rate (BR)
         │
2004 ──► Bluetooth 2.0 + EDR
         │ ├── Enhanced Data Rate (3 Mbps)
         │ └── Improved power consumption
         │
2009 ──► Bluetooth 3.0 + HS
         │ ├── High Speed (24 Mbps via WiFi)
         │ └── Enhanced Power Control
         │
2010 ──► Bluetooth 4.0 (BLE)
         │ ├── Bluetooth Low Energy introduced
         │ ├── Designed for IoT devices
         │ └── Significantly reduced power
         │
2016 ──► Bluetooth 5.0
         │ ├── 2x speed, 4x range
         │ ├── 8x broadcast capacity
         │ └── IoT/mesh networking
         │
2019 ──► Bluetooth 5.1
         │ └── Direction finding
         │
2020 ──► Bluetooth 5.2
         │ └── LE Audio, Isochronous Channels
         │
2021 ──► Bluetooth 5.3
         │ └── Enhanced reliability
         │
2024 ──► Bluetooth 5.4 / 6.0
             └── Channel sounding, improved security
```

### Classic Bluetooth vs BLE

```
Comparison:

┌──────────────────────────────────────────────────────────────────┐
│           CLASSIC BLUETOOTH              BLE (Low Energy)         │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Data Rate: 1-3 Mbps                   Data Rate: 1-2 Mbps       │
│  Range: ~100m                          Range: ~50m (typical)      │
│  Power: Higher                         Power: Very Low            │
│                                                                   │
│  Use Cases:                            Use Cases:                 │
│  ├── Audio streaming                   ├── Fitness trackers       │
│  ├── File transfer                     ├── Smart locks            │
│  ├── Keyboards/mice                    ├── Beacons                │
│  └── Hands-free calls                  ├── Medical devices        │
│                                        └── IoT sensors            │
│                                                                   │
│  Pairing: PIN-based                    Pairing: Multiple methods  │
│  Security: E0 cipher                   Security: AES-CCM          │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Bluetooth Protocol Stack

```
Bluetooth Protocol Stack:

┌─────────────────────────────────────────────────────────┐
│                    APPLICATIONS                          │
│  (Audio, File Transfer, HID, Health, etc.)              │
├─────────────────────────────────────────────────────────┤
│                    PROFILES                              │
│  (A2DP, HFP, HID, GATT, etc.)                          │
├─────────────────────────────────────────────────────────┤
│         L2CAP (Logical Link Control and Adaptation)     │
├─────────────────────────────────────────────────────────┤
│         HCI (Host Controller Interface)                 │
├─────────────────────────────────────────────────────────┤
│         LMP/LL (Link Manager / Link Layer)             │
├─────────────────────────────────────────────────────────┤
│         BASEBAND                                         │
├─────────────────────────────────────────────────────────┤
│         RADIO (2.4 GHz ISM Band)                        │
└─────────────────────────────────────────────────────────┘
```

## Common Bluetooth Vulnerabilities

### Historical Vulnerabilities

```
Major Bluetooth Vulnerabilities:

┌──────────────────────────────────────────────────────────────────┐
│  VULNERABILITY        YEAR    IMPACT                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  BlueBorne           2017    RCE without pairing, billions       │
│  CVE-2017-1000250          affected, wormable across devices    │
│                                                                   │
│  KNOB Attack         2019    Force weak encryption keys          │
│  CVE-2019-9506             (1-7 bytes instead of 16)            │
│                                                                   │
│  BLURtooth           2020    Cross-transport key derivation      │
│  CVE-2020-15802           attack, bypass authentication        │
│                                                                   │
│  BLESA               2020    BLE spoofing attack on reconnect   │
│                              Affects billions of devices         │
│                                                                   │
│  BrakTooth           2021    DoS and potential RCE              │
│                              Affects many Bluetooth SoCs         │
│                                                                   │
│  BlueFrag            2020    Android RCE via Bluetooth          │
│  CVE-2020-0022             Memory corruption in stack          │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### BlueBorne Attack

```
BlueBorne (CVE-2017-1000250, etc.):

IMPACT:
├── Affects: Windows, Linux, Android, iOS
├── Requires: Bluetooth enabled (discoverable not required!)
├── Attack: Remote code execution without pairing
└── Spread: Can worm from device to device

Attack Flow:
1. Attacker scans for Bluetooth devices
2. Determines device type and OS
3. Exploits implementation vulnerabilities
4. Achieves code execution
5. Can spread to other nearby devices

MITIGATION:
├── Update OS and firmware
├── Disable Bluetooth when not in use
└── Apply security patches immediately
```

### KNOB Attack

```
KNOB (Key Negotiation of Bluetooth) Attack:

The Problem:
┌─────────────────────────────────────────────────────────────────┐
│  Bluetooth allows negotiation of encryption key entropy         │
│  Attacker can force MINIMUM entropy (1 byte = 8 bits)          │
│  1-byte key = only 256 possible keys = easily brute-forced     │
└─────────────────────────────────────────────────────────────────┘

Attack:
    Device A                    Attacker                    Device B
        │                          │                            │
        │ ──── "Use 16-byte key" ──────────────────────────────►│
        │                          │                            │
        │◄───────────────────── MITM ───────────────────────────│
        │     "Use 1-byte key"     │                            │
        │                          │                            │
        │ ◄─── "OK, 1-byte key" ───│──── "Use 1-byte key" ─────►│
        │                          │                            │
        │         WEAK ENCRYPTION ESTABLISHED                    │
        │         Attacker can brute-force key                   │
```

### BLE Security Issues

```
BLE Common Vulnerabilities:

1. NO ENCRYPTION BY DEFAULT
   ├── Many BLE devices don't use encryption
   └── Traffic can be sniffed

2. WEAK PAIRING METHODS
   ├── Just Works: No authentication
   ├── Passkey: Vulnerable to passive eavesdropping
   └── Legacy pairing: Broken

3. STATIC IDENTITY
   ├── Many devices use static MAC addresses
   └── Enables tracking

4. GATT SERVICE EXPOSURE
   ├── Characteristics may be readable/writable
   └── Unintended information disclosure
```

## Bluetooth Reconnaissance

### Basic Scanning

```bash
# Check Bluetooth adapter
hciconfig

# Bring up adapter
sudo hciconfig hci0 up

# Enable inquiry scan
sudo hciconfig hci0 piscan

# Scan for classic Bluetooth devices
hcitool scan

# Example output:
# Scanning ...
#     AA:BB:CC:DD:EE:FF       John's iPhone
#     11:22:33:44:55:66       Galaxy Buds Pro

# Get more info about device
hcitool info AA:BB:CC:DD:EE:FF
```

### BLE Scanning

```bash
# Scan for BLE devices
sudo hcitool lescan

# Example output:
# LE Scan ...
# AA:BB:CC:DD:EE:FF (unknown)
# 11:22:33:44:55:66 Fitbit Charge 5
# 22:33:44:55:66:77 Tile Mate

# More detailed BLE scanning with bluetoothctl
bluetoothctl
[bluetooth]# scan on
# Discovery started
# [NEW] Device AA:BB:CC:DD:EE:FF DeviceName
```

### Advanced Scanning with Bettercap

```bash
# Start bettercap
sudo bettercap

# Enable Bluetooth reconnaissance
ble.recon on

# Show discovered devices
ble.show

# Enumerate services on device
ble.enum AA:BB:CC:DD:EE:FF
```

## Tools for Bluetooth Security

### Built-in Linux Tools

```bash
# hciconfig - Configure Bluetooth devices
hciconfig -a                    # Show all adapters
sudo hciconfig hci0 up          # Enable adapter
sudo hciconfig hci0 down        # Disable adapter

# hcitool - Bluetooth tool
hcitool scan                    # Classic discovery
hcitool inq                     # Inquiry scan
hcitool name AA:BB:CC:DD:EE:FF  # Get device name
sudo hcitool lescan             # BLE scan

# bluetoothctl - Modern Bluetooth control
bluetoothctl
  power on                      # Enable adapter
  scan on                       # Start scanning
  devices                       # List discovered devices
  info AA:BB:CC:DD:EE:FF       # Device info
  pair AA:BB:CC:DD:EE:FF       # Initiate pairing
  connect AA:BB:CC:DD:EE:FF    # Connect to device

# sdptool - Service discovery
sdptool browse AA:BB:CC:DD:EE:FF  # List services
```

### Specialized Tools

```bash
# btscanner - Bluetooth scanner with GUI
sudo apt install btscanner
sudo btscanner

# Bluelog - Bluetooth site survey
sudo apt install bluelog
sudo bluelog -i hci0 -o /tmp/bluetooth_log.txt

# Spooftooph - Spoof Bluetooth device info
sudo apt install spooftooph
sudo spooftooph -i hci0 -n "FakeDevice" -a AA:BB:CC:DD:EE:FF

# Redfang - Find non-discoverable devices (brute force)
# (Requires compilation)
# Warning: Very slow, generates lots of traffic

# GATTacker - BLE MITM tool
# https://github.com/securing/gattacker
```

### Ubertooth Tools (Advanced Hardware)

```bash
# Ubertooth spectrum analyzer
ubertooth-specan -l

# Bluetooth baseband sniffing
ubertooth-btle -f -c /tmp/ble_capture.pcap

# LAP sniffing
ubertooth-btbb -l

# Note: Ubertooth One costs ~$150-200
# Required for advanced attacks like:
# - Sniffing encrypted Bluetooth traffic
# - Active attacks on Classic Bluetooth
# - Breaking BLE pairing
```

## Lab Exercises

### Exercise 1: Bluetooth Discovery

```bash
# Objective: Discover Bluetooth devices in range

# Step 1: Enable Bluetooth adapter
sudo hciconfig hci0 up

# Step 2: Scan for Classic Bluetooth
timeout 30 hcitool scan

# Step 3: Scan for BLE devices
sudo timeout 30 hcitool lescan

# Step 4: Document findings
# - Device addresses
# - Device names
# - Device types (if identifiable)
```

### Exercise 2: Service Enumeration

```bash
# Objective: Enumerate services on your own device

# Step 1: Get your device's Bluetooth address
# (Use your phone or another device you own)

# Step 2: Browse services
sdptool browse AA:BB:CC:DD:EE:FF

# Step 3: Analyze services
# What profiles are supported?
# A2DP (audio), HFP (hands-free), OBEX (file transfer)?
```

### Exercise 3: BLE GATT Exploration

```bash
# Objective: Explore GATT services on a BLE device you own

# Using gatttool (if available)
gatttool -b AA:BB:CC:DD:EE:FF -I
[AA:BB:CC:DD:EE:FF][LE]> connect
[AA:BB:CC:DD:EE:FF][LE]> primary
[AA:BB:CC:DD:EE:FF][LE]> characteristics
[AA:BB:CC:DD:EE:FF][LE]> char-read-hnd 0x0001

# Or using bettercap
sudo bettercap
ble.recon on
ble.enum AA:BB:CC:DD:EE:FF
```

## Defensive Measures

### For Users

```
Bluetooth Security Best Practices:

╔══════════════════════════════════════════════════════════════════╗
║                    USER RECOMMENDATIONS                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  1. DISABLE WHEN NOT IN USE                                       ║
║     └── Turn off Bluetooth when not actively needed              ║
║                                                                   ║
║  2. USE NON-DISCOVERABLE MODE                                     ║
║     └── Only enable discoverable during pairing                  ║
║                                                                   ║
║  3. KEEP DEVICES UPDATED                                          ║
║     └── Install OS and firmware updates promptly                 ║
║                                                                   ║
║  4. REMOVE UNUSED PAIRINGS                                        ║
║     └── Regularly clean up paired device list                    ║
║                                                                   ║
║  5. BE CAREFUL WITH PAIRING REQUESTS                              ║
║     └── Verify unexpected pairing attempts                       ║
║                                                                   ║
║  6. USE STRONG PINs WHEN POSSIBLE                                 ║
║     └── Avoid default PINs like 0000 or 1234                     ║
║                                                                   ║
║  7. AVOID PAIRING IN PUBLIC                                       ║
║     └── Pairing at home is safer than in crowded areas          ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

### For Developers

```
Secure Bluetooth Development:

╔══════════════════════════════════════════════════════════════════╗
║                DEVELOPER RECOMMENDATIONS                          ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  1. ENFORCE ENCRYPTION                                            ║
║     ├── Always enable encryption for sensitive data              ║
║     └── Use Secure Connections (SC) mode                         ║
║                                                                   ║
║  2. USE SECURE PAIRING                                            ║
║     ├── Implement Secure Simple Pairing (SSP)                    ║
║     ├── Use Numeric Comparison when possible                     ║
║     └── Avoid "Just Works" for sensitive applications            ║
║                                                                   ║
║  3. IMPLEMENT PROPER AUTHENTICATION                               ║
║     └── Verify device identity before granting access            ║
║                                                                   ║
║  4. MINIMIZE ATTACK SURFACE                                       ║
║     ├── Disable unnecessary services                             ║
║     └── Restrict GATT characteristic permissions                 ║
║                                                                   ║
║  5. USE RANDOM ADDRESSING                                         ║
║     └── Implement BLE address randomization                      ║
║                                                                   ║
║  6. SECURE OTA UPDATES                                            ║
║     └── Sign and encrypt firmware updates                        ║
║                                                                   ║
║  7. TEST SECURITY                                                 ║
║     └── Perform regular security assessments                     ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

## Knowledge Check

1. What is the main difference between Classic Bluetooth and BLE?
2. What made BlueBorne particularly dangerous?
3. How does the KNOB attack work?
4. Why is "Just Works" pairing insecure?
5. What hardware is needed for advanced Bluetooth attacks?

<details>
<summary>Answers</summary>

1. Classic Bluetooth is designed for continuous connections (audio, files) with higher power, while BLE is optimized for low power, intermittent data (IoT, sensors)

2. BlueBorne could exploit devices without pairing, without discoverable mode, and could spread like a worm between devices

3. KNOB attack forces negotiation of minimum encryption key length (1 byte), which can be easily brute-forced

4. "Just Works" provides no authentication - any device can pair. No protection against MITM attacks during pairing

5. Ubertooth One for sniffing and active attacks on Classic Bluetooth; standard adapters work for basic BLE testing

</details>

## Summary

In this lab, you learned:

1. **Bluetooth Basics**: Protocol stack, versions, Classic vs BLE
2. **Vulnerabilities**: BlueBorne, KNOB, BLE issues
3. **Reconnaissance**: Device discovery and service enumeration
4. **Tools**: hcitool, bluetoothctl, bettercap, Ubertooth
5. **Defense**: Best practices for users and developers

## Key Takeaways

```
┌──────────────────────────────────────────────────────────────────┐
│                    IMPORTANT LESSONS                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Bluetooth is everywhere - phones, cars, medical devices      │
│  2. Security has improved but legacy issues persist              │
│  3. Always keep devices updated                                   │
│  4. Disable Bluetooth when not needed                            │
│  5. BLE devices often have minimal security                      │
│  6. Advanced attacks require specialized (expensive) hardware    │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

## Module Completion

Congratulations! You have completed the Wireless Security module.

### Skills Acquired

- Wireless fundamentals and 802.11 standards
- WiFi security protocols (WEP, WPA, WPA2, WPA3)
- Wireless reconnaissance techniques
- WEP cracking methodology
- WPA/WPA2 handshake capture and cracking
- Deauthentication attacks
- Evil twin/rogue AP attacks
- Bluetooth security basics

### Next Steps

1. **Practice**: Set up isolated wireless lab environments
2. **Hardware**: Invest in proper adapters (Alfa cards)
3. **Certification**: Consider OSWP for validation
4. **Continue Learning**: Proceed to Module 07 - Active Directory

## References

- [Bluetooth SIG Security](https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/)
- [BlueBorne Paper](https://www.armis.com/research/blueborne/)
- [KNOB Attack](https://knobattack.com/)
- [Ubertooth Documentation](https://ubertooth.readthedocs.io/)

---

**Flag:** `FLAG{blu3t00th_s3cur1ty}`
