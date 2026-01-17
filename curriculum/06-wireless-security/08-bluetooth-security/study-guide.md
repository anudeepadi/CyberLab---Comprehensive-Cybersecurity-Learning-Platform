# Lab 08: Bluetooth Security - Study Guide

Comprehensive study guide covering Bluetooth technology, vulnerabilities, and security measures.

```
+===============================================================+
|                       STUDY GUIDE                              |
+===============================================================+
|  Use this guide to review key concepts and prepare for        |
|  practical assessments involving Bluetooth security.          |
+===============================================================+
```

## Table of Contents

1. [Bluetooth Fundamentals](#bluetooth-fundamentals)
2. [Protocol Stack Deep Dive](#protocol-stack-deep-dive)
3. [Security Mechanisms](#security-mechanisms)
4. [Vulnerability Analysis](#vulnerability-analysis)
5. [Attack Techniques](#attack-techniques)
6. [Defense Strategies](#defense-strategies)
7. [Tools Reference](#tools-reference)
8. [Practice Questions](#practice-questions)

---

## Bluetooth Fundamentals

### Radio Specifications

```
Bluetooth Radio Characteristics:

Frequency Band:     2.4 GHz ISM (2400-2483.5 MHz)
Modulation:         GFSK (Classic), GFSK/DPSK/8DPSK (EDR)
Channels:           79 channels (Classic), 40 channels (BLE)
Hopping:            1600 hops/second (Classic)
Power Classes:
    Class 1: 100 mW (20 dBm) - ~100m range
    Class 2: 2.5 mW (4 dBm)  - ~10m range
    Class 3: 1 mW (0 dBm)    - ~1m range
```

### Device Addressing

```
Bluetooth Device Address (BD_ADDR):

Format: AA:BB:CC:DD:EE:FF (48 bits)

┌────────────────────┬────────────────────┐
│  NAP (16 bits)     │  UAP (8 bits)      │  LAP (24 bits)
│  Non-significant   │  Upper Address     │  Lower Address
│  Address Part      │  Part              │  Part
├────────────────────┴────────────────────┤
│  OUI (24 bits) - Identifies vendor      │
└─────────────────────────────────────────┘

Example: AC:37:43:12:34:56
         └─────┘
         Apple Inc. (OUI)
```

### BLE Addressing

```
BLE Address Types:

1. PUBLIC ADDRESS
   ├── Fixed, globally unique
   ├── Based on IEEE registration
   └── Can be tracked

2. RANDOM STATIC ADDRESS
   ├── Randomly generated at boot
   ├── Stays same until power cycle
   └── Two MSBs = 11

3. RANDOM PRIVATE RESOLVABLE
   ├── Changes periodically
   ├── Can be resolved by bonded devices
   └── Two MSBs = 01

4. RANDOM PRIVATE NON-RESOLVABLE
   ├── Changes periodically
   ├── Cannot be resolved
   └── Two MSBs = 00
```

---

## Protocol Stack Deep Dive

### Classic Bluetooth Stack

```
Layer-by-Layer Analysis:

┌─────────────────────────────────────────────────────────────────┐
│  APPLICATION LAYER                                               │
│  ├── Profiles: A2DP, HFP, HID, OBEX, PAN, etc.                 │
│  └── Defines specific use cases and interactions                │
├─────────────────────────────────────────────────────────────────┤
│  L2CAP (Logical Link Control and Adaptation Protocol)           │
│  ├── Multiplexing                                               │
│  ├── Segmentation and reassembly                               │
│  ├── QoS (Quality of Service)                                  │
│  └── Group abstractions                                         │
├─────────────────────────────────────────────────────────────────┤
│  SDP (Service Discovery Protocol)                               │
│  └── Discovers services on remote devices                       │
├─────────────────────────────────────────────────────────────────┤
│  RFCOMM                                                         │
│  └── Serial port emulation over L2CAP                          │
├─────────────────────────────────────────────────────────────────┤
│  HCI (Host Controller Interface)                                │
│  └── Interface between host and controller                      │
├─────────────────────────────────────────────────────────────────┤
│  LMP (Link Manager Protocol)                                    │
│  ├── Link establishment and configuration                       │
│  ├── Security (authentication, encryption)                      │
│  └── Power management                                           │
├─────────────────────────────────────────────────────────────────┤
│  BASEBAND                                                       │
│  ├── Channel management                                         │
│  ├── Frequency hopping                                          │
│  └── Packet formatting                                          │
├─────────────────────────────────────────────────────────────────┤
│  RADIO                                                          │
│  └── Physical transmission/reception                            │
└─────────────────────────────────────────────────────────────────┘
```

### BLE Stack (GATT-Based)

```
BLE Protocol Stack:

┌─────────────────────────────────────────────────────────────────┐
│  APPLICATION                                                     │
│  └── Uses GATT services and characteristics                     │
├─────────────────────────────────────────────────────────────────┤
│  GATT (Generic Attribute Profile)                               │
│  ├── Services (group of characteristics)                        │
│  ├── Characteristics (data containers)                          │
│  └── Descriptors (metadata)                                     │
├─────────────────────────────────────────────────────────────────┤
│  ATT (Attribute Protocol)                                       │
│  └── Client-server attribute operations                         │
├─────────────────────────────────────────────────────────────────┤
│  L2CAP                                                          │
│  └── Simplified for BLE (fixed channels)                       │
├─────────────────────────────────────────────────────────────────┤
│  HCI                                                            │
├─────────────────────────────────────────────────────────────────┤
│  LINK LAYER                                                     │
│  ├── Advertising                                                │
│  ├── Scanning                                                   │
│  ├── Connection management                                      │
│  └── Encryption (AES-CCM)                                      │
├─────────────────────────────────────────────────────────────────┤
│  PHYSICAL LAYER                                                 │
│  └── 2.4 GHz, 40 channels, 1/2 Mbps                           │
└─────────────────────────────────────────────────────────────────┘
```

### GATT Structure

```
GATT Hierarchy:

PROFILE
├── SERVICE 1 (e.g., Heart Rate Service)
│   ├── CHARACTERISTIC 1.1 (Heart Rate Measurement)
│   │   ├── Value
│   │   └── DESCRIPTOR (Client Char. Configuration)
│   │
│   └── CHARACTERISTIC 1.2 (Body Sensor Location)
│       └── Value
│
└── SERVICE 2 (e.g., Battery Service)
    └── CHARACTERISTIC 2.1 (Battery Level)
        ├── Value
        └── DESCRIPTOR

UUIDs:
├── Standard UUIDs: 16-bit (0x180D = Heart Rate Service)
└── Custom UUIDs: 128-bit (vendor-specific)
```

---

## Security Mechanisms

### Classic Bluetooth Security

```
Security Modes (Classic):

MODE 1: Non-secure
        └── No security enforcement

MODE 2: Service-level security
        ├── Security enforced after L2CAP connection
        └── Per-service security settings

MODE 3: Link-level security
        └── Security enforced before L2CAP connection

MODE 4: Service-level security with SSP
        ├── Secure Simple Pairing
        └── Numeric Comparison, Passkey Entry, etc.

Secure Simple Pairing (SSP) Methods:

┌─────────────────┬─────────────────┬─────────────────────────────┐
│  METHOD         │  I/O REQUIRED   │  MITM PROTECTION            │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  Numeric        │  Display +      │  Yes (if user verifies)     │
│  Comparison     │  Yes/No         │                             │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  Passkey Entry  │  Keyboard OR    │  Yes (if passkey random)    │
│                 │  Display        │                             │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  Just Works     │  None           │  NO                         │
│                 │                 │                             │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  OOB            │  Out-of-band    │  Depends on OOB channel     │
│                 │  (NFC, etc.)    │                             │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

### BLE Security

```
BLE Security Modes and Levels:

LE SECURITY MODE 1:
├── Level 1: No security (no auth, no encryption)
├── Level 2: Unauthenticated pairing with encryption
├── Level 3: Authenticated pairing with encryption
└── Level 4: Authenticated LE Secure Connections

LE SECURITY MODE 2 (signed data):
├── Level 1: Unauthenticated pairing with data signing
└── Level 2: Authenticated pairing with data signing

Pairing Methods:
┌─────────────────┬─────────────────┬─────────────────────────────┐
│  METHOD         │  AUTHENTICATION │  PROTECTION                 │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  Just Works     │  None           │  No MITM protection         │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  Passkey Entry  │  6-digit PIN    │  MITM protection            │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  Numeric        │  6-digit        │  MITM protection            │
│  Comparison     │  verification   │                             │
├─────────────────┼─────────────────┼─────────────────────────────┤
│  OOB            │  Out-of-band    │  Depends on channel         │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

### Encryption

```
Encryption Algorithms:

CLASSIC BLUETOOTH:
├── E0 Stream Cipher (legacy)
│   └── Known weaknesses, deprecated
│
└── AES-CCM (Secure Connections)
    └── 128-bit AES, secure

BLE:
└── AES-CCM
    ├── 128-bit encryption key
    └── Counter Mode with CBC-MAC

Key Hierarchy:
┌─────────────────────────────────────────────────────────────────┐
│  LINK KEY (Classic) / LTK (BLE)                                 │
│  └── Generated during pairing                                   │
│      └── Derives ENCRYPTION KEY                                 │
│          └── Encrypts actual data                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Vulnerability Analysis

### BlueBorne (2017)

```
BlueBorne Vulnerability Details:

AFFECTED:
├── Linux (CVE-2017-1000251): Stack buffer overflow in L2CAP
├── Linux (CVE-2017-1000250): Information leak in SDP
├── Android (CVE-2017-0781): Heap overflow in BNEP
├── Android (CVE-2017-0782): BNEP denial of service
├── Android (CVE-2017-0785): Information leak in SDP
├── Windows (CVE-2017-8628): MITM in Bluetooth stack
└── iOS (CVE-2017-14315): Low energy audio protocol RCE

ATTACK CHARACTERISTICS:
├── No pairing required
├── No discoverable mode required
├── Bluetooth just needs to be ON
├── Wormable (spreads device to device)
└── Can achieve full device compromise

TIMELINE:
├── April 2017: Discovered by Armis
├── September 2017: Public disclosure
└── Patches: Released by all major vendors
```

### KNOB Attack (2019)

```
Key Negotiation of Bluetooth (KNOB):

VULNERABILITY:
└── Bluetooth BR/EDR allows encryption key entropy negotiation
    └── Attacker can force 1-byte (8-bit) key entropy
        └── Only 256 possible keys
            └── Trivially brute-forced

ATTACK STEPS:
1. MITM position between two devices
2. Intercept key negotiation
3. Modify negotiated entropy to minimum
4. Devices accept weak key
5. Brute-force 256 possible keys
6. Decrypt all traffic

AFFECTED:
└── All Bluetooth BR/EDR devices before patches

MITIGATION:
├── Enforce minimum key entropy (7 bytes)
└── Update firmware/OS
```

### BLE-Specific Vulnerabilities

```
BLE Attack Surface:

1. PASSIVE EAVESDROPPING
   ├── Unencrypted advertising
   ├── Unencrypted connections
   └── Requires: BLE sniffer (Ubertooth, etc.)

2. ACTIVE ATTACKS
   ├── MITM during pairing
   ├── Replay attacks
   └── Relay attacks

3. GATT ABUSE
   ├── Unauthorized characteristic access
   ├── Information disclosure
   └── Denial of service

4. DEVICE TRACKING
   ├── Static addresses
   ├── Consistent advertising data
   └── Manufacturer-specific identifiers
```

---

## Attack Techniques

### Reconnaissance Commands

```bash
# Classic Bluetooth Discovery
hcitool scan                        # Standard inquiry
hcitool inq                         # Inquiry with more details
hcitool name <BDADDR>               # Get device name

# BLE Discovery
sudo hcitool lescan                 # LE scan
sudo hcitool lescan --duplicates   # Include duplicates

# Service Discovery
sdptool browse <BDADDR>             # Browse all services
sdptool search SP <BDADDR>          # Search specific profile

# bluetoothctl Commands
bluetoothctl
  scan on                           # Start scanning
  scan off                          # Stop scanning
  devices                           # List found devices
  info <BDADDR>                     # Device information
  pair <BDADDR>                     # Attempt pairing
  trust <BDADDR>                    # Trust device
  connect <BDADDR>                  # Connect
```

### BLE Exploration

```bash
# Using gatttool
gatttool -b <BDADDR> -I            # Interactive mode
  connect                          # Connect
  primary                          # List primary services
  characteristics                  # List characteristics
  char-read-hnd <handle>          # Read by handle
  char-write-req <handle> <value> # Write value

# Using bettercap
sudo bettercap
  ble.recon on                     # Start BLE recon
  ble.show                         # Show devices
  ble.enum <BDADDR>               # Enumerate services
  ble.write <BDADDR> <handle> <data>
```

### Sniffing (Requires Ubertooth)

```bash
# Capture BLE advertising
ubertooth-btle -f -c /tmp/ble.pcap

# Follow specific device
ubertooth-btle -f -t <BDADDR>

# Spectrum analysis
ubertooth-specan

# Classic Bluetooth sniffing (requires LAP)
ubertooth-btbb -l               # Learn LAP
ubertooth-btbb -U0              # Follow piconet
```

---

## Defense Strategies

### Security Checklist

```
DEVICE SECURITY CHECKLIST:

┌─────────────────────────────────────────────────────────────────┐
│  CONFIGURATION                                                   │
├─────────────────────────────────────────────────────────────────┤
│  [ ] Disable Bluetooth when not in use                          │
│  [ ] Use non-discoverable mode (except during pairing)         │
│  [ ] Enable encryption for all connections                      │
│  [ ] Use authenticated pairing (avoid "Just Works")            │
│  [ ] Regularly review and remove unused pairings               │
├─────────────────────────────────────────────────────────────────┤
│  UPDATES                                                         │
├─────────────────────────────────────────────────────────────────┤
│  [ ] Keep OS updated                                            │
│  [ ] Keep device firmware updated                               │
│  [ ] Apply security patches promptly                            │
├─────────────────────────────────────────────────────────────────┤
│  BEHAVIOR                                                        │
├─────────────────────────────────────────────────────────────────┤
│  [ ] Don't pair in public places                                │
│  [ ] Verify pairing codes carefully                             │
│  [ ] Reject unexpected pairing requests                         │
│  [ ] Be cautious with Bluetooth in sensitive environments       │
└─────────────────────────────────────────────────────────────────┘
```

### Enterprise Considerations

```
ENTERPRISE BLUETOOTH POLICY:

1. INVENTORY
   ├── Maintain list of authorized Bluetooth devices
   └── Regular audits for unauthorized devices

2. POLICY
   ├── Define acceptable Bluetooth usage
   ├── Prohibit Bluetooth in sensitive areas
   └── Require approval for new devices

3. TECHNICAL CONTROLS
   ├── MDM for mobile device management
   ├── Disable Bluetooth on managed devices if not needed
   └── Network monitoring for Bluetooth-related anomalies

4. TRAINING
   ├── Security awareness training
   └── Incident reporting procedures
```

---

## Tools Reference

### Quick Command Reference

```bash
# Adapter Management
hciconfig                          # List adapters
hciconfig hci0 up                 # Enable adapter
hciconfig hci0 down               # Disable adapter
hciconfig hci0 piscan             # Enable discoverable
hciconfig hci0 noscan             # Disable discoverable

# Discovery
hcitool scan                       # Classic scan
hcitool lescan                     # BLE scan
bluetoothctl scan on              # Modern scanning

# Connection
bluetoothctl connect <BDADDR>     # Connect
bluetoothctl disconnect <BDADDR>  # Disconnect
l2ping <BDADDR>                    # Bluetooth ping

# Services
sdptool browse <BDADDR>           # List services
gatttool -b <BDADDR> primary      # BLE services

# Capture (Ubertooth)
ubertooth-btle -f                  # Capture BLE
ubertooth-btbb -l                  # Classic sniff
```

### Tool Comparison

```
Tool                    Purpose                     Requirements
─────────────────────────────────────────────────────────────────
hcitool                 Basic scanning              Built-in
bluetoothctl            Modern BT management        Built-in
sdptool                 Service discovery           Built-in
gatttool                BLE GATT exploration        bluez-utils
bettercap               Multi-purpose framework     Installation
btscanner               GUI scanner                 Installation
Ubertooth tools         Advanced sniffing           Ubertooth One
Wireshark               Packet analysis             HCI/Ubertooth
```

---

## Practice Questions

### Multiple Choice

1. **Which Bluetooth pairing method provides NO MITM protection?**
   - A) Numeric Comparison
   - B) Passkey Entry
   - C) Just Works
   - D) Out-of-Band

2. **What is the frequency band used by Bluetooth?**
   - A) 900 MHz
   - B) 2.4 GHz
   - C) 5 GHz
   - D) 6 GHz

3. **What vulnerability allowed wormable RCE without pairing?**
   - A) KNOB
   - B) BlueBorne
   - C) BLESA
   - D) BrakTooth

4. **Which BLE address type changes periodically and can be resolved?**
   - A) Public Address
   - B) Random Static Address
   - C) Random Private Resolvable Address
   - D) Random Private Non-Resolvable Address

5. **What protocol is used for BLE service discovery?**
   - A) SDP
   - B) GATT/ATT
   - C) RFCOMM
   - D) L2CAP

<details>
<summary>Answers</summary>

1. C) Just Works
2. B) 2.4 GHz
3. B) BlueBorne
4. C) Random Private Resolvable Address
5. B) GATT/ATT

</details>

### Short Answer

1. Explain why the KNOB attack is effective.
2. What is the difference between Classic Bluetooth and BLE security?
3. Why should users disable Bluetooth when not in use?
4. What hardware is needed for advanced Bluetooth attacks?
5. How does address randomization improve BLE privacy?

<details>
<summary>Sample Answers</summary>

1. KNOB is effective because Bluetooth allows negotiation of encryption key entropy without authentication. An attacker can force minimum entropy (1 byte = 256 possible keys), which can be brute-forced instantly.

2. Classic Bluetooth uses E0 cipher (deprecated) or AES-CCM (Secure Connections) and has complex security modes. BLE was designed with security in mind, uses AES-CCM by default, but many implementations don't enable encryption.

3. Bluetooth vulnerabilities like BlueBorne can be exploited just by having Bluetooth enabled, even without discoverable mode. Disabling reduces attack surface.

4. Ubertooth One (~$150-200) is required for sniffing Bluetooth traffic, capturing pairing, and advanced attacks. Standard adapters only allow basic scanning and connection.

5. Address randomization prevents tracking by changing the device's advertised MAC address periodically. Only bonded devices can resolve the random address to identify the device.

</details>

---

## Summary

### Key Takeaways

```
┌──────────────────────────────────────────────────────────────────┐
│                    STUDY SUMMARY                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Bluetooth operates in 2.4 GHz band like WiFi                │
│  2. Classic BT vs BLE have different security models            │
│  3. SSP improved security but "Just Works" is still insecure    │
│  4. Major vulnerabilities (BlueBorne, KNOB) affected billions   │
│  5. Keep devices updated - patches are critical                 │
│  6. Advanced attacks require specialized hardware               │
│  7. Defense: Disable when not in use, update, use encryption    │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Certification Relevance

This material is relevant for:
- CompTIA Security+
- CEH (Certified Ethical Hacker)
- OSCP/OSWP
- Wireless security assessments
- IoT security testing

---

**Flag:** `FLAG{blu3t00th_s3cur1ty}`
