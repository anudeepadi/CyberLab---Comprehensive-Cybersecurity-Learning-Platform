# Lab 02: WiFi Security Protocols

Understanding wireless security mechanisms from WEP to WPA3, their vulnerabilities, and why they matter.

```
╔═══════════════════════════════════════════════════════════════╗
║               WIFI SECURITY PROTOCOLS                          ║
╠═══════════════════════════════════════════════════════════════╣
║  Difficulty: Beginner        Duration: 1.5 hours              ║
║  Hardware: None Required     Type: Theory                     ║
╚═══════════════════════════════════════════════════════════════╝
```

## Learning Objectives

By the end of this lab, you will:

1. Understand the evolution of WiFi security protocols
2. Explain why WEP is fundamentally broken
3. Describe WPA/WPA2 security mechanisms
4. Identify vulnerabilities in WPA2 (KRACK, PMKID)
5. Understand WPA3 improvements and SAE
6. Recognize enterprise vs personal authentication modes

## Legal Notice

This lab is purely theoretical. Understanding these protocols is essential for both attackers and defenders. Always test only on networks you own or have explicit authorization to test.

## Evolution of WiFi Security

```
Timeline of WiFi Security:

1999 ───► WEP (Wired Equivalent Privacy)
          │ ├── RC4 stream cipher
          │ ├── 40-bit or 104-bit keys
          │ └── BROKEN - Do not use!
          │
2003 ───► WPA (WiFi Protected Access)
          │ ├── TKIP (Temporal Key Integrity Protocol)
          │ ├── Message Integrity Check (MIC)
          │ └── DEPRECATED - Security vulnerabilities
          │
2004 ───► WPA2 (WiFi Protected Access 2)
          │ ├── AES-CCMP encryption
          │ ├── 4-Way Handshake
          │ ├── Still widely used
          │ └── Vulnerable to KRACK, dictionary attacks
          │
2018 ───► WPA3 (WiFi Protected Access 3)
            ├── SAE (Simultaneous Authentication of Equals)
            ├── Forward secrecy
            ├── Protected Management Frames
            └── CURRENT STANDARD
```

## WEP (Wired Equivalent Privacy) - BROKEN

### Overview

```
WEP Structure:

┌─────────────────────────────────────────────────────────────┐
│                    WEP ENCRYPTION                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────┐    ┌─────────────────────────────────────┐ │
│  │ 24-bit IV  │ + │      40 or 104-bit WEP Key          │ │
│  └────────────┘    └─────────────────────────────────────┘ │
│         │                        │                         │
│         └────────────┬───────────┘                         │
│                      ▼                                     │
│              ┌───────────────┐                            │
│              │  RC4 Cipher   │                            │
│              └───────────────┘                            │
│                      │                                     │
│                      ▼                                     │
│         ┌────────────────────────┐                        │
│         │    Keystream (XOR)     │                        │
│         └────────────────────────┘                        │
│                      │                                     │
│    Plaintext ──────► XOR ────────► Ciphertext             │
│                                                             │
└─────────────────────────────────────────────────────────────┘

CRITICAL FLAW: IV is only 24 bits = 16.7 million combinations
               IV reuse is inevitable in busy networks
```

### Why WEP is Broken

| Vulnerability | Description | Impact |
|--------------|-------------|--------|
| IV Collision | Only 2^24 possible IVs | Same keystream reused |
| Weak IVs | Certain IVs leak key bits | FMS attack |
| Static Key | Same key used indefinitely | No key rotation |
| No Replay Protection | Packets can be replayed | Injection attacks |
| Weak Integrity | CRC32, not cryptographic | Packet modification |

### WEP Attack Methods

```
1. FMS Attack (Fluhrer, Mantin, Shamir)
   ├── Exploits weak IVs
   ├── Collects ~1 million packets
   └── Derives key statistically

2. PTW Attack (Pyshkin, Tews, Weinmann)
   ├── More efficient than FMS
   ├── ~40,000 packets needed
   └── Faster cracking

3. Chop-Chop Attack
   ├── Decrypts packets without key
   ├── One byte at a time
   └── Enables packet injection

4. Fragmentation Attack
   ├── Obtains keystream
   ├── From single captured packet
   └── Enables arbitrary packet injection
```

**Cracking Time:**
```
WEP 64-bit:  ~30,000 packets (few minutes)
WEP 128-bit: ~40,000-85,000 packets (minutes)

With traffic injection: 2-5 minutes on active network
```

## WPA (WiFi Protected Access) - DEPRECATED

### Improvements Over WEP

```
WPA vs WEP:

Feature          WEP           WPA
─────────────────────────────────────────────
Encryption       RC4 (static)  RC4 (TKIP)
Key Management   Static        Dynamic per-packet
IV Size          24-bit        48-bit
Integrity        CRC32         MIC (Michael)
Replay Attack    Vulnerable    Protected
```

### TKIP (Temporal Key Integrity Protocol)

```
TKIP Key Mixing:

┌──────────────────────────────────────────────────────────┐
│                     TKIP OPERATION                        │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Temporal Key ────────┐                                  │
│                       ▼                                  │
│  Transmitter Addr ──► Phase 1 Key Mixing ──► TTAK       │
│                                                          │
│  TTAK ───────────────┐                                  │
│                      ▼                                   │
│  Sequence Counter ─► Phase 2 Key Mixing ──► Per-Packet │
│                                               Key        │
│                                                          │
│  Per-Packet Key + IV ──► RC4 ──► Encrypted Frame        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### WPA Vulnerabilities

1. **Michael MIC Weaknesses**: Countermeasures can cause DoS
2. **TKIP Attacks**: Beck-Tews and Ohigashi-Morii attacks
3. **Dictionary Attacks**: Same as WPA2 PSK

## WPA2 (WiFi Protected Access 2) - Current Standard

### Key Improvements

```
WPA2 Features:

┌─────────────────────────────────────────────────────────┐
│                    WPA2 SECURITY                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Encryption: AES-CCMP (Counter Mode CBC-MAC Protocol)   │
│  ├── 128-bit AES encryption                            │
│  ├── 64-bit MIC (Message Integrity Code)               │
│  └── Replay protection                                  │
│                                                         │
│  Key Derivation:                                        │
│  ├── PSK Mode: Passphrase → PMK                        │
│  └── Enterprise: 802.1X/RADIUS → PMK                   │
│                                                         │
│  Authentication:                                        │
│  └── 4-Way Handshake                                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### The 4-Way Handshake

```
WPA2 4-Way Handshake:

    CLIENT (Supplicant)                    ACCESS POINT (Authenticator)
           │                                        │
           │                                        │
           │  ◄─────── Message 1: ANonce ──────────│
           │           (AP sends random nonce)      │
           │                                        │
           │  Client derives PTK:                   │
           │  PTK = PRF(PMK + ANonce + SNonce +    │
           │            MAC_AP + MAC_Client)        │
           │                                        │
           │───────── Message 2: SNonce ──────────►│
           │          + MIC                         │
           │          (Client sends random nonce)   │
           │                                        │
           │                    AP derives PTK and  │
           │                    verifies MIC        │
           │                                        │
           │  ◄─────── Message 3: GTK ────────────│
           │           + MIC (encrypted)            │
           │           (Group Temporal Key)         │
           │                                        │
           │───────── Message 4: ACK ─────────────►│
           │          + MIC                         │
           │                                        │
           │       ENCRYPTED COMMUNICATION          │
           │◄═════════════════════════════════════►│
           │                                        │

Key Terms:
- PMK: Pairwise Master Key (from password or RADIUS)
- ANonce: AP's random number
- SNonce: Client's random number
- PTK: Pairwise Transient Key (session key)
- GTK: Group Temporal Key (broadcast/multicast)
- MIC: Message Integrity Code
```

### PMK Derivation (PSK Mode)

```python
# PSK Key Derivation
PMK = PBKDF2(password, SSID, 4096 iterations, 256 bits)

# This is why dictionary attacks work:
# - PMK only depends on password + SSID
# - Can be pre-computed for common SSIDs
# - Weak passwords are quickly found
```

### WPA2 Modes

```
┌─────────────────────────────────────────────────────────────┐
│                    WPA2-PERSONAL (PSK)                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  • Single shared password for all users                     │
│  • Password → PMK via PBKDF2                                │
│  • Easy to configure                                        │
│  • Vulnerable to dictionary attacks                         │
│  • No individual user accountability                        │
│                                                             │
│  Best for: Home networks, small offices                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                WPA2-ENTERPRISE (802.1X)                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  • Individual user credentials                              │
│  • RADIUS server authentication                             │
│  • Per-user encryption keys                                 │
│  • Stronger security, more complex setup                    │
│  • Supports certificate-based auth                          │
│                                                             │
│  EAP Methods:                                               │
│  ├── EAP-TLS (certificates, most secure)                   │
│  ├── PEAP (username/password)                              │
│  ├── EAP-TTLS (tunneled TLS)                               │
│  └── EAP-FAST (Cisco)                                      │
│                                                             │
│  Best for: Enterprise environments                          │
└─────────────────────────────────────────────────────────────┘
```

### WPA2 Vulnerabilities

#### 1. Dictionary/Brute Force Attacks

```
Attack Process:

1. Capture 4-Way Handshake
   └── Wait for client connection or force deauth

2. Extract from handshake:
   ├── ANonce
   ├── SNonce
   ├── MAC addresses
   └── MIC from Message 2

3. For each password in wordlist:
   ├── Compute PMK = PBKDF2(password, SSID)
   ├── Compute PTK from PMK + nonces + MACs
   ├── Compute expected MIC
   └── Compare with captured MIC

4. If MIC matches → Password found!

Speed: ~500-1000 PMKs/second (CPU)
       ~500,000+ PMKs/second (GPU with hashcat)
```

#### 2. KRACK Attack (2017)

```
Key Reinstallation Attack:

┌───────────────────────────────────────────────────────────┐
│  KRACK exploits the 4-Way Handshake by forcing           │
│  reinstallation of already-used keys                      │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  1. Attacker positions as Man-in-the-Middle              │
│  2. Blocks Message 4 from reaching AP                    │
│  3. AP retransmits Message 3                             │
│  4. Client reinstalls PTK with reset nonce               │
│  5. Nonce reuse allows decryption/injection              │
│                                                           │
│  Impact:                                                  │
│  • Decrypt packets (especially with TKIP/GCMP)           │
│  • Inject packets                                         │
│  • Hijack TCP connections                                 │
│                                                           │
│  Mitigation: Patch clients and APs                       │
└───────────────────────────────────────────────────────────┘
```

#### 3. PMKID Attack (2018)

```
PMKID Attack Advantages:

Traditional Attack:           PMKID Attack:
─────────────────────────────────────────────────────────
✗ Requires client            ✓ No client needed
✗ Wait for handshake         ✓ Request from AP directly
✗ May need deauth            ✓ Passive capture possible
✓ Works on all networks      ✓ Works on most networks

PMKID = HMAC-SHA1(PMK, "PMK Name" + MAC_AP + MAC_Client)

Capture: hcxdumptool or hcxpcaptool
Crack: hashcat -m 16800
```

## WPA3 (WiFi Protected Access 3) - Latest Standard

### Key Improvements

```
┌─────────────────────────────────────────────────────────────┐
│                     WPA3 FEATURES                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. SAE (Simultaneous Authentication of Equals)             │
│     ├── Replaces PSK authentication                        │
│     ├── Dragonfly key exchange                             │
│     ├── Forward secrecy (past sessions safe)               │
│     └── Resistant to offline dictionary attacks            │
│                                                             │
│  2. Protected Management Frames (PMF) - Mandatory          │
│     ├── Deauth frames are authenticated                    │
│     └── Harder to perform deauth attacks                   │
│                                                             │
│  3. Enhanced Open (OWE)                                     │
│     ├── Opportunistic Wireless Encryption                  │
│     └── Encryption without password                         │
│                                                             │
│  4. 192-bit Security Mode (Enterprise)                     │
│     ├── CNSA Suite algorithms                              │
│     └── For high-security environments                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### SAE (Dragonfly) Handshake

```
SAE (Simultaneous Authentication of Equals):

    CLIENT                                     AP
       │                                        │
       │────────► Commit (with element) ───────►│
       │                                        │
       │◄─────── Commit (with element) ◄───────│
       │                                        │
       │         Both derive shared secret      │
       │         (PMK) without exposing it      │
       │                                        │
       │────────► Confirm ─────────────────────►│
       │                                        │
       │◄─────── Confirm ◄─────────────────────│
       │                                        │
       │         PMK established               │
       │         4-Way Handshake follows       │
       │                                        │

Key Benefits:
• Password never transmitted (zero-knowledge proof)
• Each session uses unique keys (forward secrecy)
• Offline dictionary attack impossible
• Equal authentication (no client/server hierarchy)
```

### WPA3 Vulnerabilities (Dragonblood - 2019)

```
Dragonblood Attacks:

1. Downgrade Attacks
   └── Force transition to WPA2

2. Side-Channel Attacks
   ├── Timing attacks on SAE
   └── Cache-based attacks

3. DoS Attacks
   └── Exhaust AP resources with SAE commits

Mitigation: Firmware updates, disable WPA2 fallback
```

## Protocol Comparison Summary

| Feature | WEP | WPA | WPA2 | WPA3 |
|---------|-----|-----|------|------|
| Year | 1999 | 2003 | 2004 | 2018 |
| Encryption | RC4 | RC4+TKIP | AES-CCMP | AES-CCMP/GCMP |
| Key Size | 40/104-bit | 128-bit | 128-bit | 128/192-bit |
| IV Size | 24-bit | 48-bit | 48-bit | N/A |
| Key Exchange | Static | TKIP | 4-Way | SAE+4-Way |
| Integrity | CRC32 | Michael | CCMP | CCMP/GCMP |
| Forward Secrecy | No | No | No | Yes |
| Offline Attacks | Trivial | Possible | Possible | Resistant |
| Status | BROKEN | Deprecated | Current | Recommended |

## Lab Exercises (Theory)

### Exercise 1: Protocol Identification

Identify the security protocol from these characteristics:
1. Uses RC4 with 24-bit IV
2. Uses SAE for key exchange
3. Uses TKIP with 48-bit IV
4. Uses AES-CCMP with 4-way handshake

<details>
<summary>Answers</summary>

1. WEP
2. WPA3
3. WPA
4. WPA2

</details>

### Exercise 2: Attack Matching

Match the attack to the vulnerable protocol:
1. FMS Attack → ?
2. KRACK Attack → ?
3. Dictionary Attack (handshake) → ?
4. Dragonblood → ?

<details>
<summary>Answers</summary>

1. FMS Attack → WEP
2. KRACK Attack → WPA2
3. Dictionary Attack → WPA/WPA2 PSK
4. Dragonblood → WPA3

</details>

### Exercise 3: Security Analysis

A business uses WPA2-Personal with the password "CompanyWifi2024". Analyze the security implications.

<details>
<summary>Answer</summary>

Security Issues:
1. **Shared password** - All employees use the same password
2. **Predictable password** - Contains common words and year
3. **Dictionary attack vulnerable** - Would be found quickly
4. **No accountability** - Cannot track individual users
5. **Password rotation** - Must change for all users if one leaves

Recommendations:
- Upgrade to WPA2/WPA3-Enterprise with RADIUS
- If PSK required, use random 20+ character password
- Consider network segmentation

</details>

## Knowledge Check

1. Why is WEP's 24-bit IV a critical vulnerability?
2. What is the purpose of the 4-Way Handshake in WPA2?
3. How does WPA3's SAE prevent offline dictionary attacks?
4. What is the difference between WPA2-Personal and WPA2-Enterprise?
5. What is PMKID and why is it useful for attackers?

<details>
<summary>Answers</summary>

1. 24 bits = only 16.7 million possible IVs, causing inevitable reuse and key stream recovery
2. To derive and install per-session encryption keys (PTK, GTK) between client and AP
3. SAE uses Dragonfly key exchange where the password is never transmitted, only used to derive a shared secret through zero-knowledge proof
4. Personal uses a shared password (PSK), Enterprise uses individual credentials via 802.1X/RADIUS
5. PMKID is a hash that can be captured without a client present, allowing offline dictionary attacks without waiting for a full handshake

</details>

## Summary

| Protocol | Use Case | Security Level |
|----------|----------|----------------|
| WEP | NEVER | Broken |
| WPA | NEVER (legacy only) | Weak |
| WPA2-Personal | Home/Small Office | Moderate (strong password required) |
| WPA2-Enterprise | Enterprise | Strong |
| WPA3-Personal | Modern Home | Strong |
| WPA3-Enterprise | High Security | Very Strong |

## Next Lab

Proceed to [Lab 03: Wireless Reconnaissance](../03-wireless-reconnaissance/) to learn how to discover and enumerate wireless networks.

## References

- [WiFi Alliance WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security)
- [KRACK Attacks Paper](https://www.krackattacks.com/)
- [Dragonblood Paper](https://wpa3.mathyvanhoef.com/)
- [Aircrack-ng Theory](https://www.aircrack-ng.org/doku.php?id=theory)

---

**Flag:** `FLAG{w1f1_pr0t0c0ls_m4st3r}`
