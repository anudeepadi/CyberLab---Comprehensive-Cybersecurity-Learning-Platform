# WiFi Security Protocols - Study Guide

Quick reference for security mechanisms, vulnerabilities, and attack surfaces across WiFi protocols.

## Protocol Security at a Glance

### Security Level Summary

```
Security Strength (Lowest to Highest):

[BROKEN]     WEP        ████░░░░░░░░░░░░░░░░  Never use
[WEAK]       WPA-TKIP   ██████░░░░░░░░░░░░░░  Legacy only
[MODERATE]   WPA2-PSK   ████████████░░░░░░░░  Requires strong password
[STRONG]     WPA2-ENT   ██████████████████░░  Enterprise environments
[STRONGEST]  WPA3-SAE   ████████████████████  Current recommendation
```

## Encryption Mechanisms

### Cipher Comparison

| Protocol | Cipher | Key Size | IV Size | Security |
|----------|--------|----------|---------|----------|
| WEP | RC4 | 40/104-bit | 24-bit | Broken |
| WPA | RC4+TKIP | 128-bit | 48-bit | Weak |
| WPA2 | AES-CCMP | 128-bit | 48-bit | Strong |
| WPA3 | AES-GCMP | 128/256-bit | 96-bit | Strongest |

### Key Derivation

```
WPA/WPA2 PSK Key Derivation:

Password + SSID
      │
      ▼
  PBKDF2-SHA1
  (4096 iterations)
      │
      ▼
 256-bit PMK (Pairwise Master Key)
      │
      ▼
  PRF-384/512
  (ANonce + SNonce + MACs)
      │
      ▼
    PTK (Pairwise Transient Key)
    ├── KCK (Key Confirmation Key) - 128 bits
    ├── KEK (Key Encryption Key) - 128 bits
    └── TK (Temporal Key) - 128/256 bits
```

## Vulnerability Summary

### WEP Vulnerabilities

| Vulnerability | Description | Exploitation |
|--------------|-------------|--------------|
| Weak IVs | Certain IVs leak key information | FMS/PTW attacks |
| IV Collision | 24-bit IV exhaustion | Keystream recovery |
| No Replay Protection | Packets can be reinjected | ARP replay attack |
| Weak Integrity | CRC32 is linear | Packet modification |
| Static Keys | No automatic rotation | Long-term exposure |

### WPA/WPA2 Vulnerabilities

| Vulnerability | Description | Exploitation |
|--------------|-------------|--------------|
| Dictionary Attacks | Weak passwords crackable | Hashcat/aircrack-ng |
| KRACK | Nonce reuse in handshake | Packet decryption |
| PMKID | PMK ID leaked in roaming | Offline cracking |
| Hole196 | GTK vulnerabilities | Insider attacks |
| TKIP Attacks | MIC/fragmentation issues | Beck-Tews attack |

### WPA3 Vulnerabilities

| Vulnerability | Description | Status |
|--------------|-------------|--------|
| Dragonblood | SAE side-channel attacks | Patched |
| Downgrade | Force WPA2 fallback | Disable mixed mode |
| DoS | SAE computation exhaustion | Rate limiting |

## Attack Surface Reference

### WEP Attacks

```
1. Passive IV Collection
   └── airodump-ng capture → aircrack-ng crack

2. Active IV Injection
   ├── Fake authentication: aireplay-ng -1
   ├── ARP replay: aireplay-ng -3
   └── Collect IVs faster

3. Fragmentation/Chop-Chop
   ├── aireplay-ng -5 (fragment)
   └── aireplay-ng -4 (chop-chop)
```

### WPA/WPA2 Attacks

```
1. Handshake Capture
   ├── Passive: Wait for connection
   └── Active: Deauth → Capture reconnection

2. Dictionary Attack
   ├── aircrack-ng -w wordlist capture.cap
   └── hashcat -m 22000 hash.hc22000 wordlist

3. PMKID Attack
   ├── hcxdumptool -o capture.pcapng
   ├── hcxpcapngtool -o hash.hc22000 capture.pcapng
   └── hashcat -m 22000 hash.hc22000 wordlist

4. Rainbow Tables
   ├── Pre-computed for common SSIDs
   └── Tools: coWPAtty, genpmk
```

## Key Terms Quick Reference

### Authentication Terms

| Term | Definition |
|------|------------|
| PMK | Pairwise Master Key - derived from password/RADIUS |
| PTK | Pairwise Transient Key - per-session key |
| GTK | Group Temporal Key - for broadcast/multicast |
| PSK | Pre-Shared Key - shared password mode |
| SAE | Simultaneous Authentication of Equals (WPA3) |
| RADIUS | Remote Authentication Dial-In User Service |
| 802.1X | Port-based network access control |

### Cryptographic Terms

| Term | Definition |
|------|------------|
| AES | Advanced Encryption Standard |
| CCMP | Counter Mode CBC-MAC Protocol |
| GCMP | Galois/Counter Mode Protocol |
| TKIP | Temporal Key Integrity Protocol |
| MIC | Message Integrity Code |
| IV | Initialization Vector |
| Nonce | Number used once |

### Attack Terms

| Term | Definition |
|------|------------|
| FMS | Fluhrer-Mantin-Shamir (WEP attack) |
| PTW | Pyshkin-Tews-Weinmann (WEP attack) |
| KRACK | Key Reinstallation Attack |
| PMKID | Pairwise Master Key Identifier |
| Deauth | Deauthentication attack |
| Evil Twin | Rogue access point |

## Security Recommendations

### Password Policy for WPA2-PSK

```
Minimum Requirements:
├── Length: 16+ characters (preferably 20+)
├── Complexity: Mixed case, numbers, symbols
├── Randomness: Not dictionary words
└── Uniqueness: Not used elsewhere

Strong Example:
  #xK9$mP2&nL5@qR8!wT3

Weak Examples (AVOID):
  - CompanyName2024
  - Password123!
  - Welcome@Home
```

### Network Configuration Checklist

```
Essential Security Settings:
├── [ ] WPA3-SAE if supported, else WPA2-AES
├── [ ] Disable WPA/TKIP
├── [ ] Disable WPS
├── [ ] Change default admin credentials
├── [ ] Strong, unique WiFi password
├── [ ] Regular firmware updates
├── [ ] Enable Protected Management Frames (PMF)
├── [ ] Consider hidden SSID (minor security)
├── [ ] MAC filtering (minor security)
└── [ ] Network segmentation (IoT separate)
```

## EAP Methods (Enterprise)

### Security Comparison

| Method | Security | Client Cert | Server Cert | Complexity |
|--------|----------|-------------|-------------|------------|
| EAP-TLS | Highest | Yes | Yes | High |
| EAP-TTLS | High | Optional | Yes | Medium |
| PEAP | High | No | Yes | Medium |
| EAP-FAST | Medium | No | Optional | Medium |
| EAP-MD5 | Low | No | No | Low |

### EAP-TLS (Most Secure)

```
┌─────────────────────────────────────────────────────────────┐
│ EAP-TLS Authentication Flow                                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client ◄─────────────────► RADIUS Server                  │
│    │                             │                          │
│    │ Client Certificate ─────────►                          │
│    │                             │                          │
│    │ ◄───────── Server Certificate                          │
│    │                             │                          │
│    │ Mutual verification         │                          │
│    │                             │                          │
│    └─── TLS Tunnel Established ──┘                          │
│                                                             │
│  No passwords transmitted - certificate-based only         │
└─────────────────────────────────────────────────────────────┘
```

## Cracking Speed Reference

### WPA2 Handshake Cracking

| Hardware | Speed (PMKs/sec) | Time for 1M passwords |
|----------|------------------|----------------------|
| CPU (single) | ~500 | ~33 minutes |
| CPU (multi) | ~2,000 | ~8 minutes |
| GPU (mid) | ~100,000 | ~10 seconds |
| GPU (high) | ~500,000 | ~2 seconds |
| 8x GPU | ~2,500,000 | ~0.4 seconds |

### Password Strength vs. Crack Time

| Password Type | Example | Crack Time (1 GPU) |
|--------------|---------|-------------------|
| Common word | password | Instant |
| Word + number | password123 | Seconds |
| Word + symbol | p@ssword! | Minutes |
| Random 8 char | a8#kL2$m | Days |
| Random 12 char | a8#kL2$m9Qw! | Years |
| Random 16 char | xK9$mP2&nL5@qR8! | Centuries |

## Quick Command Reference

### Identify Security Type

```bash
# Using airodump-ng
sudo airodump-ng wlan0mon
# Look at ENC column: WEP, WPA, WPA2, WPA3

# Using iw (connected network)
iw dev wlan0 link
```

### Common Encryption Indicators

```
Beacon Frame Analysis:

WEP:   Privacy bit set, no RSN/WPA IE
WPA:   WPA Information Element (vendor specific)
WPA2:  RSN Information Element
WPA3:  RSN IE with SAE AKM suite
```

## Study Checklist

Before the next lab, ensure you can:

- [ ] Explain why WEP's RC4 implementation is broken
- [ ] Describe the WPA2 4-Way Handshake purpose
- [ ] Explain how dictionary attacks work on WPA2-PSK
- [ ] Describe what PMKID is and why it's significant
- [ ] Explain WPA3 SAE advantages over PSK
- [ ] Differentiate WPA2-Personal from WPA2-Enterprise
- [ ] List three countermeasures for wireless attacks
- [ ] Explain forward secrecy in WPA3

## Practice Scenarios

### Scenario 1: Home Network

Your friend's home network uses WPA2-PSK with password "fluffy2015" (their cat's name and birth year).

**Security Assessment:**
- Vulnerable to dictionary attacks (common pattern)
- Would be found in targeted wordlist generation
- No individual user tracking

**Recommendations:**
1. Change to random 20+ character password
2. Consider WPA3 if devices support it
3. Enable WPA3 transition mode for compatibility

### Scenario 2: Coffee Shop

A coffee shop has open WiFi and asks customers to accept terms on a captive portal.

**Security Assessment:**
- No encryption (all traffic visible)
- Susceptible to evil twin attacks
- Credential theft possible

**User Precautions:**
1. Use VPN for all connections
2. Verify HTTPS on all sites
3. Avoid sensitive transactions
4. Verify correct SSID

### Scenario 3: Corporate Office

Office uses WPA2-Enterprise with PEAP-MSCHAPv2.

**Security Assessment:**
- Individual credentials (good)
- Server certificate validation needed
- MSCHAPv2 has known weaknesses

**Improvements:**
1. Migrate to EAP-TLS (certificate-based)
2. Enable server certificate validation
3. Consider WPA3-Enterprise 192-bit for sensitive areas

---

**Next:** [03 - Wireless Reconnaissance](../03-wireless-reconnaissance/)
