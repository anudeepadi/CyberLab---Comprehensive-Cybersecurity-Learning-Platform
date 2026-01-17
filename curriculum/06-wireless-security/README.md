# Module 06: Wireless Security

Master wireless network security concepts, vulnerabilities, and attack techniques used by penetration testers and security professionals.

```
    ╔══════════════════════════════════════════════════════════════╗
    ║                    WIRELESS SECURITY                         ║
    ║                                                              ║
    ║   ((( )))     802.11 Standards | WEP/WPA/WPA2/WPA3          ║
    ║  ((     ))    Reconnaissance | Cracking | Evil Twin          ║
    ║ ((  Wifi  ))  Deauthentication | Bluetooth Security          ║
    ║  ((     ))                                                   ║
    ║   ((( )))     8 Labs | 10 Hours | Theory-Focused             ║
    ╚══════════════════════════════════════════════════════════════╝
```

## Important Notice: Theory-Focused Module

> **This module is primarily THEORY-FOCUSED.** Wireless attacks require specialized hardware (WiFi adapters with monitor mode support, Bluetooth adapters) that cannot be virtualized. The labs provide:
> - Comprehensive theoretical knowledge
> - Command syntax and tool usage
> - Simulated/demo environments where possible
> - Preparation for real-world testing with proper hardware

## Legal Disclaimer

```
╔══════════════════════════════════════════════════════════════════════╗
║                         LEGAL WARNING                                 ║
╠══════════════════════════════════════════════════════════════════════╣
║  Wireless attacks on networks you do not own or have explicit        ║
║  written permission to test are ILLEGAL in most jurisdictions.       ║
║                                                                       ║
║  Violations may result in:                                           ║
║  • Criminal charges under the Computer Fraud and Abuse Act (US)      ║
║  • Violations of the Wiretap Act                                     ║
║  • Civil liability and lawsuits                                      ║
║  • Fines up to $250,000 and imprisonment                            ║
║                                                                       ║
║  ALWAYS obtain proper authorization before testing wireless          ║
║  networks. Use isolated lab environments whenever possible.          ║
╚══════════════════════════════════════════════════════════════════════╝
```

## Hardware Requirements

To practice these techniques in a real environment, you will need:

### Essential Hardware

| Hardware | Purpose | Recommended Models |
|----------|---------|-------------------|
| WiFi Adapter (Monitor Mode) | Packet injection, monitoring | Alfa AWUS036ACH, AWUS036ACHM |
| Secondary WiFi Adapter | Evil twin attacks | TP-Link TL-WN722N v1 |
| Bluetooth Adapter | BLE attacks | Ubertooth One, Parani UD100 |

### Chipset Compatibility

**Recommended Chipsets for Kali Linux:**
- Atheros AR9271 (excellent compatibility)
- Realtek RTL8812AU (5GHz support)
- Ralink RT3070 (legacy but reliable)
- MediaTek MT7612U (modern, dual-band)

**Verify Monitor Mode Support:**
```bash
# Check if adapter supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# Look for:
#   * monitor
#   * AP (for evil twin)
```

## Module Overview

| Lab | Topic | Duration | Difficulty | Hardware Required |
|-----|-------|----------|------------|-------------------|
| 01 | Wireless Fundamentals | 1 hr | Beginner | None (Theory) |
| 02 | WiFi Security Protocols | 1.5 hrs | Beginner | None (Theory) |
| 03 | Wireless Reconnaissance | 1.5 hrs | Intermediate | WiFi Adapter |
| 04 | WEP Cracking | 1 hr | Intermediate | WiFi Adapter |
| 05 | WPA/WPA2 Attacks | 1.5 hrs | Intermediate | WiFi Adapter |
| 06 | Deauthentication Attacks | 1 hr | Intermediate | WiFi Adapter |
| 07 | Evil Twin Attacks | 1.5 hrs | Advanced | 2x WiFi Adapters |
| 08 | Bluetooth Security | 1 hr | Intermediate | Bluetooth Adapter |

## Learning Objectives

By completing this module, you will:

1. **Understand Wireless Fundamentals**
   - 802.11 standards (a/b/g/n/ac/ax)
   - Radio frequencies and channels
   - Wireless network architectures

2. **Analyze Security Protocols**
   - WEP vulnerabilities and why it's broken
   - WPA/WPA2 security mechanisms
   - WPA3 improvements and SAE

3. **Perform Wireless Reconnaissance**
   - Monitor mode configuration
   - Network discovery with airodump-ng
   - Client enumeration

4. **Execute Attack Techniques**
   - WEP key cracking
   - WPA handshake capture
   - Dictionary and PMKID attacks
   - Deauthentication attacks

5. **Understand Advanced Attacks**
   - Evil twin/rogue AP attacks
   - Captive portal credential harvesting
   - Bluetooth vulnerabilities

## Tools Covered

```bash
# Aircrack-ng Suite
airmon-ng      # Interface mode management
airodump-ng    # Wireless reconnaissance
aireplay-ng    # Packet injection/deauth
aircrack-ng    # WEP/WPA cracking
airbase-ng     # Fake AP creation

# Additional Tools
wifite         # Automated wireless auditing
reaver         # WPS attacks
bully          # WPS brute force
hostapd        # Access point daemon
dnsmasq        # DHCP/DNS for evil twin
hashcat        # GPU-accelerated cracking
hcxdumptool    # PMKID capture
hcxpcapngtool  # Convert captures

# Bluetooth Tools
hcitool        # Bluetooth device tool
bluetoothctl   # Bluetooth control
btscanner      # Bluetooth scanner
ubertooth-*    # Ubertooth tools (if hardware available)
```

## Lab Environment Options

### Option 1: Simulation with Virtual Networks (Limited)

```bash
# Create virtual wireless interface for testing commands
# Note: Cannot perform actual attacks without real hardware

# Install mac80211_hwsim for simulated radios
sudo modprobe mac80211_hwsim radios=2
iwconfig  # Will show wlan0, wlan1 (simulated)
```

### Option 2: Isolated Physical Lab (Recommended)

```
┌─────────────────────────────────────────────────────────┐
│                    ISOLATED LAB SETUP                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   [Kali Attack Machine]                                 │
│         │                                               │
│         │ USB WiFi Adapter (Monitor Mode)               │
│         │                                               │
│         ▼                                               │
│   )))  Wireless Signal  (((                             │
│         │                                               │
│         ▼                                               │
│   [Test Access Point]  ←── Isolated, not connected      │
│         │                   to internet/production      │
│         │                                               │
│         ▼                                               │
│   [Test Client Device] ←── Your own devices only        │
│                                                          │
│   IMPORTANT: Keep test network isolated!                │
│   Use Faraday cage or low-power for minimal leakage    │
└─────────────────────────────────────────────────────────┘
```

### Option 3: Pre-captured Files (Theory Practice)

Practice analysis with pre-captured packet files:
- WPA handshake files (.cap)
- PMKID captures
- Bluetooth HCI dumps

## Quick Reference: Aircrack-ng Suite

```bash
# 1. Enable Monitor Mode
sudo airmon-ng check kill          # Kill interfering processes
sudo airmon-ng start wlan0         # Start monitor mode
# Interface becomes wlan0mon

# 2. Scan for Networks
sudo airodump-ng wlan0mon          # Scan all channels
sudo airodump-ng -c 6 wlan0mon     # Scan specific channel
sudo airodump-ng --band abg wlan0mon  # All bands

# 3. Target Specific Network
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. Capture WPA Handshake (need client activity)
# Wait for handshake or force with deauth

# 5. Deauthenticate Client (to force handshake)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# 6. Crack Captured Handshake
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# 7. Restore Managed Mode
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

## Ethical Considerations

### The Pentester's Oath for Wireless Testing

1. **Written Authorization Only**
   - Never test networks without explicit written permission
   - Scope should clearly define which networks/SSIDs are in scope

2. **Minimize Collateral Damage**
   - Deauth attacks affect all users on a network
   - Schedule tests during maintenance windows when possible

3. **Protect Captured Data**
   - Handshakes contain sensitive information
   - Securely delete captures after testing

4. **Report All Findings**
   - Document vulnerabilities professionally
   - Provide remediation recommendations

5. **Know Your Local Laws**
   - Regulations vary by country
   - Some attacks (like deauth) may be illegal even with permission in certain jurisdictions

## Progression Path

```
Week 1: Foundations
├── Lab 01: Wireless Fundamentals
└── Lab 02: WiFi Security Protocols

Week 2: Reconnaissance & WEP
├── Lab 03: Wireless Reconnaissance
└── Lab 04: WEP Cracking

Week 3: WPA Attacks
├── Lab 05: WPA/WPA2 Attacks
└── Lab 06: Deauthentication Attacks

Week 4: Advanced Topics
├── Lab 07: Evil Twin Attacks
└── Lab 08: Bluetooth Security
```

## Resources

### Documentation
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/doku.php)
- [WiFi Alliance Security Specifications](https://www.wi-fi.org/discover-wi-fi/security)
- [802.11 Standards Overview](https://en.wikipedia.org/wiki/IEEE_802.11)

### Practice Platforms
- [WiFi Challenge Lab](https://wifichallengelab.com/) - Online CTF
- [Wireless CTF Archives](https://ctftime.org/tasks/?tags=wireless)
- [PwnAdventure - Wireless Challenges](https://www.pwnadventure.com/)

### Books
- "Hacking Exposed Wireless" by Johnny Cache
- "Kali Linux Wireless Penetration Testing" by Vivek Ramachandran
- "Real-World Bug Hunting" (Wireless chapters)

### Certifications
- OSWP (Offensive Security Wireless Professional)
- CEH (Wireless sections)
- GPEN (Wireless components)

## Flags

| Lab | Flag |
|-----|------|
| Lab 01 | `FLAG{802_11_fund4m3nt4ls}` |
| Lab 02 | `FLAG{w1f1_pr0t0c0ls_m4st3r}` |
| Lab 03 | `FLAG{41r0dump_r3c0n}` |
| Lab 04 | `FLAG{w3p_1s_d34d}` |
| Lab 05 | `FLAG{wp4_h4ndsh4k3_cr4ck3d}` |
| Lab 06 | `FLAG{d34uth_4tt4ck}` |
| Lab 07 | `FLAG{3v1l_tw1n_pwn3d}` |
| Lab 08 | `FLAG{blu3t00th_s3cur1ty}` |

## Next Steps

After completing this module:
1. Set up an isolated wireless lab environment
2. Practice with your own equipment and networks
3. Pursue OSWP certification for hands-on validation
4. Move on to Module 07: Active Directory for enterprise attacks
