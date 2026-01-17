# Lab 03: Wireless Reconnaissance

Discovering and enumerating wireless networks using monitor mode and the aircrack-ng suite.

```
+===============================================================+
|                  WIRELESS RECONNAISSANCE                       |
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
|  Passive wireless monitoring may be legal in some jurisdictions,    |
|  but active probing and network interaction typically requires      |
|  explicit authorization.                                             |
|                                                                      |
|  - ONLY monitor networks you own or have permission to test         |
|  - Recording traffic from other networks may violate privacy laws   |
|  - When in doubt, use only YOUR OWN isolated test network           |
|                                                                      |
|  Unauthorized network monitoring can result in criminal charges.    |
+=====================================================================+
```

## Learning Objectives

By the end of this lab, you will:

1. Configure a wireless adapter for monitor mode
2. Use airodump-ng to discover networks
3. Identify network security configurations
4. Enumerate connected clients
5. Capture network traffic for analysis
6. Understand channel hopping and band selection

## Prerequisites

- Compatible wireless adapter with monitor mode support
- Kali Linux or similar security distribution
- Aircrack-ng suite installed
- Basic understanding of 802.11 protocols (Lab 01)
- Understanding of WiFi security protocols (Lab 02)

## Hardware Requirements

### Recommended Adapters

| Adapter | Chipset | Bands | Monitor Mode | Packet Injection |
|---------|---------|-------|--------------|------------------|
| Alfa AWUS036ACH | RTL8812AU | 2.4/5 GHz | Yes | Yes |
| Alfa AWUS036ACHM | MT7612U | 2.4/5 GHz | Yes | Yes |
| Alfa AWUS036ACM | MT7612U | 2.4/5 GHz | Yes | Yes |
| TP-Link TL-WN722N v1 | AR9271 | 2.4 GHz | Yes | Yes |

**Warning:** TP-Link TL-WN722N v2/v3 use different chipsets and do NOT support monitor mode!

## Lab Overview

### What is Wireless Reconnaissance?

Wireless reconnaissance is the process of discovering, identifying, and gathering information about wireless networks in range. This includes:

- **Network Discovery**: Finding SSIDs, BSSIDs, channels
- **Security Identification**: Determining encryption types (WEP, WPA, WPA2, WPA3)
- **Client Enumeration**: Identifying devices connected to networks
- **Signal Analysis**: Mapping signal strength and coverage
- **Traffic Analysis**: Capturing and analyzing wireless frames

### The Aircrack-ng Suite

```
Aircrack-ng Suite Tools:

+------------------+----------------------------------------+
| Tool             | Purpose                                |
+------------------+----------------------------------------+
| airmon-ng        | Enable/disable monitor mode            |
| airodump-ng      | Capture wireless traffic               |
| aireplay-ng      | Packet injection (deauth, replay)      |
| aircrack-ng      | WEP/WPA key cracking                   |
| airbase-ng       | Create fake access points              |
| airdecap-ng      | Decrypt captured traffic               |
| airolib-ng       | Manage PMK database                    |
| packetforge-ng   | Create custom packets                  |
+------------------+----------------------------------------+
```

## Step-by-Step Instructions

### Step 1: Identify Your Wireless Interface

```bash
# List all wireless interfaces
iwconfig

# OR use iw
iw dev

# Check USB devices (for USB adapters)
lsusb

# Example output:
# wlan0     IEEE 802.11  ESSID:off/any
#           Mode:Managed  Access Point: Not-Associated
```

### Step 2: Check Monitor Mode Support

```bash
# Check supported interface modes
iw list | grep -A 10 "Supported interface modes"

# Look for:
#     * monitor
#     * AP
#     * managed

# If monitor mode is listed, your adapter is compatible
```

### Step 3: Kill Interfering Processes

```bash
# Check for processes that may interfere
sudo airmon-ng check

# Kill interfering processes
sudo airmon-ng check kill

# This stops:
# - NetworkManager
# - wpa_supplicant
# - dhclient
# - Other WiFi management processes
```

### Step 4: Enable Monitor Mode

```bash
# Method 1: Using airmon-ng (recommended)
sudo airmon-ng start wlan0

# Your interface is now wlan0mon (or similar)
# Verify with:
iwconfig

# Method 2: Using iw (manual)
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up

# Method 3: Using iwconfig (legacy)
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

### Step 5: Verify Monitor Mode

```bash
# Check interface mode
iwconfig wlan0mon

# Should show:
# Mode:Monitor

# Verify with iw
iw dev wlan0mon info
```

### Step 6: Basic Network Discovery

```bash
# Scan all channels (2.4 GHz + 5 GHz)
sudo airodump-ng wlan0mon

# Scan 2.4 GHz only
sudo airodump-ng --band g wlan0mon

# Scan 5 GHz only
sudo airodump-ng --band a wlan0mon

# Scan all bands
sudo airodump-ng --band abg wlan0mon
```

### Understanding Airodump-ng Output

```
 CH  6 ][ Elapsed: 1 min ][ 2024-01-15 14:30

 BSSID              PWR  Beacons    #Data  #/s  CH   MB   ENC    CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -45      250      125   12   6   54e  WPA2   CCMP    PSK  HomeNetwork
 11:22:33:44:55:66  -72       85       45    3  11   54e  WPA2   CCMP    PSK  CoffeeShop
 AA:AA:AA:AA:AA:AA  -88       12        0    0   1   54   WEP    WEP         OldRouter
 <length:  0>       -65       95       23    2   6   54e  WPA2   CCMP    PSK  <hidden>

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 AA:BB:CC:DD:EE:FF  11:11:11:11:11:11  -52   54e-54e      0       85
 AA:BB:CC:DD:EE:FF  22:22:22:22:22:22  -61   54e-54e      5       42
 (not associated)   33:33:33:33:33:33  -78   0 - 1        0       12         HomeNetwork
```

### Column Explanations

**Top Section (Access Points):**

| Column | Description |
|--------|-------------|
| BSSID | MAC address of access point |
| PWR | Signal strength (dBm, closer to 0 = stronger) |
| Beacons | Number of beacon frames received |
| #Data | Number of data frames captured |
| #/s | Data frames per second |
| CH | Channel number |
| MB | Maximum speed supported |
| ENC | Encryption type (WEP, WPA, WPA2, WPA3, OPN) |
| CIPHER | Cipher suite (CCMP, TKIP, WEP) |
| AUTH | Authentication (PSK, MGT, SKA, OPN) |
| ESSID | Network name (SSID) |

**Bottom Section (Clients):**

| Column | Description |
|--------|-------------|
| BSSID | AP the client is connected to |
| STATION | Client MAC address |
| PWR | Client signal strength |
| Rate | Speed (RX-TX) |
| Lost | Lost frames |
| Frames | Captured frames |
| Probes | SSIDs client is probing for |

### Step 7: Target Specific Network

```bash
# Focus on specific network for handshake capture
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Parameters:
# -c 6           : Lock to channel 6
# --bssid        : Filter by AP MAC address
# -w capture     : Save to files starting with "capture"
# wlan0mon       : Interface name

# Output files created:
# capture-01.cap      : Packet capture
# capture-01.csv      : CSV summary
# capture-01.kismet.csv
# capture-01.kismet.netxml
# capture-01.log.csv
```

### Step 8: Advanced Filtering

```bash
# Filter by ESSID
sudo airodump-ng --essid "TargetNetwork" wlan0mon

# Filter by encryption type
sudo airodump-ng --encrypt WPA2 wlan0mon
sudo airodump-ng --encrypt WEP wlan0mon
sudo airodump-ng --encrypt OPN wlan0mon

# Show WPS status
sudo airodump-ng --wps wlan0mon

# Save only specific network's traffic
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w target_capture wlan0mon
```

### Step 9: Client Analysis

```bash
# Identify clients connected to target network
# Clients appear in bottom section when associated with AP

# Look for:
# - (not associated) clients - devices searching for networks
# - Probes column - reveals SSIDs the device has connected to before
# - This information can be used for evil twin attacks

# Save client probes for analysis
sudo airodump-ng --output-format csv -w probe_dump wlan0mon
```

### Step 10: Restore Normal Mode

```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager
sudo systemctl start NetworkManager

# OR
sudo service NetworkManager start

# Verify interface restored
iwconfig
```

## Alternative Tools

### Kismet (Advanced Wireless Detection)

```bash
# Install Kismet
sudo apt install kismet

# Run Kismet
sudo kismet

# Kismet provides:
# - Web interface (http://localhost:2501)
# - GPS integration
# - Multiple data sources
# - Advanced logging
```

### Wifite (Automated Auditing)

```bash
# Install wifite
sudo apt install wifite

# Run automated scan
sudo wifite

# Wifite automates:
# - Monitor mode setup
# - Network discovery
# - WEP/WPA attacks
# - Handshake capture
```

### Bettercap (Modern Framework)

```bash
# Install bettercap
sudo apt install bettercap

# Start with WiFi module
sudo bettercap -iface wlan0mon

# Enable WiFi recon
wifi.recon on

# Show results
wifi.show
```

## Lab Exercises

### Exercise 1: Basic Discovery

1. Put your adapter in monitor mode
2. Run airodump-ng and identify:
   - How many networks are in range?
   - What encryption types are used?
   - Which channel has the most networks?

### Exercise 2: Client Enumeration

1. Target your test network
2. Identify all connected clients
3. Determine what SSIDs are being probed by unassociated clients

### Exercise 3: Capture and Analysis

1. Capture traffic from your test network for 5 minutes
2. Open the .cap file in Wireshark
3. Identify beacon frames, probe requests, and data frames

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| "Monitor mode" not listed | Use a compatible adapter with proper chipset |
| Interface disappears | Check USB connection, try `sudo airmon-ng check kill` first |
| No networks found | Check antenna connection, try different channels |
| Permission denied | Run with sudo |
| NetworkManager conflicts | `sudo airmon-ng check kill` |

## Knowledge Check

1. What command enables monitor mode on wlan0?
2. What does the PWR column represent in airodump-ng?
3. How can you filter airodump-ng to show only WPA2 networks?
4. What do "Probes" reveal about a client device?
5. Why is channel hopping important during reconnaissance?

<details>
<summary>Answers</summary>

1. `sudo airmon-ng start wlan0`
2. Signal strength in dBm (closer to 0 is stronger)
3. `sudo airodump-ng --encrypt WPA2 wlan0mon`
4. SSIDs the client has previously connected to (potential targets for evil twin)
5. Networks operate on different channels; hopping allows discovery of all networks

</details>

## Summary

In this lab, you learned:

- How to configure monitor mode on wireless adapters
- Using airodump-ng for network discovery
- Understanding output fields and their significance
- Identifying security configurations and connected clients
- Capturing traffic for later analysis

## Next Lab

Proceed to [Lab 04: WEP Cracking](../04-wep-cracking/) to learn how to crack deprecated WEP encryption.

## References

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/doku.php?id=airodump-ng)
- [Kali Linux WiFi Tools](https://www.kali.org/tools/)
- [Wireshark 802.11 Analysis](https://wiki.wireshark.org/Wi-Fi)

---

**Flag:** `FLAG{41r0dump_r3c0n}`
