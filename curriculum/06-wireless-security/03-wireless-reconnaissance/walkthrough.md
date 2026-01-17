# Lab 03: Wireless Reconnaissance - Walkthrough

Complete step-by-step solution guide for the wireless reconnaissance lab.

```
+===============================================================+
|                    WALKTHROUGH GUIDE                           |
+===============================================================+
|  WARNING: This contains complete solutions.                   |
|  Try the exercises yourself first!                            |
+===============================================================+
```

## Legal Disclaimer

```
+=====================================================================+
|                         LEGAL WARNING                                |
+=====================================================================+
|  This walkthrough is for EDUCATIONAL PURPOSES ONLY.                 |
|                                                                      |
|  - Only perform these actions on networks you OWN                   |
|  - Or have EXPLICIT WRITTEN PERMISSION to test                      |
|  - Unauthorized wireless monitoring is a CRIMINAL OFFENSE           |
|  - Always use an isolated lab environment when possible             |
+=====================================================================+
```

## Prerequisites Verification

### Step 1: Verify Hardware

```bash
# Check if wireless adapter is connected
lsusb | grep -i wireless

# Example output for Alfa AWUS036ACH:
# Bus 001 Device 003: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU

# List wireless interfaces
iwconfig 2>/dev/null | grep -E "^[a-z]"

# Expected output:
# wlan0     IEEE 802.11  ESSID:off/any
```

### Step 2: Verify Software Installation

```bash
# Check aircrack-ng suite
which airmon-ng airodump-ng aireplay-ng aircrack-ng

# Expected output:
# /usr/bin/airmon-ng
# /usr/bin/airodump-ng
# /usr/bin/aireplay-ng
# /usr/bin/aircrack-ng

# Check version
aircrack-ng --version
```

## Exercise 1: Basic Discovery - Complete Walkthrough

### Objective
Put your adapter in monitor mode and identify all networks in range.

### Step-by-Step Solution

```bash
# 1. Identify your wireless interface
iwconfig
# Note: Your interface is likely wlan0 or wlan1

# 2. Check for interfering processes
sudo airmon-ng check

# Output shows processes that may interfere:
#  PID Name
# 1234 NetworkManager
# 5678 wpa_supplicant

# 3. Kill interfering processes
sudo airmon-ng check kill

# Output:
# Killing these processes:
#  PID Name
# 1234 NetworkManager
# 5678 wpa_supplicant

# 4. Enable monitor mode
sudo airmon-ng start wlan0

# Output:
# PHY     Interface       Driver          Chipset
# phy0    wlan0           rtl8812au       Realtek Semiconductor Corp. RTL8812AU
#               (monitor mode enabled on wlan0mon)

# 5. Verify monitor mode is enabled
iwconfig wlan0mon

# Output should show:
# wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.437 GHz

# 6. Start network discovery
sudo airodump-ng wlan0mon

# Let it run for 30-60 seconds to discover all networks
# Press Ctrl+C to stop
```

### Understanding the Output

```
 CH  9 ][ Elapsed: 1 min ][ 2024-01-15 14:30

 BSSID              PWR  Beacons    #Data  #/s  CH   MB   ENC    CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -45      312      156   15   6   54e  WPA2   CCMP    PSK  HomeNetwork
 11:22:33:44:55:66  -68      145       67    5  11   54e  WPA2   CCMP    PSK  CoffeeShop_Guest
 AA:AA:AA:AA:AA:AA  -82       45       12    1   1   54   WEP    WEP         LegacyRouter
 BB:BB:BB:BB:BB:BB  -55      201       89    8   6   54e  OPN                OpenNetwork
 CC:CC:CC:CC:CC:CC  -71       98       34    3   3   54e  WPA2   CCMP    MGT  Corporate_Secure
```

### Analysis

**Answering the exercise questions:**

1. **How many networks are in range?**
   - 5 networks visible in this example capture

2. **What encryption types are used?**
   - WPA2 with CCMP (most common): HomeNetwork, CoffeeShop_Guest, Corporate_Secure
   - WEP (legacy, vulnerable): LegacyRouter
   - Open (no encryption): OpenNetwork

3. **Which channel has the most networks?**
   - Channel 6 has 2 networks (HomeNetwork, OpenNetwork)
   - This is common as channel 6 is a default for many routers

### Band-Specific Scanning

```bash
# Scan 2.4 GHz only (channels 1-14)
sudo airodump-ng --band g wlan0mon

# Scan 5 GHz only (channels 36-165)
sudo airodump-ng --band a wlan0mon

# Scan all bands
sudo airodump-ng --band abg wlan0mon
```

## Exercise 2: Client Enumeration - Complete Walkthrough

### Objective
Target your test network and identify all connected clients.

### Step-by-Step Solution

```bash
# 1. First, identify your target network from the scan
# Let's target HomeNetwork on channel 6
# BSSID: AA:BB:CC:DD:EE:FF

# 2. Focus on the target network
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon

# This locks to channel 6 and filters to only show our target
```

### Sample Output

```
 CH  6 ][ Elapsed: 2 min ][ 2024-01-15 14:35

 BSSID              PWR RXQ  Beacons    #Data  #/s  CH   MB   ENC    CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -45  85     1245      856   42   6   54e  WPA2   CCMP    PSK  HomeNetwork

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 AA:BB:CC:DD:EE:FF  11:11:11:11:11:11  -52   54e-54e      2      425
 AA:BB:CC:DD:EE:FF  22:22:22:22:22:22  -61   24e-24e     15      312
 AA:BB:CC:DD:EE:FF  33:33:33:33:33:33  -78   11e-11e     45      156
 (not associated)   44:44:44:44:44:44  -72   0 - 1        0       28         HomeNetwork, CoffeeShop
 (not associated)   55:55:55:55:55:55  -85   0 - 1        0       12         OfficeWiFi
```

### Analysis

**Connected Clients (associated with AP):**

| Station MAC | Signal | Status | Analysis |
|-------------|--------|--------|----------|
| 11:11:11:11:11:11 | -52 dBm | Strong | Likely in same room as AP |
| 22:22:22:22:22:22 | -61 dBm | Good | Connected, moderate distance |
| 33:33:33:33:33:33 | -78 dBm | Poor | Far from AP, may have connectivity issues |

**Unassociated Clients (probing):**

| Station MAC | Probes | Analysis |
|-------------|--------|----------|
| 44:44:44:44:44:44 | HomeNetwork, CoffeeShop | Device has connected to these networks before |
| 55:55:55:55:55:55 | OfficeWiFi | Looking for work network |

**Security Implications:**
- Probe requests reveal preferred networks
- This information can be used for evil twin attacks
- Device 44:44:44:44:44:44 could be targeted with a fake "HomeNetwork" AP

## Exercise 3: Capture and Analysis - Complete Walkthrough

### Objective
Capture traffic from your test network and analyze it in Wireshark.

### Step-by-Step Solution

```bash
# 1. Start capturing traffic to a file
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w lab03_capture wlan0mon

# Output files created:
# lab03_capture-01.cap      - Packet capture (Wireshark compatible)
# lab03_capture-01.csv      - CSV summary
# lab03_capture-01.kismet.csv
# lab03_capture-01.kismet.netxml
# lab03_capture-01.log.csv

# 2. Let it run for 5 minutes
# Press Ctrl+C after 5 minutes

# 3. Verify capture file
ls -la lab03_capture*
file lab03_capture-01.cap

# 4. Check packet count
tcpdump -r lab03_capture-01.cap 2>/dev/null | wc -l
```

### Wireshark Analysis

```bash
# Open the capture in Wireshark
wireshark lab03_capture-01.cap &
```

#### Filter: Beacon Frames

```
# Wireshark display filter
wlan.fc.type_subtype == 0x08
```

**Beacon Frame Analysis:**

Beacons contain:
- SSID (network name)
- Supported rates
- Channel information
- Security capabilities (RSN IE)
- Vendor information

#### Filter: Probe Requests

```
# Wireshark display filter
wlan.fc.type_subtype == 0x04
```

**Probe Request Analysis:**

Probe requests show:
- Client MAC addresses
- SSIDs clients are looking for
- Can reveal travel history and preferred networks

#### Filter: Probe Responses

```
# Wireshark display filter
wlan.fc.type_subtype == 0x05
```

#### Filter: Data Frames

```
# Wireshark display filter
wlan.fc.type == 2
```

**Data Frame Analysis:**

Data frames contain:
- Source and destination MAC addresses
- Encrypted payload (if WPA2)
- QoS information
- Sequence numbers

### Frame Type Summary

| Frame Type | Subtype | Purpose | Filter |
|------------|---------|---------|--------|
| Management | Beacon (0x08) | AP announces presence | wlan.fc.type_subtype == 0x08 |
| Management | Probe Req (0x04) | Client searches | wlan.fc.type_subtype == 0x04 |
| Management | Probe Resp (0x05) | AP responds to probe | wlan.fc.type_subtype == 0x05 |
| Management | Auth (0x0b) | Authentication | wlan.fc.type_subtype == 0x0b |
| Management | Assoc Req (0x00) | Association request | wlan.fc.type_subtype == 0x00 |
| Management | Deauth (0x0c) | Deauthentication | wlan.fc.type_subtype == 0x0c |
| Control | ACK (0x1d) | Acknowledgment | wlan.fc.type_subtype == 0x1d |
| Control | RTS (0x1b) | Request to Send | wlan.fc.type_subtype == 0x1b |
| Control | CTS (0x1c) | Clear to Send | wlan.fc.type_subtype == 0x1c |
| Data | Data (0x20) | Data frame | wlan.fc.type == 2 |

## Cleanup - Restoring Normal Mode

```bash
# 1. Stop monitor mode
sudo airmon-ng stop wlan0mon

# 2. Restart NetworkManager
sudo systemctl start NetworkManager

# OR
sudo service NetworkManager start

# 3. Verify restoration
iwconfig
# Should show wlan0 in Managed mode

# 4. Test connectivity
ping -c 3 google.com
```

## Alternative Tool: Bettercap

```bash
# Start bettercap
sudo bettercap -iface wlan0mon

# In bettercap console:
wifi.recon on
wifi.show

# Filter by specific ESSID
wifi.recon on
wifi.show "HomeNetwork"

# Deauth clients (for handshake capture - advanced)
wifi.deauth AA:BB:CC:DD:EE:FF
```

## Alternative Tool: Kismet

```bash
# Start Kismet
sudo kismet

# Access web interface
# Open browser to http://localhost:2501

# Kismet provides:
# - Real-time network map
# - GPS integration (if available)
# - Extended logging
# - Multi-source support
```

## Troubleshooting

### Issue: No Networks Found

```bash
# Check if interface is up
ip link show wlan0mon

# Check if antenna is connected
# Physical check of adapter

# Try different band
sudo airodump-ng --band a wlan0mon  # 5 GHz
sudo airodump-ng --band g wlan0mon  # 2.4 GHz
```

### Issue: Interface Disappears

```bash
# Restart adapter
sudo ip link set wlan0 down
sudo ip link set wlan0 up

# Check dmesg for errors
dmesg | tail -20

# Reinstall driver if needed
sudo apt install realtek-rtl88xxau-dkms  # For Alfa adapters
```

### Issue: Low Packet Capture

```bash
# Check signal strength
# Move closer to target network

# Verify correct channel
sudo airodump-ng -c 6 wlan0mon  # Lock to specific channel

# Check for driver issues
lsmod | grep -E "rtl|ath|mt7"
```

## Summary

In this walkthrough, you learned:

1. **Monitor Mode Setup**
   - Kill interfering processes
   - Enable monitor mode with airmon-ng
   - Verify mode change

2. **Network Discovery**
   - Use airodump-ng for scanning
   - Understand output columns
   - Filter by band, channel, encryption

3. **Client Enumeration**
   - Target specific networks
   - Identify connected clients
   - Analyze probe requests

4. **Traffic Capture**
   - Save captures to files
   - Analyze with Wireshark
   - Identify frame types

5. **Cleanup**
   - Restore managed mode
   - Restart network services

## Next Steps

Continue to [Lab 04: WEP Cracking](../04-wep-cracking/) to learn how to exploit WEP vulnerabilities.

---

**Flag:** `FLAG{41r0dump_r3c0n}`
