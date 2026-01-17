# Wireless Fundamentals - Study Guide

Quick reference guide for key concepts and terminology in wireless networking.

## Key Concepts at a Glance

### 802.11 Standards Quick Reference

| Standard | Name | Speed | Frequency | Year |
|----------|------|-------|-----------|------|
| 802.11a | WiFi 1 | 54 Mbps | 5 GHz | 1999 |
| 802.11b | WiFi 2 | 11 Mbps | 2.4 GHz | 1999 |
| 802.11g | WiFi 3 | 54 Mbps | 2.4 GHz | 2003 |
| 802.11n | WiFi 4 | 600 Mbps | 2.4/5 GHz | 2009 |
| 802.11ac | WiFi 5 | 6.9 Gbps | 5 GHz | 2013 |
| 802.11ax | WiFi 6/6E | 9.6 Gbps | 2.4/5/6 GHz | 2019 |

### Frequency Band Comparison

| Feature | 2.4 GHz | 5 GHz | 6 GHz |
|---------|---------|-------|-------|
| Range | Long | Medium | Short |
| Wall Penetration | Good | Fair | Poor |
| Interference | High | Low | Very Low |
| Non-overlap Channels | 3 (US) | 25 | 59 |
| Speed Potential | Lower | Higher | Highest |
| Device Support | Universal | Common | New Only |

## Essential Terminology

### Network Identifiers

**SSID (Service Set Identifier)**
- The network name you see when connecting
- Up to 32 characters
- Can be hidden (not broadcast)
- Example: "HomeWiFi", "CoffeeShop_Guest"

**BSSID (Basic Service Set Identifier)**
- MAC address of the access point
- Format: XX:XX:XX:XX:XX:XX
- Unique to each AP
- Example: "00:1A:2B:3C:4D:5E"

**ESSID (Extended Service Set Identifier)**
- Same as SSID when used across multiple APs
- Allows roaming between APs
- Single ESSID, multiple BSSIDs

### Network Components

**Access Point (AP)**
- Central device broadcasting WiFi
- Bridges wireless to wired network
- Has unique BSSID
- Broadcasts on specific channel

**Station (STA)**
- Any WiFi client device
- Phones, laptops, IoT devices
- Has unique MAC address

**Router**
- Often combined with AP
- Handles IP routing
- Provides DHCP, NAT, firewall

### Network Modes

**Infrastructure Mode**
- Clients connect through AP
- Most common configuration
- AP controls medium access

**Ad-Hoc Mode (IBSS)**
- Peer-to-peer connections
- No central AP
- Less common today

**Monitor Mode**
- Special mode for security testing
- Receives all frames in range
- Required for packet capture

## Channel Reference

### 2.4 GHz Channels (US)

```
Non-Overlapping: 1, 6, 11

Channel Map:
Ch 1  ████████████████████
Ch 2    ████████████████████
Ch 3      ████████████████████
Ch 4        ████████████████████
Ch 5          ████████████████████
Ch 6            ████████████████████
Ch 7              ████████████████████
Ch 8                ████████████████████
Ch 9                  ████████████████████
Ch 10                   ████████████████████
Ch 11                     ████████████████████

Best Practice: Only use 1, 6, or 11
```

### 5 GHz Channels

**No DFS Required (Preferred):**
- 36, 40, 44, 48 (U-NII-1)
- 149, 153, 157, 161, 165 (U-NII-3)

**DFS Required:**
- 52-64 (U-NII-2A)
- 100-144 (U-NII-2C)

## 802.11 Frame Types

### Management Frames

| Frame Type | Purpose | Security Relevance |
|------------|---------|-------------------|
| Beacon | AP presence announcement | Network discovery |
| Probe Request | Client network search | Client enumeration |
| Probe Response | AP reply to probe | Information disclosure |
| Authentication | Begin connection | Open or SAE |
| Association | Complete connection | Device linking |
| **Deauthentication** | Force disconnect | **Attack vector!** |
| Disassociation | Clean disconnect | Network disruption |

### Control Frames

| Frame Type | Purpose |
|------------|---------|
| RTS | Request to Send |
| CTS | Clear to Send |
| ACK | Acknowledgment |

### Data Frames

- Carry actual network payload
- Encrypted if WPA/WPA2/WPA3 enabled
- Contains source/destination addresses

## Signal Strength Guide

### RSSI (dBm) Interpretation

| dBm Range | Quality | Usability |
|-----------|---------|-----------|
| -30 to -50 | Excellent | Max performance |
| -50 to -60 | Good | Reliable streaming |
| -60 to -70 | Fair | Web/email OK |
| -70 to -80 | Poor | Slow, intermittent |
| -80 to -90 | Very Poor | Barely usable |
| < -90 | None | Disconnected |

### Signal Loss Through Materials

| Material | Typical Loss |
|----------|-------------|
| Glass | 2-3 dB |
| Drywall | 3-4 dB |
| Wood | 4-6 dB |
| Brick | 6-8 dB |
| Concrete | 10-15 dB |
| Metal | 20+ dB |

## Key Technologies

### MIMO (Multiple Input Multiple Output)
- Multiple antennas for increased throughput
- Notation: TxR (e.g., 4x4 = 4 transmit, 4 receive)
- Enables spatial multiplexing
- WiFi 4 introduced, enhanced in 5/6

### MU-MIMO (Multi-User MIMO)
- Serve multiple clients simultaneously
- Reduces waiting time
- WiFi 5/6 feature
- Requires compatible clients

### OFDMA (Orthogonal Frequency Division Multiple Access)
- Divides channel into subcarriers
- Multiple clients on single channel
- WiFi 6 feature
- Improves dense environment performance

### Beamforming
- Focuses signal toward client
- Improves range and reliability
- Standard in WiFi 5/6
- Requires compatible hardware

## Security Quick Reference

| Protocol | Status | Key Facts |
|----------|--------|-----------|
| Open | Insecure | No encryption |
| WEP | Broken | Never use, easily cracked |
| WPA | Deprecated | TKIP vulnerable |
| WPA2 | Standard | AES-CCMP, vulnerable to KRACK |
| WPA3 | Current | SAE, forward secrecy |

## Common Commands (Linux)

```bash
# View wireless interfaces
iwconfig

# See detailed interface info
iw dev

# List supported modes
iw list | grep -A 10 "Supported interface modes"

# Check current channel
iw dev wlan0 info

# Scan for networks
sudo iw dev wlan0 scan | grep -E "SSID|signal|freq"

# Check driver in use
lspci -k | grep -A 3 -i network
# or for USB:
lsusb
```

## Study Checklist

Before moving to the next lab, ensure you can:

- [ ] List all 802.11 standards and their key characteristics
- [ ] Explain the difference between 2.4 GHz and 5 GHz bands
- [ ] Identify non-overlapping channels in 2.4 GHz
- [ ] Define SSID, BSSID, ESSID
- [ ] Explain the difference between Infrastructure and Ad-Hoc modes
- [ ] List the three main frame types
- [ ] Explain why deauthentication frames are a security concern
- [ ] Interpret RSSI values
- [ ] Describe what MIMO and MU-MIMO accomplish

## Practice Questions

1. A client is connected at -75 dBm. What quality is this?
2. How many non-overlapping channels exist in 2.4 GHz?
3. Which 802.11 standard introduced OFDMA?
4. What is the BSSID of an access point?
5. What type of frame does an AP use to announce itself?

<details>
<summary>Answers</summary>

1. Fair/Poor - usable but may experience issues
2. 3 (Channels 1, 6, 11 in US)
3. 802.11ax (WiFi 6)
4. The MAC address of the access point
5. Beacon frame

</details>

## Additional Resources

- [IEEE 802.11 Working Group](https://www.ieee802.org/11/)
- [WiFi Alliance](https://www.wi-fi.org/)
- [Wireless LAN Professionals](https://www.wlanpros.com/)
- [Revolution WiFi](https://www.revolutionwifi.net/)

---

**Next:** [02 - WiFi Security Protocols](../02-wifi-security-protocols/)
