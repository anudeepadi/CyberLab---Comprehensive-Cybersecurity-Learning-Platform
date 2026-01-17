# Lab 03: Wireless Reconnaissance - Hints

Progressive hints to help you complete the lab without giving away the full solution.

```
+===============================================================+
|                        HINT GUIDE                              |
+===============================================================+
|  Start with Hint Level 1. Only proceed if still stuck.        |
|  Challenge yourself - learning happens through struggle!       |
+===============================================================+
```

## Legal Reminder

```
+=====================================================================+
|                         LEGAL WARNING                                |
+=====================================================================+
|  Only perform wireless reconnaissance on networks you OWN or have   |
|  EXPLICIT WRITTEN PERMISSION to test. Unauthorized monitoring of    |
|  wireless networks is illegal in most jurisdictions.                |
+=====================================================================+
```

---

## Exercise 1: Basic Discovery

### Task
Put your adapter in monitor mode and discover all networks in range.

### Hint Level 1 - Conceptual
You need to change your wireless interface from "managed" mode (normal operation) to "monitor" mode (passive listening). The aircrack-ng suite has a tool specifically for this.

### Hint Level 2 - Tool Name
The tool you need is `airmon-ng`. It manages interface modes for the aircrack-ng suite.

### Hint Level 3 - Process
1. First, some processes interfere with monitor mode
2. You need to stop these processes
3. Then enable monitor mode on your interface
4. Finally, use a scanning tool to discover networks

### Hint Level 4 - Commands Structure
```bash
# Step 1: Check what might interfere
sudo airmon-ng ____

# Step 2: Stop interfering processes
sudo airmon-ng ____ ____

# Step 3: Enable monitor mode
sudo airmon-ng ____ wlan0

# Step 4: Scan networks
sudo airodump-ng ________
```

### Hint Level 5 - Specific Commands
```bash
sudo airmon-ng check
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
```

---

## Exercise 2: Client Enumeration

### Task
Target your test network and identify all connected clients.

### Hint Level 1 - Conceptual
Instead of scanning all channels and networks, you need to focus on a single network. This requires knowing the channel and BSSID.

### Hint Level 2 - Information Needed
From your Exercise 1 scan, you should have noted:
- The BSSID (MAC address of the access point)
- The channel the network operates on

### Hint Level 3 - Airodump-ng Options
`airodump-ng` has options to filter by:
- `-c` : Channel number
- `--bssid` : Access point MAC address
- `-w` : Write output to file

### Hint Level 4 - Command Structure
```bash
sudo airodump-ng -c [CHANNEL] --bssid [AP_MAC_ADDRESS] [INTERFACE]
```

### Hint Level 5 - Example Command
```bash
# Replace with your network's values
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon
```

---

## Exercise 3: Capture and Analysis

### Task
Capture traffic for 5 minutes and analyze it in Wireshark.

### Hint Level 1 - Conceptual
You need to save the captured packets to a file that Wireshark can read. The capture format used by airodump-ng is compatible with Wireshark.

### Hint Level 2 - File Output
The `-w` option in airodump-ng specifies the output filename prefix. Multiple files will be created with different extensions.

### Hint Level 3 - Capture Command
```bash
sudo airodump-ng -c [CHANNEL] --bssid [BSSID] -w [PREFIX] [INTERFACE]
```

### Hint Level 4 - Wireshark Filters
To find specific frame types in Wireshark:
- Beacon frames: `wlan.fc.type_subtype == 0x08`
- Probe requests: `wlan.fc.type_subtype == 0x04`
- Data frames: `wlan.fc.type == 2`

### Hint Level 5 - Complete Process
```bash
# Capture traffic
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Wait 5 minutes, then Ctrl+C

# Open in Wireshark
wireshark capture-01.cap
```

---

## Understanding Airodump-ng Output

### Hint: Column Meanings

**If you're confused about the output columns:**

| Column | Description |
|--------|-------------|
| BSSID | MAC address of access point |
| PWR | Signal strength (closer to 0 is stronger) |
| CH | Channel number |
| ENC | Encryption type (WPA2, WEP, OPN) |
| ESSID | Network name (SSID) |
| STATION | Client MAC address |

### Hint: Signal Strength
- -30 to -50 dBm = Excellent (very close)
- -50 to -60 dBm = Good
- -60 to -70 dBm = Fair
- -70 to -80 dBm = Weak
- Below -80 dBm = Very weak

---

## Common Issues

### Issue: "Monitor mode not supported"

**Hint Level 1:** Not all wireless adapters support monitor mode. Check if yours does.

**Hint Level 2:** Use `iw list | grep -A 10 "Supported interface modes"` to verify.

**Hint Level 3:** If monitor mode isn't listed, you need a different adapter (see README for recommendations).

### Issue: "No networks showing"

**Hint Level 1:** The adapter might not be scanning the right frequencies.

**Hint Level 2:** Try different bands: `--band g` for 2.4GHz, `--band a` for 5GHz.

**Hint Level 3:** Check if the antenna is properly connected to your adapter.

### Issue: "Interface disappeared"

**Hint Level 1:** The interface name changes when entering monitor mode.

**Hint Level 2:** After `airmon-ng start wlan0`, your interface becomes `wlan0mon`.

**Hint Level 3:** Run `iwconfig` to see current interface names.

---

## Knowledge Check Hints

### Question 1: What command enables monitor mode on wlan0?

**Hint:** It's an airmon-ng command with 'start' and the interface name.

### Question 2: What does PWR column represent?

**Hint:** It's measured in dBm and relates to how strong the received signal is.

### Question 3: How to filter for WPA2 networks only?

**Hint:** airodump-ng has an `--encrypt` option.

### Question 4: What do "Probes" reveal?

**Hint:** Think about what a device does when searching for known networks.

### Question 5: Why is channel hopping important?

**Hint:** Networks can operate on different channels (1-14 for 2.4GHz, 36-165 for 5GHz).

---

## Hardware Troubleshooting Hints

### USB Adapter Not Recognized

1. **Check USB connection:** Try different USB ports
2. **Check power:** Some adapters need USB 3.0 for power
3. **Check drivers:** `dmesg | tail -20` after plugging in

### Monitor Mode Fails

1. **Kill NetworkManager first:** `sudo airmon-ng check kill`
2. **Try manual method:**
   ```bash
   sudo ip link set wlan0 down
   sudo iw wlan0 set monitor control
   sudo ip link set wlan0 up
   ```

### Weak Signal

1. **Check antenna:** Is it screwed on properly?
2. **Position:** Move closer to target AP
3. **Interference:** Move away from other electronic devices

---

## Quick Reference Card

```bash
# Interface Status
iwconfig
iw dev

# Enable Monitor Mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Scan Networks
sudo airodump-ng wlan0mon               # All channels
sudo airodump-ng --band abg wlan0mon    # All bands
sudo airodump-ng -c 6 wlan0mon          # Specific channel

# Target Network
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon

# Save Capture
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Restore Managed Mode
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

---

## Still Stuck?

If you've worked through all the hints and are still having trouble:

1. **Review Prerequisites:** Make sure you have a compatible adapter
2. **Check Lab 01 & 02:** Ensure you understand wireless fundamentals
3. **Lab Environment:** Consider using simulated radios for testing commands
4. **Consult Walkthrough:** Use walkthrough.md as a last resort

Remember: The goal is learning, not just completion. Take your time to understand each step.

---

**Flag Location:** Complete all exercises to find: `FLAG{41r0dump_r3c0n}`
