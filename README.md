# DVWA Attack Payloads & Tools

Educational resources for practicing web application security with DVWA.

## 📚 Documentation

- **[QUICK-START.md](QUICK-START.md)** - One-page reference card (After git pull? Start here!)
- **[GETTING-STARTED.md](GETTING-STARTED.md)** - Complete walkthrough and guide
- **[NETWORK-LABS-GUIDE.md](NETWORK-LABS-GUIDE.md)** - Network analysis lab details
- **[DVWA_GUIDE.md](DVWA_GUIDE.md)** - Complete DVWA attack guide with concepts

## Quick Start

```bash
# Start DVWA
docker-compose -f docker/docker-compose.yml up -d

# Start payload server (for CSRF, RFI)
python3 -m http.server 9000
```

**DVWA Login:** http://localhost:8081 (admin:password)

## Labs & Payloads

| Lab | Files | URL |
|-----|-------|-----|
| Brute Force | `payloads/brute_force.txt` | /vulnerabilities/brute/ |
| Command Injection | `payloads/command_injection.txt` | /vulnerabilities/exec/ |
| CSRF | `csrf_attack.html`, `csrf_attack2.html` | /vulnerabilities/csrf/ |
| File Inclusion | `payloads/file_inclusion.txt` | /vulnerabilities/fi/ |
| File Upload | `shell.php`, `advanced_shell.php`, `shell.gif` | /vulnerabilities/upload/ |
| SQL Injection | `payloads/sql_injection.txt` | /vulnerabilities/sqli/ |
| SQL Injection (Blind) | `payloads/sql_injection_blind.txt` | /vulnerabilities/sqli_blind/ |
| XSS | `payloads/xss_payloads.txt`, `xss_cookie_stealer.html` | /vulnerabilities/xss_* |

## Shell Usage

After uploading `shell.php`:
```
http://localhost:8081/hackable/uploads/shell.php?cmd=whoami
http://localhost:8081/hackable/uploads/shell.php?cmd=cat /etc/passwd
```

## Target Systems

| Service | Port | Credentials | Purpose |
|---------|------|-------------|---------|
| **DVWA** | 8081 | admin:password | Web vulnerabilities (beginner) |
| **Juice Shop** | 8082 | - | Modern OWASP challenges |
| **WebGoat** | 8083 | - | Guided web security |
| **bWAPP** | 8084 | bee:bug | 100+ web vulnerabilities |
| **Mutillidae** | 8085 | - | OWASP testing |
| **MySQL** | 3307 | admin:admin123 | SQL injection practice |
| **PostgreSQL** | 5433 | postgres:postgres | Database attacks |
| **Redis** | 6380 | (no auth) | Unauthorized access |
| **MongoDB** | 27018 | (no auth) | NoSQL injection |
| **SSH** | 2222 | admin:admin | Weak credentials |
| **FTP** | 2121 | anonymous | Directory traversal |
| **Buffer Overflow** | 9999 | - | Binary exploitation |

## Learning Modules (52 Labs Total)

### Module 01: Foundations (5 labs - Beginner)
- Linux basics, command line mastery, networking fundamentals, security tools, environment setup

### Module 02: Network Analysis (6 labs)
- Packet capture, traffic analysis, protocol analysis, network scanning, MITM attacks, Scapy

### Module 03: Web Application Security (8 labs)
- SQL Injection, XSS, CSRF, Command Injection, File Upload, Authentication, XXE, Deserialization

### Module 04: System Exploitation (6 labs)
- Enumeration, reverse shells, privilege escalation, buffer overflow, password attacks, post-exploitation

### Module 05: Cryptography (8 labs)
- Encoding, classical ciphers, symmetric/asymmetric encryption, hashing, hash cracking, steganography, crypto attacks

### Module 06: Wireless Security (8 labs)
- Wireless fundamentals, WiFi protocols, WEP/WPA cracking, deauth attacks, evil twin, Bluetooth

### Module 07: Active Directory (7 labs)
- AD fundamentals, enumeration, Kerberos attacks, credential attacks, delegation, domain dominance, persistence

### Module 08: CTF Challenges (4 labs)
- Mixed difficulty challenges across all domains

## Disclaimer

For educational purposes only. Only use on systems you own or have permission to test.
