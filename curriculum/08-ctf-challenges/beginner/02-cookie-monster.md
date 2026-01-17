# Challenge 02 - Cookie Monster

**Category:** Web
**Difficulty:** Beginner
**Points:** 100
**Target:** DVWA (http://localhost:8081)

## Challenge Description

The Cookie Monster is hungry for flags! This web application stores sensitive information in browser cookies. Your mission is to find and decode the hidden flag.

Remember: Cookies are just text stored in your browser - nothing is truly hidden there!

## Objectives

- Understand how cookies work
- Inspect browser cookies
- Decode encoded cookie values
- Extract the flag

## Target Information

- **URL:** http://localhost:8081
- **Credentials:** admin / password
- **Security Level:** Low

## Getting Started

1. Ensure DVWA is running:
   ```bash
   cd docker && docker-compose up -d dvwa
   ```

2. Navigate to http://localhost:8081
3. Login with the provided credentials
4. Inspect the cookies stored by the application

---

## Hints

<details>
<summary>Hint 1 (Cost: -10 points)</summary>

Use your browser's Developer Tools (F12) to inspect cookies. Look for the Application or Storage tab.

</details>

<details>
<summary>Hint 2 (Cost: -20 points)</summary>

One of the cookie values looks like it might be encoded. Base64 is a common encoding method for cookie data.

</details>

<details>
<summary>Hint 3 (Cost: -30 points)</summary>

Look for a cookie named `secret_flag` or similar. Decode its Base64 value using:
```bash
echo "encoded_value" | base64 -d
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Login to DVWA

Navigate to http://localhost:8081 and login with admin:password.

### Step 2: Open Developer Tools

Press F12 to open Developer Tools, then:
- **Chrome/Edge:** Go to Application > Cookies
- **Firefox:** Go to Storage > Cookies

### Step 3: Examine Cookies

Look through the cookies set by localhost:8081. You'll find several cookies including:
- PHPSESSID (session identifier)
- security (DVWA security level)
- ctf_flag (suspicious!)

### Step 4: Decode the Flag

The `ctf_flag` cookie contains: `RkxBR3tjMDBrMTNzX2FyM19kM2wxYzEwdXN9`

Decode it:
```bash
echo "RkxBR3tjMDBrMTNzX2FyM19kM2wxYzEwdXN9" | base64 -d
```

Output: `FLAG{c00k13s_ar3_d3l1c10us}`

### Alternative Method: Using JavaScript

In the browser console (F12 > Console):
```javascript
// View all cookies
console.log(document.cookie);

// Decode Base64
atob("RkxBR3tjMDBrMTNzX2FyM19kM2wxYzEwdXN9");
```

### Understanding the Vulnerability

This demonstrates several cookie-related security issues:
- **Storing sensitive data in cookies** - Cookies are client-side and easily readable
- **Weak encoding** - Base64 is NOT encryption, just encoding
- **Missing HttpOnly flag** - Allows JavaScript access to cookies

### Prevention

- Never store sensitive data in cookies
- Use HttpOnly and Secure flags
- Implement proper session management
- If encoding is needed, use encryption instead

</details>

---

## Flag

```
FLAG{c00k13s_ar3_d3l1c10us}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Browser Developer Tools usage
- Cookie inspection
- Base64 decoding
- Client-side data analysis

## Tools Used

- Browser Developer Tools
- base64 command line utility
- JavaScript console

## Related Challenges

- [01 - Hidden in Plain Sight](01-hidden-in-plain-sight.md) - Source code analysis
- [03 - Decode Me](03-decode-me.md) - More encoding challenges

## References

- [MDN - HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [OWASP - Testing for Cookies](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
