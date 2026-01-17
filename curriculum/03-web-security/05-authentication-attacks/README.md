# Authentication Attacks Labs

Master authentication attacks from brute force to session hijacking and password reset vulnerabilities.

## What are Authentication Attacks?

Authentication attacks target the mechanisms that verify user identity. When authentication is poorly implemented, attackers can bypass login controls, hijack sessions, or impersonate legitimate users.

Authentication attacks can lead to:
- Unauthorized access to user accounts
- Privilege escalation to admin accounts
- Session hijacking and impersonation
- Data theft and privacy breaches
- Account takeover (ATO)
- Lateral movement within applications

## Types of Authentication Attacks

### 1. Brute Force Attacks
Systematically trying all possible passwords until finding the correct one.

### 2. Credential Stuffing
Using leaked username/password pairs from data breaches against other sites.

### 3. Password Spraying
Trying a few common passwords against many usernames to avoid lockouts.

### 4. Session Attacks
- **Session Hijacking** - Stealing valid session tokens
- **Session Fixation** - Forcing users to use attacker-controlled sessions
- **Session Prediction** - Guessing valid session IDs

### 5. Password Reset Flaws
Exploiting weak password reset mechanisms to gain access.

### 6. Multi-Factor Authentication Bypass
Circumventing 2FA through various techniques.

## Lab Series

### Lab 1: Brute Force Login
**Difficulty:** Beginner | **Duration:** 30 min | **Target:** DVWA

Learn the fundamentals:
- Manual brute force testing
- Using Burp Suite Intruder
- Hydra for automated attacks
- Understanding rate limiting

### Lab 2: Credential Stuffing
**Difficulty:** Intermediate | **Duration:** 45 min | **Target:** Juice Shop

Using leaked credentials:
- Loading credential lists
- Automating login attempts
- Identifying successful logins
- Bypass techniques

### Lab 3: Password Spraying
**Difficulty:** Intermediate | **Duration:** 30 min | **Target:** Multiple

Avoiding account lockouts:
- Common password lists
- Username enumeration first
- Timing attacks between attempts
- Distributed attacks

### Lab 4: Session Hijacking
**Difficulty:** Intermediate | **Duration:** 1 hr | **Target:** DVWA, bWAPP

Stealing sessions:
- Cookie theft via XSS
- Network sniffing (unencrypted)
- Session ID in URL
- Predictable session tokens

### Lab 5: Session Fixation
**Difficulty:** Advanced | **Duration:** 45 min | **Target:** bWAPP

Forcing sessions:
- Setting session before login
- Exploiting session regeneration flaws
- URL-based session fixation

### Lab 6: Password Reset Attacks
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Juice Shop, WebGoat

Exploiting reset flows:
- Token manipulation
- Host header injection
- Rate limiting bypass
- Predictable tokens

### Lab 7: JWT Attacks
**Difficulty:** Advanced | **Duration:** 1.5 hrs | **Target:** Juice Shop

JSON Web Token exploitation:
- None algorithm attack
- Weak secret cracking
- Key confusion attacks
- Token manipulation

## Tools

```bash
# Hydra - Brute force tool
hydra -l admin -P passwords.txt http-post-form "target.com/login:user=^USER^&pass=^PASS^:Invalid"

# Burp Suite Intruder - GUI-based brute forcing

# ffuf - Fast fuzzer
ffuf -w passwords.txt -u http://target.com/login -X POST -d "user=admin&pass=FUZZ" -fc 401

# John the Ripper - Password cracking
john --wordlist=passwords.txt hashes.txt

# Hashcat - GPU password cracking
hashcat -m 0 -a 0 hashes.txt wordlist.txt
```

## Common Default Credentials

| Application | Username | Password |
|-------------|----------|----------|
| DVWA | admin | password |
| bWAPP | bee | bug |
| WordPress | admin | admin |
| Tomcat | admin | admin |
| phpMyAdmin | root | (empty) |
| Jenkins | admin | admin |
| Grafana | admin | admin |

## Session Token Analysis

### Weak Session IDs

```
# Sequential
session=1
session=2
session=3

# Time-based
session=1609459200
session=1609459201

# Predictable patterns
session=user123_session
session=admin_20210101

# Base64 encoded user data
session=YWRtaW46MTIzNDU2  # admin:123456
```

### Strong Session IDs

```
# Random, high entropy
session=7f3d9a2e8c4b1f6d5a0e3c8b
session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Common Vulnerabilities

### Username Enumeration

```
# Different error messages
"Invalid username" vs "Invalid password"

# Response time differences
Valid user: 500ms response
Invalid user: 50ms response

# Account lockout behavior
Lockout for valid usernames only
```

### Rate Limiting Bypass

```
# Header manipulation
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1

# Case manipulation
admin vs Admin vs ADMIN

# Adding extra parameters
username=admin&username=test
```

## Defense Techniques (Know Your Enemy)

Understanding defenses helps craft better attacks:

1. **Account Lockout** - Lock after N failed attempts
2. **Rate Limiting** - Limit requests per time period
3. **CAPTCHA** - Challenge-response tests
4. **MFA** - Additional authentication factors
5. **Secure Session Management** - Random tokens, regeneration
6. **Password Policies** - Complexity requirements

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 - Brute Force | `FLAG{brut3_f0rc3_succ3ss}` |
| Lab 2 - Credential Stuffing | `FLAG{cr3d_stuff1ng_pwn}` |
| Lab 3 - Password Spraying | `FLAG{spr4y_4nd_pr4y}` |
| Lab 4 - Session Hijacking | `FLAG{s3ss10n_h1j4ck3d}` |
| Lab 5 - Session Fixation | `FLAG{s3ss10n_f1x4t10n}` |
| Lab 6 - Password Reset | `FLAG{p4ssw0rd_r3s3t_pwn}` |
| Lab 7 - JWT Attacks | `FLAG{jwt_n0n3_4lg0r1thm}` |

## OWASP References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)

## Additional Resources

- [PortSwigger Authentication](https://portswigger.net/web-security/authentication)
- [PayloadsAllTheThings Authentication Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass)
- [HackTricks Authentication](https://book.hacktricks.xyz/pentesting-web/login-bypass)
- [SecLists Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
