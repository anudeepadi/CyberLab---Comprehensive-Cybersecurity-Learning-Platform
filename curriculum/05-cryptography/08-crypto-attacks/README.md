# Lab 08 - Crypto Attacks

Master advanced attacks on cryptographic implementations and weak algorithms.

## Overview

**Difficulty:** Advanced
**Duration:** 2.5 hours
**Category:** Cryptographic Attacks
**Flag:** `FLAG{crypt0_br34k3r}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Exploit padding oracle vulnerabilities
2. Perform bit-flipping attacks on CBC mode
3. Attack weak RSA implementations
4. Exploit nonce reuse in stream ciphers
5. Understand timing attacks
6. Identify and exploit weak PRNGs

## Attack Categories

```
CRYPTOGRAPHIC ATTACKS

┌──────────────────────────────────────────────────────────────────┐
│ Implementation Attacks     │ Algorithm Attacks                   │
├────────────────────────────┼─────────────────────────────────────┤
│ • Padding Oracle           │ • Weak key attacks                  │
│ • Timing Attacks           │ • Small exponent (RSA)              │
│ • Side-channel             │ • Factorization                     │
│ • Nonce/IV reuse           │ • Hash collisions                   │
│ • Key management flaws     │ • Length extension                  │
└────────────────────────────┴─────────────────────────────────────┘
```

## 1. Padding Oracle Attack

### The Vulnerability

When a system reveals whether decrypted data has valid padding:

```
              PADDING ORACLE ATTACK

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Attacker   │ --> │   Server    │ --> │  Response   │
│ (Modified   │     │ (Decrypts)  │     │             │
│  Ciphertext)│     └─────────────┘     │ "Valid" or  │
└─────────────┘                         │ "Invalid"   │
                                        └─────────────┘

Server responses leak information about plaintext!
```

### PKCS#7 Padding

```
Block size: 16 bytes

If plaintext ends at:
- Byte 15: Add \x01
- Byte 14: Add \x02\x02
- Byte 13: Add \x03\x03\x03
...
- Byte 1:  Add \x0f (15 times)
- Byte 0:  Add \x10 (16 times) - full padding block

Valid: "HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
Invalid: "HELLO\x0b\x0b\x0b\x0b\x05\x0b\x0b\x0b\x0b\x0b\x0b"
```

### Attack Process

```
CBC Decryption: P[i] = Decrypt(C[i]) XOR C[i-1]

To find P[n] (last byte of plaintext block):
1. Modify C[i-1] to get valid padding \x01
2. Try all 256 values for last byte of C[i-1]
3. When padding valid: we found Decrypt(C[i])[n] XOR modified_byte = 0x01
4. Therefore: Decrypt(C[i])[n] = modified_byte XOR 0x01
5. Original plaintext: P[n] = Decrypt(C[i])[n] XOR original_C[i-1][n]
```

### Python Implementation

```python
#!/usr/bin/env python3
"""Padding Oracle Attack Implementation"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# ============================================================================
# VULNERABLE SERVER SIMULATION
# ============================================================================

class VulnerableOracle:
    def __init__(self):
        self.key = os.urandom(16)

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), 16))
        return iv + ciphertext

    def check_padding(self, data):
        """VULNERABLE: Returns True/False based on padding validity"""
        iv = data[:16]
        ciphertext = data[16:]
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            unpad(decrypted, 16)
            return True
        except ValueError:
            return False

# ============================================================================
# PADDING ORACLE ATTACK
# ============================================================================

def padding_oracle_attack(oracle, ciphertext):
    """Decrypt ciphertext using padding oracle"""
    block_size = 16
    iv = ciphertext[:block_size]
    ct_blocks = [ciphertext[i:i+block_size]
                 for i in range(block_size, len(ciphertext), block_size)]

    plaintext = b''

    # Process each block
    for block_idx, ct_block in enumerate(ct_blocks):
        prev_block = iv if block_idx == 0 else ct_blocks[block_idx - 1]
        decrypted_block = bytearray(16)
        intermediate = bytearray(16)

        # Decrypt each byte (from last to first)
        for byte_idx in range(15, -1, -1):
            padding_value = 16 - byte_idx

            # Create attack IV with known intermediate values
            attack_iv = bytearray(16)
            for i in range(byte_idx + 1, 16):
                attack_iv[i] = intermediate[i] ^ padding_value

            # Brute force current byte
            for guess in range(256):
                attack_iv[byte_idx] = guess
                test_data = bytes(attack_iv) + ct_block

                if oracle.check_padding(test_data):
                    # Handle edge case for first byte found
                    if byte_idx == 15:
                        # Verify it's not coincidental padding
                        attack_iv[14] ^= 1
                        if not oracle.check_padding(bytes(attack_iv) + ct_block):
                            attack_iv[14] ^= 1
                            continue

                    intermediate[byte_idx] = guess ^ padding_value
                    decrypted_block[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx]
                    break

        plaintext += bytes(decrypted_block)
        print(f"Block {block_idx}: {bytes(decrypted_block)}")

    # Remove padding
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]

# Example usage
if __name__ == "__main__":
    oracle = VulnerableOracle()
    secret = "The password is: FLAG{crypt0_br34k3r}"
    ciphertext = oracle.encrypt(secret)

    print("Attacking padding oracle...")
    recovered = padding_oracle_attack(oracle, ciphertext)
    print(f"\nRecovered: {recovered.decode()}")
```

## 2. CBC Bit-Flipping Attack

### The Vulnerability

Modifying ciphertext changes predictable bits in next plaintext block:

```
CBC Decryption:
P[i] = Decrypt(C[i]) XOR C[i-1]

If we flip bit X in C[i-1]:
- Block i-1 becomes garbage
- Block i has bit X flipped in plaintext!
```

### Attack Scenario

```
Original: "admin=false;role=user"
Goal:     "admin=true;role=user"
                   ^
                   Change 'f' to 't'

If this is in block 2, modify corresponding byte in C[1]:
C[1][6] ^= ord('f') ^ ord('t')
```

### Python Implementation

```python
#!/usr/bin/env python3
"""CBC Bit-Flipping Attack"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def cbc_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext.encode(), 16))

def cbc_decrypt(key, data):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

def bit_flip_attack(ciphertext, position, old_byte, new_byte):
    """Flip a byte in the plaintext by modifying ciphertext"""
    ct = bytearray(ciphertext)

    # Target is in block N, modify block N-1
    # Position 0-15 in block 0 -> modify IV
    # Position 16-31 in block 1 -> modify block 0
    block_num = position // 16
    byte_in_block = position % 16

    # Modify the previous block (or IV for block 0)
    modify_pos = block_num * 16 + byte_in_block
    ct[modify_pos] ^= ord(old_byte) ^ ord(new_byte)

    return bytes(ct)

# Example
key = os.urandom(16)
plaintext = "comment=hello;admin=false;uid=1"

print(f"Original: {plaintext}")
ciphertext = cbc_encrypt(key, plaintext)

# Find position of 'f' in "false" (position depends on padding/alignment)
# "admin=false" - the 'f' is at position that we need to calculate
target_pos = plaintext.find("admin=") + len("admin=")  # Position of 'f'

# Flip 'f' to 't'
modified = bit_flip_attack(ciphertext, target_pos, 'f', 't')

try:
    result = cbc_decrypt(key, modified)
    print(f"Modified: {result}")
except:
    print("Decryption failed (expected - previous block corrupted)")
```

## 3. RSA Attacks

### Small Public Exponent Attack

When e=3 and m^3 < n:

```python
import gmpy2

def small_e_attack(ciphertext, e, n):
    """When m^e < n, ciphertext = m^e (no mod)"""
    root, exact = gmpy2.iroot(ciphertext, e)
    if exact:
        return int(root)
    return None

# Example
e = 3
n = 10**100  # Large n
m = 10**20   # Small message
c = pow(m, e)  # m^3 < n, so c = m^3 exactly

recovered = small_e_attack(c, e, n)
print(f"Recovered: {recovered}")
```

### Hastad's Broadcast Attack

Same message sent to e or more recipients:

```python
from functools import reduce

def chinese_remainder_theorem(remainders, moduli):
    """Solve system of congruences"""
    total = 0
    prod = reduce(lambda a, b: a * b, moduli)

    for r, m in zip(remainders, moduli):
        p = prod // m
        total += r * modinv(p, m) * p

    return total % prod

def modinv(a, m):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m

def hastad_broadcast_attack(ciphertexts, moduli, e=3):
    """Attack when same message encrypted for e recipients"""
    # Use CRT to find m^e
    m_pow_e = chinese_remainder_theorem(ciphertexts, moduli)

    # Take e-th root
    import gmpy2
    m, exact = gmpy2.iroot(m_pow_e, e)

    if exact:
        return int(m)
    return None
```

### Wiener's Attack (Small d)

When d < n^0.25 / 3:

```python
# pip install owiener
import owiener

def wiener_attack(e, n):
    """Attack RSA when d is small"""
    d = owiener.attack(e, n)
    return d

# Example vulnerable key
# e is unusually large, d is small
e = 17993...  # Large e
n = 12345...  # n

d = wiener_attack(e, n)
if d:
    print(f"Found private exponent: {d}")
```

### Common Modulus Attack

Same n, different e values:

```python
def common_modulus_attack(c1, c2, e1, e2, n):
    """Attack when same n used with different e"""
    from math import gcd

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        return None  # Not coprime

    # m = c1^a * c2^b mod n
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

## 4. Stream Cipher Attacks

### Nonce Reuse (Two-Time Pad)

```
CTR/OFB mode: C = P XOR Keystream

If same keystream used twice:
C1 = P1 XOR K
C2 = P2 XOR K

Then: C1 XOR C2 = P1 XOR P2

Known P1 -> recover P2!
```

### Python Implementation

```python
def nonce_reuse_attack(c1, c2, known_p1):
    """Exploit nonce reuse to recover plaintext"""
    # XOR ciphertexts
    xored = bytes(a ^ b for a, b in zip(c1, c2))

    # XOR with known plaintext
    recovered = bytes(a ^ b for a, b in zip(xored, known_p1))

    return recovered

# Example
key = os.urandom(16)
nonce = os.urandom(16)  # REUSED - BAD!

from Crypto.Cipher import AES
cipher1 = AES.new(key, AES.MODE_CTR, nonce=nonce)
cipher2 = AES.new(key, AES.MODE_CTR, nonce=nonce)  # Same nonce!

p1 = b"attack at dawn!!"
p2 = b"defend the fort!"

c1 = cipher1.encrypt(p1)
c2 = cipher2.encrypt(p2)

# Attack
recovered = nonce_reuse_attack(c1, c2, p1)
print(f"Recovered P2: {recovered}")
```

## 5. Timing Attacks

### Vulnerable Comparison

```python
# VULNERABLE - early exit reveals information
def vulnerable_compare(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Exits immediately on mismatch!
    return True

# SECURE - constant time
import hmac
def secure_compare(a, b):
    return hmac.compare_digest(a, b)
```

### Timing Attack Example

```python
import time

def timing_attack(oracle_func, known_prefix, charset, length):
    """Recover secret by measuring response time"""
    secret = known_prefix

    while len(secret) < length:
        best_time = 0
        best_char = None

        for char in charset:
            guess = secret + char
            start = time.perf_counter_ns()
            oracle_func(guess)
            elapsed = time.perf_counter_ns() - start

            if elapsed > best_time:
                best_time = elapsed
                best_char = char

        secret += best_char
        print(f"Found: {secret}")

    return secret
```

## 6. Weak PRNG Attacks

### Predictable Random

```python
import random
import time

def predict_random():
    """If seed is based on time, we can predict"""
    # Attacker knows approximate time
    for seed in range(int(time.time()) - 10, int(time.time()) + 10):
        random.seed(seed)
        predicted = random.randint(0, 2**32)
        # Check if prediction matches observed value
        # ...
```

### MT19937 State Recovery

```python
# With 624 consecutive outputs, can recover full MT19937 state
# Use libraries like randcrack

# pip install randcrack
from randcrack import RandCrack

def crack_mt19937(outputs):
    """Recover state from 624 outputs"""
    rc = RandCrack()
    for output in outputs[:624]:
        rc.submit(output)

    # Now can predict future values
    return rc.predict_getrandbits(32)
```

## CTF Challenges

### Challenge 1: Padding Oracle

Exploit the padding oracle to decrypt the secret message.

### Challenge 2: CBC Bit Flip

Change "role=user" to "role=admin" using bit-flipping.

### Challenge 3: RSA e=3

Decrypt a message encrypted with e=3 where m^3 < n.

### Challenge 4: Nonce Reuse

Two messages encrypted with the same nonce. Recover the second message.

### Challenge 5: Weak PRNG

The server uses `random.randint()` seeded with current timestamp.

## OpenSSL Forensics

### Analyze RSA Keys

```bash
# View RSA key details
openssl rsa -in key.pem -text -noout

# Check for weak keys
openssl rsa -in key.pem -text -noout | grep "Public-Exponent"
# Look for e=3, small modulus, etc.

# Factor small modulus
factor $(openssl rsa -in key.pem -noout -modulus | cut -d= -f2)
```

### Detect Weak Ciphers

```bash
# Check cipher suites
openssl ciphers -v

# Test server for weak ciphers
openssl s_client -connect target:443 -cipher 'EXPORT'
nmap --script ssl-enum-ciphers -p 443 target
```

## Tasks

- [ ] Implement and exploit a padding oracle
- [ ] Perform a CBC bit-flipping attack
- [ ] Attack RSA with small public exponent
- [ ] Exploit nonce reuse in CTR mode
- [ ] Understand timing attack principles
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{crypt0_br34k3r}`

## Tools

| Tool | Purpose |
|------|---------|
| PadBuster | Automated padding oracle attacks |
| RsaCtfTool | Comprehensive RSA attack tool |
| featherduster | Cryptanalysis tool suite |
| xortool | XOR analysis and attacks |
| randcrack | MT19937 PRNG cracking |

## Best Practices (Defense)

1. **Use authenticated encryption** (AES-GCM, ChaCha20-Poly1305)
2. **Never reuse IVs/nonces**
3. **Use constant-time comparisons**
4. **Secure random number generators** (os.urandom, secrets)
5. **Proper padding validation** (don't reveal padding errors)
6. **Adequate key sizes** (RSA >= 2048, AES >= 128)

## References

- [Padding Oracle Attacks (Robert Heaton)](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
- [Twenty Years of RSA Attacks](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)
- [Cryptopals Challenges](https://cryptopals.com/)
- [PadBuster Tool](https://github.com/AonCyberLabs/PadBuster)
