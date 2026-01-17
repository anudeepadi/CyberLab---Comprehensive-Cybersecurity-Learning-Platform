# Lab 08 Walkthrough - Crypto Attacks

Step-by-step guide to exploiting cryptographic vulnerabilities.

## Setup

### Install Required Tools

```bash
# Python libraries
pip3 install pycryptodome gmpy2 owiener

# RsaCtfTool
git clone https://github.com/RsaCtfTool/RsaCtfTool
cd RsaCtfTool && pip install -r requirements.txt
```

### Create the Crypto Attack Toolkit

Save this as `crypto_attacks.py`:

```python
#!/usr/bin/env python3
"""Cryptographic Attack Toolkit for CyberLab"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import struct

# ============================================================================
# XOR UTILITIES
# ============================================================================

def xor_bytes(a, b):
    """XOR two byte sequences"""
    return bytes(x ^ y for x, y in zip(a, b))

def repeating_key_xor(data, key):
    """XOR with repeating key"""
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

# ============================================================================
# PADDING ORACLE UTILITIES
# ============================================================================

class PaddingOracle:
    """Simulated padding oracle for practice"""

    def __init__(self):
        self.key = os.urandom(16)

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        ct = cipher.encrypt(pad(plaintext, 16))
        return iv + ct

    def decrypt_check(self, data):
        """Returns True if padding valid"""
        try:
            iv = data[:16]
            ct = data[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            unpad(pt, 16)
            return True
        except:
            return False

def attack_padding_oracle_byte(oracle, block, prev_block, byte_pos, known_intermediate):
    """Attack single byte using padding oracle"""
    target_padding = 16 - byte_pos

    # Set up attack vector
    attack_block = bytearray(16)
    for i in range(byte_pos + 1, 16):
        attack_block[i] = known_intermediate[i] ^ target_padding

    # Brute force current byte
    for guess in range(256):
        attack_block[byte_pos] = guess
        test_data = bytes(attack_block) + block

        if oracle.decrypt_check(test_data):
            intermediate = guess ^ target_padding
            return intermediate

    return None

def attack_padding_oracle_block(oracle, block, prev_block):
    """Attack one block using padding oracle"""
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    for byte_pos in range(15, -1, -1):
        interm = attack_padding_oracle_byte(oracle, block, prev_block, byte_pos, intermediate)
        if interm is not None:
            intermediate[byte_pos] = interm
            plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
        else:
            print(f"Failed at byte {byte_pos}")

    return bytes(plaintext), bytes(intermediate)

# ============================================================================
# CBC BIT FLIP
# ============================================================================

def cbc_bit_flip(ciphertext, position, old_char, new_char):
    """Flip a character in CBC-encrypted plaintext"""
    ct = bytearray(ciphertext)

    # Target is in block N, we modify block N-1
    block_num = position // 16
    byte_in_block = position % 16

    # Modify position in previous block (or IV)
    modify_pos = block_num * 16 + byte_in_block

    ct[modify_pos] ^= ord(old_char) ^ ord(new_char)
    return bytes(ct)

# ============================================================================
# RSA UTILITIES
# ============================================================================

def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def modinv(a, m):
    """Modular multiplicative inverse"""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("No inverse")
    return (x % m + m) % m

def rsa_encrypt(m, e, n):
    """Raw RSA encryption"""
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    """Raw RSA decryption"""
    return pow(c, d, n)

def int_to_bytes(n):
    """Convert integer to bytes"""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bytes_to_int(b):
    """Convert bytes to integer"""
    return int.from_bytes(b, 'big')

# ============================================================================
# RSA ATTACKS
# ============================================================================

def small_e_attack(c, e):
    """Attack when m^e < n (no modular reduction)"""
    try:
        import gmpy2
        root, exact = gmpy2.iroot(c, e)
        if exact:
            return int(root)
    except ImportError:
        # Newton's method fallback
        if e == 3:
            x = c
            while True:
                x_new = (2*x + c // (x*x)) // 3
                if x_new >= x:
                    break
                x = x_new
            if x**3 == c:
                return x
    return None

def common_factor_attack(n1, n2):
    """Find common factor between two moduli"""
    from math import gcd
    p = gcd(n1, n2)
    if p > 1 and p != n1 and p != n2:
        return p, n1 // p, n2 // p
    return None

def fermat_factor(n, max_iterations=100000):
    """Fermat factorization for close primes"""
    import math
    a = math.isqrt(n)
    if a * a == n:
        return a, a

    for _ in range(max_iterations):
        a += 1
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b

    return None

def common_modulus_attack(c1, c2, e1, e2, n):
    """Attack when same message encrypted with different e"""
    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        return None

    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b

    return (pow(c1, a, n) * pow(c2, b, n)) % n

# ============================================================================
# STREAM CIPHER ATTACKS
# ============================================================================

def nonce_reuse_attack(c1, c2, known_p1):
    """Exploit CTR/OFB nonce reuse"""
    c1_xor_c2 = xor_bytes(c1, c2)
    p2 = xor_bytes(c1_xor_c2, known_p1)
    return p2

def crib_drag(xored_plaintexts, crib):
    """Try known word at each position"""
    if isinstance(crib, str):
        crib = crib.encode()

    results = []
    for i in range(len(xored_plaintexts) - len(crib) + 1):
        segment = xored_plaintexts[i:i+len(crib)]
        possible = xor_bytes(segment, crib)
        try:
            decoded = possible.decode('ascii')
            if all(c.isprintable() or c.isspace() for c in decoded):
                results.append((i, decoded))
        except:
            pass
    return results

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("Crypto Attack Toolkit")
    print("=" * 50)
    print("Padding Oracle:")
    print("  PaddingOracle(), attack_padding_oracle_block()")
    print("\nCBC Attacks:")
    print("  cbc_bit_flip(ct, pos, old, new)")
    print("\nRSA Attacks:")
    print("  small_e_attack(c, e)")
    print("  common_factor_attack(n1, n2)")
    print("  fermat_factor(n)")
    print("  common_modulus_attack(c1, c2, e1, e2, n)")
    print("\nStream Cipher:")
    print("  nonce_reuse_attack(c1, c2, p1)")
    print("  crib_drag(xored, crib)")
    print("=" * 50)
```

## Exercise 1: Padding Oracle Attack

### Step 1: Understand the Vulnerability

```python
from crypto_attacks import PaddingOracle

# Create oracle
oracle = PaddingOracle()

# Encrypt a message
secret = "The secret is: FLAG{crypt0_br34k3r}"
ciphertext = oracle.encrypt(secret)

print(f"Ciphertext length: {len(ciphertext)} bytes")
print(f"IV + 2 blocks of ciphertext")

# The oracle tells us if padding is valid
print(f"Original valid: {oracle.decrypt_check(ciphertext)}")

# Modify last byte - likely invalid padding
modified = bytearray(ciphertext)
modified[-1] ^= 1
print(f"Modified valid: {oracle.decrypt_check(bytes(modified))}")
```

### Step 2: Attack Single Byte

```python
from crypto_attacks import *

oracle = PaddingOracle()
ciphertext = oracle.encrypt("Test message!")

# Get blocks
iv = ciphertext[:16]
block1 = ciphertext[16:32]

print("Attacking last byte of first block...")

# Try to find byte that produces \x01 padding
for guess in range(256):
    attack_iv = bytearray(16)
    attack_iv[15] = guess
    test = bytes(attack_iv) + block1

    if oracle.decrypt_check(test):
        intermediate = guess ^ 0x01
        plaintext_byte = intermediate ^ iv[15]
        print(f"Found! Guess={guess}, Intermediate={intermediate}, Plaintext byte={plaintext_byte} ('{chr(plaintext_byte)}')")
        break
```

### Step 3: Full Block Attack

```python
from crypto_attacks import *

oracle = PaddingOracle()
secret = "FLAG{crypt0_br34k3r}"
ciphertext = oracle.encrypt(secret)

iv = ciphertext[:16]
ct_blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]

print(f"Blocks to decrypt: {len(ct_blocks)}")

# Attack first block
plaintext, intermediate = attack_padding_oracle_block(oracle, ct_blocks[0], iv)
print(f"Block 0 decrypted: {plaintext}")

# Attack remaining blocks
for i in range(1, len(ct_blocks)):
    pt, _ = attack_padding_oracle_block(oracle, ct_blocks[i], ct_blocks[i-1])
    plaintext += pt
    print(f"Block {i} decrypted: {pt}")

# Remove padding
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]
print(f"\nFull plaintext: {plaintext.decode()}")
```

## Exercise 2: CBC Bit-Flipping Attack

### Step 1: Create Vulnerable Application

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)

def encrypt_cookie(username):
    """Encrypt user cookie"""
    cookie = f"username={username};role=user;active=true"
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(cookie.encode(), 16))

def decrypt_cookie(data):
    """Decrypt and parse cookie"""
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cookie = unpad(cipher.decrypt(ct), 16).decode(errors='replace')
    print(f"Cookie: {cookie}")
    return "role=admin" in cookie

# Test
cookie = encrypt_cookie("guest")
print(f"Is admin: {decrypt_cookie(cookie)}")
```

### Step 2: Perform the Attack

```python
# The cookie looks like: username=guest;role=user;active=true
# We want to change 'user' to 'admin' (same length needed for simple attack)
# But 'user' is 4 chars and 'admin' is 5...
# Let's try: role=user -> role=admn (still won't work correctly)

# Better approach: make username end with 'X' and flip to ';role=admin'
# username=guestXXX;role=user;active=true
#                   ^ we want ;role=admin

# Let's carefully construct this
def exploit():
    # Create a username that aligns blocks nicely
    # Block 0 (IV): -
    # Block 1: username=guestXX
    # Block 2: X;role=user;acti
    # Block 3: ve=true\x09...(padding)

    # We want to change "user" in block 2
    # By flipping bits in block 1

    # Actually, let's use a simpler example
    username = "A" * 8  # username=AAAAAAAA
    # Block 1: username=AAAAAAA
    # Block 2: A;role=user;acti

    cookie = encrypt_cookie(username)

    # Find position of 'u' in 'user'
    # "username=" is 9 chars, then "AAAAAAAA" is 8, then ";role=" is 6
    # So 'user' starts at position 9+8+6 = 23

    # In block 2, 'user' is at positions 7-10 (0-indexed within block)
    # To flip 'u' to 'a', modify block 1 at same position

    modified = bytearray(cookie)

    # Position in block 2: "A;role=user;acti"
    #                       01234567890...
    # 'u' of 'user' is at position 7 in block 2

    # We need to modify IV+block1, which is bytes 0-31
    # Block 1 is bytes 16-31
    # Position 7 in block 2 needs modification at position 16+7 = 23

    # Change 'user' to 'admn' (note: wrong length, just demo)
    # Actually change just 'u' to 'a' first
    pos = 16 + 7  # Modify block 1 at position 7
    modified[pos] ^= ord('u') ^ ord('a')

    print("\nAfter modification:")
    return decrypt_cookie(bytes(modified))

exploit()
```

### Step 3: Proper Attack Setup

```python
from crypto_attacks import cbc_bit_flip

# For a proper attack, we need the target string position
# Let's create a cookie where we know exactly where everything is

def create_admin_cookie():
    key = os.urandom(16)

    def encrypt(data):
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data.encode(), 16))

    def decrypt(data):
        iv = data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data[16:]), 16)

    # Carefully craft input to align
    # "admin=0" at a position we can flip to "admin=1"
    plaintext = "comment=AAAAAAA;admin=0;user=guest"
    print(f"Original: {plaintext}")

    ct = encrypt(plaintext)

    # Find position of '0' in "admin=0"
    pos = plaintext.find("admin=0") + len("admin=")
    print(f"Target position: {pos}")

    # Flip '0' to '1'
    modified = cbc_bit_flip(ct, pos, '0', '1')

    try:
        result = decrypt(modified)
        print(f"Modified: {result}")
        return b"admin=1" in result
    except:
        # Block before target is corrupted
        print("Previous block corrupted (expected)")
        return False

create_admin_cookie()
```

## Exercise 3: RSA Small Exponent Attack

### Step 1: Understand the Attack

```python
from crypto_attacks import *

# When e=3 and message is small, m^3 might be less than n
# In that case, c = m^3 (no modular reduction)
# We can just take the cube root!

# Example
m = 12345  # Small message
e = 3
n = 10**20  # Large modulus

# Encryption
c = pow(m, e, n)
print(f"m = {m}")
print(f"c = m^3 mod n = {c}")
print(f"m^3 = {m**3}")
print(f"m^3 < n? {m**3 < n}")

# Attack
recovered = small_e_attack(c, e)
print(f"Recovered: {recovered}")
```

### Step 2: Attack with Text Message

```python
from crypto_attacks import *

# Encrypt short message
message = b"Hi!"
m = bytes_to_int(message)
e = 3
n = 10**100  # Much larger than m^3

c = pow(m, e, n)
print(f"Message: {message}")
print(f"m = {m}")
print(f"c = {c}")

# Attack
recovered_int = small_e_attack(c, e)
if recovered_int:
    recovered = int_to_bytes(recovered_int)
    print(f"Recovered: {recovered}")
```

## Exercise 4: Nonce Reuse Attack

### Step 1: Set Up Vulnerable System

```python
from Crypto.Cipher import AES
import os

key = os.urandom(16)
nonce = os.urandom(8)  # REUSED - VULNERABILITY!

def encrypt_message(plaintext):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(plaintext.encode())

# Encrypt two messages with same nonce
m1 = "Meet me at the park at noon"
m2 = "The secret code is FLAG{nonce_reuse}"

c1 = encrypt_message(m1)
c2 = encrypt_message(m2)

print(f"C1: {c1.hex()}")
print(f"C2: {c2.hex()}")
```

### Step 2: Exploit Nonce Reuse

```python
from crypto_attacks import nonce_reuse_attack, xor_bytes

# Attacker knows m1 (or guesses it)
known_m1 = b"Meet me at the park at noon"

# Attack
recovered_m2 = nonce_reuse_attack(c1, c2, known_m1)
print(f"Recovered M2: {recovered_m2[:len(m2)]}")
```

### Step 3: Crib Dragging

```python
from crypto_attacks import xor_bytes, crib_drag

# If we don't know the full plaintext, use crib dragging
c1_xor_c2 = xor_bytes(c1, c2)

# Try common words
cribs = ["the", "and", "Meet", "FLAG", "secret", "at", "is"]

for crib in cribs:
    results = crib_drag(c1_xor_c2, crib)
    if results:
        print(f"Crib '{crib}' found at:")
        for pos, text in results[:3]:  # Show first 3
            print(f"  Position {pos}: '{text}'")
```

## Solving CTF Challenges

### Challenge 3: RSA e=3

```python
from crypto_attacks import *

# Given
n = 12345678901234567890123456789012345678901234567890  # Example
e = 3
c = 1881676412  # This is (1234)^3

# Check if m^3 < n (no modular reduction)
recovered = small_e_attack(c, e)
if recovered:
    print(f"Recovered: {recovered}")
    try:
        text = int_to_bytes(recovered)
        print(f"As text: {text}")
    except:
        pass
```

### Challenge 4: Nonce Reuse

```python
from crypto_attacks import nonce_reuse_attack

# Given ciphertexts and known plaintext
c1 = bytes.fromhex("...")  # First ciphertext
c2 = bytes.fromhex("...")  # Second ciphertext
known_p1 = b"Known first message"

p2 = nonce_reuse_attack(c1, c2, known_p1)
print(f"Recovered: {p2}")
```

## Finding the Lab Flag

```python
from crypto_attacks import *

# The flag can be recovered through various attacks
flag = "FLAG{crypt0_br34k3r}"

# Demonstrate with padding oracle
oracle = PaddingOracle()
ct = oracle.encrypt(flag)

# Attack would recover the flag
print(f"Flag: {flag}")
```

## Summary

In this lab, you learned:

1. **Padding Oracle Attack** - Decrypt CBC ciphertext byte by byte
2. **CBC Bit Flipping** - Modify plaintext by changing ciphertext
3. **RSA Attacks** - Small exponent, common modulus, factoring
4. **Nonce Reuse** - Recover plaintext from stream cipher
5. **Implementation Flaws** - How small mistakes break crypto

## References

- [Cryptopals Challenges](https://cryptopals.com/) - Practice these attacks
- [PadBuster](https://github.com/AonCyberLabs/PadBuster) - Automated padding oracle
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) - RSA attack automation
