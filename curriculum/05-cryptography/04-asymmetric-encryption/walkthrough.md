# Lab 04 Walkthrough - Asymmetric Encryption

Step-by-step guide to mastering public key cryptography with hands-on exercises.

## Setup

### Install Required Tools

```bash
# Install Python cryptography libraries
pip3 install cryptography pycryptodome gmpy2

# Verify OpenSSL is installed
openssl version
```

### Create the Asymmetric Encryption Toolkit

Save this as `asymmetric_toolkit.py`:

```python
#!/usr/bin/env python3
"""Asymmetric Encryption Toolkit for CyberLab"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import math
import binascii

# ============================================================================
# RSA KEY OPERATIONS
# ============================================================================

def generate_rsa_keypair(key_size=2048):
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def extract_rsa_components(private_key):
    """Extract RSA key components (n, e, d, p, q)"""
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    return {
        'n': public_numbers.n,
        'e': public_numbers.e,
        'd': private_numbers.d,
        'p': private_numbers.p,
        'q': private_numbers.q
    }

def key_to_pem(key, is_private=True):
    """Convert key to PEM format"""
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

def pem_to_key(pem_data, is_private=True):
    """Load key from PEM format"""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()

    if is_private:
        return serialization.load_pem_private_key(pem_data, password=None)
    else:
        return serialization.load_pem_public_key(pem_data)

# ============================================================================
# RSA ENCRYPTION/DECRYPTION
# ============================================================================

def rsa_encrypt(plaintext, public_key):
    """Encrypt with RSA-OAEP"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ciphertext, private_key):
    """Decrypt with RSA-OAEP"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ============================================================================
# RAW RSA (EDUCATIONAL - NO PADDING)
# ============================================================================

def raw_rsa_encrypt(m, e, n):
    """Raw RSA encryption: c = m^e mod n"""
    return pow(m, e, n)

def raw_rsa_decrypt(c, d, n):
    """Raw RSA decryption: m = c^d mod n"""
    return pow(c, d, n)

def text_to_int(text):
    """Convert text to integer"""
    return int.from_bytes(text.encode(), 'big')

def int_to_text(num):
    """Convert integer to text"""
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, 'big').decode()

def bytes_to_int(data):
    """Convert bytes to integer"""
    return int.from_bytes(data, 'big')

def int_to_bytes(num, length=None):
    """Convert integer to bytes"""
    if length is None:
        length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, 'big')

# ============================================================================
# DIGITAL SIGNATURES
# ============================================================================

def sign_message(message, private_key):
    """Sign with RSA-PSS"""
    if isinstance(message, str):
        message = message.encode()

    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(message, signature, public_key):
    """Verify RSA-PSS signature"""
    if isinstance(message, str):
        message = message.encode()

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# ============================================================================
# RSA ATTACKS
# ============================================================================

def gcd(a, b):
    """Greatest common divisor"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inverse(e, phi):
    """Modular multiplicative inverse"""
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return (x % phi + phi) % phi

def factor_n_from_d(n, e, d):
    """Factor n given (e, d) - useful when d is known"""
    k = e * d - 1
    while k % 2 == 0:
        k //= 2

    import random
    for _ in range(100):
        g = random.randrange(2, n - 1)
        t = k
        while True:
            if t % 2 != 0:
                break
            t //= 2
            x = pow(g, t, n)
            if x > 1 and gcd(x - 1, n) > 1:
                p = gcd(x - 1, n)
                return p, n // p
    return None

def common_factor_attack(n1, n2):
    """Attack when two moduli share a prime factor"""
    p = gcd(n1, n2)
    if p > 1 and p != n1 and p != n2:
        return p, n1 // p, n2 // p
    return None

def small_e_attack(c, e, n):
    """Attack when message^e < n (no modular reduction)"""
    # Try to compute integer e-th root
    try:
        import gmpy2
        m, exact = gmpy2.iroot(c, e)
        if exact:
            return int(m)
    except ImportError:
        # Fallback: Newton's method
        def integer_nth_root(x, n):
            if x < 0:
                raise ValueError("x must be non-negative")
            if x == 0:
                return 0
            a = 1 << ((x.bit_length() + n - 1) // n)
            while True:
                b = ((n - 1) * a + x // pow(a, n - 1)) // n
                if b >= a:
                    return a
                a = b

        m = integer_nth_root(c, e)
        if pow(m, e) == c:
            return m
    return None

def hastad_broadcast_attack(ciphertexts, moduli, e):
    """Hastad's broadcast attack when same message sent to e recipients"""
    # Uses Chinese Remainder Theorem
    from functools import reduce

    def chinese_remainder_theorem(remainders, moduli):
        total = 0
        prod = reduce(lambda a, b: a * b, moduli)
        for r, m in zip(remainders, moduli):
            p = prod // m
            total += r * mod_inverse(p, m) * p
        return total % prod

    combined = chinese_remainder_theorem(ciphertexts, moduli)
    return small_e_attack(combined, e, reduce(lambda a, b: a * b, moduli))

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hex_to_bytes(h):
    return binascii.unhexlify(h)

def bytes_to_hex(b):
    return binascii.hexlify(b).decode()

def print_key_info(n, e, d=None, p=None, q=None):
    """Pretty print RSA key information"""
    print("=" * 60)
    print("RSA KEY INFORMATION")
    print("=" * 60)
    print(f"n (modulus):       {n}")
    print(f"e (public exp):    {e}")
    if d:
        print(f"d (private exp):   {d}")
    if p and q:
        print(f"p (prime 1):       {p}")
        print(f"q (prime 2):       {q}")
        print(f"phi(n):            {(p-1)*(q-1)}")
    print(f"Bit length:        {n.bit_length()} bits")
    print("=" * 60)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("Asymmetric Encryption Toolkit")
    print("=" * 50)
    print("Key Functions:")
    print("  generate_rsa_keypair(key_size)")
    print("  rsa_encrypt(plaintext, public_key)")
    print("  rsa_decrypt(ciphertext, private_key)")
    print("  sign_message(message, private_key)")
    print("  verify_signature(message, signature, public_key)")
    print("\nRaw RSA (educational):")
    print("  raw_rsa_encrypt(m, e, n)")
    print("  raw_rsa_decrypt(c, d, n)")
    print("\nAttacks:")
    print("  common_factor_attack(n1, n2)")
    print("  small_e_attack(c, e, n)")
    print("=" * 50)
```

## Exercise 1: Generate RSA Keys with OpenSSL

### Step 1: Generate Private Key

```bash
# Generate 2048-bit RSA private key
openssl genrsa -out private.pem 2048

# View the private key structure
openssl rsa -in private.pem -text -noout
```

**Output shows:**
- modulus (n)
- publicExponent (e) - typically 65537
- privateExponent (d)
- prime1 (p)
- prime2 (q)
- Various CRT optimization values

### Step 2: Extract Public Key

```bash
# Extract public key from private key
openssl rsa -in private.pem -pubout -out public.pem

# View public key
openssl rsa -pubin -in public.pem -text -noout
```

### Step 3: Generate Key with Custom Size

```bash
# 4096-bit key for higher security
openssl genrsa -out private_4096.pem 4096

# Password-protected private key
openssl genrsa -aes256 -out private_encrypted.pem 2048
```

## Exercise 2: RSA Encryption/Decryption

### Step 1: Encrypt with Public Key

```bash
# Create message
echo "Secret message for RSA encryption" > message.txt

# Encrypt with public key
openssl rsautl -encrypt -pubin -inkey public.pem \
    -in message.txt -out encrypted.bin

# View encrypted data
xxd encrypted.bin
```

### Step 2: Decrypt with Private Key

```bash
# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem \
    -in encrypted.bin -out decrypted.txt

# Verify
cat decrypted.txt
```

### Step 3: Use OAEP Padding (Recommended)

```bash
# Encrypt with OAEP padding
openssl pkeyutl -encrypt -pubin -inkey public.pem \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -in message.txt -out encrypted_oaep.bin

# Decrypt with OAEP
openssl pkeyutl -decrypt -inkey private.pem \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -in encrypted_oaep.bin -out decrypted_oaep.txt
```

## Exercise 3: Digital Signatures

### Step 1: Sign a File

```bash
# Create document
echo "This document is legally binding" > document.txt

# Sign with SHA-256 hash
openssl dgst -sha256 -sign private.pem -out signature.bin document.txt

# View signature
xxd signature.bin
```

### Step 2: Verify Signature

```bash
# Verify signature
openssl dgst -sha256 -verify public.pem \
    -signature signature.bin document.txt

# Output: "Verified OK" if valid
```

### Step 3: Detect Tampering

```bash
# Modify the document
echo "Modified document" > document.txt

# Try to verify (should fail)
openssl dgst -sha256 -verify public.pem \
    -signature signature.bin document.txt

# Output: "Verification Failure"
```

## Exercise 4: Python RSA Operations

### Step 1: Generate and Use Keys

```python
from asymmetric_toolkit import *

# Generate key pair
print("[*] Generating RSA-2048 key pair...")
private_key, public_key = generate_rsa_keypair(2048)

# Extract components
components = extract_rsa_components(private_key)
print_key_info(components['n'], components['e'],
               components['d'], components['p'], components['q'])

# Encrypt
message = b"Hello, RSA!"
ciphertext = rsa_encrypt(message, public_key)
print(f"\nCiphertext (hex): {bytes_to_hex(ciphertext)[:64]}...")

# Decrypt
plaintext = rsa_decrypt(ciphertext, private_key)
print(f"Decrypted: {plaintext.decode()}")
```

### Step 2: Save and Load Keys

```python
# Save keys to PEM files
with open('my_private.pem', 'w') as f:
    f.write(key_to_pem(private_key, is_private=True))

with open('my_public.pem', 'w') as f:
    f.write(key_to_pem(public_key, is_private=False))

# Load keys
with open('my_private.pem', 'r') as f:
    loaded_private = pem_to_key(f.read(), is_private=True)

with open('my_public.pem', 'r') as f:
    loaded_public = pem_to_key(f.read(), is_private=False)

# Verify they work
test_encrypted = rsa_encrypt(b"Test", loaded_public)
test_decrypted = rsa_decrypt(test_encrypted, loaded_private)
print(f"Load test: {test_decrypted.decode()}")
```

### Step 3: Sign and Verify

```python
# Sign a message
message = "This transaction is authorized"
signature = sign_message(message, private_key)
print(f"Signature: {bytes_to_hex(signature)[:64]}...")

# Verify signature
is_valid = verify_signature(message, signature, public_key)
print(f"Valid: {is_valid}")

# Try with tampered message
is_valid = verify_signature("This transaction is NOT authorized", signature, public_key)
print(f"Tampered valid: {is_valid}")
```

## Exercise 5: Raw RSA (Understanding the Math)

### Step 1: Small RSA Example

```python
# Small primes for demonstration (NEVER use in production!)
p = 61
q = 53
n = p * q  # 3233
phi_n = (p - 1) * (q - 1)  # 3120
e = 17  # Public exponent
d = mod_inverse(e, phi_n)  # 2753

print(f"p = {p}, q = {q}")
print(f"n = {n}")
print(f"e = {e}")
print(f"d = {d}")

# Encrypt letter 'H' (ASCII 72)
m = 72
c = raw_rsa_encrypt(m, e, n)
print(f"\nEncrypt {m} ('H'): {c}")

# Decrypt
decrypted = raw_rsa_decrypt(c, d, n)
print(f"Decrypt {c}: {decrypted} ('{chr(decrypted)}')")
```

### Step 2: Encrypt/Decrypt Text

```python
# Encrypt a short message (must be smaller than n)
message = "Hi"
m = text_to_int(message)
print(f"Message '{message}' as integer: {m}")

# Use our toy RSA
c = raw_rsa_encrypt(m, e, n)
print(f"Ciphertext: {c}")

decrypted_int = raw_rsa_decrypt(c, d, n)
decrypted_text = int_to_text(decrypted_int)
print(f"Decrypted: {decrypted_text}")
```

## Exercise 6: Diffie-Hellman Key Exchange

### Step 1: Understand the Protocol

```python
#!/usr/bin/env python3
"""Manual Diffie-Hellman demonstration"""

import random

# Public parameters (normally much larger!)
p = 23  # Prime modulus
g = 5   # Generator

print(f"Public parameters: p={p}, g={g}")

# Alice's private value
a = random.randint(2, p-2)
print(f"\nAlice's private: a={a}")

# Alice's public value
A = pow(g, a, p)
print(f"Alice's public:  A = g^a mod p = {A}")

# Bob's private value
b = random.randint(2, p-2)
print(f"\nBob's private:   b={b}")

# Bob's public value
B = pow(g, b, p)
print(f"Bob's public:    B = g^b mod p = {B}")

# Shared secret computation
alice_secret = pow(B, a, p)  # B^a mod p = g^(ab) mod p
bob_secret = pow(A, b, p)    # A^b mod p = g^(ab) mod p

print(f"\nAlice computes: B^a mod p = {alice_secret}")
print(f"Bob computes:   A^b mod p = {bob_secret}")
print(f"\nShared secret matches: {alice_secret == bob_secret}")
```

### Step 2: Using OpenSSL

```bash
# Generate DH parameters
openssl dhparam -out dhparams.pem 2048

# Generate Alice's key pair
openssl genpkey -paramfile dhparams.pem -out alice_dh.pem

# Generate Bob's key pair
openssl genpkey -paramfile dhparams.pem -out bob_dh.pem

# Extract public keys
openssl pkey -in alice_dh.pem -pubout -out alice_dh_pub.pem
openssl pkey -in bob_dh.pem -pubout -out bob_dh_pub.pem

# Derive shared secrets
openssl pkeyutl -derive -inkey alice_dh.pem -peerkey bob_dh_pub.pem -out alice_secret.bin
openssl pkeyutl -derive -inkey bob_dh.pem -peerkey alice_dh_pub.pem -out bob_secret.bin

# Compare (should be identical)
xxd alice_secret.bin
xxd bob_secret.bin
diff alice_secret.bin bob_secret.bin && echo "Secrets match!"
```

## Solving CTF Challenges

### Challenge 1: Basic RSA

```python
# Given values
n = 323
e = 5
c = 246

# Factor n (small enough to factor manually)
# 323 = 17 * 19
p = 17
q = 19

# Calculate private exponent
phi_n = (p - 1) * (q - 1)  # 16 * 18 = 288
d = mod_inverse(e, phi_n)
print(f"d = {d}")

# Decrypt
m = raw_rsa_decrypt(c, d, n)
print(f"Decrypted integer: {m}")
print(f"As character: {chr(m)}")
```

### Challenge 2: Factor n

```python
# Use FactorDB for larger numbers
# pip install factordb-pycli

from factordb.factordb import FactorDB

n = 7829873491387
f = FactorDB(n)
f.connect()
factors = f.get_factor_list()
print(f"Factors: {factors}")

# Now decrypt
p, q = factors[0], factors[1]
e = 65537
c = 1234567890

phi_n = (p - 1) * (q - 1)
d = mod_inverse(e, phi_n)
m = raw_rsa_decrypt(c, d, n)
print(f"Decrypted: {m}")
```

### Challenge 3: Common Factor Attack

```python
n1 = 143  # 11 * 13
n2 = 187  # 11 * 17

# Find common factor
result = common_factor_attack(n1, n2)
if result:
    shared_p, q1, q2 = result
    print(f"Shared prime: {shared_p}")
    print(f"n1 = {shared_p} * {q1}")
    print(f"n2 = {shared_p} * {q2}")

    # Now we can compute both private keys!
    e = 65537
    d1 = mod_inverse(e, (shared_p - 1) * (q1 - 1))
    d2 = mod_inverse(e, (shared_p - 1) * (q2 - 1))
    print(f"d1 = {d1}")
    print(f"d2 = {d2}")
```

### Challenge 4: Small e Attack

```python
# When m^e < n, ciphertext = m^e (no modular reduction)
e = 3
c = 1728  # This is 12^3

# Take cube root
m = small_e_attack(c, e, 999999999999)
print(f"Message: {m}")  # 12
```

## Finding the Lab Flag

The flag `FLAG{publ1c_k3y_m4st3r}` can be found by:

```python
from asymmetric_toolkit import *

# Challenge: Decrypt this with the given key
n = 3233
e = 17
c = 2201  # Encrypted flag character

# Factor n
p = 61
q = 53
phi_n = (p - 1) * (q - 1)
d = mod_inverse(e, phi_n)

# Decrypt
m = raw_rsa_decrypt(c, d, n)
print(f"First character: {chr(m)}")

# For the full flag, decrypt each character
ciphertext = [2201, ...]  # Full encrypted flag
flag = ''.join(chr(raw_rsa_decrypt(c, d, n)) for c in ciphertext)
print(f"Flag: {flag}")
```

## Summary

In this lab, you learned:

1. **RSA Fundamentals** - Key generation, encryption, decryption
2. **Key Management** - PEM format, public/private key extraction
3. **Digital Signatures** - Signing and verification
4. **Diffie-Hellman** - Key exchange protocol
5. **RSA Attacks** - Common factor, small e, factoring

## Next Lab

Continue to **Lab 05: Hashing** to learn about cryptographic hash functions like MD5 and SHA.
