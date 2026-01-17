# Lab 04 - Asymmetric Encryption

Master public key cryptography including RSA, key exchange, and digital signatures.

## Overview

**Difficulty:** Intermediate
**Duration:** 2 hours
**Category:** Public Key Cryptography
**Flag:** `FLAG{publ1c_k3y_m4st3r}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand asymmetric encryption principles
2. Generate and use RSA key pairs
3. Perform RSA encryption and decryption
4. Create and verify digital signatures
5. Understand Diffie-Hellman key exchange
6. Identify common RSA vulnerabilities

## What is Asymmetric Encryption?

**Asymmetric encryption** uses a pair of mathematically related keys:

```
              ASYMMETRIC ENCRYPTION

    PUBLIC KEY                    PRIVATE KEY
    (Anyone can have)             (Keep secret!)
         │                              │
         ▼                              ▼
    ┌─────────┐                   ┌─────────┐
    │ Encrypt │ ───────────────>  │ Decrypt │
    └─────────┘                   └─────────┘

    ┌─────────┐                   ┌─────────┐
    │ Verify  │ <───────────────  │  Sign   │
    └─────────┘                   └─────────┘
```

**Key Properties:**
- Two keys: public (shared) and private (secret)
- Public key encrypts, private key decrypts
- Private key signs, public key verifies
- Slower than symmetric encryption
- Solves key distribution problem

## RSA Algorithm

### How RSA Works

```
KEY GENERATION:
1. Choose two large primes: p and q
2. Calculate n = p × q (modulus)
3. Calculate φ(n) = (p-1) × (q-1)
4. Choose e (typically 65537) where gcd(e, φ(n)) = 1
5. Calculate d = e⁻¹ mod φ(n)

Public Key:  (e, n)
Private Key: (d, n)

ENCRYPTION:
Ciphertext = Plaintext^e mod n

DECRYPTION:
Plaintext = Ciphertext^d mod n
```

### RSA Key Sizes

| Key Size | Security Level | Usage |
|----------|---------------|-------|
| 1024-bit | Broken | Never use |
| 2048-bit | Minimum | Legacy systems |
| 3072-bit | Recommended | Current standard |
| 4096-bit | Strong | High security |

### Mathematical Foundation

```
Example with small primes (INSECURE - for learning only):

p = 61, q = 53
n = 61 × 53 = 3233
φ(n) = 60 × 52 = 3120
e = 17 (public exponent)
d = 2753 (private exponent, calculated as e⁻¹ mod φ(n))

Public Key:  (17, 3233)
Private Key: (2753, 3233)

Encrypt 'H' (ASCII 72):
C = 72^17 mod 3233 = 513

Decrypt 513:
P = 513^2753 mod 3233 = 72 = 'H'
```

## Diffie-Hellman Key Exchange

Allows two parties to establish a shared secret over an insecure channel:

```
        ALICE                           BOB
          │                               │
    ┌─────┴─────┐                   ┌─────┴─────┐
    │ Private: a │                   │ Private: b │
    └─────┬─────┘                   └─────┬─────┘
          │                               │
    A = g^a mod p  ───────────────>  B = g^b mod p
          │        <───────────────       │
          │                               │
    s = B^a mod p                   s = A^b mod p
          │                               │
    ┌─────┴─────┐                   ┌─────┴─────┐
    │  Shared   │ ═════════════════ │  Shared   │
    │  Secret s │                   │  Secret s │
    └───────────┘                   └───────────┘

Both calculate: s = g^(ab) mod p
```

**Parameters:**
- p: Large prime number
- g: Generator (primitive root mod p)
- a, b: Private values (kept secret)
- A, B: Public values (exchanged)
- s: Shared secret (never transmitted)

## Digital Signatures

Digital signatures provide:
- **Authentication** - Proof of identity
- **Integrity** - Message not modified
- **Non-repudiation** - Signer cannot deny signing

```
SIGNING (with private key):
┌──────────┐      ┌──────────┐      ┌──────────┐
│ Message  │ ──>  │  Hash    │ ──>  │ Encrypt  │ ──> Signature
└──────────┘      │ (SHA-256)│      │ (RSA)    │
                  └──────────┘      └──────────┘

VERIFYING (with public key):
┌──────────┐      ┌──────────┐
│ Message  │ ──>  │  Hash    │ ──> Hash1
└──────────┘      │ (SHA-256)│          │
                  └──────────┘          │
┌──────────┐      ┌──────────┐          │
│Signature │ ──>  │ Decrypt  │ ──> Hash2 ──> Compare
└──────────┘      │ (RSA)    │
                  └──────────┘

If Hash1 == Hash2: Valid signature
```

## OpenSSL Commands

### Generate RSA Key Pair

```bash
# Generate 4096-bit private key
openssl genrsa -out private.pem 4096

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem

# View key details
openssl rsa -in private.pem -text -noout
```

### RSA Encryption/Decryption

```bash
# Create test message
echo "Secret message" > plaintext.txt

# Encrypt with public key
openssl rsautl -encrypt -pubin -inkey public.pem \
    -in plaintext.txt -out encrypted.bin

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem \
    -in encrypted.bin -out decrypted.txt

# Using OAEP padding (recommended)
openssl pkeyutl -encrypt -pubin -inkey public.pem \
    -pkeyopt rsa_padding_mode:oaep \
    -in plaintext.txt -out encrypted_oaep.bin
```

### Digital Signatures

```bash
# Sign a file
openssl dgst -sha256 -sign private.pem -out signature.bin message.txt

# Verify signature
openssl dgst -sha256 -verify public.pem -signature signature.bin message.txt

# Create detached signature (base64)
openssl dgst -sha256 -sign private.pem message.txt | base64 > signature.b64
```

### Diffie-Hellman

```bash
# Generate DH parameters
openssl dhparam -out dhparams.pem 2048

# View parameters
openssl dhparam -in dhparams.pem -text -noout

# Generate DH key pair
openssl genpkey -paramfile dhparams.pem -out dhkey.pem
```

### Certificate Operations

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=localhost"

# View certificate
openssl x509 -in cert.pem -text -noout

# Extract public key from certificate
openssl x509 -in cert.pem -pubkey -noout > pubkey.pem
```

## Python Implementation

### RSA with cryptography library

```python
#!/usr/bin/env python3
"""RSA encryption/decryption examples"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ============================================================================
# KEY GENERATION
# ============================================================================

def generate_rsa_keypair(key_size=2048):
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key, private_path="private.pem", public_path="public.pem"):
    """Save keys to PEM files"""
    # Save private key
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(path):
    """Load private key from PEM file"""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    """Load public key from PEM file"""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

# ============================================================================
# ENCRYPTION/DECRYPTION
# ============================================================================

def rsa_encrypt(plaintext, public_key):
    """Encrypt with RSA-OAEP"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """Decrypt with RSA-OAEP"""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# ============================================================================
# DIGITAL SIGNATURES
# ============================================================================

def sign_message(message, private_key):
    """Sign message with RSA-PSS"""
    if isinstance(message, str):
        message = message.encode()

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

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
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Generate key pair
    print("[*] Generating RSA-2048 key pair...")
    private_key, public_key = generate_rsa_keypair(2048)

    # Encryption demo
    print("\n" + "=" * 50)
    print("RSA ENCRYPTION")
    print("=" * 50)
    message = "FLAG{publ1c_k3y_m4st3r}"
    print(f"Original: {message}")

    encrypted = rsa_encrypt(message, public_key)
    print(f"Encrypted: {encrypted.hex()[:64]}...")

    decrypted = rsa_decrypt(encrypted, private_key)
    print(f"Decrypted: {decrypted.decode()}")

    # Signature demo
    print("\n" + "=" * 50)
    print("DIGITAL SIGNATURES")
    print("=" * 50)
    message = "This message is authentic"
    signature = sign_message(message, private_key)
    print(f"Message: {message}")
    print(f"Signature: {signature.hex()[:64]}...")

    is_valid = verify_signature(message, signature, public_key)
    print(f"Valid: {is_valid}")

    # Tampered message
    is_valid = verify_signature("This message is tampered", signature, public_key)
    print(f"Tampered message valid: {is_valid}")
```

### Diffie-Hellman Key Exchange

```python
#!/usr/bin/env python3
"""Diffie-Hellman key exchange demonstration"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_dh_parameters():
    """Generate DH parameters"""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

def generate_dh_keypair(parameters):
    """Generate DH key pair"""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    """Derive shared secret"""
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

if __name__ == "__main__":
    print("[*] Diffie-Hellman Key Exchange Demo")
    print("=" * 50)

    # Generate shared parameters
    print("[1] Generating DH parameters (this takes a moment)...")
    params = generate_dh_parameters()

    # Alice generates her key pair
    print("[2] Alice generates key pair...")
    alice_private, alice_public = generate_dh_keypair(params)

    # Bob generates his key pair
    print("[3] Bob generates key pair...")
    bob_private, bob_public = generate_dh_keypair(params)

    # Exchange public keys and derive shared secret
    print("[4] Deriving shared secrets...")
    alice_shared = derive_shared_secret(alice_private, bob_public)
    bob_shared = derive_shared_secret(bob_private, alice_public)

    print(f"\nAlice's shared secret: {alice_shared.hex()[:32]}...")
    print(f"Bob's shared secret:   {bob_shared.hex()[:32]}...")
    print(f"\nSecrets match: {alice_shared == bob_shared}")
```

### Raw RSA (Educational Only)

```python
#!/usr/bin/env python3
"""Raw RSA implementation for educational purposes - NEVER use in production!"""

import random
from math import gcd

def is_prime(n, k=10):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number with specified bits"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Ensure it's odd and has correct bit length
        if is_prime(p):
            return p

def mod_inverse(e, phi):
    """Calculate modular multiplicative inverse using extended Euclidean algorithm"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi

def generate_keypair(bits=512):
    """Generate RSA key pair (small for demo)"""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)

    return (e, n), (d, n), (p, q)

def encrypt(message, public_key):
    """Encrypt integer message"""
    e, n = public_key
    return pow(message, e, n)

def decrypt(ciphertext, private_key):
    """Decrypt to integer"""
    d, n = private_key
    return pow(ciphertext, d, n)

def text_to_int(text):
    """Convert text to integer"""
    return int.from_bytes(text.encode(), 'big')

def int_to_text(num):
    """Convert integer to text"""
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, 'big').decode()

if __name__ == "__main__":
    print("Raw RSA Demo (Educational)")
    print("=" * 50)

    print("[*] Generating 512-bit keys (INSECURE - demo only)...")
    public_key, private_key, factors = generate_keypair(512)

    e, n = public_key
    d, _ = private_key
    p, q = factors

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"d = {d}")

    message = "Hi!"
    print(f"\nMessage: {message}")

    m = text_to_int(message)
    print(f"As integer: {m}")

    c = encrypt(m, public_key)
    print(f"Encrypted: {c}")

    decrypted = decrypt(c, private_key)
    print(f"Decrypted int: {decrypted}")
    print(f"Decrypted text: {int_to_text(decrypted)}")
```

## Common RSA Vulnerabilities

### 1. Small Public Exponent with Small Message

If e=3 and m^3 < n, then c = m^3 and m = cube_root(c).

```python
import gmpy2

# If ciphertext c = m^3 (no modular reduction occurred)
c = 12345678901234567890
m = gmpy2.iroot(c, 3)[0]  # Integer cube root
```

### 2. Common Modulus Attack

If same n is used with different e values:

```python
def common_modulus_attack(c1, c2, e1, e2, n):
    """Attack when same n used with different e"""
    # Find Bezout coefficients: a*e1 + b*e2 = 1
    from math import gcd
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    _, a, b = extended_gcd(e1, e2)

    # m = c1^a * c2^b mod n
    if a < 0:
        c1 = pow(c1, -1, n)  # Modular inverse
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

### 3. Factoring Small n

```python
# Using FactorDB or yafu for small n
# pip install factordb-pycli
from factordb.factordb import FactorDB

n = 323  # Small n for demo
f = FactorDB(n)
f.connect()
factors = f.get_factor_list()
print(f"Factors of {n}: {factors}")  # [17, 19]
```

### 4. Wiener's Attack (Small d)

When d < n^0.25 / 3, continued fractions can recover d:

```python
# pip install owiener
import owiener

e = 65537
n = 12345...  # Your modulus

d = owiener.attack(e, n)
if d:
    print(f"Found d: {d}")
```

## CTF Challenges

### Challenge 1: Basic RSA

Given:
```
n = 323
e = 5
c = 246
```
Decrypt to find the message.

### Challenge 2: Factor n

Given:
```
n = 7829873491387
e = 65537
c = 1234567890
```
Factor n and decrypt.

### Challenge 3: Weak Random

Two RSA moduli share a prime factor:
```
n1 = 143
n2 = 187
```
Find the shared factor and recover both private keys.

### Challenge 4: Signature Forgery

Verify a message was signed correctly, then forge a signature for a different message.

### Challenge 5: Diffie-Hellman Intercept

Given DH parameters and public values, compute the shared secret.

## Tasks

- [ ] Generate RSA key pair with OpenSSL
- [ ] Encrypt/decrypt a message with RSA
- [ ] Create and verify a digital signature
- [ ] Implement Diffie-Hellman key exchange in Python
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{publ1c_k3y_m4st3r}`

## Tools

### Online Tools
- **RsaCtfTool** - Automated RSA attacks
- **FactorDB** - Integer factorization database
- **Alpertron** - Online factorization calculator

### Command Line
- **OpenSSL** - Key generation and crypto operations
- **yafu** - Fast integer factorization
- **msieve** - Number field sieve factoring

### Python Libraries
- **cryptography** - Modern crypto library
- **pycryptodome** - Comprehensive crypto tools
- **gmpy2** - Fast arbitrary precision arithmetic
- **sympy** - Symbolic mathematics

## Next Steps

After mastering asymmetric encryption:
- **Lab 05: Hashing** - Cryptographic hash functions
- **Lab 08: Crypto Attacks** - Advanced cryptographic attacks

## References

- [RSA Algorithm (Wikipedia)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Diffie-Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [Twenty Years of Attacks on RSA](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)
- [The cryptography Library Documentation](https://cryptography.io/en/latest/)
