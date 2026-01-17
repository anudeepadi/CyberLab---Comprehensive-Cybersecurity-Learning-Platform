# Lab 05 - Hashing

Master cryptographic hash functions and their applications in security.

## Overview

**Difficulty:** Beginner to Intermediate
**Duration:** 1.5 hours
**Category:** Cryptographic Hash Functions
**Flag:** `FLAG{h4sh_1t_0ut}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand cryptographic hash function properties
2. Calculate hashes using MD5, SHA-1, SHA-256, and SHA-512
3. Identify hash types from their format
4. Understand hash collisions and their implications
5. Use hashing for file integrity verification
6. Apply hashing in password storage and HMACs

## What is a Hash Function?

A **cryptographic hash function** transforms input data of any size into a fixed-size output (hash/digest):

```
INPUT (any size)            HASH FUNCTION           OUTPUT (fixed size)
┌─────────────────┐         ┌───────────┐          ┌──────────────────┐
│ "Hello"         │ ──────> │           │ ──────>  │ 8b1a9953c4611296a│
│ "Hello World!"  │ ──────> │  SHA-256  │ ──────>  │ 7f83b1657ff1fc53b│
│ (1GB file)      │ ──────> │           │ ──────>  │ 9a87c32a6782e8d9f│
└─────────────────┘         └───────────┘          └──────────────────┘
                                                    (always 256 bits)
```

## Properties of Cryptographic Hash Functions

### 1. Deterministic
Same input always produces same output.

```
SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
                  ↑ Always identical
```

### 2. Fixed Output Size
Regardless of input size, output is always the same length.

| Algorithm | Output Size |
|-----------|-------------|
| MD5 | 128 bits (32 hex chars) |
| SHA-1 | 160 bits (40 hex chars) |
| SHA-256 | 256 bits (64 hex chars) |
| SHA-512 | 512 bits (128 hex chars) |

### 3. Pre-image Resistance (One-Way)
Given a hash h, it's computationally infeasible to find any message m such that hash(m) = h.

```
Easy:     message  ───────>  hash
Hard:     hash     ───X───>  message
```

### 4. Second Pre-image Resistance
Given input m1, it's hard to find different m2 where hash(m1) = hash(m2).

### 5. Collision Resistance
It's hard to find any two different messages m1 and m2 where hash(m1) = hash(m2).

### 6. Avalanche Effect
A tiny change in input drastically changes the output.

```
SHA256("hello")  = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA256("hellp")  = 4617f0e0fa45ac6c32a7d6d9a7ab2ae34c6c9e4d4a7e11c8c3ab3eb3d0d1a8f1
                   ↑ Completely different!
```

## Common Hash Functions

### MD5 (Message Digest 5) - BROKEN

```
Length: 128 bits (32 hex characters)
Status: CRYPTOGRAPHICALLY BROKEN
Use:    File checksums only (not security)

Example:
MD5("hello") = 5d41402abc4b2a76b9719d911017c592
```

**Known Issues:**
- Collision attacks are practical (seconds to minutes)
- Should NOT be used for passwords, signatures, or certificates
- Still commonly found in legacy systems

### SHA-1 (Secure Hash Algorithm 1) - DEPRECATED

```
Length: 160 bits (40 hex characters)
Status: DEPRECATED (collisions found in 2017)
Use:    Legacy compatibility only

Example:
SHA1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
```

### SHA-256 (SHA-2 Family) - RECOMMENDED

```
Length: 256 bits (64 hex characters)
Status: SECURE (current standard)
Use:    Passwords, digital signatures, certificates

Example:
SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

### SHA-512 (SHA-2 Family) - RECOMMENDED

```
Length: 512 bits (128 hex characters)
Status: SECURE
Use:    High-security applications

Example:
SHA512("hello") = 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7...
```

### SHA-3 (Keccak) - LATEST STANDARD

```
Length: Variable (224, 256, 384, 512 bits)
Status: SECURE (standardized 2015)
Use:    When SHA-2 alternative needed

Example:
SHA3-256("hello") = 3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392
```

## Hash Type Identification

### By Length

| Hex Length | Possible Algorithms |
|------------|---------------------|
| 32 chars | MD5, MD4, NTLM |
| 40 chars | SHA-1, RIPEMD-160 |
| 56 chars | SHA-224, SHA3-224 |
| 64 chars | SHA-256, SHA3-256, BLAKE2s |
| 96 chars | SHA-384, SHA3-384 |
| 128 chars | SHA-512, SHA3-512, BLAKE2b |

### By Format

```
$1$salt$hash          - MD5crypt (Unix)
$5$salt$hash          - SHA-256crypt (Unix)
$6$salt$hash          - SHA-512crypt (Unix)
$2a$cost$salt+hash    - bcrypt
$argon2i$...          - Argon2
```

## OpenSSL and Command Line

### Calculate Hashes

```bash
# MD5
echo -n "hello" | md5sum
# or
openssl dgst -md5 <<< "hello"

# SHA-1
echo -n "hello" | sha1sum
# or
openssl dgst -sha1 <<< "hello"

# SHA-256
echo -n "hello" | sha256sum
# or
openssl dgst -sha256 <<< "hello"

# SHA-512
echo -n "hello" | sha512sum
# or
openssl dgst -sha512 <<< "hello"
```

**Note:** Use `echo -n` to avoid adding a newline character!

### Hash Files

```bash
# Calculate hash of a file
sha256sum file.txt

# Verify file integrity
sha256sum -c checksums.txt

# Create checksum file
sha256sum *.txt > checksums.sha256

# Multiple algorithms at once
openssl dgst -md5 -sha1 -sha256 file.txt
```

### Generate Random Hashes

```bash
# Hash random data
openssl rand 32 | sha256sum

# Create random token
openssl rand -hex 32
```

## Python Implementation

### Using hashlib

```python
#!/usr/bin/env python3
"""Hash function examples using Python's hashlib"""

import hashlib

# ============================================================================
# BASIC HASHING
# ============================================================================

def md5_hash(data):
    """Calculate MD5 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.md5(data).hexdigest()

def sha1_hash(data):
    """Calculate SHA-1 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha1(data).hexdigest()

def sha256_hash(data):
    """Calculate SHA-256 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def sha512_hash(data):
    """Calculate SHA-512 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()

def sha3_256_hash(data):
    """Calculate SHA3-256 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha3_256(data).hexdigest()

# ============================================================================
# FILE HASHING
# ============================================================================

def hash_file(filepath, algorithm='sha256'):
    """Calculate hash of a file"""
    h = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

# ============================================================================
# HASH IDENTIFICATION
# ============================================================================

def identify_hash(hash_string):
    """Identify possible hash type by length"""
    hash_len = len(hash_string)

    types = {
        32: ['MD5', 'MD4', 'NTLM', 'LM'],
        40: ['SHA-1', 'RIPEMD-160'],
        56: ['SHA-224', 'SHA3-224'],
        64: ['SHA-256', 'SHA3-256', 'BLAKE2s-256'],
        96: ['SHA-384', 'SHA3-384'],
        128: ['SHA-512', 'SHA3-512', 'BLAKE2b-512']
    }

    return types.get(hash_len, ['Unknown'])

# ============================================================================
# EXAMPLES
# ============================================================================

if __name__ == "__main__":
    message = "hello"

    print("=" * 60)
    print(f"Message: '{message}'")
    print("=" * 60)

    print(f"MD5:      {md5_hash(message)}")
    print(f"SHA-1:    {sha1_hash(message)}")
    print(f"SHA-256:  {sha256_hash(message)}")
    print(f"SHA-512:  {sha512_hash(message)}")
    print(f"SHA3-256: {sha3_256_hash(message)}")

    print("\n" + "=" * 60)
    print("Avalanche Effect Demo")
    print("=" * 60)
    print(f"SHA256('hello'):  {sha256_hash('hello')}")
    print(f"SHA256('hellp'):  {sha256_hash('hellp')}")

    print("\n" + "=" * 60)
    print("Hash Identification")
    print("=" * 60)
    test_hash = "5d41402abc4b2a76b9719d911017c592"
    print(f"Hash: {test_hash}")
    print(f"Possible types: {identify_hash(test_hash)}")
```

### HMAC (Hash-based Message Authentication Code)

```python
#!/usr/bin/env python3
"""HMAC examples"""

import hmac
import hashlib

def hmac_sha256(key, message):
    """Calculate HMAC-SHA256"""
    if isinstance(key, str):
        key = key.encode()
    if isinstance(message, str):
        message = message.encode()

    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_hmac(key, message, expected_hmac):
    """Securely verify HMAC (constant-time comparison)"""
    calculated = hmac_sha256(key, message)
    return hmac.compare_digest(calculated, expected_hmac)

# Example
key = "secret_key"
message = "Hello, World!"

mac = hmac_sha256(key, message)
print(f"HMAC-SHA256: {mac}")

# Verify
is_valid = verify_hmac(key, message, mac)
print(f"Valid: {is_valid}")

# Tampered message
is_valid = verify_hmac(key, "Hello, World?", mac)
print(f"Tampered valid: {is_valid}")
```

### Password Hashing (Secure)

```python
#!/usr/bin/env python3
"""Secure password hashing examples"""

import hashlib
import os

# ============================================================================
# PBKDF2 (Password-Based Key Derivation Function 2)
# ============================================================================

def hash_password_pbkdf2(password, salt=None, iterations=100000):
    """Hash password using PBKDF2-SHA256"""
    if salt is None:
        salt = os.urandom(32)

    if isinstance(password, str):
        password = password.encode()

    key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    return salt + key  # Store salt + hash together

def verify_password_pbkdf2(password, stored_hash, iterations=100000):
    """Verify password against PBKDF2 hash"""
    salt = stored_hash[:32]
    stored_key = stored_hash[32:]

    if isinstance(password, str):
        password = password.encode()

    calculated_key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    return hmac.compare_digest(stored_key, calculated_key)

# Example
password = "mysecretpassword"
hashed = hash_password_pbkdf2(password)
print(f"Stored hash: {hashed.hex()}")

# Verify
is_valid = verify_password_pbkdf2(password, hashed)
print(f"Correct password: {is_valid}")

is_valid = verify_password_pbkdf2("wrongpassword", hashed)
print(f"Wrong password: {is_valid}")
```

## Applications of Hashing

### 1. File Integrity Verification

```bash
# Download file and checksum
wget https://example.com/file.tar.gz
wget https://example.com/file.tar.gz.sha256

# Verify
sha256sum -c file.tar.gz.sha256
```

### 2. Password Storage

```
WRONG: Store password in plaintext
WRONG: Store MD5(password)
WRONG: Store SHA256(password)

RIGHT: Store bcrypt(password)
RIGHT: Store argon2(password)
RIGHT: Store PBKDF2(password, salt, iterations)
```

### 3. Digital Signatures

```
1. Hash the document: h = SHA256(document)
2. Sign the hash: signature = RSA_encrypt(h, private_key)
3. Verify: SHA256(document) == RSA_decrypt(signature, public_key)
```

### 4. Blockchain/Proof of Work

```
Find nonce where SHA256(block + nonce) starts with N zeros
```

## CTF Challenges

### Challenge 1: Identify the Hash

```
5d41402abc4b2a76b9719d911017c592
```
What algorithm and what plaintext?

### Challenge 2: Hash Collision

These two files have the same MD5 but different content. Why is this bad?

### Challenge 3: Length Extension

Given: `SHA256(secret || message) = <hash>`
Can you compute `SHA256(secret || message || padding || evil)` without knowing the secret?

### Challenge 4: Rainbow Table Lookup

```
Hash: 5f4dcc3b5aa765d61d8327deb882cf99
```
What is the original password?

### Challenge 5: HMAC Verification

Verify this message was not tampered with:
```
Message: "Transfer $1000 to account 12345"
HMAC-SHA256: 8a9f2b3c4d5e6f7a8b9c0d1e2f3a4b5c...
Key hint: It's a common 8-letter word
```

## Hash Collisions

### MD5 Collisions

In 2004, researchers demonstrated practical MD5 collisions. Two different inputs can produce the same hash:

```python
# These two different byte sequences produce the same MD5 hash!
# (Actual collision example - these are different!)

import hashlib

# Collision block 1 (hex)
block1 = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89...")

# Collision block 2 (hex)
block2 = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89...")

# Both produce the same MD5!
print(hashlib.md5(block1).hexdigest())
print(hashlib.md5(block2).hexdigest())
```

### SHA-1 Collisions (SHAttered, 2017)

Google demonstrated a practical SHA-1 collision by creating two different PDF files with identical SHA-1 hashes.

## Tools

### Hash Identification
- **hashid** - `pip install hashid`
- **hash-identifier** - Kali tool
- **haiti** - `gem install haiti-hash`

### Hash Cracking (covered in Lab 06)
- **hashcat** - GPU-accelerated
- **John the Ripper** - CPU-based
- **CrackStation** - Online rainbow tables

### Hash Calculation
- **OpenSSL** - `openssl dgst`
- **md5sum, sha256sum** - Linux utilities
- **CyberChef** - Online multi-tool

## Tasks

- [ ] Calculate MD5, SHA-1, SHA-256 of a string
- [ ] Hash a file and verify its integrity
- [ ] Demonstrate the avalanche effect
- [ ] Identify hash types by their format
- [ ] Implement HMAC in Python
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{h4sh_1t_0ut}`

## Next Steps

After mastering hashing:
- **Lab 06: Password Cracking** - Breaking password hashes
- **Lab 08: Crypto Attacks** - Hash-related attacks

## References

- [NIST Secure Hash Standard (FIPS 180-4)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [SHA-3 Standard (FIPS 202)](https://csrc.nist.gov/publications/detail/fips/202/final)
- [How To Safely Store A Password](https://codahale.com/how-to-safely-store-a-password/)
- [SHAttered - SHA-1 Collision](https://shattered.io/)
