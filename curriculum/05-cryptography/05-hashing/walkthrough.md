# Lab 05 Walkthrough - Hashing

Step-by-step guide to mastering cryptographic hash functions.

## Setup

### Install Required Tools

```bash
# Install Python libraries
pip3 install hashlib-compat pycryptodome

# Verify command-line tools
which md5sum sha256sum openssl

# Install hash identification tool
pip3 install hashid
```

### Create the Hashing Toolkit

Save this as `hash_toolkit.py`:

```python
#!/usr/bin/env python3
"""Hashing Toolkit for CyberLab"""

import hashlib
import hmac
import os
import binascii

# ============================================================================
# BASIC HASH FUNCTIONS
# ============================================================================

def md5(data):
    """Calculate MD5 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.md5(data).hexdigest()

def sha1(data):
    """Calculate SHA-1 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha1(data).hexdigest()

def sha256(data):
    """Calculate SHA-256 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def sha512(data):
    """Calculate SHA-512 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()

def sha3_256(data):
    """Calculate SHA3-256 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha3_256(data).hexdigest()

# ============================================================================
# HASH ALL ALGORITHMS
# ============================================================================

def hash_all(data):
    """Calculate hash with multiple algorithms"""
    if isinstance(data, str):
        data = data.encode()

    results = {
        'MD5': hashlib.md5(data).hexdigest(),
        'SHA-1': hashlib.sha1(data).hexdigest(),
        'SHA-256': hashlib.sha256(data).hexdigest(),
        'SHA-512': hashlib.sha512(data).hexdigest(),
        'SHA3-256': hashlib.sha3_256(data).hexdigest(),
    }
    return results

def print_all_hashes(data):
    """Pretty print all hashes"""
    print("=" * 70)
    print(f"Input: '{data}'")
    print("=" * 70)
    for algo, hash_value in hash_all(data).items():
        print(f"{algo:10}: {hash_value}")
    print("=" * 70)

# ============================================================================
# FILE HASHING
# ============================================================================

def hash_file(filepath, algorithm='sha256', chunk_size=8192):
    """Calculate hash of a file"""
    h = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def verify_file_hash(filepath, expected_hash, algorithm='sha256'):
    """Verify file matches expected hash"""
    calculated = hash_file(filepath, algorithm)
    return calculated.lower() == expected_hash.lower()

# ============================================================================
# HASH IDENTIFICATION
# ============================================================================

HASH_LENGTHS = {
    32: ['MD5', 'MD4', 'MD2', 'NTLM', 'LM', 'Domain Cached Credentials'],
    40: ['SHA-1', 'RIPEMD-160', 'Haval-160', 'Tiger-160'],
    48: ['Haval-192', 'Tiger-192'],
    56: ['SHA-224', 'SHA3-224', 'Haval-224'],
    64: ['SHA-256', 'SHA3-256', 'RIPEMD-256', 'Haval-256', 'GOST', 'Snefru-256', 'BLAKE2s-256'],
    80: ['RIPEMD-320'],
    96: ['SHA-384', 'SHA3-384'],
    128: ['SHA-512', 'SHA3-512', 'Whirlpool', 'BLAKE2b-512'],
}

def identify_hash(hash_string):
    """Identify possible hash type by length"""
    # Remove any whitespace
    hash_string = hash_string.strip()

    # Check if it's hex
    try:
        int(hash_string, 16)
    except ValueError:
        return "Not a valid hex hash"

    length = len(hash_string)
    return HASH_LENGTHS.get(length, [f'Unknown (length {length})'])

# ============================================================================
# HMAC
# ============================================================================

def hmac_sha256(key, message):
    """Calculate HMAC-SHA256"""
    if isinstance(key, str):
        key = key.encode()
    if isinstance(message, str):
        message = message.encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_hmac(key, message, expected_mac, algorithm=hashlib.sha256):
    """Verify HMAC with constant-time comparison"""
    if isinstance(key, str):
        key = key.encode()
    if isinstance(message, str):
        message = message.encode()

    calculated = hmac.new(key, message, algorithm).hexdigest()
    return hmac.compare_digest(calculated, expected_mac)

# ============================================================================
# PASSWORD HASHING
# ============================================================================

def hash_password(password, salt=None, iterations=100000):
    """Hash password using PBKDF2-SHA256"""
    if salt is None:
        salt = os.urandom(32)
    if isinstance(password, str):
        password = password.encode()

    key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    return salt.hex() + ':' + key.hex()

def verify_password(password, stored_hash, iterations=100000):
    """Verify password against stored hash"""
    parts = stored_hash.split(':')
    salt = bytes.fromhex(parts[0])
    stored_key = bytes.fromhex(parts[1])

    if isinstance(password, str):
        password = password.encode()

    calculated_key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    return hmac.compare_digest(calculated_key, stored_key)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hex_to_bytes(h):
    return binascii.unhexlify(h)

def bytes_to_hex(b):
    return binascii.hexlify(b).decode()

def compare_hashes(hash1, hash2):
    """Case-insensitive hash comparison"""
    return hash1.lower().strip() == hash2.lower().strip()

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("Hash Toolkit")
    print("=" * 50)
    print("Functions:")
    print("  md5(data), sha1(data), sha256(data), sha512(data)")
    print("  hash_all(data), print_all_hashes(data)")
    print("  hash_file(filepath, algorithm)")
    print("  identify_hash(hash_string)")
    print("  hmac_sha256(key, message)")
    print("  hash_password(password), verify_password(password, hash)")
    print("=" * 50)

    # Demo
    print_all_hashes("hello")
```

## Exercise 1: Basic Hashing with Command Line

### Step 1: Hash a String

```bash
# MD5 (note: use -n to avoid newline!)
echo -n "hello" | md5sum
# Output: 5d41402abc4b2a76b9719d911017c592  -

# SHA-1
echo -n "hello" | sha1sum
# Output: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  -

# SHA-256
echo -n "hello" | sha256sum
# Output: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  -
```

### Step 2: Understand the Newline Problem

```bash
# WITH newline (wrong for "hello")
echo "hello" | md5sum
# Output: b1946ac92492d2347c6235b4d2611184  -

# WITHOUT newline (correct)
echo -n "hello" | md5sum
# Output: 5d41402abc4b2a76b9719d911017c592  -

# The outputs are different because "hello\n" != "hello"
```

### Step 3: Using OpenSSL

```bash
# OpenSSL hash commands
openssl dgst -md5 <<< "hello"    # Note: <<< adds newline
printf "hello" | openssl dgst -md5
printf "hello" | openssl dgst -sha256
printf "hello" | openssl dgst -sha512
```

## Exercise 2: File Hashing

### Step 1: Create Test Files

```bash
# Create test files
echo "This is file 1" > file1.txt
echo "This is file 2" > file2.txt
cp file1.txt file1_copy.txt
```

### Step 2: Calculate File Hashes

```bash
# Hash all files
sha256sum file1.txt file2.txt file1_copy.txt

# Output shows file1.txt and file1_copy.txt have same hash
```

### Step 3: Create Checksum File

```bash
# Generate checksums
sha256sum *.txt > checksums.sha256

# View checksum file
cat checksums.sha256
```

### Step 4: Verify File Integrity

```bash
# Verify all files
sha256sum -c checksums.sha256

# Modify a file and re-verify
echo "modified" >> file1.txt
sha256sum -c checksums.sha256
# Output: file1.txt: FAILED
```

## Exercise 3: Avalanche Effect Demonstration

### Step 1: Python Demonstration

```python
from hash_toolkit import *

# Original message
msg1 = "hello"
msg2 = "hellp"  # Only last character changed

print("Avalanche Effect Demonstration")
print("=" * 70)
print(f"Message 1: '{msg1}'")
print(f"Message 2: '{msg2}'")
print("-" * 70)
print(f"SHA256('{msg1}'): {sha256(msg1)}")
print(f"SHA256('{msg2}'): {sha256(msg2)}")

# Count bit differences
hash1 = int(sha256(msg1), 16)
hash2 = int(sha256(msg2), 16)
xor = hash1 ^ hash2
bit_diff = bin(xor).count('1')
print(f"\nBits changed: {bit_diff} out of 256 ({bit_diff/256*100:.1f}%)")
```

### Step 2: Visualize Changes

```python
def visualize_avalanche(msg1, msg2):
    """Visualize how hash changes between similar inputs"""
    h1 = sha256(msg1)
    h2 = sha256(msg2)

    print(f"Input 1: '{msg1}'")
    print(f"Input 2: '{msg2}'")
    print()

    # Show character-by-character comparison
    diff_chars = 0
    for i, (c1, c2) in enumerate(zip(h1, h2)):
        if c1 != c2:
            print(f"Position {i:2d}: {c1} -> {c2} (DIFFERENT)")
            diff_chars += 1

    print(f"\nTotal different characters: {diff_chars}/64 ({diff_chars/64*100:.1f}%)")

visualize_avalanche("hello", "hellp")
visualize_avalanche("hello", "Hello")
visualize_avalanche("password", "password1")
```

## Exercise 4: Hash Identification

### Step 1: Using hashid Tool

```bash
# Install hashid
pip3 install hashid

# Identify hash types
hashid '5d41402abc4b2a76b9719d911017c592'
hashid 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
hashid '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
```

### Step 2: Python Hash Identification

```python
from hash_toolkit import identify_hash

# Test various hashes
test_hashes = [
    "5d41402abc4b2a76b9719d911017c592",  # MD5
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # SHA-1
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",  # SHA-256
]

for h in test_hashes:
    types = identify_hash(h)
    print(f"Hash: {h[:32]}...")
    print(f"Length: {len(h)} chars")
    print(f"Possible types: {types}")
    print()
```

### Step 3: Identify Format-Based Hashes

```python
def identify_formatted_hash(hash_string):
    """Identify hash by format prefix"""
    formats = {
        '$1$': 'MD5crypt (Unix)',
        '$5$': 'SHA-256crypt (Unix)',
        '$6$': 'SHA-512crypt (Unix)',
        '$2a$': 'bcrypt',
        '$2b$': 'bcrypt',
        '$2y$': 'bcrypt',
        '$argon2i$': 'Argon2i',
        '$argon2d$': 'Argon2d',
        '$argon2id$': 'Argon2id',
        '$pbkdf2': 'PBKDF2',
    }

    for prefix, name in formats.items():
        if hash_string.startswith(prefix):
            return name

    return "Unknown format"

# Test
test_formatted = [
    "$6$rounds=5000$saltsalt$hashhashhashhash...",
    "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.i",
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$hash",
]

for h in test_formatted:
    print(f"{h[:40]}... -> {identify_formatted_hash(h)}")
```

## Exercise 5: HMAC (Hash-based Message Authentication)

### Step 1: Generate HMAC

```python
from hash_toolkit import hmac_sha256

key = "secret_key"
message = "Transfer $1000 to account 12345"

mac = hmac_sha256(key, message)
print(f"Message: {message}")
print(f"HMAC-SHA256: {mac}")
```

### Step 2: Verify HMAC

```python
from hash_toolkit import verify_hmac

key = "secret_key"
message = "Transfer $1000 to account 12345"
mac = hmac_sha256(key, message)

# Verify original
print(f"Original valid: {verify_hmac(key, message, mac)}")

# Verify tampered message
tampered = "Transfer $9999 to account 12345"
print(f"Tampered valid: {verify_hmac(key, tampered, mac)}")
```

### Step 3: Command Line HMAC

```bash
# HMAC with OpenSSL
echo -n "message" | openssl dgst -sha256 -hmac "key"

# HMAC for file
openssl dgst -sha256 -hmac "secret" file.txt
```

## Exercise 6: Secure Password Hashing

### Step 1: Why Simple Hashing is Bad

```python
# DON'T DO THIS - vulnerable to rainbow tables
password = "password123"
simple_hash = sha256(password)
print(f"Simple SHA256: {simple_hash}")
# This hash can be looked up in rainbow tables!
```

### Step 2: Use PBKDF2

```python
from hash_toolkit import hash_password, verify_password

password = "mysecretpassword"

# Hash password (salt is auto-generated)
hashed = hash_password(password)
print(f"Stored hash: {hashed}")

# Verify correct password
print(f"Correct password: {verify_password(password, hashed)}")

# Verify wrong password
print(f"Wrong password: {verify_password('wrongpassword', hashed)}")
```

### Step 3: Using bcrypt (Recommended)

```python
# pip install bcrypt
import bcrypt

password = b"mysecretpassword"

# Hash password
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)
print(f"bcrypt hash: {hashed.decode()}")

# Verify
if bcrypt.checkpw(password, hashed):
    print("Password matches!")
```

## Solving CTF Challenges

### Challenge 1: Identify the Hash

```python
hash_value = "5d41402abc4b2a76b9719d911017c592"

# Identify by length
types = identify_hash(hash_value)
print(f"Possible types: {types}")  # MD5

# Try to crack with known common words
common_words = ["hello", "password", "admin", "test", "user", "root"]
for word in common_words:
    if md5(word) == hash_value:
        print(f"Cracked! Plaintext: {word}")
        break
# Output: Cracked! Plaintext: hello
```

### Challenge 4: Rainbow Table Lookup

```python
hash_value = "5f4dcc3b5aa765d61d8327deb882cf99"

# This is a common password hash - check online:
# https://crackstation.net/
# Or use a local wordlist

# Simple wordlist check
common_passwords = [
    "password", "123456", "admin", "letmein", "qwerty",
    "monkey", "dragon", "master", "login", "abc123"
]

for pw in common_passwords:
    if md5(pw) == hash_value:
        print(f"Password found: {pw}")
        break
# Output: Password found: password
```

### Challenge 5: HMAC Verification

```python
message = "Transfer $1000 to account 12345"
given_hmac = "8a9f2b3c4d5e6f7a8b9c0d1e2f3a4b5c..."  # truncated

# Try common 8-letter words as keys
common_keys = [
    "password", "security", "transfer", "banking",
    "finances", "accounts", "payments", "verified"
]

for key in common_keys:
    if len(key) == 8:
        calculated = hmac_sha256(key, message)
        if calculated.startswith(given_hmac[:16]):  # partial match
            print(f"Key found: {key}")
```

## Finding the Lab Flag

The flag `FLAG{h4sh_1t_0ut}` can be found by:

```python
from hash_toolkit import *

# The flag hashed with different algorithms
flag = "FLAG{h4sh_1t_0ut}"

print("Flag Hashes:")
print_all_hashes(flag)

# To verify you found the correct flag:
# MD5 of the flag should be a specific value
expected_md5 = md5(flag)
print(f"\nFlag: {flag}")
print(f"MD5: {expected_md5}")
```

## Summary

In this lab, you learned:

1. **Hash Functions** - MD5, SHA-1, SHA-256, SHA-512, SHA-3
2. **Hash Properties** - Deterministic, one-way, collision resistant
3. **Avalanche Effect** - Small input changes cause large output changes
4. **Hash Identification** - By length and format
5. **HMAC** - Hash-based message authentication
6. **Password Hashing** - PBKDF2, bcrypt, argon2

## Next Lab

Continue to **Lab 06: Password Cracking** to learn how to crack password hashes using wordlists, rainbow tables, and tools like hashcat and John the Ripper.
