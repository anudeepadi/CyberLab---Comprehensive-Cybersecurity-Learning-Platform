# Lab 06 Walkthrough - Password Cracking

Step-by-step guide to cracking password hashes with hands-on exercises.

## Setup

### Install Required Tools

```bash
# Install Hashcat
sudo apt-get install hashcat

# Install John the Ripper
sudo apt-get install john

# Install Python libraries
pip3 install passlib bcrypt

# Get wordlists
sudo apt-get install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

### Create the Password Cracking Toolkit

Save this as `crack_toolkit.py`:

```python
#!/usr/bin/env python3
"""Password Cracking Toolkit for CyberLab"""

import hashlib
import itertools
import string
import time

# ============================================================================
# HASH GENERATION
# ============================================================================

def md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()

def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def ntlm(text):
    """Generate NTLM hash (Windows)"""
    import binascii
    return binascii.hexlify(
        hashlib.new('md4', text.encode('utf-16le')).digest()
    ).decode()

def sha256_salted(text, salt):
    return hashlib.sha256((salt + text).encode()).hexdigest()

# ============================================================================
# DICTIONARY ATTACK
# ============================================================================

def dictionary_attack(target_hash, wordlist_path, hash_func=md5):
    """Basic dictionary attack"""
    attempts = 0
    start_time = time.time()

    with open(wordlist_path, 'r', errors='ignore') as f:
        for word in f:
            word = word.strip()
            attempts += 1

            if hash_func(word) == target_hash:
                elapsed = time.time() - start_time
                return {
                    'password': word,
                    'attempts': attempts,
                    'time': elapsed,
                    'speed': attempts / elapsed if elapsed > 0 else 0
                }

    return None

# ============================================================================
# RULE-BASED ATTACK
# ============================================================================

def apply_rules(word):
    """Generate variations of a word"""
    variations = set()

    # Original
    variations.add(word)

    # Case variations
    variations.add(word.lower())
    variations.add(word.upper())
    variations.add(word.capitalize())
    variations.add(word.swapcase())

    # Reverse
    variations.add(word[::-1])

    # Common suffixes
    for suffix in ['1', '12', '123', '1234', '!', '!!', '@', '#', '2023', '2024', '2025']:
        variations.add(word + suffix)
        variations.add(word.capitalize() + suffix)

    # Common prefixes
    for prefix in ['1', '123', 'the', 'my']:
        variations.add(prefix + word)

    # Leet speak
    leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
    leet_word = word
    for char, replacement in leet_map.items():
        leet_word = leet_word.replace(char, replacement)
    variations.add(leet_word)

    return list(variations)

def rule_attack(target_hash, wordlist_path, hash_func=md5):
    """Dictionary attack with rules"""
    attempts = 0
    start_time = time.time()

    with open(wordlist_path, 'r', errors='ignore') as f:
        for word in f:
            word = word.strip()

            for variant in apply_rules(word):
                attempts += 1

                if hash_func(variant) == target_hash:
                    elapsed = time.time() - start_time
                    return {
                        'password': variant,
                        'base_word': word,
                        'attempts': attempts,
                        'time': elapsed,
                        'speed': attempts / elapsed if elapsed > 0 else 0
                    }

    return None

# ============================================================================
# BRUTE FORCE ATTACK
# ============================================================================

def brute_force(target_hash, charset, min_len, max_len, hash_func=md5, max_attempts=None):
    """Brute force attack with progress"""
    attempts = 0
    start_time = time.time()

    for length in range(min_len, max_len + 1):
        print(f"Trying length {length}...")

        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            attempts += 1

            if max_attempts and attempts >= max_attempts:
                return None

            if attempts % 100000 == 0:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                print(f"  Attempts: {attempts:,} | Speed: {speed:,.0f}/s | Current: {candidate}")

            if hash_func(candidate) == target_hash:
                elapsed = time.time() - start_time
                return {
                    'password': candidate,
                    'attempts': attempts,
                    'time': elapsed,
                    'speed': attempts / elapsed if elapsed > 0 else 0
                }

    return None

# ============================================================================
# HYBRID ATTACK
# ============================================================================

def hybrid_attack(target_hash, wordlist_path, suffix_charset, suffix_len, hash_func=md5):
    """Dictionary + brute force suffix"""
    attempts = 0
    start_time = time.time()

    with open(wordlist_path, 'r', errors='ignore') as f:
        for word in f:
            word = word.strip()

            for suffix in itertools.product(suffix_charset, repeat=suffix_len):
                candidate = word + ''.join(suffix)
                attempts += 1

                if hash_func(candidate) == target_hash:
                    elapsed = time.time() - start_time
                    return {
                        'password': candidate,
                        'attempts': attempts,
                        'time': elapsed,
                        'speed': attempts / elapsed if elapsed > 0 else 0
                    }

    return None

# ============================================================================
# MASK ATTACK
# ============================================================================

def mask_attack(target_hash, mask, hash_func=md5):
    """
    Mask attack similar to hashcat

    Mask characters:
    ?l = lowercase (a-z)
    ?u = uppercase (A-Z)
    ?d = digits (0-9)
    ?s = special characters
    ?a = all printable
    """
    charsets = {
        '?l': string.ascii_lowercase,
        '?u': string.ascii_uppercase,
        '?d': string.digits,
        '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?',
        '?a': string.printable.strip(),
    }

    # Parse mask into list of charsets
    pattern = []
    i = 0
    while i < len(mask):
        if mask[i] == '?' and i + 1 < len(mask):
            char_type = mask[i:i+2]
            if char_type in charsets:
                pattern.append(charsets[char_type])
                i += 2
                continue
        pattern.append(mask[i])
        i += 1

    attempts = 0
    start_time = time.time()

    for combo in itertools.product(*pattern):
        candidate = ''.join(combo)
        attempts += 1

        if hash_func(candidate) == target_hash:
            elapsed = time.time() - start_time
            return {
                'password': candidate,
                'attempts': attempts,
                'time': elapsed,
                'speed': attempts / elapsed if elapsed > 0 else 0
            }

    return None

# ============================================================================
# HASH IDENTIFICATION
# ============================================================================

def identify_hash_type(hash_string):
    """Identify hash type by format"""
    hash_len = len(hash_string)

    if hash_string.startswith('$2a$') or hash_string.startswith('$2b$'):
        return 'bcrypt'
    if hash_string.startswith('$6$'):
        return 'SHA-512crypt'
    if hash_string.startswith('$5$'):
        return 'SHA-256crypt'
    if hash_string.startswith('$1$'):
        return 'MD5crypt'

    types = {
        32: 'MD5/NTLM',
        40: 'SHA-1',
        64: 'SHA-256',
        128: 'SHA-512'
    }

    return types.get(hash_len, f'Unknown ({hash_len} chars)')

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("Password Cracking Toolkit")
    print("=" * 50)
    print("Functions:")
    print("  dictionary_attack(hash, wordlist, hash_func)")
    print("  rule_attack(hash, wordlist, hash_func)")
    print("  brute_force(hash, charset, min_len, max_len, hash_func)")
    print("  hybrid_attack(hash, wordlist, suffix_charset, suffix_len)")
    print("  mask_attack(hash, mask, hash_func)")
    print("  identify_hash_type(hash)")
    print("=" * 50)
```

## Exercise 1: Basic Dictionary Attack with Python

### Step 1: Create Test Hashes

```python
from crack_toolkit import *

# Create some test hashes
passwords = ["password", "123456", "letmein", "qwerty", "admin"]
print("Test hashes (MD5):")
for pw in passwords:
    print(f"  {pw}: {md5(pw)}")
```

### Step 2: Create a Small Wordlist

```bash
# Create test wordlist
cat > test_wordlist.txt << 'EOF'
password
123456
admin
letmein
qwerty
welcome
monkey
dragon
master
login
EOF
```

### Step 3: Run Dictionary Attack

```python
from crack_toolkit import *

# Target hash (MD5 of "letmein")
target = "0d107d09f5bbe40cade3de5c71e9e9b7"

result = dictionary_attack(target, "test_wordlist.txt", md5)
if result:
    print(f"Cracked!")
    print(f"  Password: {result['password']}")
    print(f"  Attempts: {result['attempts']}")
    print(f"  Time: {result['time']:.2f}s")
else:
    print("Not found")
```

## Exercise 2: Hashcat Basics

### Step 1: Create Hash File

```bash
# Create hash file
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
echo "e10adc3949ba59abbe56e057f20f883e" >> hash.txt
echo "0d107d09f5bbe40cade3de5c71e9e9b7" >> hash.txt
```

### Step 2: Run Hashcat Dictionary Attack

```bash
# Basic dictionary attack on MD5
hashcat -m 0 hash.txt test_wordlist.txt

# Check cracked hashes
hashcat -m 0 hash.txt --show
```

### Step 3: Hashcat with Rules

```bash
# Using built-in rules
hashcat -m 0 hash.txt test_wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Common rule files:
# best64.rule - Best 64 rules
# rockyou-30000.rule - Rules from rockyou analysis
# d3ad0ne.rule - Comprehensive rule set
```

## Exercise 3: John the Ripper Basics

### Step 1: Create Hash File for John

```bash
# John prefers specific formats
# MD5 raw:
echo "user1:5f4dcc3b5aa765d61d8327deb882cf99" > john_hashes.txt
echo "user2:e10adc3949ba59abbe56e057f20f883e" >> john_hashes.txt
```

### Step 2: Run John

```bash
# Auto-detect and crack
john --format=raw-md5 john_hashes.txt

# Use wordlist
john --format=raw-md5 --wordlist=test_wordlist.txt john_hashes.txt

# Show results
john --show john_hashes.txt
```

### Step 3: John with Rules

```bash
# Enable rules
john --format=raw-md5 --wordlist=test_wordlist.txt --rules john_hashes.txt
```

## Exercise 4: Rule-Based Attacks

### Step 1: Python Rule Attack

```python
from crack_toolkit import *

# Hash of "Password1" (capitalize + number)
target = md5("Password1")
print(f"Target hash: {target}")

# Base wordlist only has "password"
# But our rules will find "Password1"
result = rule_attack(target, "test_wordlist.txt", md5)
if result:
    print(f"Cracked: {result['password']}")
    print(f"Base word: {result['base_word']}")
```

### Step 2: Custom Hashcat Rules

```bash
# Create custom rule file
cat > my_rules.rule << 'EOF'
:
l
u
c
$1
$123
$!
sa@
se3
so0
EOF

# Use custom rules
hashcat -m 0 hash.txt wordlist.txt -r my_rules.rule
```

### Step 3: Understanding Rule Syntax

```python
# Demonstrate what rules produce
def demonstrate_rules(word):
    print(f"Original: {word}")
    print(f"  l (lowercase): {word.lower()}")
    print(f"  u (uppercase): {word.upper()}")
    print(f"  c (capitalize): {word.capitalize()}")
    print(f"  $1 (append 1): {word}1")
    print(f"  ^1 (prepend 1): 1{word}")
    print(f"  sa@ (a->@): {word.replace('a', '@')}")
    print(f"  r (reverse): {word[::-1]}")

demonstrate_rules("password")
```

## Exercise 5: Brute Force Attacks

### Step 1: Python Brute Force (Small)

```python
from crack_toolkit import *

# Crack a 4-digit PIN
target = md5("1234")
print(f"Cracking MD5 of 4-digit PIN...")

result = brute_force(target, string.digits, 4, 4, md5)
if result:
    print(f"PIN: {result['password']}")
    print(f"Attempts: {result['attempts']:,}")
    print(f"Time: {result['time']:.2f}s")
```

### Step 2: Hashcat Brute Force (Mask Attack)

```bash
# Create hash of "abc123"
echo -n "abc123" | md5sum | cut -d' ' -f1 > hash.txt

# Brute force 6 chars: 3 lowercase + 3 digits
hashcat -m 0 hash.txt -a 3 ?l?l?l?d?d?d

# Show result
hashcat -m 0 hash.txt --show
```

### Step 3: Mask Attack in Python

```python
from crack_toolkit import *

# Target: "Ab1" (uppercase, lowercase, digit)
target = md5("Ab1")

# Mask: ?u?l?d = one uppercase, one lowercase, one digit
result = mask_attack(target, "?u?l?d", md5)
if result:
    print(f"Password: {result['password']}")
```

## Exercise 6: Cracking Different Hash Types

### Step 1: NTLM Hashes (Windows)

```python
from crack_toolkit import *

# Create NTLM hash
password = "Password1"
hash_ntlm = ntlm(password)
print(f"NTLM hash: {hash_ntlm}")

# Crack with hashcat
# hashcat -m 1000 ntlm_hash.txt wordlist.txt
```

### Step 2: SHA-256 Hashes

```bash
# Create SHA-256 hash
echo -n "password" | sha256sum | cut -d' ' -f1 > sha256_hash.txt

# Crack with hashcat (mode 1400)
hashcat -m 1400 sha256_hash.txt wordlist.txt
```

### Step 3: Salted Hashes

```python
from crack_toolkit import *

# Salted hash
salt = "abc123"
password = "secret"
salted_hash = sha256_salted(password, salt)
print(f"Salt: {salt}")
print(f"Hash: {salted_hash}")

# To crack, you need the salt!
# hashcat format for sha256($salt.$pass): mode 1420
# hashcat -m 1420 hash.txt wordlist.txt (with hash:salt format)
```

## Exercise 7: Cracking Linux Password Hashes

### Step 1: Understanding /etc/shadow

```bash
# Shadow file format:
# username:$algorithm$salt$hash:...

# $1$ = MD5crypt
# $5$ = SHA-256crypt
# $6$ = SHA-512crypt
```

### Step 2: Extract and Crack

```bash
# Combine passwd and shadow (need root)
sudo unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Crack with John
john unshadowed.txt

# Or with hashcat (mode 1800 for SHA-512crypt)
hashcat -m 1800 shadow_hash.txt wordlist.txt
```

## Solving CTF Challenges

### Challenge 1: Basic MD5

```python
from crack_toolkit import *

target = "e10adc3949ba59abbe56e057f20f883e"

# Check common passwords first
common = ["password", "123456", "admin", "letmein", "qwerty"]
for pw in common:
    if md5(pw) == target:
        print(f"Password: {pw}")
        break
# Output: Password: 123456
```

### Challenge 2: SHA-256 with Rules

```python
target = "5e884898da28047d9165091e2205ad02ba4aca1a7c34e8d3c0b87b3462f13a8e"

# Try common word + rules
result = rule_attack(target, "/usr/share/wordlists/rockyou.txt", sha256)
if result:
    print(f"Password: {result['password']}")
```

Or recognize this is a well-known hash:
```python
# This is sha256 of "test"
if sha256("test") == target:
    print("Password: test")
```

### Challenge 3: NTLM Hash

```python
target = "32ed87bdb5fdc5e9cba88547376818d4"

# Dictionary attack for NTLM
def crack_ntlm(target, wordlist):
    with open(wordlist, 'r', errors='ignore') as f:
        for word in f:
            word = word.strip()
            if ntlm(word) == target:
                return word
    return None

result = crack_ntlm(target, "/usr/share/wordlists/rockyou.txt")
print(f"Password: {result}")
```

### Challenge 4: Salted Hash

```python
salt = "deadbeef"
target = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

# Dictionary with salt prepended
with open("wordlist.txt", 'r') as f:
    for word in f:
        word = word.strip()
        if sha256_salted(word, salt) == target:
            print(f"Password: {word}")
            break
```

### Challenge 5: bcrypt

```bash
# bcrypt hash
echo '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrPSCr9YH9Q7xZLqvA6j5e8dKjPf7qC' > bcrypt.txt

# Crack with hashcat (mode 3200) - SLOW!
hashcat -m 3200 bcrypt.txt wordlist.txt

# Or John
john --format=bcrypt bcrypt.txt
```

This bcrypt hash is "password" - one of the most common.

## Finding the Lab Flag

```python
from crack_toolkit import *

# The flag can be verified:
flag = "FLAG{cr4ck_th3_h4sh}"
print(f"Flag: {flag}")
print(f"MD5: {md5(flag)}")
print(f"SHA256: {sha256(flag)}")
```

## Summary

In this lab, you learned:

1. **Attack Types** - Dictionary, brute force, rule-based, hybrid
2. **Hashcat** - GPU-accelerated password cracking
3. **John the Ripper** - Versatile CPU cracker
4. **Rules** - Transformations to expand wordlists
5. **Hash Types** - MD5, SHA, NTLM, bcrypt, Unix crypt

## Next Lab

Continue to **Lab 07: Steganography** to learn how to hide and find data concealed in images and files.
