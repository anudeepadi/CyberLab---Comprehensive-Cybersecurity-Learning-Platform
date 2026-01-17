# Lab 06 - Password Cracking

Master the techniques and tools used to crack password hashes.

## Overview

**Difficulty:** Intermediate
**Duration:** 2 hours
**Category:** Password Security
**Flag:** `FLAG{cr4ck_th3_h4sh}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand password storage mechanisms
2. Use wordlists for dictionary attacks
3. Perform rule-based attacks
4. Understand and use rainbow tables
5. Crack hashes with Hashcat and John the Ripper
6. Identify weak password patterns

## Password Storage Mechanisms

### Evolution of Password Storage

```
TERRIBLE:    Store plaintext password
BAD:         Store MD5(password)
POOR:        Store SHA256(password)
OKAY:        Store SHA256(salt + password)
GOOD:        Store bcrypt(password)
BEST:        Store Argon2id(password)
```

### Why Plain Hashes Are Weak

```
Password Storage Attack:

Database leaked!
┌─────────────────────────────────────────────────┐
│ user      │ password_hash                       │
├───────────┼─────────────────────────────────────┤
│ alice     │ 5f4dcc3b5aa765d61d8327deb882cf99    │ <- MD5("password")
│ bob       │ e10adc3949ba59abbe56e057f20f883e    │ <- MD5("123456")
│ charlie   │ 5f4dcc3b5aa765d61d8327deb882cf99    │ <- Same as alice!
└─────────────────────────────────────────────────┘

Problems:
1. Same password = Same hash (no salt)
2. Common hashes in rainbow tables
3. Fast hashing = Fast cracking
```

### Salted Hashes

```
Better approach - add random salt:

hash = SHA256(salt + password)

┌─────────────────────────────────────────────────────────────────────┐
│ user      │ salt           │ password_hash                          │
├───────────┼────────────────┼────────────────────────────────────────┤
│ alice     │ a1b2c3d4e5f6   │ 9f86d081884c7d659a2feaa0c55ad015...    │
│ bob       │ x9y8z7w6v5u4   │ 3c9909afec25354d551dae21590bb26e...    │
│ charlie   │ m3n4o5p6q7r8   │ 7b502c3a1f48c8609ae212cdfb639dee...    │
└─────────────────────────────────────────────────────────────────────┘

Now: Same password + Different salt = Different hash
Rainbow tables won't work!
```

### Modern Password Hashing

```
bcrypt/argon2 add:
1. Unique salt per password
2. Configurable work factor (slowness)
3. Memory-hard operations (argon2)

$2a$12$LQv3c1yqBWVHxkd0LHAkCO...
  │  │  └── 22-char salt + 31-char hash
  │  └── Cost factor (2^12 = 4096 iterations)
  └── Algorithm version
```

## Attack Types

### 1. Dictionary Attack
Try words from a wordlist:

```
Wordlist:
password
123456
qwerty
letmein
...

For each word in wordlist:
    if hash(word) == target_hash:
        return word
```

### 2. Brute Force Attack
Try all possible combinations:

```
a, b, c, ..., z
aa, ab, ..., az, ba, bb, ...
aaa, aab, ...

Time complexity: O(charset^length)
8 chars, lowercase+numbers = 36^8 = 2.8 trillion combinations
```

### 3. Rule-Based Attack
Apply transformations to wordlist:

```
Word: password
Rules:
  - Capitalize first: Password
  - Add number: password1
  - Leet speak: p4ssw0rd
  - Reverse: drowssap
  - Append year: password2024
```

### 4. Rainbow Table Attack
Pre-computed hash lookup:

```
Rainbow Table:
┌────────────────────────────────────┬──────────────┐
│ Hash (MD5)                         │ Plaintext    │
├────────────────────────────────────┼──────────────┤
│ 5f4dcc3b5aa765d61d8327deb882cf99   │ password     │
│ e10adc3949ba59abbe56e057f20f883e   │ 123456       │
│ 25d55ad283aa400af464c76d713c07ad   │ 12345678     │
└────────────────────────────────────┴──────────────┘

Lookup is O(1) but tables are huge (TB+ for complex passwords)
```

### 5. Hybrid Attack
Combine dictionary + brute force:

```
Dictionary word + brute force suffix:
password + [0-9][0-9] = password00 to password99
admin + [!@#$%] = admin!, admin@, admin#...
```

## Common Hash Types

### Hash Format Reference

| Hash Type | Example | Length |
|-----------|---------|--------|
| MD5 | 5f4dcc3b5aa765d61d8327deb882cf99 | 32 |
| SHA-1 | 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 | 40 |
| SHA-256 | 5e884898da28047d9165... | 64 |
| NTLM | 32ed87bdb5fdc5e9cba... | 32 |
| bcrypt | $2a$10$N9qo8uLOi... | 60 |
| SHA-512crypt | $6$rounds=5000$... | ~100+ |

### Hashcat Mode Numbers

| Mode | Hash Type |
|------|-----------|
| 0 | MD5 |
| 100 | SHA-1 |
| 1400 | SHA-256 |
| 1000 | NTLM |
| 3200 | bcrypt |
| 1800 | SHA-512crypt |
| 500 | MD5crypt |

## Wordlists

### Popular Wordlists

```bash
# RockYou (14M passwords from 2009 breach)
/usr/share/wordlists/rockyou.txt

# SecLists (multiple categorized lists)
/usr/share/seclists/Passwords/

# Custom location
/usr/share/wordlists/
```

### Creating Custom Wordlists

```bash
# Combine multiple wordlists
cat list1.txt list2.txt | sort -u > combined.txt

# Generate from website (cewl)
cewl https://target.com -d 3 -m 5 > custom.txt

# Username-based (using username-anarchy)
username-anarchy john smith > usernames.txt
```

## Hashcat

### Basic Usage

```bash
# Basic dictionary attack
hashcat -m 0 hashes.txt wordlist.txt

# With rules
hashcat -m 0 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force (mask attack)
hashcat -m 0 hashes.txt -a 3 ?a?a?a?a?a?a

# Show cracked passwords
hashcat -m 0 hashes.txt --show
```

### Mask Attack Characters

```
?l = lowercase (a-z)
?u = uppercase (A-Z)
?d = digits (0-9)
?s = special (!@#$%...)
?a = all printable
?b = all bytes (0x00-0xff)
```

### Example Masks

```bash
# 8-character lowercase
hashcat -m 0 hash.txt -a 3 ?l?l?l?l?l?l?l?l

# Common pattern: Word + 4 digits
hashcat -m 0 hash.txt -a 3 password?d?d?d?d

# First uppercase, rest lowercase + numbers
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?l?l?d?d
```

### Hashcat Rules

```bash
# Built-in rules
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Multiple rules (combined)
hashcat -m 0 hash.txt wordlist.txt -r rule1.rule -r rule2.rule
```

### Rule Syntax Examples

```
# Rule file syntax:
:           # Do nothing (original word)
l           # Lowercase all
u           # Uppercase all
c           # Capitalize first, lower rest
t           # Toggle case
r           # Reverse word
$1          # Append "1"
^0          # Prepend "0"
sa@         # Replace 'a' with '@'
se3         # Replace 'e' with '3'
```

## John the Ripper

### Basic Usage

```bash
# Auto-detect hash type
john hashes.txt

# Specify format
john --format=raw-md5 hashes.txt

# Use wordlist
john --wordlist=rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt
```

### Common Formats

```bash
# MD5
john --format=raw-md5 hash.txt

# SHA-256
john --format=raw-sha256 hash.txt

# NTLM (Windows)
john --format=nt hash.txt

# Linux shadow file
john --format=sha512crypt shadow.txt

# bcrypt
john --format=bcrypt hash.txt
```

### John Rules

```bash
# Use default rules
john --wordlist=words.txt --rules hash.txt

# Specific rule set
john --wordlist=words.txt --rules=Jumbo hash.txt

# Incremental (brute force)
john --incremental hash.txt
```

### Extracting Hashes

```bash
# /etc/shadow (need root)
sudo unshadow /etc/passwd /etc/shadow > unshadowed.txt

# ZIP file
zip2john protected.zip > zip_hash.txt

# PDF file
pdf2john protected.pdf > pdf_hash.txt

# SSH key
ssh2john id_rsa > ssh_hash.txt

# Office documents
office2john document.docx > office_hash.txt
```

## Python Password Cracking

### Basic Dictionary Attack

```python
#!/usr/bin/env python3
"""Simple dictionary attack"""

import hashlib

def crack_md5(target_hash, wordlist_path):
    """Crack MD5 hash using wordlist"""
    with open(wordlist_path, 'r', errors='ignore') as f:
        for word in f:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == target_hash:
                return word
    return None

# Example
target = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 of "password"
result = crack_md5(target, "/usr/share/wordlists/rockyou.txt")
print(f"Cracked: {result}")
```

### With Rules

```python
#!/usr/bin/env python3
"""Dictionary attack with basic rules"""

import hashlib
import itertools

def apply_rules(word):
    """Generate variations of a word"""
    variations = [
        word,                           # Original
        word.lower(),                   # lowercase
        word.upper(),                   # UPPERCASE
        word.capitalize(),              # Capitalize
        word + "1",                     # Append 1
        word + "123",                   # Append 123
        word + "!",                     # Append !
        word[::-1],                     # Reverse
        word.replace('a', '@'),         # Leet a
        word.replace('e', '3'),         # Leet e
        word.replace('o', '0'),         # Leet o
        word.replace('i', '1'),         # Leet i
    ]

    # Add year variations
    for year in range(2020, 2026):
        variations.append(word + str(year))

    return list(set(variations))

def crack_with_rules(target_hash, wordlist_path, hash_func=hashlib.md5):
    """Crack hash using wordlist with rules"""
    with open(wordlist_path, 'r', errors='ignore') as f:
        for word in f:
            word = word.strip()
            for variant in apply_rules(word):
                if hash_func(variant.encode()).hexdigest() == target_hash:
                    return variant
    return None

# Example
target = hashlib.md5(b"Password123").hexdigest()
result = crack_with_rules(target, "wordlist.txt")
print(f"Cracked: {result}")
```

### Brute Force Generator

```python
#!/usr/bin/env python3
"""Brute force password generator"""

import hashlib
import itertools
import string

def brute_force(target_hash, charset, min_len, max_len, hash_func=hashlib.md5):
    """Brute force crack"""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            if hash_func(candidate.encode()).hexdigest() == target_hash:
                return candidate
    return None

# Example: Crack 4-digit PIN
target = hashlib.md5(b"1234").hexdigest()
result = brute_force(target, string.digits, 4, 4)
print(f"PIN: {result}")

# Example: Crack short lowercase password
target = hashlib.md5(b"cat").hexdigest()
result = brute_force(target, string.ascii_lowercase, 1, 4)
print(f"Password: {result}")
```

## Rainbow Tables

### How They Work

```
Traditional:          Rainbow Table:
┌──────────────┐      ┌────────────────────────────────────────────┐
│ For each     │      │ Pre-compute chains:                        │
│ candidate:   │      │                                            │
│ hash(word)   │      │ Start -> Hash -> Reduce -> Hash -> ... End │
│ compare      │      │                                            │
└──────────────┘      │ Store only Start and End                   │
                      │ Regenerate chain to find password          │
                      └────────────────────────────────────────────┘
```

### Using RainbowCrack

```bash
# Generate rainbow tables
rtgen md5 loweralpha 1 7 0 3800 33554432 0

# Sort tables
rtsort .

# Crack hash
rcrack . -h 5d41402abc4b2a76b9719d911017c592
```

### Online Rainbow Tables

- **CrackStation** - https://crackstation.net/
- **Hashes.com** - https://hashes.com/
- **MD5Decrypt** - https://md5decrypt.net/

## CTF Challenges

### Challenge 1: Basic MD5

```
Hash: e10adc3949ba59abbe56e057f20f883e
```
Crack this MD5 hash.

### Challenge 2: SHA-256 with Rules

```
Hash: 5e884898da28047d9165091e2205ad02ba4aca1a7c34e8d3c0b87b3462f13a8e
```
Hint: It's a common word with modifications.

### Challenge 3: NTLM Hash

```
Hash: 32ed87bdb5fdc5e9cba88547376818d4
```
Windows NTLM hash. Find the password.

### Challenge 4: Salted Hash

```
Salt: deadbeef
Hash (SHA256): 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```
Crack the salted password.

### Challenge 5: bcrypt

```
$2a$10$N9qo8uLOickgx2ZMRZoMy.MrPSCr9YH9Q7xZLqvA6j5e8dKjPf7qC
```
Crack this bcrypt hash. Hint: Very common password.

## Tasks

- [ ] Crack MD5 hashes using hashcat
- [ ] Create custom rules for password patterns
- [ ] Use John the Ripper on Linux shadow file
- [ ] Build a Python dictionary cracker
- [ ] Use online rainbow tables
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{cr4ck_th3_h4sh}`

## Security Best Practices

### For Developers

1. **Use strong hashing:** bcrypt, Argon2, PBKDF2
2. **Unique salts:** Per-password random salt
3. **High work factor:** Make hashing slow
4. **Upgrade legacy hashes:** On user login

### For Users

1. **Long passwords:** 16+ characters
2. **Unique passwords:** Never reuse
3. **Password manager:** Generate random passwords
4. **Enable 2FA:** Additional protection layer

## Tools Summary

| Tool | Purpose | Best For |
|------|---------|----------|
| Hashcat | GPU cracking | Fast, complex attacks |
| John | CPU cracking | Versatile, many formats |
| CrackStation | Online lookup | Quick checks |
| Hydra | Online brute force | Web/network logins |
| Cewl | Wordlist generation | Target-specific lists |

## Next Steps

After mastering password cracking:
- **Lab 07: Steganography** - Hidden data in images
- **Lab 08: Crypto Attacks** - Advanced cryptographic attacks

## References

- [Hashcat Wiki](https://hashcat.net/wiki/)
- [John the Ripper Documentation](https://www.openwall.com/john/doc/)
- [SecLists Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
- [Have I Been Pwned](https://haveibeenpwned.com/)
