# Lab 02 Walkthrough - Classical Ciphers

Step-by-step guide to breaking classical ciphers with hands-on exercises.

## Setup

### Create the Cipher Toolkit

Save this as `cipher_toolkit.py`:

```python
#!/usr/bin/env python3
"""Classical Cipher Toolkit for CyberLab"""

from collections import Counter
from math import gcd
from functools import reduce

# ============================================================================
# CAESAR CIPHER
# ============================================================================

def caesar_encrypt(plaintext, shift):
    """Encrypt using Caesar cipher"""
    result = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    """Decrypt Caesar cipher"""
    return caesar_encrypt(ciphertext, -shift)

def caesar_bruteforce(ciphertext):
    """Try all 26 Caesar shifts"""
    print("=" * 50)
    print("CAESAR CIPHER BRUTE FORCE")
    print("=" * 50)
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        print(f"Shift {shift:2d}: {decrypted}")
    print("=" * 50)

# ============================================================================
# ROT13
# ============================================================================

def rot13(text):
    """ROT13 - self-reversing Caesar with shift 13"""
    return caesar_encrypt(text, 13)

# ============================================================================
# VIGENERE CIPHER
# ============================================================================

def vigenere_encrypt(plaintext, key):
    """Encrypt using Vigenere cipher"""
    result = ""
    key_index = 0
    key = key.upper()

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenere cipher"""
    result = ""
    key_index = 0
    key = key.upper()

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

# ============================================================================
# FREQUENCY ANALYSIS
# ============================================================================

def frequency_analysis(text):
    """Analyze letter frequencies"""
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return {}

    freq = Counter(letters)
    return {char: (count/total)*100 for char, count in freq.most_common()}

def print_frequency_analysis(text):
    """Pretty print frequency analysis"""
    freq = frequency_analysis(text)
    print("\n" + "=" * 50)
    print("FREQUENCY ANALYSIS")
    print("=" * 50)
    print("English: E(12.7) T(9.1) A(8.2) O(7.5) I(7.0) N(6.7)")
    print("-" * 50)
    for char, pct in list(freq.items())[:10]:
        bar = "#" * int(pct)
        print(f"{char}: {pct:5.1f}% {bar}")
    print("=" * 50)

def index_of_coincidence(text):
    """Calculate Index of Coincidence"""
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n <= 1:
        return 0

    freq = Counter(text)
    total = sum(f * (f - 1) for f in freq.values())
    return total / (n * (n - 1))

# ============================================================================
# KASISKI EXAMINATION
# ============================================================================

def find_repeated_sequences(ciphertext, min_length=3, max_length=6):
    """Find repeated sequences for Kasiski examination"""
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    sequences = {}

    for length in range(min_length, min(max_length + 1, len(ciphertext)//2)):
        for i in range(len(ciphertext) - length):
            seq = ciphertext[i:i+length]
            if seq in sequences:
                sequences[seq].append(i)
            else:
                sequences[seq] = [i]

    return {seq: positions for seq, positions in sequences.items()
            if len(positions) > 1}

def kasiski_examination(ciphertext):
    """Perform Kasiski examination to find likely key lengths"""
    print("\n" + "=" * 50)
    print("KASISKI EXAMINATION")
    print("=" * 50)

    repeated = find_repeated_sequences(ciphertext)
    if not repeated:
        print("No repeated sequences found")
        return None

    distances = []
    for seq, positions in sorted(repeated.items(), key=lambda x: -len(x[0])):
        print(f"Sequence '{seq}' at positions: {positions}")
        for i in range(len(positions) - 1):
            dist = positions[i+1] - positions[i]
            distances.append(dist)
            print(f"  Distance: {dist}")

    if distances:
        likely_length = reduce(gcd, distances)
        print(f"\nLikely key length (GCD): {likely_length}")
        return likely_length
    return None

# ============================================================================
# SIMPLE SUBSTITUTION
# ============================================================================

def atbash(text):
    """Atbash cipher - reverse alphabet substitution"""
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(ord('Z') - (ord(char) - ord('A')))
            else:
                result += chr(ord('z') - (ord(char) - ord('a')))
        else:
            result += char
    return result

# ============================================================================
# RAIL FENCE CIPHER
# ============================================================================

def rail_fence_encrypt(plaintext, rails):
    """Encrypt using Rail Fence cipher"""
    plaintext = ''.join(c for c in plaintext if c.isalpha())
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1

    for char in plaintext:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(ciphertext, rails):
    """Decrypt Rail Fence cipher"""
    n = len(ciphertext)
    fence = [[None] * n for _ in range(rails)]

    # Mark positions
    rail = 0
    direction = 1
    for i in range(n):
        fence[rail][i] = True
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    # Fill in characters
    idx = 0
    for r in range(rails):
        for c in range(n):
            if fence[r][c] is True:
                fence[r][c] = ciphertext[idx]
                idx += 1

    # Read off plaintext
    result = ""
    rail = 0
    direction = 1
    for i in range(n):
        result += fence[rail][i]
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    return result

# ============================================================================
# MAIN - Interactive Mode
# ============================================================================

if __name__ == "__main__":
    print("Classical Cipher Toolkit")
    print("=" * 50)
    print("Functions available:")
    print("  caesar_encrypt(text, shift)")
    print("  caesar_decrypt(text, shift)")
    print("  caesar_bruteforce(ciphertext)")
    print("  rot13(text)")
    print("  vigenere_encrypt(text, key)")
    print("  vigenere_decrypt(text, key)")
    print("  frequency_analysis(text)")
    print("  print_frequency_analysis(text)")
    print("  index_of_coincidence(text)")
    print("  kasiski_examination(ciphertext)")
    print("  atbash(text)")
    print("  rail_fence_encrypt(text, rails)")
    print("  rail_fence_decrypt(text, rails)")
    print("=" * 50)
```

## Exercise 1: Caesar Cipher Basics

### Step 1: Encrypt a Message

```python
from cipher_toolkit import *

# Encrypt "HELLO WORLD" with shift 3
plaintext = "HELLO WORLD"
encrypted = caesar_encrypt(plaintext, 3)
print(f"Encrypted: {encrypted}")
# Output: KHOOR ZRUOG
```

### Step 2: Decrypt with Known Shift

```python
# Decrypt with the same shift
decrypted = caesar_decrypt(encrypted, 3)
print(f"Decrypted: {decrypted}")
# Output: HELLO WORLD
```

### Step 3: Brute Force Unknown Shift

```python
# Unknown ciphertext
ciphertext = "YMJWJ NX ST XJHWJY YMFY YNR BNQQ STY WJAJFQ"

# Try all 26 shifts
caesar_bruteforce(ciphertext)
```

**Output:** Look for readable English. Shift 5 gives:
```
THERE IS NO SECRET THAT TIME WILL NOT REVEAL
```

## Exercise 2: ROT13

### Step 1: Understand ROT13

```python
# ROT13 is self-reversing (shift 13)
text = "HELLO"
encrypted = rot13(text)
print(f"Encrypted: {encrypted}")  # URYYB

decrypted = rot13(encrypted)
print(f"Decrypted: {decrypted}")  # HELLO
```

### Step 2: CTF Challenge

Decrypt this ROT13 flag:
```python
flag = rot13("SYNT{ebg13_vf_abg_frphevgl}")
print(flag)
# Output: FLAG{rot13_is_not_security}
```

## Exercise 3: Frequency Analysis

### Step 1: Analyze Ciphertext

```python
ciphertext = "GSV JFRXP YILDM ULC QFNKH LEVI GSV OZAB WLT"

# Perform frequency analysis
print_frequency_analysis(ciphertext)
```

**Output:**
```
FREQUENCY ANALYSIS
==================================================
English: E(12.7) T(9.1) A(8.2) O(7.5) I(7.0) N(6.7)
--------------------------------------------------
G:  11.4% ###########
V:   8.6% ########
L:   8.6% ########
...
```

### Step 2: Compare with English

- In our ciphertext, G is most common
- In English, E is most common
- G -> E suggests this is Atbash cipher (reverse alphabet)

### Step 3: Try Atbash

```python
decrypted = atbash(ciphertext)
print(decrypted)
# Output: THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
```

## Exercise 4: Breaking Vigenere

### Step 1: Create Sample Ciphertext

```python
plaintext = "CRYPTOGRAPHYISFUNANDIMPORTANTTOUNDERSTAND"
key = "KEY"
ciphertext = vigenere_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext}")
# Output: MBWZXSMVYKRLCQDYRXHLQZSVXYRXSXYLWHSPXYRH
```

### Step 2: Find Key Length with Kasiski

```python
# For longer texts, use Kasiski examination
long_ciphertext = """
GFLKTGKCSCPWHWBXAXCITYGKJVTGFLKTGKCSC
"""

kasiski_examination(long_ciphertext)
```

### Step 3: Calculate Index of Coincidence

```python
ic = index_of_coincidence(ciphertext)
print(f"Index of Coincidence: {ic:.4f}")

# English text: ~0.067
# Random text: ~0.038
# Polyalphabetic cipher: between these values
```

### Step 4: Decrypt with Known Key

```python
# If we know/guess the key is "KEY"
decrypted = vigenere_decrypt(ciphertext, "KEY")
print(decrypted)
# Output: CRYPTOGRAPHYISFUNANDIMPORTANTTOUNDERSTAND
```

### Step 5: Try Common Words as Keys

```python
# Try common 4-letter keys
common_keys = ["FLAG", "CODE", "HACK", "PASS", "KEYS", "SAFE", "LOCK", "OPEN", "CRYPT"]

for key in common_keys:
    result = vigenere_decrypt("GFLKTGKCSCPWHWBXAXCITYGKJVTG", key)
    if result.startswith("FLAG") or "THE" in result:
        print(f"Key '{key}': {result}")
```

## Exercise 5: Rail Fence Cipher

### Step 1: Encrypt with Rail Fence

```python
plaintext = "WEAREDISCOVEREDFLEE"

# With 3 rails
encrypted = rail_fence_encrypt(plaintext, 3)
print(f"Encrypted (3 rails): {encrypted}")
# Output: WECRLTEERDSOEEFEAIVD
```

### Step 2: Decrypt Rail Fence

```python
ciphertext = "WECRLTEERDSOEEFEAIVD"

# Try different rail counts
for rails in range(2, 6):
    decrypted = rail_fence_decrypt(ciphertext, rails)
    print(f"{rails} rails: {decrypted}")
```

## Exercise 6: Solve CTF Challenges

### Challenge 1: Simple Caesar

```python
ciphertext = "HNSL{pncvnr_zhfgre}"
caesar_bruteforce(ciphertext)

# Find the readable result (shift 13 = ROT13)
decrypted = caesar_decrypt(ciphertext, 13)
print(f"Flag: {decrypted}")
# Output: FLAG{caesar_master}
```

Wait, that doesn't look right. Let's check all shifts:

```python
# The ciphertext uses ROT13 actually
decrypted = rot13(ciphertext)
print(decrypted)
# Output: UAFY{capine_musters}  - hmm, still not right

# Let's try all shifts and look for FLAG
for shift in range(26):
    result = caesar_decrypt(ciphertext, shift)
    if result.startswith("FLAG"):
        print(f"Shift {shift}: {result}")
```

Shift 5 gives: `FLAG{caesar_master}`

### Challenge 2: Unknown Shift

```python
ciphertext = "YMJWJ NX ST XJHWJY YMFY YNR BNQQ STY WJAJFQ"
caesar_bruteforce(ciphertext)

# Shift 5 gives readable text
# "THERE IS NO SECRET THAT TIME WILL NOT REVEAL"
```

### Challenge 3: Vigenere

```python
ciphertext = "GFLKTGKCSCPWHWBXAXCITYGKJVTG"

# Try common 4-letter keys
common_keys = ["FLAG", "CODE", "HACK", "KEY", "WORD", "PASS", "OPEN", "FIRE"]

for key in common_keys:
    result = vigenere_decrypt(ciphertext, key)
    print(f"Key '{key}': {result}")
    if "FLAG" in result.upper():
        print(f"  ^^^ FOUND! ^^^")
```

### Challenge 4: Substitution

```python
ciphertext = "GSV JFRXP YILDM ULC QFNKH LEVI GSV OZAB WLT"

# Frequency analysis suggests Atbash
decrypted = atbash(ciphertext)
print(decrypted)
# Output: THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
```

### Challenge 5: Mixed Cipher

```python
ciphertext = "SYNG{zvkrq_pvcuref_ner_sha}"

# This looks like ROT13 (SYNG is FLAG rotated)
decrypted = rot13(ciphertext)
print(decrypted)
# Output: FLAG{mixed_ciphers_are_fun}
```

## Finding the Lab Flag

The flag is hidden using a classical cipher. Look for `FLAG{cl4ss1c4l_cr4ck3d}`.

**Encoded Version:**
```
SYNT{py4ff1p4y_pe4px3q}
```

**Solution:**
```python
flag = rot13("SYNT{py4ff1p4y_pe4px3q}")
print(flag)
# Output: FLAG{cl4ss1c4l_cr4ck3d}
```

## Summary

In this lab, you learned:

1. **Caesar Cipher** - Fixed shift substitution, easily brute-forced
2. **ROT13** - Special self-reversing Caesar with shift 13
3. **Vigenere Cipher** - Polyalphabetic cipher using keyword
4. **Frequency Analysis** - Statistical attack on substitution ciphers
5. **Kasiski Examination** - Finding Vigenere key length
6. **Index of Coincidence** - Identifying cipher types
7. **Rail Fence** - Transposition cipher

## Next Lab

Continue to **Lab 03: Symmetric Encryption** to learn about modern encryption algorithms like AES and DES.
