# Lab 02 - Classical Ciphers

Explore the history of cryptography by learning and breaking classical ciphers that laid the foundation for modern encryption.

## Overview

**Difficulty:** Beginner
**Duration:** 1 hour
**Category:** Cryptography Fundamentals
**Flag:** `FLAG{cl4ss1c4l_cr4ck3d}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand substitution and transposition cipher principles
2. Encrypt and decrypt using Caesar cipher
3. Break Vigenere cipher with known techniques
4. Perform frequency analysis on ciphertext
5. Use automated tools to identify and crack classical ciphers

## Historical Context

Classical ciphers were used from ancient times through World War II. Understanding them provides insight into:

- **Cryptographic principles** that still apply today
- **Cryptanalysis techniques** used to break modern systems
- **Why modern encryption** evolved to be more complex

```
    TIMELINE OF CLASSICAL CRYPTOGRAPHY

    500 BCE        100 BCE       1500s        1920s
       │              │            │            │
       ▼              ▼            ▼            ▼
    ┌──────┐     ┌────────┐   ┌─────────┐  ┌────────┐
    │Spartan│     │ Caesar │   │Vigenere │  │ Enigma │
    │Scytale│     │ Cipher │   │ Cipher  │  │Machine │
    └──────┘     └────────┘   └─────────┘  └────────┘
       ↓              ↓            ↓            ↓
  Transposition   Simple      Polyalphabetic  Mechanical
                 Substitution  Substitution   Encryption
```

## Types of Classical Ciphers

### 1. Substitution Ciphers

Each letter is replaced by another letter or symbol.

#### Caesar Cipher (Shift Cipher)

Shifts each letter by a fixed number of positions.

```
Alphabet:  ABCDEFGHIJKLMNOPQRSTUVWXYZ
Shift 3:   DEFGHIJKLMNOPQRSTUVWXYZABC

Plaintext:  HELLO
Ciphertext: KHOOR
```

**Python Implementation:**

```python
def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Example
plaintext = "HELLO WORLD"
encrypted = caesar_encrypt(plaintext, 3)
print(f"Encrypted: {encrypted}")  # KHOOR ZRUOG

decrypted = caesar_decrypt(encrypted, 3)
print(f"Decrypted: {decrypted}")  # HELLO WORLD
```

#### ROT13

A special case of Caesar cipher with shift 13. It's self-reversing!

```bash
echo "HELLO" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: URYYB

echo "URYYB" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: HELLO
```

#### Simple Substitution Cipher

Each letter maps to a different letter (26! possible keys).

```
Plaintext alphabet:  ABCDEFGHIJKLMNOPQRSTUVWXYZ
Ciphertext alphabet: QWERTYUIOPASDFGHJKLZXCVBNM

Plaintext:  HELLO
Ciphertext: ITSSG
```

### 2. Polyalphabetic Ciphers

#### Vigenere Cipher

Uses a keyword to determine different shifts for each letter.

```
Key:        KEYKEYKEYKE
Plaintext:  ATTACKATDAWN
            ↓↓↓↓↓↓↓↓↓↓↓↓
Ciphertext: KXVARNOBKHYR
```

**How it works:**
- K shifts A by 10 (K=10) → K
- E shifts T by 4 (E=4) → X
- Y shifts T by 24 (Y=24) → R
- ...and so on, repeating the key

**Python Implementation:**

```python
def vigenere_encrypt(plaintext, key):
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

# Example
plaintext = "ATTACK AT DAWN"
key = "KEY"
encrypted = vigenere_encrypt(plaintext, key)
print(f"Encrypted: {encrypted}")  # KXVARK EX NHGR
```

### 3. Transposition Ciphers

Letters are rearranged rather than substituted.

#### Rail Fence Cipher

Write plaintext in a zigzag pattern, then read row by row.

```
Plaintext: WEAREDISCOVERED (3 rails)

W . . . E . . . C . . . R . .
. E . R . D . S . O . E . E .
. . A . . . I . . . V . . . D

Ciphertext: WECREDSOEEIDAERV
```

#### Columnar Transposition

Write plaintext in rows under a keyword, then read columns in alphabetical order.

```
Key: SECRET (alphabetical order: 3,2,1,5,4,6)
     S E C R E T
     3 2 1 5 4 6
     ---------
     W E A R E D
     I S C O V E
     R E D X X X

Reading columns by order (1,2,3,4,5,6): ACDESESWIREXVORX
```

## Cryptanalysis Techniques

### Frequency Analysis

English letters have predictable frequencies:

```
Most Common Letters:    E T A O I N S H R
Frequency (approx):     13% 9% 8% 8% 7% 7% 6% 6% 6%

Common Digraphs: TH, HE, IN, ER, AN, RE
Common Trigraphs: THE, AND, ING, ION, TIO
```

**Python Frequency Analysis:**

```python
from collections import Counter

def frequency_analysis(text):
    """Analyze letter frequencies in text"""
    # Count only letters
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters)

    if total == 0:
        return {}

    freq = Counter(letters)
    # Convert to percentages
    return {char: (count/total)*100 for char, count in freq.most_common()}

# Standard English frequencies
english_freq = {'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
                'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3}

ciphertext = "KHOOR ZRUOG"
print(frequency_analysis(ciphertext))
```

### Kasiski Examination

Used to find Vigenere key length by looking for repeated sequences.

```python
def find_repeated_sequences(ciphertext, min_length=3):
    """Find repeated sequences and their distances"""
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    sequences = {}

    for length in range(min_length, min(10, len(ciphertext)//2)):
        for i in range(len(ciphertext) - length):
            seq = ciphertext[i:i+length]
            if seq in sequences:
                sequences[seq].append(i)
            else:
                sequences[seq] = [i]

    # Return sequences that appear more than once
    return {seq: positions for seq, positions in sequences.items()
            if len(positions) > 1}

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def likely_key_length(ciphertext):
    """Estimate Vigenere key length using Kasiski method"""
    from math import gcd
    from functools import reduce

    repeated = find_repeated_sequences(ciphertext)
    distances = []

    for seq, positions in repeated.items():
        for i in range(len(positions) - 1):
            distances.append(positions[i+1] - positions[i])

    if not distances:
        return None

    # GCD of all distances suggests key length
    return reduce(gcd, distances)
```

### Index of Coincidence

Measures how likely two random letters are the same.

- **English text:** ~0.067
- **Random text:** ~0.038

Used to determine if a cipher is monoalphabetic or polyalphabetic, and to find key length.

## Tools

### Online Tools

- **dcode.fr** - Cipher identification and solving
- **quipqiup.com** - Substitution cipher solver
- **CyberChef** - ROT13, Vigenere, various ciphers
- **guballa.de/vigenere-solver** - Vigenere breaker

### Command Line

```bash
# ROT13
echo "URYYB" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Caesar brute force (all 26 shifts)
for i in {0..25}; do
    echo "Shift $i: $(echo 'KHOOR' | tr $(printf '%s' {A..Z} | cut -c$((i+1))-26)$(printf '%s' {A..Z} | cut -c1-$i) 'A-Z')"
done
```

### Python Tools

```python
#!/usr/bin/env python3
"""Classical cipher toolkit"""

def caesar_bruteforce(ciphertext):
    """Try all 26 Caesar shifts"""
    print("Caesar Cipher Brute Force:")
    print("-" * 40)
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        print(f"Shift {shift:2d}: {decrypted}")

def detect_cipher_type(ciphertext):
    """Attempt to identify cipher type"""
    # Remove non-alpha characters
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())

    if len(text) < 20:
        print("Warning: Short text, analysis may be unreliable")

    freq = frequency_analysis(text)
    ic = index_of_coincidence(text)

    print(f"Index of Coincidence: {ic:.4f}")
    print(f"Most common letters: {list(freq.keys())[:5]}")

    if ic > 0.06:
        print("Likely: Monoalphabetic substitution (Caesar, simple sub)")
    elif ic > 0.04:
        print("Likely: Polyalphabetic substitution (Vigenere)")
    else:
        print("Likely: Transposition or complex cipher")

def index_of_coincidence(text):
    """Calculate Index of Coincidence"""
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n <= 1:
        return 0

    freq = Counter(text)
    total = sum(f * (f - 1) for f in freq.values())
    return total / (n * (n - 1))
```

## CTF Challenges

### Challenge 1: Simple Caesar

Decrypt this Caesar cipher:
```
HNSL{pncvnr_zhfgre}
```

### Challenge 2: Unknown Shift

The shift is unknown. Find the plaintext:
```
YMJWJ NX ST XJHWJY YMFY YNR BNQQ STY WJAJFQ
```

### Challenge 3: Vigenere

This is encrypted with Vigenere. The key is 4 letters long:
```
GFLKTGKCSCPWHWBXAXCITYGKJVTG
```
Hint: The key is a common English word.

### Challenge 4: Substitution

Solve this simple substitution cipher using frequency analysis:
```
GSV JFRXP YILDM ULC QFNKH LEVI GSV OZAB WLT
```

### Challenge 5: Mixed Cipher

This uses a combination of techniques:
```
SYNG{zvkrq_pvcuref_ner_sha}
```

## Common Patterns

### Identifying Caesar Cipher
- Only 26 possible keys
- Frequency distribution matches English (but shifted)
- Common words might be recognizable after shifting

### Identifying Vigenere
- Flatter frequency distribution
- Repeated patterns in ciphertext
- Index of Coincidence between 0.04-0.06

### Identifying Simple Substitution
- 26! possible keys
- Frequency distribution matches English
- Patterns like double letters preserved

## Tasks

- [ ] Encrypt and decrypt a message using Caesar cipher
- [ ] Brute force a Caesar cipher using all 26 shifts
- [ ] Perform frequency analysis on English ciphertext
- [ ] Use Kasiski examination to find Vigenere key length
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{cl4ss1c4l_cr4ck3d}`

## Next Steps

After mastering classical ciphers:
- **Lab 03: Symmetric Encryption** - Modern encryption with AES
- **Lab 04: Asymmetric Encryption** - Public key cryptography

## References

- [Practical Cryptography](http://practicalcryptography.com/)
- [dcode.fr Cipher Identifier](https://www.dcode.fr/cipher-identifier)
- [CryptoCorner - Classical Ciphers](https://crypto.interactive-maths.com/)
- [Kasiski Examination](https://en.wikipedia.org/wiki/Kasiski_examination)
