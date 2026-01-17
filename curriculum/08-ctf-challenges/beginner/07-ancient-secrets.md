# Challenge 07 - Ancient Secrets

**Category:** Cryptography
**Difficulty:** Beginner
**Points:** 100
**Target:** Local (No Docker required)

## Challenge Description

An ancient scroll has been discovered with a mysterious message. The Romans used this encryption technique thousands of years ago, and it's still found in CTF challenges today.

Your mission is to decrypt this classical cipher and reveal the hidden flag.

## The Encrypted Message

```
SYNT{p43f4e_jnf_u3e3}
```

Hint: Julius Caesar would approve of this cipher...

## Objectives

- Identify the cipher type
- Understand how the cipher works
- Decrypt the message
- Find the flag

---

## Hints

<details>
<summary>Hint 1 (Cost: -10 points)</summary>

This is a Caesar cipher - a substitution cipher where each letter is shifted by a fixed number of positions in the alphabet.

</details>

<details>
<summary>Hint 2 (Cost: -20 points)</summary>

The most common Caesar cipher variant is ROT13, which shifts letters by 13 positions. Since the alphabet has 26 letters, ROT13 is its own inverse.

</details>

<details>
<summary>Hint 3 (Cost: -30 points)</summary>

Use CyberChef's ROT13 operation, or in the terminal:
```bash
echo "SYNT{p43f4e_jnf_u3e3}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Identify the Cipher

Looking at the ciphertext: `SYNT{p43f4e_jnf_u3e3}`

Observations:
- Maintains the FLAG{...} structure
- Only letters are changed
- Numbers and special characters unchanged
- This is characteristic of a Caesar cipher

### Step 2: Understand Caesar/ROT13

**Caesar Cipher:**
- Shifts each letter by N positions
- A becomes B (shift 1), or A becomes N (shift 13)
- Wraps around: Z + 1 = A

**ROT13 (Rotation by 13):**
```
Plain:  ABCDEFGHIJKLMNOPQRSTUVWXYZ
Cipher: NOPQRSTUVWXYZABCDEFGHIJKLM

S -> F, Y -> L, N -> A, T -> G
```

### Step 3: Decrypt

**Method 1: Command Line**
```bash
echo "SYNT{p43f4e_jnf_u3e3}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: FLAG{c43s4r_was_h3r3}
```

**Method 2: Python**
```python
import codecs
encrypted = "SYNT{p43f4e_jnf_u3e3}"
decrypted = codecs.decode(encrypted, 'rot_13')
print(decrypted)
# Output: FLAG{c43s4r_was_h3r3}
```

**Method 3: CyberChef**
1. Go to https://gchq.github.io/CyberChef/
2. Add "ROT13" operation
3. Paste the ciphertext
4. Read the output

**Method 4: Manual Decryption**
```
S -> F (S is 13 positions after F)
Y -> L
N -> A
T -> G

p -> c
4 -> 4 (numbers unchanged)
3 -> 3
f -> s
...
```

### Result

```
FLAG{c43s4r_was_h3r3}
```

### Understanding Caesar Ciphers

**Strengths:**
- Simple to implement
- Easy to understand

**Weaknesses:**
- Only 25 possible keys (trivial brute force)
- Frequency analysis reveals patterns
- Not suitable for real security

### Brute Force Script

If you didn't know the shift value:

```python
#!/usr/bin/env python3
"""Brute force all Caesar cipher rotations"""

def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

ciphertext = "SYNT{p43f4e_jnf_u3e3}"

print("Trying all 26 rotations:\n")
for i in range(26):
    decrypted = caesar_decrypt(ciphertext, i)
    print(f"ROT-{i:02d}: {decrypted}")
    if "FLAG" in decrypted:
        print(f"\n[+] Found likely flag at ROT-{i}!")
```

### Related Ciphers

| Cipher | Description |
|--------|-------------|
| Caesar | Shift by N positions |
| ROT13 | Shift by 13 (self-inverse) |
| ROT47 | ROT13 for ASCII characters |
| Atbash | A=Z, B=Y (mirror alphabet) |
| Vigenere | Multiple Caesar ciphers with keyword |

</details>

---

## Flag

```
FLAG{c43s4r_was_h3r3}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Classical cipher identification
- Caesar/ROT13 decryption
- Command-line text manipulation
- Using cryptography tools

## Tools Used

- tr (Unix command)
- Python codecs module
- CyberChef
- Custom scripts

## Bonus Challenges

1. Encrypt your own message with ROT13
2. Write a script to brute force all 26 rotations
3. Try to crack a ROT47 cipher (includes numbers/symbols)

## ROT13 Fun Facts

- Used in forums to hide spoilers
- Early internet "encryption" for jokes
- Self-inverse: encrypt and decrypt are the same operation
- Still used in some CTF challenges as a "warm-up"

## Related Challenges

- [03 - Decode Me](03-decode-me.md) - Multi-layer encoding
- [Crypto Cascade (Advanced)](../advanced/05-crypto-cascade.md) - Complex ciphers

## References

- [Caesar Cipher - Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [Cryptography 101](https://cryptohack.org/courses/intro/course_details/)
