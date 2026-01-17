# Lab 01 - Encoding Basics

Master the fundamentals of data encoding - the essential first step in understanding cryptography.

## Overview

**Difficulty:** Beginner
**Duration:** 45 minutes
**Category:** Cryptography Fundamentals
**Flag:** `FLAG{3nc0d1ng_n0t_3ncrypt10n}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand the difference between encoding and encryption
2. Recognize common encoding schemes (Base64, Hex, URL, ASCII)
3. Encode and decode data using command-line tools
4. Use CyberChef for complex encoding operations
5. Identify encoding types from their characteristics

## What is Encoding?

**Encoding** is the process of converting data from one format to another for proper transmission or storage. Unlike encryption, encoding is:

- **Reversible without a key** - Anyone can decode it
- **Not meant for security** - It provides no confidentiality
- **Format transformation** - Changes how data is represented

```
     ENCODING (No Key Required)

     "Hello" ──[Base64 Encode]──> "SGVsbG8="
     "SGVsbG8=" ──[Base64 Decode]──> "Hello"

     ENCRYPTION (Key Required)

     "Hello" + KEY ──[Encrypt]──> "x#$@!"
     "x#$@!" + KEY ──[Decrypt]──> "Hello"
```

## Common Encoding Schemes

### 1. ASCII (American Standard Code for Information Interchange)

Maps characters to numbers (0-127).

| Character | Decimal | Hex | Binary |
|-----------|---------|-----|--------|
| A | 65 | 0x41 | 01000001 |
| a | 97 | 0x61 | 01100001 |
| 0 | 48 | 0x30 | 00110000 |
| Space | 32 | 0x20 | 00100000 |

```bash
# ASCII to decimal
echo -n "A" | od -An -td1
# Output: 65

# Decimal to ASCII
printf "\x41"
# Output: A
```

### 2. Hexadecimal (Base16)

Represents binary data using 16 symbols (0-9, A-F).

**Characteristics:**
- Each hex digit = 4 bits
- Two hex digits = 1 byte
- Only contains: 0-9, A-F (case insensitive)
- Often prefixed with `0x` or suffixed with `h`

```bash
# Text to Hex
echo -n "Hello" | xxd -p
# Output: 48656c6c6f

# Hex to Text
echo "48656c6c6f" | xxd -r -p
# Output: Hello
```

### 3. Base64

Represents binary data using 64 printable ASCII characters.

**Characteristics:**
- Alphabet: A-Z, a-z, 0-9, +, /
- Padding: Uses `=` at the end (0, 1, or 2)
- Output is ~33% larger than input
- Common in email, web, data URIs

```bash
# Encode
echo -n "Hello World" | base64
# Output: SGVsbG8gV29ybGQ=

# Decode
echo "SGVsbG8gV29ybGQ=" | base64 -d
# Output: Hello World
```

**Variations:**
- **Base64URL:** Uses `-` and `_` instead of `+` and `/` (URL-safe)
- **Base32:** Uses A-Z, 2-7 (case insensitive)

### 4. URL Encoding (Percent Encoding)

Encodes special characters for safe URL transmission.

**Format:** `%XX` where XX is the hex value

| Character | URL Encoded |
|-----------|-------------|
| Space | %20 or + |
| < | %3C |
| > | %3E |
| # | %23 |
| & | %26 |
| = | %3D |

```bash
# Python URL encoding
python3 -c "import urllib.parse; print(urllib.parse.quote('Hello World!'))"
# Output: Hello%20World%21

# Python URL decoding
python3 -c "import urllib.parse; print(urllib.parse.unquote('Hello%20World%21'))"
# Output: Hello World!
```

### 5. Binary

Raw binary representation using 0s and 1s.

```bash
# Convert text to binary
echo -n "Hi" | xxd -b | cut -d' ' -f2-7
# Output: 01001000 01101001
```

## Identifying Encoding Types

| Encoding | Characteristics | Example |
|----------|-----------------|---------|
| Hex | 0-9, a-f only | `48656c6c6f` |
| Base64 | A-Z, a-z, 0-9, +, /, = | `SGVsbG8=` |
| Base32 | A-Z, 2-7, = | `JBSWY3DP` |
| URL | % followed by hex | `Hello%20World` |
| Binary | 0s and 1s only | `01001000` |
| Octal | 0-7 only | `110 145 154 154 157` |

## Python Encoding Toolkit

```python
#!/usr/bin/env python3
"""Encoding utilities for CTF challenges"""

import base64
import urllib.parse
from binascii import hexlify, unhexlify

def all_decodes(data):
    """Try common decodings on input data"""
    print(f"Input: {data}\n")

    # Try Base64
    try:
        decoded = base64.b64decode(data).decode()
        print(f"[+] Base64: {decoded}")
    except:
        print("[-] Base64: Failed")

    # Try Hex
    try:
        decoded = unhexlify(data).decode()
        print(f"[+] Hex: {decoded}")
    except:
        print("[-] Hex: Failed")

    # Try URL
    try:
        decoded = urllib.parse.unquote(data)
        if decoded != data:
            print(f"[+] URL: {decoded}")
    except:
        pass

    # ASCII values (space-separated)
    try:
        values = data.split()
        decoded = ''.join(chr(int(v)) for v in values)
        print(f"[+] ASCII Decimal: {decoded}")
    except:
        pass

def multi_decode(data, depth=5):
    """Recursively decode nested encodings"""
    print(f"Level 0: {data}")

    for i in range(1, depth + 1):
        # Try Base64
        try:
            data = base64.b64decode(data).decode()
            print(f"Level {i} (Base64): {data}")
            continue
        except:
            pass

        # Try Hex
        try:
            if all(c in '0123456789abcdefABCDEF' for c in data):
                data = unhexlify(data).decode()
                print(f"Level {i} (Hex): {data}")
                continue
        except:
            pass

        break

    return data

if __name__ == "__main__":
    # Test multi-layer decoding
    # This is "FLAG{nested}" encoded: Base64(Hex(Base64(text)))
    encoded = "NTI0NzRjNGI0ODMwNWE1ODRhNjg1NTMyNTY3YTY0NDc1NjkzNTk1ODRlNmY1OTMyNTU3YQ=="
    multi_decode(encoded)
```

## Tools

### Command Line

```bash
# base64
echo -n "text" | base64           # Encode
echo "dGV4dA==" | base64 -d       # Decode

# xxd (Hex)
echo -n "text" | xxd -p           # Encode
echo "74657874" | xxd -r -p       # Decode

# od (Octal/Decimal)
echo -n "A" | od -An -to1         # Octal
echo -n "A" | od -An -td1         # Decimal

# Python one-liners
python3 -c "import base64; print(base64.b64decode('dGV4dA==').decode())"
python3 -c "print(bytes.fromhex('74657874').decode())"
```

### CyberChef

CyberChef is a web-based tool for encoding/decoding operations:

**URL:** https://gchq.github.io/CyberChef/

Key Features:
- Drag and drop operations (recipes)
- Magic mode - auto-detect encoding
- Chain multiple operations
- Supports 300+ operations

Common Operations:
- From Base64 / To Base64
- From Hex / To Hex
- URL Decode / URL Encode
- From Binary / To Binary
- ROT13 (rotate by 13)

## CTF Challenges

### Challenge 1: Simple Base64
Decode this flag:
```
RkxBR3tiYXNlNjRfaXNfZWFzeX0=
```

### Challenge 2: Hex Encoded
Decode this hex string:
```
464c41477b6865785f6465636f64696e677d
```

### Challenge 3: Nested Encoding
This flag has multiple layers. Decode it:
```
NTI0NzRjNGI0ODM1NmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA==
```

### Challenge 4: Mixed Encoding
Decode this URL-encoded, Base64 string:
```
VkRKV2VtUklTbXhqTTFaNlpFaEtkbVJZVW14amJUVm9Xa2RXZVU1WFVubFpNamt4WW0xc2JHTnRWakJqU0Vwc1dtMDVNMlJIVm5OaU0wWXdZM2s0ZUU1dE9URmpiVlp6V2xkR2VtTXlWblZrUjFaNVRGaGtiRnBIVW5wTlIxWjVUR3hLY0dNelVteGhTRUV6VFdsM2VFOUVWWGhOUkdNMQ==
```

### Challenge 5: Binary Message
Convert this binary to text:
```
01000110 01001100 01000001 01000111 01111011 01100010 00110001 01101110 01100001 01110010 01111001 01011111 01101101 00110000 01100100 00110011 01111101
```

## Common Mistakes to Avoid

1. **Confusing encoding with encryption** - Encoding provides NO security
2. **Wrong padding in Base64** - Must be multiple of 4 characters
3. **Hex case sensitivity** - Usually case-insensitive, but check
4. **Newline issues** - `echo` adds newline, use `echo -n`
5. **URL encoding spaces** - Can be `%20` or `+`

## Tasks

- [ ] Identify and decode 3 different encoding types
- [ ] Use CyberChef to decode a multi-layer encoded string
- [ ] Write a Python script that auto-detects encoding
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{3nc0d1ng_n0t_3ncrypt10n}`

## Next Steps

After mastering encoding, proceed to:
- **Lab 02: Classical Ciphers** - Learn historical encryption techniques
- **Lab 03: Symmetric Encryption** - Modern encryption with shared keys

## References

- [CyberChef - GCHQ](https://gchq.github.io/CyberChef/)
- [ASCII Table](https://www.asciitable.com/)
- [Base64 RFC 4648](https://tools.ietf.org/html/rfc4648)
- [URL Encoding Reference](https://www.w3schools.com/tags/ref_urlencode.asp)
