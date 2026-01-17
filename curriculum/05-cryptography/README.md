# Module 05 - Cryptography

Master the art and science of cryptography, from encoding fundamentals to advanced attacks on cryptographic implementations.

## Module Overview

```
                    CRYPTOGRAPHY LEARNING PATH

    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
    │  01 - Encoding   │ -> │  02 - Classical  │ -> │  03 - Symmetric  │
    │     Basics       │    │     Ciphers      │    │   Encryption     │
    │  (Base64, Hex)   │    │ (Caesar, Vigenere)│    │   (AES, DES)     │
    └──────────────────┘    └──────────────────┘    └──────────────────┘
             │                                               │
             v                                               v
    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
    │  04 - Asymmetric │ <- │   05 - Hashing   │ <- │  06 - Password   │
    │   Encryption     │    │  (MD5, SHA, etc) │    │    Cracking      │
    │   (RSA, ECC)     │    │                  │    │                  │
    └──────────────────┘    └──────────────────┘    └──────────────────┘
             │                                               │
             v                                               v
    ┌──────────────────┐    ┌──────────────────┐
    │ 07 - Steganography│ -> │ 08 - Crypto      │
    │  (Hidden Data)   │    │    Attacks       │
    │                  │    │(Padding Oracle)  │
    └──────────────────┘    └──────────────────┘
```

## Labs Overview

| # | Lab | Difficulty | Duration | Description |
|---|-----|------------|----------|-------------|
| 01 | Encoding Basics | Beginner | 45 min | Base64, Hex, URL encoding, ASCII conversion |
| 02 | Classical Ciphers | Beginner | 1 hr | Caesar, Vigenere, substitution cipher analysis |
| 03 | Symmetric Encryption | Intermediate | 1.5 hrs | AES, DES, block vs stream ciphers |
| 04 | Asymmetric Encryption | Intermediate | 1.5 hrs | RSA, key exchange, digital signatures |
| 05 | Hashing | Intermediate | 1 hr | MD5, SHA family, hash function properties |
| 06 | Password Cracking | Intermediate | 1.5 hrs | Rainbow tables, wordlists, hash cracking |
| 07 | Steganography | Beginner | 45 min | Hiding data in images, audio, and files |
| 08 | Crypto Attacks | Advanced | 2 hrs | Padding oracle, timing attacks, weak crypto |

**Total Duration:** ~12 hours

## Prerequisites

- Basic understanding of binary and hexadecimal
- Python 3 installed with common libraries
- Familiarity with Linux command line
- Understanding of basic math concepts (modular arithmetic helpful)

## Tools Required

### Encoding/Decoding
- **CyberChef** - The Swiss army knife of data transformation
- **Base64** - Command line encoding/decoding
- **xxd** - Hex dump utility

### Encryption Analysis
- **OpenSSL** - Comprehensive cryptography toolkit
- **gpg** - GNU Privacy Guard
- **Python cryptography libraries** - pycryptodome, cryptography

### Hash Cracking
- **John the Ripper** - Versatile password cracker
- **Hashcat** - GPU-accelerated hash cracking
- **hash-identifier** - Hash type identification

### Steganography
- **steghide** - Hide data in images
- **binwalk** - Firmware analysis and extraction
- **exiftool** - Metadata analysis
- **zsteg** - PNG/BMP steganography detection
- **stegseek** - Fast steghide password cracker

## Key Concepts

### Encoding vs Encryption

| Aspect | Encoding | Encryption |
|--------|----------|------------|
| Purpose | Data representation | Data protection |
| Key Required | No | Yes |
| Reversible | Always | Only with key |
| Security | None | Confidentiality |
| Examples | Base64, URL, Hex | AES, RSA, ChaCha20 |

### Symmetric vs Asymmetric Encryption

```
SYMMETRIC (Same key for encrypt/decrypt)
┌─────────┐     [KEY]      ┌─────────┐     [KEY]      ┌─────────┐
│ Message │ ──────────── > │ Cipher  │ ──────────── > │ Message │
└─────────┘    Encrypt     └─────────┘    Decrypt     └─────────┘

ASYMMETRIC (Public/Private key pair)
┌─────────┐  [PUBLIC KEY]  ┌─────────┐ [PRIVATE KEY]  ┌─────────┐
│ Message │ ──────────── > │ Cipher  │ ──────────── > │ Message │
└─────────┘    Encrypt     └─────────┘    Decrypt     └─────────┘
```

### Hash Function Properties

1. **Deterministic** - Same input always produces same output
2. **One-way** - Cannot reverse hash to get original input
3. **Collision-resistant** - Hard to find two inputs with same hash
4. **Avalanche effect** - Small input change causes large hash change

## CTF Crypto Challenge Categories

| Category | Description | Common Tools |
|----------|-------------|--------------|
| Encoding | Multiple layers of encoding | CyberChef, base64, xxd |
| Classical | Breaking historical ciphers | dcode.fr, frequency analysis |
| RSA | Weak key attacks, math exploits | RsaCtfTool, factordb |
| Hash | Cracking or finding collisions | John, hashcat, hash-identifier |
| Block Cipher | ECB, padding oracle attacks | Custom scripts, padding oracle tools |
| Steganography | Hidden data extraction | steghide, binwalk, zsteg |

## Quick Reference Commands

```bash
# Base64 encoding/decoding
echo "Hello" | base64
echo "SGVsbG8K" | base64 -d

# Hex encoding/decoding
echo "Hello" | xxd -p
echo "48656c6c6f0a" | xxd -r -p

# Generate MD5/SHA hashes
echo -n "password" | md5sum
echo -n "password" | sha256sum

# OpenSSL AES encryption
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc -k password
openssl enc -aes-256-cbc -d -in file.enc -out file.txt -k password

# RSA key generation
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Hash cracking with John
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt

# Steghide
steghide embed -cf image.jpg -ef secret.txt
steghide extract -sf image.jpg
```

## Python Crypto Toolkit

```python
#!/usr/bin/env python3
"""CyberLab Crypto Toolkit - Common Operations"""

import base64
import hashlib
from binascii import hexlify, unhexlify

# ===== ENCODING =====
def b64_encode(data):
    """Base64 encode string or bytes"""
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()

def b64_decode(data):
    """Base64 decode to string"""
    return base64.b64decode(data).decode()

def hex_encode(data):
    """Hex encode string or bytes"""
    if isinstance(data, str):
        data = data.encode()
    return hexlify(data).decode()

def hex_decode(data):
    """Hex decode to string"""
    return unhexlify(data).decode()

# ===== HASHING =====
def hash_md5(data):
    """Generate MD5 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.md5(data).hexdigest()

def hash_sha256(data):
    """Generate SHA256 hash"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

# ===== CLASSICAL CIPHERS =====
def caesar_encrypt(text, shift):
    """Caesar cipher encryption"""
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    """Caesar cipher decryption"""
    return caesar_encrypt(text, -shift)

def caesar_bruteforce(ciphertext):
    """Try all 26 Caesar shifts"""
    for shift in range(26):
        print(f"Shift {shift:2d}: {caesar_decrypt(ciphertext, shift)}")

# ===== XOR =====
def xor_bytes(data, key):
    """XOR data with repeating key"""
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def xor_single_byte(data):
    """Try XOR with all single bytes"""
    if isinstance(data, str):
        data = bytes.fromhex(data)
    for key in range(256):
        try:
            result = bytes([b ^ key for b in data])
            decoded = result.decode('utf-8')
            if decoded.isprintable():
                print(f"Key 0x{key:02x} ({key:3d}): {decoded}")
        except:
            pass

if __name__ == "__main__":
    # Example usage
    print("=== Base64 ===")
    print(b64_encode("FLAG{crypto_master}"))

    print("\n=== Hashing ===")
    print(f"MD5:    {hash_md5('password')}")
    print(f"SHA256: {hash_sha256('password')}")

    print("\n=== Caesar ===")
    caesar_bruteforce("HNSL{pncvnr_zhfgre}")
```

## Flags for This Module

| Lab | Flag |
|-----|------|
| 01 - Encoding Basics | `FLAG{3nc0d1ng_n0t_3ncrypt10n}` |
| 02 - Classical Ciphers | `FLAG{cl4ss1c4l_cr4ck3d}` |
| 03 - Symmetric Encryption | `FLAG{symm3tr1c_s3cr3ts}` |
| 04 - Asymmetric Encryption | `FLAG{rsa_m4th_m4st3r}` |
| 05 - Hashing | `FLAG{h4sh_1t_0ut}` |
| 06 - Password Cracking | `FLAG{cr4ck3d_w1th_r0cky0u}` |
| 07 - Steganography | `FLAG{h1dd3n_1n_pl41n_s1ght}` |
| 08 - Crypto Attacks | `FLAG{p4dd1ng_0r4cl3_pwn3d}` |

## References and Resources

### Learning Resources
- [CryptoHack](https://cryptohack.org/) - Interactive cryptography challenges
- [CryptoPals](https://cryptopals.com/) - Crypto challenges by Matasano
- [Khan Academy Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography)

### Tools Documentation
- [CyberChef](https://gchq.github.io/CyberChef/) - Online data manipulation
- [dcode.fr](https://www.dcode.fr/) - Cipher identification and solving
- [FactorDB](http://factordb.com/) - Integer factorization database
- [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) - RSA attack tool

### Cheat Sheets
- [John the Ripper Cheat Sheet](https://countuponsecurity.files.wordpress.com/2016/09/jtr-cheat-sheet.pdf)
- [Hashcat Wiki](https://hashcat.net/wiki/)
- [PayloadsAllTheThings - Hash Cracking](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Hash%20Cracking.md)

## Directory Structure

```
05-cryptography/
├── README.md                      # This file
├── 01-encoding-basics/
│   ├── README.md                  # Encoding concepts
│   ├── walkthrough.md             # CyberChef exercises
│   └── hints.md                   # Progressive hints
├── 02-classical-ciphers/
│   ├── README.md                  # Classical cipher theory
│   ├── walkthrough.md             # Breaking ciphers
│   └── hints.md
├── 03-symmetric-encryption/
│   ├── README.md                  # Symmetric algorithms
│   ├── walkthrough.md             # OpenSSL exercises
│   └── hints.md
├── 04-asymmetric-encryption/
│   ├── README.md                  # RSA, key exchange
│   ├── walkthrough.md             # RSA exercises
│   └── hints.md
├── 05-hashing/
│   ├── README.md                  # Hash functions
│   ├── walkthrough.md             # Hash identification
│   └── hints.md
├── 06-password-cracking/
│   ├── README.md                  # Cracking techniques
│   ├── walkthrough.md             # John/hashcat exercises
│   └── hints.md
├── 07-steganography/
│   ├── README.md                  # Stego concepts
│   ├── walkthrough.md             # Tool usage
│   └── hints.md
└── 08-crypto-attacks/
    ├── README.md                  # Attack vectors
    ├── walkthrough.md             # Practical attacks
    └── hints.md
```
