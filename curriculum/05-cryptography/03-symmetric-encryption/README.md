# Lab 03 - Symmetric Encryption

Master modern symmetric encryption algorithms used to protect data in the real world.

## Overview

**Difficulty:** Intermediate
**Duration:** 1.5 hours
**Category:** Modern Cryptography
**Flag:** `FLAG{symm3tr1c_s3cr3ts}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand symmetric encryption principles
2. Work with AES in various modes (ECB, CBC, CTR, GCM)
3. Use OpenSSL for encryption operations
4. Identify weaknesses in symmetric encryption implementations
5. Perform basic block cipher attacks

## What is Symmetric Encryption?

**Symmetric encryption** uses the same key for both encryption and decryption:

```
                     SYMMETRIC ENCRYPTION

    ┌───────────┐      [SECRET KEY]       ┌───────────┐
    │ Plaintext │ ─────────────────────> │ Ciphertext│
    └───────────┘        Encrypt          └───────────┘

    ┌───────────┐      [SECRET KEY]       ┌───────────┐
    │ Plaintext │ <───────────────────── │ Ciphertext│
    └───────────┘        Decrypt          └───────────┘
```

**Key Properties:**
- Same key for encrypt and decrypt
- Fast (much faster than asymmetric)
- Key must be kept secret
- Key distribution is the main challenge

## Common Symmetric Algorithms

### 1. AES (Advanced Encryption Standard)

The current gold standard for symmetric encryption.

| Property | Value |
|----------|-------|
| Block Size | 128 bits (16 bytes) |
| Key Sizes | 128, 192, or 256 bits |
| Rounds | 10, 12, or 14 (based on key size) |
| Status | NSA approved for TOP SECRET |

### 2. DES (Data Encryption Standard) - DEPRECATED

| Property | Value |
|----------|-------|
| Block Size | 64 bits (8 bytes) |
| Key Size | 56 bits (effectively) |
| Status | **BROKEN** - Do not use |

### 3. 3DES (Triple DES) - DEPRECATED

| Property | Value |
|----------|-------|
| Block Size | 64 bits |
| Key Size | 168 bits (3 keys) |
| Status | **Deprecated** - Use AES instead |

### 4. ChaCha20

| Property | Value |
|----------|-------|
| Type | Stream cipher |
| Key Size | 256 bits |
| Status | Modern alternative to AES |

## Block vs Stream Ciphers

```
BLOCK CIPHER (AES, DES)
┌────────────────────────────────────┐
│ Plaintext divided into fixed blocks│
│ [Block 1][Block 2][Block 3]...     │
│      ↓        ↓        ↓           │
│ [Cipher1][Cipher2][Cipher3]...     │
└────────────────────────────────────┘

STREAM CIPHER (ChaCha20, RC4)
┌────────────────────────────────────┐
│ Keystream XORed with plaintext     │
│ Byte-by-byte encryption            │
│ P1 ⊕ K1 = C1, P2 ⊕ K2 = C2, ...   │
└────────────────────────────────────┘
```

## Block Cipher Modes of Operation

### ECB (Electronic Codebook) - INSECURE

Each block encrypted independently with same key.

```
Plaintext:  [Block1] [Block2] [Block1] [Block3]
                ↓        ↓        ↓        ↓
Ciphertext: [Cipher1][Cipher2][Cipher1][Cipher3]
                ^                   ^
                └───── SAME! ───────┘
```

**Problem:** Identical plaintext blocks produce identical ciphertext blocks.

**The ECB Penguin:**
```
Original Image    ECB Encrypted     CBC Encrypted
┌────────────┐    ┌────────────┐    ┌────────────┐
│            │    │            │    │░░░░░░░░░░░░│
│   (o  o)   │ -> │   (o  o)   │    │░░░░░░░░░░░░│
│    /__\    │    │    /__\    │    │░░░░░░░░░░░░│
│            │    │            │    │░░░░░░░░░░░░│
└────────────┘    └────────────┘    └────────────┘
  Penguin!        Still visible!    Random noise
```

### CBC (Cipher Block Chaining)

Each block XORed with previous ciphertext before encryption.

```
       IV
       ↓
P1 -> XOR -> [AES] -> C1
              ↓
P2 --------> XOR -> [AES] -> C2
                     ↓
P3 --------------> XOR -> [AES] -> C3
```

**Properties:**
- Requires Initialization Vector (IV)
- IV must be unpredictable
- Vulnerable to padding oracle attacks

### CTR (Counter Mode)

Turns block cipher into stream cipher.

```
       ┌─────────────────────────────────────┐
       │     Nonce + Counter                 │
       │     [Nonce|0] [Nonce|1] [Nonce|2]   │
       │         ↓         ↓         ↓       │
       │      [AES]     [AES]     [AES]      │
       │         ↓         ↓         ↓       │
       │  P1 -> XOR   P2->XOR   P3->XOR      │
       │         ↓         ↓         ↓       │
       │        C1        C2        C3       │
       └─────────────────────────────────────┘
```

**Properties:**
- Parallelizable (faster)
- No padding needed
- Nonce must NEVER be reused with same key

### GCM (Galois/Counter Mode)

CTR mode + authentication (AEAD).

```
Authenticated Encryption with Associated Data (AEAD)
┌──────────────────────────────────────────────┐
│ Input:  Key, Nonce, Plaintext, Associated    │
│ Output: Ciphertext, Authentication Tag       │
│                                              │
│ - Encryption (confidentiality)               │
│ - Authentication (integrity)                 │
│ - Detects tampering                          │
└──────────────────────────────────────────────┘
```

## Padding Schemes

Block ciphers require input to be multiple of block size.

### PKCS#7 Padding

```
Block size: 16 bytes

Input (10 bytes): "HELLO WORLD"
Padding needed: 16 - 10 = 6 bytes
Padded: "HELLO WORLD\x06\x06\x06\x06\x06\x06"

Input (16 bytes): "HELLOWORLDHELLO!"
Padding needed: 16 bytes (add full block)
Padded: "HELLOWORLDHELLO!\x10\x10\x10...(16 times)"
```

### Padding Oracle Attack

If an application reveals whether padding is valid:

1. Attacker modifies ciphertext
2. Sends to decryption oracle
3. Oracle responds "valid" or "invalid" padding
4. Attacker can decrypt entire message byte-by-byte

## OpenSSL Commands

### Generate Random Key

```bash
# Generate 256-bit key (32 bytes)
openssl rand -hex 32

# Generate key and IV
openssl rand -hex 32 > key.txt
openssl rand -hex 16 > iv.txt
```

### AES Encryption

```bash
# AES-256-CBC encryption with password
openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.bin -k "password"

# AES-256-CBC decryption
openssl enc -aes-256-cbc -d -in encrypted.bin -out decrypted.txt -k "password"

# With explicit key and IV (hex)
openssl enc -aes-256-cbc -in plaintext.txt -out encrypted.bin \
    -K $(cat key.txt) -iv $(cat iv.txt)

# ECB mode (insecure - for demonstration)
openssl enc -aes-128-ecb -in plaintext.txt -out encrypted.bin -K 00112233445566778899aabbccddeeff
```

### View Cipher Information

```bash
# List all ciphers
openssl enc -list

# Get cipher details
openssl enc -aes-256-cbc -P -k "password" -S "0123456789abcdef"
```

## Python Implementation

### Using cryptography library

```python
#!/usr/bin/env python3
"""AES encryption examples using cryptography library"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# ============================================================================
# AES-CBC Encryption
# ============================================================================

def aes_cbc_encrypt(plaintext, key, iv):
    """AES-CBC encryption with PKCS7 padding"""
    # Pad plaintext to block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

def aes_cbc_decrypt(ciphertext, key, iv):
    """AES-CBC decryption with PKCS7 unpadding"""
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext

# ============================================================================
# AES-ECB (Insecure - for demonstration only)
# ============================================================================

def aes_ecb_encrypt(plaintext, key):
    """AES-ECB encryption - INSECURE, for demonstration only"""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_ecb_decrypt(ciphertext, key):
    """AES-ECB decryption"""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# ============================================================================
# AES-GCM (Authenticated Encryption)
# ============================================================================

def aes_gcm_encrypt(plaintext, key, nonce, associated_data=b""):
    """AES-GCM authenticated encryption"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag

def aes_gcm_decrypt(ciphertext, key, nonce, tag, associated_data=b""):
    """AES-GCM authenticated decryption"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Generate random key and IV
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV

    plaintext = b"FLAG{symm3tr1c_s3cr3ts}"

    print("=" * 50)
    print("AES-CBC Example")
    print("=" * 50)
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")

    decrypted = aes_cbc_decrypt(ciphertext, key, iv)
    print(f"Decrypted:  {decrypted}")

    print("\n" + "=" * 50)
    print("AES-GCM Example (Authenticated)")
    print("=" * 50)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext, tag = aes_gcm_encrypt(plaintext, key, nonce)
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Auth Tag:   {tag.hex()}")

    decrypted = aes_gcm_decrypt(ciphertext, key, nonce, tag)
    print(f"Decrypted:  {decrypted}")
```

### Using PyCryptodome

```python
#!/usr/bin/env python3
"""AES encryption examples using PyCryptodome"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key, mode='CBC'):
    """Encrypt with AES"""
    if mode == 'CBC':
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ciphertext
    elif mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, AES.block_size))
    elif mode == 'GCM':
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce + tag + ciphertext

def aes_decrypt(data, key, mode='CBC'):
    """Decrypt with AES"""
    if mode == 'CBC':
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), AES.block_size)
    elif mode == 'GCM':
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

# Example
key = get_random_bytes(32)  # AES-256
plaintext = b"Secret message here"

encrypted = aes_encrypt(plaintext, key, 'GCM')
decrypted = aes_decrypt(encrypted, key, 'GCM')
print(f"Original:  {plaintext}")
print(f"Decrypted: {decrypted}")
```

## CTF Challenges

### Challenge 1: ECB Detection

You intercepted this ciphertext (hex). What mode was used?
```
aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344
```

### Challenge 2: Find the Key

This message was encrypted with AES-128-ECB using a weak key:
```
Ciphertext (hex): 4e6f77207468617427732077686174204920
Key hint: The key is a common 16-character password
```

### Challenge 3: IV Reuse

Two messages encrypted with the same key and IV in CTR mode:
```
C1: 7b5a4215415d544115415d5015455447
C2: 6b5f4115415d5c5e156a455c5d5e4a4c
Known P1: "attack at dawn!!"
```
Find P2.

### Challenge 4: Padding Oracle

A server responds with "Invalid padding" or "Decryption successful":
```
Ciphertext: 8b1e3c4f5a7d9e2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b
IV: 00112233445566778899aabbccddeeff
```
Can you decrypt the message?

### Challenge 5: Key Recovery

AES-128 was used with a key derived from a 4-digit PIN:
```
Ciphertext: 59c4b0a2d7f3e8...
```
Brute force the PIN and decrypt.

## Common Vulnerabilities

### 1. ECB Mode Usage
- Patterns in plaintext visible in ciphertext
- Easy to detect with image encryption

### 2. Key Reuse with CTR/GCM
- Nonce reuse allows XOR of plaintexts
- Catastrophic for security

### 3. Weak Key Derivation
- Using passwords directly as keys
- Insufficient iterations in PBKDF2

### 4. Missing Authentication
- CBC without HMAC allows bit-flipping
- Always use authenticated modes (GCM)

### 5. Predictable IVs
- IV must be random/unpredictable
- Reusing IVs breaks CBC security

## Tools

### Online Tools
- **CyberChef** - AES encryption/decryption
- **Cryptii** - Multiple cipher modes
- **aesencryption.net** - Online AES tool

### Command Line
- **OpenSSL** - Comprehensive crypto toolkit
- **xxd** - Hex dump utility
- **base64** - Encoding utility

### Python Libraries
- **cryptography** - Modern crypto library
- **PyCryptodome** - Fork of PyCrypto
- **pyaes** - Pure Python AES

## Tasks

- [ ] Encrypt a file using AES-256-CBC with OpenSSL
- [ ] Demonstrate the ECB penguin vulnerability
- [ ] Implement AES encryption in Python
- [ ] Perform a padding oracle attack (simulated)
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{symm3tr1c_s3cr3ts}`

## Next Steps

After mastering symmetric encryption:
- **Lab 04: Asymmetric Encryption** - RSA and public key cryptography
- **Lab 08: Crypto Attacks** - Advanced attacks on implementations

## References

- [NIST AES Specification (FIPS 197)](https://csrc.nist.gov/publications/detail/fips/197/final)
- [Block Cipher Modes (NIST SP 800-38A)](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [Padding Oracle Attacks](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
- [The Cryptography Library Docs](https://cryptography.io/en/latest/)
