# Lab 03 Walkthrough - Symmetric Encryption

Step-by-step guide to mastering symmetric encryption with hands-on exercises.

## Setup

### Install Required Tools

```bash
# Install Python cryptography libraries
pip3 install cryptography pycryptodome

# Verify OpenSSL is installed
openssl version
```

### Create the Symmetric Encryption Toolkit

Save this as `symmetric_toolkit.py`:

```python
#!/usr/bin/env python3
"""Symmetric Encryption Toolkit for CyberLab"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import binascii

# ============================================================================
# AES-CBC ENCRYPTION/DECRYPTION
# ============================================================================

def aes_cbc_encrypt(plaintext, key, iv=None):
    """AES-CBC encryption with PKCS7 padding"""
    if iv is None:
        iv = os.urandom(16)

    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    # Pad plaintext to block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext  # Prepend IV

def aes_cbc_decrypt(data, key):
    """AES-CBC decryption with PKCS7 unpadding"""
    iv = data[:16]
    ciphertext = data[16:]

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext

# ============================================================================
# AES-ECB ENCRYPTION/DECRYPTION (INSECURE - FOR DEMONSTRATION)
# ============================================================================

def aes_ecb_encrypt(plaintext, key):
    """AES-ECB encryption - INSECURE, for demonstration only"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

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
# AES-CTR ENCRYPTION/DECRYPTION
# ============================================================================

def aes_ctr_encrypt(plaintext, key, nonce=None):
    """AES-CTR encryption"""
    if nonce is None:
        nonce = os.urandom(16)

    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return nonce + ciphertext

def aes_ctr_decrypt(data, key):
    """AES-CTR decryption"""
    nonce = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# ============================================================================
# AES-GCM AUTHENTICATED ENCRYPTION
# ============================================================================

def aes_gcm_encrypt(plaintext, key, nonce=None, associated_data=b""):
    """AES-GCM authenticated encryption"""
    if nonce is None:
        nonce = os.urandom(12)

    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return nonce + encryptor.tag + ciphertext  # nonce(12) + tag(16) + ciphertext

def aes_gcm_decrypt(data, key, associated_data=b""):
    """AES-GCM authenticated decryption"""
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hex_to_bytes(hex_string):
    """Convert hex string to bytes"""
    return binascii.unhexlify(hex_string)

def bytes_to_hex(data):
    """Convert bytes to hex string"""
    return binascii.hexlify(data).decode()

def xor_bytes(a, b):
    """XOR two byte strings"""
    return bytes(x ^ y for x, y in zip(a, b))

def detect_ecb(ciphertext, block_size=16):
    """Detect ECB mode by finding repeated blocks"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    unique_blocks = set(blocks)
    return len(blocks) != len(unique_blocks)

def analyze_ciphertext(ciphertext):
    """Analyze ciphertext for common patterns"""
    print("=" * 50)
    print("CIPHERTEXT ANALYSIS")
    print("=" * 50)
    print(f"Length: {len(ciphertext)} bytes")
    print(f"Hex: {bytes_to_hex(ciphertext)[:64]}...")

    # Check for ECB patterns
    if detect_ecb(ciphertext):
        print("[!] WARNING: Repeated 16-byte blocks detected!")
        print("    This suggests ECB mode - INSECURE!")
    else:
        print("[+] No repeated blocks detected")

    # Check if length is multiple of 16 (block cipher)
    if len(ciphertext) % 16 == 0:
        print(f"[+] Length is multiple of 16 (likely block cipher)")

    print("=" * 50)

# ============================================================================
# PADDING ORACLE SIMULATOR
# ============================================================================

class PaddingOracle:
    """Simulated padding oracle for educational purposes"""

    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        return aes_cbc_encrypt(plaintext, self.key)

    def check_padding(self, ciphertext):
        """Returns True if padding is valid, False otherwise"""
        try:
            aes_cbc_decrypt(ciphertext, self.key)
            return True
        except:
            return False

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("Symmetric Encryption Toolkit")
    print("=" * 50)
    print("Functions available:")
    print("  aes_cbc_encrypt(plaintext, key, iv=None)")
    print("  aes_cbc_decrypt(data, key)")
    print("  aes_ecb_encrypt(plaintext, key)")
    print("  aes_ecb_decrypt(ciphertext, key)")
    print("  aes_ctr_encrypt(plaintext, key, nonce=None)")
    print("  aes_ctr_decrypt(data, key)")
    print("  aes_gcm_encrypt(plaintext, key, nonce=None)")
    print("  aes_gcm_decrypt(data, key)")
    print("  detect_ecb(ciphertext)")
    print("  analyze_ciphertext(ciphertext)")
    print("  xor_bytes(a, b)")
    print("=" * 50)

    # Demo
    key = os.urandom(32)  # 256-bit key
    plaintext = b"FLAG{symm3tr1c_s3cr3ts}"

    print("\n[*] Demo: Encrypting flag with AES-256-CBC")
    encrypted = aes_cbc_encrypt(plaintext, key)
    print(f"Ciphertext (hex): {bytes_to_hex(encrypted)}")

    decrypted = aes_cbc_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted.decode()}")
```

## Exercise 1: AES-CBC Encryption with OpenSSL

### Step 1: Generate Key and IV

```bash
# Generate random 256-bit key (32 bytes in hex = 64 chars)
openssl rand -hex 32 > key.txt
cat key.txt

# Generate random 128-bit IV (16 bytes in hex = 32 chars)
openssl rand -hex 16 > iv.txt
cat iv.txt
```

### Step 2: Create a Test File

```bash
echo "This is a secret message!" > plaintext.txt
```

### Step 3: Encrypt with AES-256-CBC

```bash
# Encrypt using key and IV
openssl enc -aes-256-cbc -in plaintext.txt -out encrypted.bin \
    -K $(cat key.txt) -iv $(cat iv.txt)

# View encrypted data in hex
xxd encrypted.bin
```

### Step 4: Decrypt

```bash
# Decrypt
openssl enc -aes-256-cbc -d -in encrypted.bin -out decrypted.txt \
    -K $(cat key.txt) -iv $(cat iv.txt)

# Verify
cat decrypted.txt
```

### Step 5: Using Password-Based Encryption

```bash
# Encrypt with password (uses PBKDF2 to derive key)
openssl enc -aes-256-cbc -salt -pbkdf2 -in plaintext.txt -out encrypted_pw.bin

# Decrypt with password
openssl enc -aes-256-cbc -d -pbkdf2 -in encrypted_pw.bin -out decrypted_pw.txt
```

## Exercise 2: Demonstrating ECB Weakness

### Step 1: Create Repeating Data

```bash
# Create a file with repeated patterns
python3 -c "print('AAAAAAAAAAAAAAAA' * 10)" > repeated.txt
```

### Step 2: Encrypt with ECB vs CBC

```bash
# Generate key
KEY=$(openssl rand -hex 16)

# ECB encryption (insecure)
openssl enc -aes-128-ecb -in repeated.txt -out ecb_encrypted.bin -K $KEY

# CBC encryption (secure)
IV=$(openssl rand -hex 16)
openssl enc -aes-128-cbc -in repeated.txt -out cbc_encrypted.bin -K $KEY -iv $IV

# Compare - ECB will have repeated blocks!
echo "ECB encrypted (notice patterns):"
xxd ecb_encrypted.bin

echo -e "\nCBC encrypted (random looking):"
xxd cbc_encrypted.bin
```

### Step 3: Analyze with Python

```python
from symmetric_toolkit import *

# Read the encrypted files
with open('ecb_encrypted.bin', 'rb') as f:
    ecb_data = f.read()

with open('cbc_encrypted.bin', 'rb') as f:
    cbc_data = f.read()

print("ECB Analysis:")
analyze_ciphertext(ecb_data)

print("\nCBC Analysis:")
analyze_ciphertext(cbc_data)
```

## Exercise 3: The ECB Penguin

### Step 1: Create Simple Image

```python
#!/usr/bin/env python3
"""Demonstrate ECB mode weakness with image encryption"""

from PIL import Image
import os

# Create a simple image with patterns
width, height = 128, 128
img = Image.new('RGB', (width, height), 'white')
pixels = img.load()

# Draw a simple pattern (black circle on white)
for x in range(width):
    for y in range(height):
        if (x - 64)**2 + (y - 64)**2 < 900:
            pixels[x, y] = (0, 0, 0)  # Black
        else:
            pixels[x, y] = (255, 255, 255)  # White

img.save('original.bmp')
print("[+] Created original.bmp")
```

### Step 2: Encrypt Image Header-Aware

```python
#!/usr/bin/env python3
"""Encrypt BMP image with ECB and CBC to show difference"""

from symmetric_toolkit import *

# Read image
with open('original.bmp', 'rb') as f:
    data = f.read()

# BMP header is typically 54 bytes
header = data[:54]
body = data[54:]

key = os.urandom(16)  # AES-128

# Encrypt body only with ECB
ecb_encrypted = aes_ecb_encrypt(body, key)
with open('ecb_penguin.bmp', 'wb') as f:
    f.write(header + ecb_encrypted[:len(body)])

# Encrypt body only with CBC
cbc_encrypted = aes_cbc_encrypt(body, key)
# Remove IV from CBC output for fair comparison
with open('cbc_penguin.bmp', 'wb') as f:
    f.write(header + cbc_encrypted[16:16+len(body)])

print("[+] Created ecb_penguin.bmp - patterns visible!")
print("[+] Created cbc_penguin.bmp - looks like noise")
```

## Exercise 4: CTR Mode and Nonce Reuse Attack

### Step 1: Understand CTR Mode

```python
from symmetric_toolkit import *

key = os.urandom(32)
plaintext1 = b"Attack at dawn!!"  # 16 bytes
plaintext2 = b"Defend the fort!"  # 16 bytes

# Safe: Different nonces
nonce1 = os.urandom(16)
nonce2 = os.urandom(16)

c1 = aes_ctr_encrypt(plaintext1, key, nonce1)
c2 = aes_ctr_encrypt(plaintext2, key, nonce2)

print("Safe CTR usage:")
print(f"C1: {bytes_to_hex(c1)}")
print(f"C2: {bytes_to_hex(c2)}")
```

### Step 2: Demonstrate Nonce Reuse Vulnerability

```python
# DANGEROUS: Same nonce reused!
nonce = os.urandom(16)

c1 = aes_ctr_encrypt(plaintext1, key, nonce)
c2 = aes_ctr_encrypt(plaintext2, key, nonce)

print("\n[!] DANGEROUS: Nonce reuse!")
print(f"C1: {bytes_to_hex(c1)}")
print(f"C2: {bytes_to_hex(c2)}")

# In CTR mode: C1 = P1 XOR Keystream, C2 = P2 XOR Keystream
# Therefore: C1 XOR C2 = P1 XOR P2

c1_body = c1[16:]  # Remove nonce
c2_body = c2[16:]

xored = xor_bytes(c1_body, c2_body)
print(f"\nC1 XOR C2: {bytes_to_hex(xored)}")
print(f"P1 XOR P2: {bytes_to_hex(xor_bytes(plaintext1, plaintext2))}")
print("These should match! Attacker can now recover plaintexts.")
```

### Step 3: Crib Dragging Attack

```python
def crib_drag(xored_plaintexts, crib):
    """Try a known word at each position"""
    crib = crib.encode() if isinstance(crib, str) else crib
    results = []

    for i in range(len(xored_plaintexts) - len(crib) + 1):
        segment = xored_plaintexts[i:i+len(crib)]
        possible = xor_bytes(segment, crib)
        try:
            decoded = possible.decode('ascii')
            if all(c.isprintable() or c.isspace() for c in decoded):
                results.append((i, decoded))
        except:
            pass

    return results

# If we know P1 contains "Attack"
p1_xor_p2 = xor_bytes(plaintext1, plaintext2)
results = crib_drag(p1_xor_p2, "Attack")
print("\nCrib drag results for 'Attack':")
for pos, text in results:
    print(f"  Position {pos}: '{text}'")
```

## Exercise 5: AES-GCM Authenticated Encryption

### Step 1: Encrypt with Authentication

```python
from symmetric_toolkit import *

key = os.urandom(32)
plaintext = b"Top secret message"
associated_data = b"Header: Unencrypted but authenticated"

# Encrypt
encrypted = aes_gcm_encrypt(plaintext, key, associated_data=associated_data)
print(f"Encrypted (with auth tag): {bytes_to_hex(encrypted)}")

# Decrypt
decrypted = aes_gcm_decrypt(encrypted, key, associated_data=associated_data)
print(f"Decrypted: {decrypted.decode()}")
```

### Step 2: Detect Tampering

```python
# Modify one byte of ciphertext
tampered = bytearray(encrypted)
tampered[-1] ^= 0x01  # Flip one bit
tampered = bytes(tampered)

try:
    aes_gcm_decrypt(tampered, key, associated_data=associated_data)
    print("Decryption succeeded - BAD!")
except Exception as e:
    print(f"[+] Tampering detected! Error: {type(e).__name__}")
```

## Exercise 6: Padding Oracle Attack (Educational)

### Step 1: Understand the Vulnerability

```python
from symmetric_toolkit import PaddingOracle

# Create oracle
key = os.urandom(32)
oracle = PaddingOracle(key)

# Encrypt a message
plaintext = b"Secret message!!"
ciphertext = oracle.encrypt(plaintext)

print(f"Ciphertext: {bytes_to_hex(ciphertext)}")
print(f"Valid padding: {oracle.check_padding(ciphertext)}")

# Corrupt ciphertext
corrupted = bytearray(ciphertext)
corrupted[-1] ^= 0x01
print(f"Corrupted valid: {oracle.check_padding(bytes(corrupted))}")
```

### Step 2: Simplified Attack Demonstration

```python
#!/usr/bin/env python3
"""Simplified padding oracle attack demonstration"""

def padding_oracle_attack_block(oracle, iv, block):
    """
    Decrypt one block using padding oracle
    This is simplified for educational purposes
    """
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    # For each byte (starting from last)
    for byte_index in range(15, -1, -1):
        padding_value = 16 - byte_index

        # Craft IV to get correct padding for already-found bytes
        crafted_iv = bytearray(16)
        for i in range(byte_index + 1, 16):
            crafted_iv[i] = intermediate[i] ^ padding_value

        # Try all possible values for current byte
        for guess in range(256):
            crafted_iv[byte_index] = guess
            test_cipher = bytes(crafted_iv) + block

            if oracle.check_padding(test_cipher):
                intermediate[byte_index] = guess ^ padding_value
                plaintext[byte_index] = intermediate[byte_index] ^ iv[byte_index]
                break

    return bytes(plaintext)

# Note: Full implementation requires handling edge cases
print("[*] Padding oracle attacks decrypt ciphertext byte-by-byte")
print("[*] They exploit applications that reveal padding validity")
print("[*] Mitigation: Use authenticated encryption (GCM)")
```

## Solving CTF Challenges

### Challenge 1: ECB Detection

```python
# Given ciphertext (hex)
ciphertext_hex = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
ciphertext = hex_to_bytes(ciphertext_hex)

# Check for repeated blocks
if detect_ecb(ciphertext):
    print("[+] ECB mode detected! Repeated blocks found.")
else:
    print("[-] Not ECB mode")
```

### Challenge 3: IV Reuse in CTR Mode

```python
# Given values
c1_hex = "7b5a4215415d544115415d5015455447"
c2_hex = "6b5f4115415d5c5e156a455c5d5e4a4c"
p1 = b"attack at dawn!!"

c1 = hex_to_bytes(c1_hex)
c2 = hex_to_bytes(c2_hex)

# C1 XOR C2 = P1 XOR P2 (when same key and nonce used)
c1_xor_c2 = xor_bytes(c1, c2)

# P2 = P1 XOR (C1 XOR C2)
p2 = xor_bytes(p1, c1_xor_c2)
print(f"P2: {p2.decode()}")
```

### Challenge 5: Weak Key Derivation

```python
import hashlib

# 4-digit PIN brute force
ciphertext_hex = "59c4b0a2d7f3e8..."  # Full ciphertext from challenge
ciphertext = hex_to_bytes(ciphertext_hex)

for pin in range(10000):
    # Derive key from PIN (weak!)
    pin_str = f"{pin:04d}"
    key = hashlib.sha256(pin_str.encode()).digest()[:16]  # AES-128

    try:
        decrypted = aes_cbc_decrypt(ciphertext, key)
        if b"FLAG" in decrypted:
            print(f"PIN: {pin_str}")
            print(f"Decrypted: {decrypted}")
            break
    except:
        continue
```

## Finding the Lab Flag

The flag for this lab is `FLAG{symm3tr1c_s3cr3ts}`. Here's how to verify:

```python
from symmetric_toolkit import *

# The flag encrypted with a known key
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
iv = bytes.fromhex("00000000000000000000000000000000")

# Encrypt the flag
flag = b"FLAG{symm3tr1c_s3cr3ts}"
encrypted = aes_cbc_encrypt(flag, key, iv)
print(f"Encrypted flag: {bytes_to_hex(encrypted)}")

# Decrypt to verify
decrypted = aes_cbc_decrypt(encrypted, key)
print(f"Flag: {decrypted.decode()}")
```

## Summary

In this lab, you learned:

1. **AES Block Cipher** - Modern standard with 128/192/256-bit keys
2. **ECB Mode** - Insecure, reveals patterns in plaintext
3. **CBC Mode** - Requires IV, vulnerable to padding oracle
4. **CTR Mode** - Stream cipher mode, vulnerable to nonce reuse
5. **GCM Mode** - Authenticated encryption, prevents tampering
6. **Padding** - PKCS7 padding and its vulnerabilities
7. **OpenSSL** - Command-line encryption/decryption

## Next Lab

Continue to **Lab 04: Asymmetric Encryption** to learn about RSA, key exchange, and digital signatures.
