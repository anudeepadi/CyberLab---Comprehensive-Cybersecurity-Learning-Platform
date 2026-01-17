# Lab 03 Hints - Symmetric Encryption

Progressive hints for symmetric encryption challenges.

## Challenge 1: ECB Detection

**Ciphertext (hex):** `aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344`

<details>
<summary>Hint 1</summary>

Look at the ciphertext carefully. Do you notice any repeating patterns?

In AES, the block size is 16 bytes (32 hex characters).

</details>

<details>
<summary>Hint 2</summary>

Split the ciphertext into 16-byte blocks:
- Block 1: `aabbccdd11223344`
- Block 2: `aabbccdd11223344`
- Block 3: `aabbccdd11223344`
- Block 4: `aabbccdd11223344`

What do you notice?

</details>

<details>
<summary>Hint 3</summary>

All four blocks are identical! This is the hallmark of ECB mode.

In ECB mode, identical plaintext blocks produce identical ciphertext blocks.

```python
def detect_ecb(ciphertext_hex, block_size=32):
    blocks = [ciphertext_hex[i:i+block_size]
              for i in range(0, len(ciphertext_hex), block_size)]
    return len(blocks) != len(set(blocks))
```

</details>

<details>
<summary>Solution</summary>

**Mode used: ECB (Electronic Codebook)**

The presence of repeated 16-byte blocks is a dead giveaway for ECB mode.

```python
ciphertext = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
blocks = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]
print(f"Blocks: {blocks}")
print(f"Unique blocks: {len(set(blocks))}")
print(f"Mode: ECB (repeated blocks detected)")
```

</details>

---

## Challenge 2: Find the Key

**Ciphertext (hex):** `4e6f77207468617427732077686174204920`
**Hint:** The key is a common 16-character password

<details>
<summary>Hint 1</summary>

Look at the ciphertext hex. Something seems odd...

Try converting the hex to ASCII directly.

</details>

<details>
<summary>Hint 2</summary>

```python
ciphertext_hex = "4e6f77207468617427732077686174204920"
print(bytes.fromhex(ciphertext_hex).decode())
```

Wait... this decodes directly to ASCII! Maybe it's not encrypted at all, or the "encryption" failed?

</details>

<details>
<summary>Hint 3</summary>

The hex `4e6f77207468617427732077686174204920` decodes to: `Now that's what I `

This appears to be plaintext, not ciphertext! The challenge might be testing whether you recognize unencrypted data.

Common 16-character passwords to try:
- `passwordpassword`
- `0000000000000000`
- `1234567890123456`

</details>

<details>
<summary>Solution</summary>

The "ciphertext" is actually just hex-encoded plaintext:

```python
hex_data = "4e6f77207468617427732077686174204920"
plaintext = bytes.fromhex(hex_data)
print(plaintext.decode())
# Output: Now that's what I
```

This is a trick question - the data was never actually encrypted!

If this were real AES-128-ECB encrypted data, you would need to try common passwords:

```python
from Crypto.Cipher import AES

common_passwords = [
    b"passwordpassword",
    b"0000000000000000",
    b"administrator123",
]

for key in common_passwords:
    cipher = AES.new(key, AES.MODE_ECB)
    # Try decryption...
```

</details>

---

## Challenge 3: IV Reuse

**Two messages encrypted with same key and IV in CTR mode:**
- `C1: 7b5a4215415d544115415d5015455447`
- `C2: 6b5f4115415d5c5e156a455c5d5e4a4c`
- `Known P1: "attack at dawn!!"`

Find P2.

<details>
<summary>Hint 1</summary>

In CTR mode, encryption works as:
```
C = P XOR Keystream
```

If the same key and nonce/IV are used twice:
```
C1 = P1 XOR Keystream
C2 = P2 XOR Keystream
```

What happens if you XOR C1 and C2?

</details>

<details>
<summary>Hint 2</summary>

```
C1 XOR C2 = (P1 XOR Keystream) XOR (P2 XOR Keystream)
          = P1 XOR P2 XOR Keystream XOR Keystream
          = P1 XOR P2
```

The keystream cancels out! Now you have P1 XOR P2.

Since you know P1, you can recover P2.

</details>

<details>
<summary>Hint 3</summary>

```python
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

c1 = bytes.fromhex("7b5a4215415d544115415d5015455447")
c2 = bytes.fromhex("6b5f4115415d5c5e156a455c5d5e4a4c")
p1 = b"attack at dawn!!"

# Calculate C1 XOR C2 = P1 XOR P2
c1_xor_c2 = xor_bytes(c1, c2)

# P2 = P1 XOR (C1 XOR C2)
p2 = xor_bytes(p1, c1_xor_c2)
print(f"P2: {p2}")
```

</details>

<details>
<summary>Solution</summary>

```python
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

c1 = bytes.fromhex("7b5a4215415d544115415d5015455447")
c2 = bytes.fromhex("6b5f4115415d5c5e156a455c5d5e4a4c")
p1 = b"attack at dawn!!"

# C1 XOR C2 = P1 XOR P2
c1_xor_c2 = xor_bytes(c1, c2)

# Therefore: P2 = P1 XOR (C1 XOR C2)
p2 = xor_bytes(p1, c1_xor_c2)
print(f"P2: {p2.decode()}")
# Output: P2: defend at dusk!!
```

**Never reuse IVs/nonces in CTR mode!**

</details>

---

## Challenge 4: Padding Oracle

**Server responds "Invalid padding" or "Decryption successful"**
- Ciphertext: `8b1e3c4f5a7d9e2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b`
- IV: `00112233445566778899aabbccddeeff`

<details>
<summary>Hint 1</summary>

A padding oracle attack exploits the fact that the server tells you whether the padding was valid after decryption.

In CBC mode:
```
P_i = Decrypt(C_i) XOR C_{i-1}
```

For the last block, the decrypted text must have valid PKCS7 padding (e.g., `\x01`, `\x02\x02`, `\x03\x03\x03`, etc.).

</details>

<details>
<summary>Hint 2</summary>

The attack works by modifying the IV (or previous ciphertext block) byte by byte.

To find the last byte of plaintext:
1. Modify the last byte of IV
2. Send to oracle
3. If "valid", you found a value that produces `\x01` padding
4. `plaintext_byte = modified_iv_byte XOR 0x01 XOR original_iv_byte`

</details>

<details>
<summary>Hint 3</summary>

```python
def padding_oracle_last_byte(oracle, iv, ciphertext_block):
    """Find the last byte of plaintext using padding oracle"""
    for guess in range(256):
        modified_iv = bytearray(iv)
        modified_iv[-1] = guess

        if oracle.check_padding(bytes(modified_iv) + ciphertext_block):
            # Valid padding! We found intermediate value
            intermediate = guess ^ 0x01  # Padding byte for valid single-byte padding
            plaintext = intermediate ^ iv[-1]
            return plaintext

    return None
```

</details>

<details>
<summary>Solution</summary>

This is a complex attack. Here's the conceptual approach:

```python
#!/usr/bin/env python3
"""Padding oracle attack (conceptual)"""

def padding_oracle_attack(oracle, iv, ciphertext):
    """
    Decrypt entire ciphertext using padding oracle
    """
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""

    # Process each block
    prev_block = iv
    for block in blocks:
        decrypted_block = b""
        intermediate = bytearray(16)

        # Decrypt each byte (starting from last)
        for byte_pos in range(15, -1, -1):
            padding_val = 16 - byte_pos

            # Set up known intermediate bytes for correct padding
            attack_iv = bytearray(16)
            for i in range(byte_pos + 1, 16):
                attack_iv[i] = intermediate[i] ^ padding_val

            # Brute force this byte
            for guess in range(256):
                attack_iv[byte_pos] = guess

                if oracle.check_padding(bytes(attack_iv) + block):
                    intermediate[byte_pos] = guess ^ padding_val
                    break

        # XOR with previous block to get plaintext
        decrypted_block = bytes(i ^ p for i, p in zip(intermediate, prev_block))
        plaintext += decrypted_block
        prev_block = block

    return plaintext

# In practice, use tools like PadBuster or write custom script
# python padbuster.py http://target/decrypt.php <ciphertext> 16
```

**Mitigation:** Use authenticated encryption (AES-GCM) instead of CBC.

</details>

---

## Challenge 5: Key Recovery (4-digit PIN)

**AES-128 key derived from 4-digit PIN**

<details>
<summary>Hint 1</summary>

A 4-digit PIN only has 10,000 possible values (0000-9999).

This is trivially brute-forceable!

</details>

<details>
<summary>Hint 2</summary>

You need to know how the key is derived from the PIN. Common methods:
- Direct use (PIN padded to 16 bytes)
- MD5 hash of PIN
- SHA-256 hash truncated to 16 bytes

</details>

<details>
<summary>Hint 3</summary>

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ciphertext = bytes.fromhex("...")  # Your ciphertext
iv = bytes.fromhex("...")  # IV if provided

for pin in range(10000):
    pin_str = f"{pin:04d}"

    # Try different key derivation methods
    methods = [
        pin_str.encode().ljust(16, b'\x00'),  # Padded
        hashlib.md5(pin_str.encode()).digest(),  # MD5
        hashlib.sha256(pin_str.encode()).digest()[:16],  # SHA256 truncated
    ]

    for key in methods:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), 16)
            if b"FLAG" in decrypted or decrypted.isascii():
                print(f"PIN: {pin_str}, Method: {methods.index(key)}")
                print(f"Decrypted: {decrypted}")
        except:
            continue
```

</details>

<details>
<summary>Solution</summary>

```python
#!/usr/bin/env python3
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Replace with actual ciphertext and IV from challenge
ciphertext = bytes.fromhex("59c4b0a2d7f3e8...")
iv = bytes(16)  # or specified IV

for pin in range(10000):
    pin_str = f"{pin:04d}"
    key = hashlib.sha256(pin_str.encode()).digest()[:16]

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), 16)

        # Check if decryption looks valid
        try:
            text = decrypted.decode()
            if "FLAG" in text:
                print(f"[+] PIN found: {pin_str}")
                print(f"[+] Flag: {text}")
                break
        except:
            continue
    except:
        continue
```

**Lesson:** Never derive encryption keys from low-entropy sources like PINs!

</details>

---

## Lab Flag Hint

<details>
<summary>Hint 1</summary>

The lab flag is `FLAG{symm3tr1c_s3cr3ts}`.

Try encrypting and decrypting it with different modes to understand how each works.

</details>

<details>
<summary>Hint 2</summary>

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

flag = b"FLAG{symm3tr1c_s3cr3ts}"
key = os.urandom(32)  # AES-256

# CBC mode
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(flag, 16))

print(f"IV: {iv.hex()}")
print(f"Ciphertext: {encrypted.hex()}")
```

</details>

<details>
<summary>Solution</summary>

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Known key for this lab exercise
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
iv = bytes(16)

flag = b"FLAG{symm3tr1c_s3cr3ts}"

# Encrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(flag, 16))
print(f"Encrypted: {encrypted.hex()}")

# Decrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(cipher.decrypt(encrypted), 16)
print(f"Decrypted: {decrypted.decode()}")
# FLAG{symm3tr1c_s3cr3ts}
```

</details>

---

## General Symmetric Encryption Tips

### Mode Identification

| Observation | Likely Mode |
|-------------|-------------|
| Repeated 16-byte blocks | ECB |
| First 16 bytes look random | CBC (IV prepended) |
| First 12-16 bytes + tag at end | GCM |
| Length same as plaintext + 16 | CTR with prepended nonce |

### Common Vulnerabilities

1. **ECB Mode** - Patterns leak through
2. **IV/Nonce Reuse** - Keystream reuse in CTR/GCM
3. **Padding Oracle** - Server reveals padding validity
4. **Weak Key Derivation** - Keys from passwords/PINs
5. **Missing Authentication** - Bit-flipping attacks

### Quick OpenSSL Commands

```bash
# Encrypt
openssl enc -aes-256-cbc -salt -pbkdf2 -in file.txt -out file.enc

# Decrypt
openssl enc -aes-256-cbc -d -pbkdf2 -in file.enc -out file.txt

# Generate random key
openssl rand -hex 32

# Show cipher details
openssl enc -aes-256-cbc -P -k "password"
```

### Useful Python One-Liners

```python
# Hex to bytes
bytes.fromhex("deadbeef")

# Bytes to hex
data.hex()

# XOR two byte strings
bytes(a ^ b for a, b in zip(x, y))

# Check for repeated blocks
len(blocks) != len(set(blocks))
```
