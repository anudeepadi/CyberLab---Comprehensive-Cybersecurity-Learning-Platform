# Lab 01 Walkthrough - Encoding Basics

Step-by-step guide to mastering encoding fundamentals with CyberChef and command-line tools.

## Setup

### Required Tools

```bash
# Most tools are pre-installed on Kali Linux
# Verify installations:
which base64 xxd python3

# Open CyberChef in browser
firefox https://gchq.github.io/CyberChef/ &
```

## Exercise 1: ASCII Exploration

**Objective:** Understand ASCII character mapping

### Step 1: View ASCII Table

```bash
# Print ASCII table (partial)
man ascii

# Or use Python
python3 -c "
for i in range(32, 127):
    print(f'{i:3d} 0x{i:02x} {chr(i)}')
"
```

### Step 2: Convert Text to ASCII Values

```bash
# Convert "FLAG" to decimal ASCII
echo -n "FLAG" | od -An -td1
# Output: 70  76  65  71

# Convert to hex
echo -n "FLAG" | od -An -tx1
# Output: 46  4c  41  47
```

### Step 3: Convert ASCII Values Back to Text

```bash
# Decimal to text
python3 -c "print(''.join(chr(i) for i in [70, 76, 65, 71]))"
# Output: FLAG

# Hex to text
printf "\x46\x4c\x41\x47"
# Output: FLAG
```

## Exercise 2: Hexadecimal Encoding

**Objective:** Master hex encoding/decoding

### Step 1: Encode Text to Hex

```bash
# Using xxd
echo -n "Hello World" | xxd -p
# Output: 48656c6c6f20576f726c64

# Using Python
python3 -c "print('Hello World'.encode().hex())"
# Output: 48656c6c6f20576f726c64
```

### Step 2: Decode Hex to Text

```bash
# Using xxd
echo "48656c6c6f20576f726c64" | xxd -r -p
# Output: Hello World

# Using Python
python3 -c "print(bytes.fromhex('48656c6c6f20576f726c64').decode())"
# Output: Hello World
```

### Step 3: Hex CTF Challenge

Decode this hex-encoded flag:
```
464c41477b6865785f6d61737465727d
```

**Solution:**
```bash
echo "464c41477b6865785f6d61737465727d" | xxd -r -p
# Output: FLAG{hex_master}
```

## Exercise 3: Base64 Encoding

**Objective:** Understand Base64 encoding mechanics

### Step 1: Basic Base64 Operations

```bash
# Encode
echo -n "CyberLab is awesome!" | base64
# Output: Q3liZXJMYWIgaXMgYXdlc29tZSE=

# Decode
echo "Q3liZXJMYWIgaXMgYXdlc29tZSE=" | base64 -d
# Output: CyberLab is awesome!
```

### Step 2: Understanding Padding

```bash
# No padding (length divisible by 3)
echo -n "abc" | base64      # YWJj

# One = padding
echo -n "ab" | base64       # YWI=

# Two = padding
echo -n "a" | base64        # YQ==
```

### Step 3: Identify Base64 by Pattern

Look for:
- Characters: A-Z, a-z, 0-9, +, /
- Padding: = at the end
- Length: multiple of 4

```bash
# This looks like Base64
candidate="VGhpcyBpcyBhIHNlY3JldCE="

# Verify by decoding
echo "$candidate" | base64 -d
# Output: This is a secret!
```

## Exercise 4: URL Encoding

**Objective:** Handle URL-safe encoding

### Step 1: URL Encode Special Characters

```bash
# Python URL encoding
python3 -c "
import urllib.parse
text = 'Hello World! @#$%'
encoded = urllib.parse.quote(text)
print(f'Original: {text}')
print(f'Encoded:  {encoded}')
"
# Output:
# Original: Hello World! @#$%
# Encoded:  Hello%20World%21%20%40%23%24%25
```

### Step 2: URL Decode

```bash
python3 -c "
import urllib.parse
encoded = 'FLAG%7Burl_3nc0d3d%7D'
decoded = urllib.parse.unquote(encoded)
print(decoded)
"
# Output: FLAG{url_3nc0d3d}
```

### Step 3: Double URL Encoding

Sometimes data is URL-encoded twice:

```bash
python3 -c "
import urllib.parse
# Single encoded
single = 'FLAG%7Bhello%7D'
# Double encoded
double = 'FLAG%257Bhello%257D'

print('Single decode:', urllib.parse.unquote(single))
print('Double decode:', urllib.parse.unquote(urllib.parse.unquote(double)))
"
```

## Exercise 5: CyberChef Magic

**Objective:** Use CyberChef for automatic detection

### Step 1: Open CyberChef

Navigate to: https://gchq.github.io/CyberChef/

### Step 2: Use Magic Mode

1. Paste encoded data in the "Input" field
2. Drag "Magic" from Operations to Recipe
3. CyberChef will auto-detect encoding

### Step 3: Build a Recipe

Create a recipe for multi-layer decoding:

**Input:** `NTI0NzRjNGI0ODM1NmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA==`

**Recipe:**
1. From Base64
2. From Hex
3. From Base64

**Output:** `FLAG{5nc0d1ng_n0t_3ncrypt10n}`

### Step 4: Save and Share Recipes

CyberChef recipes can be saved as URLs for sharing.

## Exercise 6: Binary Encoding

**Objective:** Work with binary representation

### Step 1: Text to Binary

```bash
# Using Python
python3 -c "
text = 'FLAG'
binary = ' '.join(format(ord(c), '08b') for c in text)
print(binary)
"
# Output: 01000110 01001100 01000001 01000111
```

### Step 2: Binary to Text

```bash
python3 -c "
binary = '01000110 01001100 01000001 01000111'
text = ''.join(chr(int(b, 2)) for b in binary.split())
print(text)
"
# Output: FLAG
```

## Exercise 7: Multi-Layer Decoding Script

**Objective:** Automate nested encoding detection

Create this Python script:

```python
#!/usr/bin/env python3
"""multi_decode.py - Automatic multi-layer decoder"""

import base64
import sys
from binascii import unhexlify

def try_base64(data):
    """Attempt Base64 decode"""
    try:
        # Check for valid Base64 characters
        import re
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', data):
            decoded = base64.b64decode(data)
            return decoded.decode('utf-8'), 'Base64'
    except:
        pass
    return None, None

def try_hex(data):
    """Attempt hex decode"""
    try:
        # Check for valid hex
        if all(c in '0123456789abcdefABCDEF' for c in data):
            if len(data) % 2 == 0:
                decoded = unhexlify(data)
                return decoded.decode('utf-8'), 'Hex'
    except:
        pass
    return None, None

def multi_decode(data, max_depth=10):
    """Recursively decode nested encodings"""
    results = [f"Layer 0: {data}"]

    for depth in range(1, max_depth + 1):
        # Try Base64 first
        decoded, encoding = try_base64(data)
        if decoded:
            results.append(f"Layer {depth} ({encoding}): {decoded}")
            data = decoded
            continue

        # Try Hex
        decoded, encoding = try_hex(data)
        if decoded:
            results.append(f"Layer {depth} ({encoding}): {decoded}")
            data = decoded
            continue

        # No more layers to decode
        break

    return results

if __name__ == "__main__":
    if len(sys.argv) > 1:
        data = sys.argv[1]
    else:
        print("Usage: python3 multi_decode.py <encoded_string>")
        print("\nExample with test data:")
        # Base64(Hex(Base64("FLAG{nested_encoding}")))
        data = "NTI0NzRjNGI0ODM1NmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA=="

    results = multi_decode(data)
    for r in results:
        print(r)
```

### Usage

```bash
chmod +x multi_decode.py
./multi_decode.py "NTI0NzRjNGI0ODM1NmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA=="
```

## Exercise 8: Solve the CTF Challenges

### Challenge 1: Simple Base64

```bash
echo "RkxBR3tiYXNlNjRfaXNfZWFzeX0=" | base64 -d
# Output: FLAG{base64_is_easy}
```

### Challenge 2: Hex Encoded

```bash
echo "464c41477b6865785f6465636f64696e677d" | xxd -r -p
# Output: FLAG{hex_decoding}
```

### Challenge 3: Nested Encoding

```bash
# This is Base64 -> Hex -> Base64
python3 -c "
import base64
from binascii import unhexlify

data = 'NTI0NzRjNGI0ODM1NmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA=='

# Layer 1: Base64 decode
layer1 = base64.b64decode(data).decode()
print(f'Layer 1: {layer1}')

# Layer 2: Hex decode
layer2 = unhexlify(layer1).decode()
print(f'Layer 2: {layer2}')

# Layer 3: Base64 decode
layer3 = base64.b64decode(layer2).decode()
print(f'Layer 3: {layer3}')
"
```

### Challenge 4: Mixed Encoding

Use CyberChef with this recipe:
1. URL Decode
2. From Base64
3. From Base64 (multiple times)

### Challenge 5: Binary Message

```bash
python3 -c "
binary = '01000110 01001100 01000001 01000111 01111011 01100010 00110001 01101110 01100001 01110010 01111001 01011111 01101101 00110000 01100100 00110011 01111101'
print(''.join(chr(int(b, 2)) for b in binary.split()))
"
# Output: FLAG{b1nary_m0d3}
```

## Finding the Lab Flag

The final flag combines all skills learned.

**Encoded Flag:**
```
NTI0NzRjNGI0ODMzNmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA==
```

**Solution:**
```bash
python3 -c "
import base64
from binascii import unhexlify

encoded = 'NTI0NzRjNGI0ODMzNmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA=='

# Decode Base64
hex_data = base64.b64decode(encoded).decode()

# Decode Hex
result = unhexlify(hex_data).decode()
print(result)
"
```

**Flag:** `FLAG{3nc0d1ng_n0t_3ncrypt10n}`

## Summary

In this lab, you learned:

1. **ASCII** - Character to number mapping
2. **Hexadecimal** - Base16 representation (0-9, A-F)
3. **Base64** - 64-character alphabet with padding
4. **URL Encoding** - Percent encoding for special characters
5. **Binary** - Raw bit representation
6. **CyberChef** - Visual encoding/decoding tool
7. **Multi-layer detection** - Automated decoding scripts

## Next Lab

Continue to **Lab 02: Classical Ciphers** to learn about historical encryption methods like Caesar and Vigenere ciphers.
