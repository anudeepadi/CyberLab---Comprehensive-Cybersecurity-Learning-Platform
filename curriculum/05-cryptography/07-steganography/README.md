# Lab 07 - Steganography

Master the art of hiding and finding secret data within images, audio, and files.

## Overview

**Difficulty:** Intermediate
**Duration:** 2 hours
**Category:** Data Hiding
**Flag:** `FLAG{h1dd3n_1n_pl41n_s1ght}`

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand steganography concepts and techniques
2. Hide data in images using LSB encoding
3. Extract hidden data with steghide and stegsolve
4. Analyze images for hidden content
5. Use various steganography tools
6. Detect steganographic content

## What is Steganography?

**Steganography** is the practice of hiding secret information within ordinary, non-secret data:

```
CRYPTOGRAPHY vs STEGANOGRAPHY

Cryptography:
┌────────────────────┐
│ "Meet at noon"     │ ──> │ X8#kL9$mZ... │
└────────────────────┘     └──────────────┘
Message is visible but unreadable

Steganography:
┌────────────────────┐     ┌────────────────────┐
│ [Image of cat]     │ ──> │ [Image of cat]     │
│ + hidden message   │     │ (looks identical)  │
└────────────────────┘     └────────────────────┘
Message existence is hidden
```

### Key Concepts

- **Cover Object:** The innocent-looking carrier (image, audio, video)
- **Payload:** The secret data to hide
- **Stego Object:** The cover with embedded payload
- **Steganalysis:** Detecting hidden data

## Types of Steganography

### 1. Image Steganography

```
Methods:
- LSB (Least Significant Bit) encoding
- DCT (Discrete Cosine Transform) for JPEG
- Palette manipulation
- Metadata/EXIF hiding
```

### 2. Audio Steganography

```
Methods:
- LSB in audio samples
- Phase coding
- Spread spectrum
- Echo hiding
```

### 3. Text Steganography

```
Methods:
- Whitespace encoding
- Unicode homoglyphs
- Word spacing
- First letter of words (acrostic)
```

### 4. File/Protocol Steganography

```
Methods:
- Appended data after EOF
- Hidden in file headers
- TCP/IP header manipulation
- DNS tunneling
```

## LSB (Least Significant Bit) Encoding

The most common image steganography technique:

```
Pixel Value: 10110110  (182 in decimal)
                    ^
                    └── Least Significant Bit

Changing LSB: 10110110 -> 10110111
              182      -> 183

Visual difference: Imperceptible!
```

### How LSB Works

```
Original RGB Pixel: (182, 200, 150)
Binary: (10110110, 11001000, 10010110)

Hide letter 'H' (01001000):

1. Take bits from 'H': 0 1 0 0 1 0 0 0

2. Replace LSBs:
   R: 10110110 -> 1011011[0]  (bit 0)
   G: 11001000 -> 1100100[1]  (bit 1)
   B: 10010110 -> 1001011[0]  (bit 0)
   (continue with more pixels...)

3. New pixel: (182, 201, 150)
   Difference: Unnoticeable to human eye!
```

### LSB Capacity

```
24-bit RGB image (1000x1000 pixels):
- 3 million color values
- 3 million bits if using 1 LSB per channel
- 375,000 bytes (375 KB) of hidden data

Trade-off: More bits = more capacity but more detectability
```

## Common Tools

### steghide
Command-line tool for hiding data in JPEG/BMP/WAV/AU files.

```bash
# Install
sudo apt-get install steghide

# Hide data
steghide embed -cf cover.jpg -ef secret.txt -p password

# Extract data
steghide extract -sf stego.jpg -p password

# Get file info
steghide info stego.jpg
```

### stegsolve
GUI tool for analyzing images and extracting LSB data.

```bash
# Run (requires Java)
java -jar stegsolve.jar
```

Features:
- Bit plane analysis
- Frame browsing
- Data extraction
- File format analysis

### zsteg
Ruby tool for detecting LSB steganography in PNG/BMP.

```bash
# Install
gem install zsteg

# Analyze image
zsteg image.png

# All checks
zsteg -a image.png

# Extract specific payload
zsteg -E "b1,rgb,lsb" image.png > extracted.txt
```

### binwalk
Firmware analysis tool that finds embedded files.

```bash
# Install
sudo apt-get install binwalk

# Scan for embedded files
binwalk image.png

# Extract all
binwalk -e image.png

# Extract with recursion
binwalk -eM image.png
```

### exiftool
Read and write metadata in files.

```bash
# Install
sudo apt-get install exiftool

# View all metadata
exiftool image.jpg

# View specific tag
exiftool -Comment image.jpg

# Remove all metadata
exiftool -all= image.jpg
```

### strings
Find readable strings in binary files.

```bash
# Basic search
strings image.png

# Minimum length
strings -n 10 image.png

# With offset
strings -t x image.png
```

## OpenSSL for Steganography

### Encrypt Before Hiding

```bash
# Encrypt the secret first
openssl enc -aes-256-cbc -salt -in secret.txt -out secret.enc -k password

# Then hide with steghide
steghide embed -cf cover.jpg -ef secret.enc -p stegpassword

# To extract and decrypt
steghide extract -sf stego.jpg -p stegpassword
openssl enc -aes-256-cbc -d -in secret.enc -out recovered.txt -k password
```

## Python Implementation

### LSB Encoding in Python

```python
#!/usr/bin/env python3
"""LSB Steganography implementation"""

from PIL import Image
import numpy as np

def text_to_binary(text):
    """Convert text to binary string"""
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary):
    """Convert binary string to text"""
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if len(c) == 8)

def encode_lsb(image_path, secret_message, output_path):
    """Hide message in image using LSB encoding"""
    img = Image.open(image_path)
    pixels = np.array(img)

    # Add delimiter to know where message ends
    message = secret_message + "$$END$$"
    binary_message = text_to_binary(message)

    # Check capacity
    max_bytes = pixels.size // 8
    if len(binary_message) > pixels.size:
        raise ValueError(f"Message too large! Max: {max_bytes} bytes")

    # Flatten pixels for easier manipulation
    flat_pixels = pixels.flatten()

    # Encode message
    for i, bit in enumerate(binary_message):
        # Clear LSB and set to message bit
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)

    # Reshape and save
    encoded_pixels = flat_pixels.reshape(pixels.shape)
    encoded_img = Image.fromarray(encoded_pixels.astype('uint8'))
    encoded_img.save(output_path)

    print(f"Message hidden in {output_path}")
    return output_path

def decode_lsb(image_path):
    """Extract hidden message from image"""
    img = Image.open(image_path)
    pixels = np.array(img)

    # Extract LSBs
    flat_pixels = pixels.flatten()
    binary_message = ''.join(str(p & 1) for p in flat_pixels)

    # Convert to text
    message = binary_to_text(binary_message)

    # Find delimiter
    if "$$END$$" in message:
        message = message.split("$$END$$")[0]

    return message

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Create test image
    from PIL import Image
    import os

    # Create a simple test image
    test_img = Image.new('RGB', (100, 100), color='red')
    test_img.save('test_cover.png')

    # Hide message
    secret = "FLAG{h1dd3n_1n_pl41n_s1ght}"
    encode_lsb('test_cover.png', secret, 'test_stego.png')

    # Extract message
    extracted = decode_lsb('test_stego.png')
    print(f"Extracted: {extracted}")

    # Cleanup
    os.remove('test_cover.png')
    os.remove('test_stego.png')
```

### Image Analysis Tools

```python
#!/usr/bin/env python3
"""Image analysis for steganography detection"""

from PIL import Image
import numpy as np

def extract_bit_planes(image_path, output_prefix):
    """Extract and save individual bit planes"""
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img)

    for channel, color in enumerate(['R', 'G', 'B']):
        for bit in range(8):
            # Extract bit plane
            plane = (pixels[:, :, channel] >> bit) & 1
            plane_img = (plane * 255).astype('uint8')

            # Save
            output_path = f"{output_prefix}_{color}_bit{bit}.png"
            Image.fromarray(plane_img).save(output_path)
            print(f"Saved: {output_path}")

def analyze_lsb(image_path):
    """Analyze LSB for signs of steganography"""
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img)

    print(f"Image: {image_path}")
    print(f"Size: {img.size}")
    print(f"Mode: {img.mode}")
    print()

    for channel, color in enumerate(['Red', 'Green', 'Blue']):
        channel_data = pixels[:, :, channel].flatten()

        # Count LSB values
        zeros = np.sum(channel_data & 1 == 0)
        ones = np.sum(channel_data & 1 == 1)
        total = len(channel_data)

        ratio = zeros / total
        print(f"{color} channel LSB:")
        print(f"  0s: {zeros} ({zeros/total*100:.1f}%)")
        print(f"  1s: {ones} ({ones/total*100:.1f}%)")

        # Suspicious if very close to 50/50
        if 0.48 < ratio < 0.52:
            print(f"  [!] Suspicious: Nearly equal distribution")
        print()

def check_eof_data(file_path):
    """Check for data appended after image EOF"""
    with open(file_path, 'rb') as f:
        data = f.read()

    # PNG ends with IEND chunk
    if b'IEND' in data:
        end_pos = data.find(b'IEND') + 12  # IEND + CRC
        if end_pos < len(data):
            extra = data[end_pos:]
            print(f"[!] Found {len(extra)} bytes after PNG IEND marker!")
            print(f"First 100 bytes: {extra[:100]}")
            return extra

    # JPEG ends with FFD9
    if data[:2] == b'\xff\xd8':  # JPEG magic
        end_pos = data.rfind(b'\xff\xd9') + 2
        if end_pos < len(data):
            extra = data[end_pos:]
            print(f"[!] Found {len(extra)} bytes after JPEG EOF!")
            print(f"First 100 bytes: {extra[:100]}")
            return extra

    print("No obvious EOF data found")
    return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_lsb(sys.argv[1])
        check_eof_data(sys.argv[1])
```

## Detection Techniques

### Visual Analysis

```
1. Bit Plane Analysis
   - Extract each bit plane separately
   - LSB plane should look random in natural images
   - Patterns in LSB = likely steganography

2. Histogram Analysis
   - Compare histogram of suspect vs original
   - LSB encoding can create "pairs of values"

3. Chi-Square Analysis
   - Statistical test for LSB embedding
   - Detects non-random bit distributions
```

### Tool-Based Detection

```bash
# Check all common hiding methods
binwalk image.png           # Embedded files
strings image.png           # Hidden strings
exiftool image.png          # Metadata
zsteg image.png             # LSB analysis
steghide info image.jpg     # Steghide detection
```

## CTF Challenges

### Challenge 1: Basic Strings

Find the hidden flag in `challenge1.png`.

### Challenge 2: Metadata

A flag is hidden in the image metadata.

### Challenge 3: LSB Encoding

Extract the LSB-encoded message from `challenge3.png`.

### Challenge 4: Steghide

The image was created with steghide. Password is "secret".

### Challenge 5: Multi-Layer

The image contains multiple hidden elements. Find them all!

## Common CTF Patterns

### Quick Checks Workflow

```bash
# 1. Basic information
file image.png
exiftool image.png

# 2. String search
strings image.png | grep -i flag
strings image.png | grep -i ctf

# 3. Check for embedded files
binwalk image.png

# 4. LSB analysis
zsteg image.png       # PNG/BMP
steghide info image.jpg  # JPEG

# 5. Visual analysis
stegsolve             # GUI tool
```

### Password Guessing for Steghide

```bash
# Common passwords to try
for pw in "" "password" "secret" "admin" "flag" "stego" "hidden"; do
    steghide extract -sf image.jpg -p "$pw" 2>/dev/null && echo "Password: $pw"
done

# Or use stegcracker for dictionary attack
stegcracker image.jpg wordlist.txt
```

## Tasks

- [ ] Hide a message using steghide
- [ ] Extract LSB data with zsteg
- [ ] Analyze bit planes with stegsolve
- [ ] Find embedded files with binwalk
- [ ] Check metadata with exiftool
- [ ] Implement LSB encoding in Python
- [ ] Solve all 5 CTF challenges
- [ ] Find the flag: `FLAG{h1dd3n_1n_pl41n_s1ght}`

## Tools Summary

| Tool | Purpose | File Types |
|------|---------|------------|
| steghide | Hide/extract with password | JPEG, BMP, WAV, AU |
| zsteg | LSB analysis | PNG, BMP |
| stegsolve | Visual bit analysis | Multiple |
| binwalk | Embedded file detection | Any |
| exiftool | Metadata analysis | Multiple |
| strings | Text extraction | Any binary |
| stegcracker | Password cracking | steghide files |

## Next Steps

After mastering steganography:
- **Lab 08: Crypto Attacks** - Advanced cryptographic attacks

## References

- [Steghide Documentation](http://steghide.sourceforge.net/)
- [zsteg GitHub](https://github.com/zed-0xff/zsteg)
- [Stegsolve](http://www.caesum.com/handbook/stego.htm)
- [Digital Invisible Ink Toolkit](http://diit.sourceforge.net/)
