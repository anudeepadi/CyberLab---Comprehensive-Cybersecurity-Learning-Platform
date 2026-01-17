# Lab 07 Walkthrough - Steganography

Step-by-step guide to hiding and finding secret data in images and files.

## Setup

### Install Required Tools

```bash
# Install steganography tools
sudo apt-get install steghide binwalk exiftool

# Install zsteg (Ruby gem)
sudo gem install zsteg

# Install stegcracker for password cracking
pip3 install stegcracker

# Install Python libraries
pip3 install pillow numpy
```

### Download Stegsolve

```bash
# Download stegsolve
wget http://www.caesum.com/handbook/Stegsolve.jar

# Run (requires Java)
java -jar Stegsolve.jar
```

### Create the Steganography Toolkit

Save this as `stego_toolkit.py`:

```python
#!/usr/bin/env python3
"""Steganography Toolkit for CyberLab"""

from PIL import Image
import numpy as np
import os

# ============================================================================
# LSB ENCODING/DECODING
# ============================================================================

def text_to_bits(text):
    """Convert text to bit string"""
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    """Convert bit string to text"""
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if len(c) == 8)

def lsb_encode(image_path, message, output_path):
    """Hide message in image using LSB"""
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img)

    # Add delimiter
    message += '\x00\x00\x00'  # Null bytes as delimiter
    bits = text_to_bits(message)

    if len(bits) > pixels.size:
        raise ValueError(f"Message too large! Max {pixels.size // 8} characters")

    flat = pixels.flatten()
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)

    result = flat.reshape(pixels.shape)
    Image.fromarray(result.astype('uint8')).save(output_path)
    print(f"[+] Message hidden in {output_path}")

def lsb_decode(image_path):
    """Extract LSB-encoded message from image"""
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img).flatten()

    bits = ''.join(str(p & 1) for p in pixels)
    message = bits_to_text(bits)

    # Find delimiter
    if '\x00\x00\x00' in message:
        message = message.split('\x00\x00\x00')[0]

    return message

# ============================================================================
# BIT PLANE EXTRACTION
# ============================================================================

def extract_bit_plane(image_path, channel, bit, output_path=None):
    """Extract specific bit plane from image"""
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img)

    channel_idx = {'R': 0, 'G': 1, 'B': 2}[channel.upper()]

    plane = (pixels[:, :, channel_idx] >> bit) & 1
    plane_img = (plane * 255).astype('uint8')

    result = Image.fromarray(plane_img)
    if output_path:
        result.save(output_path)
        print(f"[+] Saved {channel} bit {bit} to {output_path}")
    return result

def extract_all_bit_planes(image_path, output_dir):
    """Extract all bit planes from image"""
    os.makedirs(output_dir, exist_ok=True)

    for channel in ['R', 'G', 'B']:
        for bit in range(8):
            output_path = f"{output_dir}/{channel}_bit{bit}.png"
            extract_bit_plane(image_path, channel, bit, output_path)

    print(f"[+] All bit planes saved to {output_dir}/")

# ============================================================================
# ANALYSIS
# ============================================================================

def analyze_image(image_path):
    """Analyze image for steganography indicators"""
    print(f"\n{'='*60}")
    print(f"ANALYZING: {image_path}")
    print(f"{'='*60}")

    # Basic info
    img = Image.open(image_path)
    print(f"\n[File Info]")
    print(f"  Format: {img.format}")
    print(f"  Mode: {img.mode}")
    print(f"  Size: {img.size[0]}x{img.size[1]}")

    # Convert to RGB for analysis
    img_rgb = img.convert('RGB')
    pixels = np.array(img_rgb)

    # LSB distribution
    print(f"\n[LSB Distribution]")
    for idx, color in enumerate(['Red', 'Green', 'Blue']):
        channel = pixels[:, :, idx].flatten()
        zeros = np.sum((channel & 1) == 0)
        total = len(channel)
        ratio = zeros / total

        print(f"  {color}: {zeros}/{total} zeros ({ratio*100:.1f}%)")

        if 0.48 < ratio < 0.52:
            print(f"    [!] SUSPICIOUS: Near 50/50 distribution")

    # Chi-square test (simplified)
    print(f"\n[Chi-Square Analysis]")
    for idx, color in enumerate(['Red', 'Green', 'Blue']):
        channel = pixels[:, :, idx].flatten()

        # Count pairs
        pairs = {}
        for i in range(0, len(channel) - 1, 2):
            v1, v2 = channel[i], channel[i+1]
            key = (min(v1, v2) // 2) * 2
            pairs[key] = pairs.get(key, 0) + 1

        # Simplified chi-square indicator
        chi_sum = 0
        for key, count in pairs.items():
            expected = count
            chi_sum += abs(count - expected)

        print(f"  {color} chi-sum: {chi_sum}")

    print(f"\n{'='*60}")

def check_file_signature(file_path):
    """Check file magic bytes and look for anomalies"""
    signatures = {
        b'\x89PNG': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF87a': 'GIF87',
        b'GIF89a': 'GIF89',
        b'BM': 'BMP',
        b'PK\x03\x04': 'ZIP/DOCX/JAR',
        b'%PDF': 'PDF',
        b'Rar!': 'RAR',
        b'\x1f\x8b': 'GZIP',
    }

    with open(file_path, 'rb') as f:
        header = f.read(16)
        f.seek(0)
        data = f.read()

    print(f"\n[File Signature Check]")
    print(f"  Header: {header[:8].hex()}")

    detected = None
    for sig, name in signatures.items():
        if header.startswith(sig):
            detected = name
            print(f"  Detected: {name}")
            break

    # Check for appended data
    if detected == 'PNG' and b'IEND' in data:
        iend_pos = data.find(b'IEND') + 12
        if iend_pos < len(data):
            extra = len(data) - iend_pos
            print(f"  [!] Found {extra} bytes after PNG IEND!")
            return data[iend_pos:]

    if detected == 'JPEG':
        eof_pos = data.rfind(b'\xff\xd9') + 2
        if eof_pos < len(data):
            extra = len(data) - eof_pos
            print(f"  [!] Found {extra} bytes after JPEG EOF!")
            return data[eof_pos:]

    return None

# ============================================================================
# UTILITY
# ============================================================================

def strings_search(file_path, min_length=4):
    """Extract printable strings from file"""
    with open(file_path, 'rb') as f:
        data = f.read()

    result = []
    current = ""

    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current += chr(byte)
        else:
            if len(current) >= min_length:
                result.append(current)
            current = ""

    if len(current) >= min_length:
        result.append(current)

    return result

def find_flags(file_path):
    """Search for common flag patterns"""
    strings = strings_search(file_path)
    patterns = ['FLAG{', 'flag{', 'CTF{', 'ctf{', 'key{', 'secret']

    print(f"\n[Flag Search]")
    found = []
    for s in strings:
        for pattern in patterns:
            if pattern.lower() in s.lower():
                print(f"  Found: {s}")
                found.append(s)
    return found

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("Steganography Toolkit")
    print("=" * 50)
    print("Functions:")
    print("  lsb_encode(image, message, output)")
    print("  lsb_decode(image)")
    print("  extract_bit_plane(image, channel, bit, output)")
    print("  extract_all_bit_planes(image, output_dir)")
    print("  analyze_image(image)")
    print("  check_file_signature(file)")
    print("  find_flags(file)")
    print("=" * 50)
```

## Exercise 1: Hiding Data with steghide

### Step 1: Create a Cover Image and Secret

```bash
# Create a simple test message
echo "This is a secret message!" > secret.txt

# Use any JPEG image as cover (or create one)
# For testing, let's convert a simple image to JPEG
convert -size 200x200 xc:blue cover.jpg
```

### Step 2: Embed the Secret

```bash
# Hide the secret in the image
steghide embed -cf cover.jpg -ef secret.txt

# Enter passphrase when prompted (or use -p flag)
steghide embed -cf cover.jpg -ef secret.txt -p "mypassword"
```

### Step 3: Extract the Secret

```bash
# Extract from the stego image
steghide extract -sf cover.jpg -p "mypassword"

# View extracted content
cat secret.txt
```

### Step 4: Get Information

```bash
# Check if an image has embedded data
steghide info cover.jpg
```

## Exercise 2: LSB Encoding with Python

### Step 1: Create Test Image

```python
from stego_toolkit import *
from PIL import Image

# Create a simple test image
img = Image.new('RGB', (100, 100), color='white')
img.save('test_cover.png')
```

### Step 2: Encode Message

```python
# Hide a message
secret = "FLAG{h1dd3n_1n_pl41n_s1ght}"
lsb_encode('test_cover.png', secret, 'test_stego.png')
```

### Step 3: Decode Message

```python
# Extract the message
extracted = lsb_decode('test_stego.png')
print(f"Extracted: {extracted}")
```

### Step 4: Compare Images

```python
from PIL import Image
import numpy as np

# Load both images
original = np.array(Image.open('test_cover.png'))
stego = np.array(Image.open('test_stego.png'))

# Check difference
diff = np.abs(original.astype(int) - stego.astype(int))
print(f"Max pixel difference: {diff.max()}")
print(f"Pixels changed: {np.sum(diff > 0)}")
```

## Exercise 3: Using zsteg

### Step 1: Basic Analysis

```bash
# Analyze PNG for hidden data
zsteg image.png

# Show all results (verbose)
zsteg -a image.png
```

### Step 2: Extract Specific Payload

```bash
# Extract LSB from RGB channels
zsteg -E "b1,rgb,lsb" image.png

# Extract from specific channel/bit
zsteg -E "b1,r,lsb" image.png > extracted.txt

# Try all extractions
zsteg -e all image.png
```

### Step 3: Common zsteg Options

```bash
# Check for specific patterns
zsteg image.png -l 0           # Only show results with 0 limit
zsteg image.png --bits 1-2     # Check bits 1-2
zsteg image.png --channel rgb  # RGB channels only
```

## Exercise 4: Bit Plane Analysis with Stegsolve

### Step 1: Open Image in Stegsolve

```bash
java -jar Stegsolve.jar
# File -> Open -> Select image
```

### Step 2: Browse Bit Planes

Use the arrow buttons to browse through:
- Red plane 0-7
- Green plane 0-7
- Blue plane 0-7
- Alpha plane (if present)

### Step 3: Look for Hidden Data

- **Patterns in LSB:** Hidden data often appears as patterns
- **Text in bit planes:** Sometimes ASCII is visible
- **QR codes:** Hidden QR codes in specific planes

### Step 4: Extract Data

```
Analyse -> Data Extract
- Select bit planes to extract from
- Choose extraction order (MSB/LSB)
- Click "Extract" or "Preview"
```

## Exercise 5: Finding Embedded Files with binwalk

### Step 1: Scan for Embedded Files

```bash
# Scan image
binwalk image.png

# Output shows embedded files with offsets
```

### Step 2: Extract All Files

```bash
# Extract embedded files
binwalk -e image.png

# Recursive extraction
binwalk -eM image.png

# Check extracted files
ls _image.png.extracted/
```

### Step 3: Manual Extraction

```bash
# If binwalk finds a file at offset 0x1234
dd if=image.png of=extracted.zip bs=1 skip=$((0x1234))

# Or use binwalk with specific signature
binwalk -D 'zip archive:zip' image.png
```

## Exercise 6: Metadata Analysis

### Step 1: View Metadata

```bash
# Full metadata dump
exiftool image.jpg

# Specific fields
exiftool -Comment image.jpg
exiftool -XPComment image.jpg
exiftool -UserComment image.jpg
```

### Step 2: Check for Hidden Data

```bash
# Comments often hide flags
exiftool image.jpg | grep -i comment
exiftool image.jpg | grep -i flag
exiftool image.jpg | grep -i secret

# Thumbnail might be different
exiftool -b -ThumbnailImage image.jpg > thumbnail.jpg
```

### Step 3: Create Hidden Metadata

```bash
# Add hidden comment
exiftool -Comment="FLAG{hidden_in_metadata}" image.jpg

# Verify
exiftool -Comment image.jpg
```

## Exercise 7: Python Bit Plane Analysis

```python
from stego_toolkit import *

# Analyze an image
analyze_image('suspicious.png')

# Extract all bit planes
extract_all_bit_planes('suspicious.png', 'bit_planes')

# Check file signature and appended data
extra_data = check_file_signature('suspicious.png')
if extra_data:
    print(f"Extra data: {extra_data[:100]}")

# Search for flags
find_flags('suspicious.png')
```

## Solving CTF Challenges

### Challenge 1: Basic Strings

```bash
# Check strings first
strings challenge1.png | grep -i flag

# If not found, try with minimum length
strings -n 4 challenge1.png
```

### Challenge 2: Metadata

```bash
# Check all metadata
exiftool challenge2.jpg

# Look for comments
exiftool challenge2.jpg | grep -i -E "(comment|flag|secret)"
```

### Challenge 3: LSB Encoding

```bash
# Use zsteg for PNG
zsteg challenge3.png

# Or Python
python3 -c "from stego_toolkit import *; print(lsb_decode('challenge3.png'))"
```

### Challenge 4: Steghide

```bash
# Try common passwords
for pw in "" "password" "secret" "flag"; do
    steghide extract -sf challenge4.jpg -p "$pw" 2>/dev/null && \
    echo "Password: $pw" && break
done

# Or use stegcracker
stegcracker challenge4.jpg rockyou.txt
```

### Challenge 5: Multi-Layer

```bash
# Step 1: Basic checks
file challenge5.png
exiftool challenge5.png
strings challenge5.png | grep -i flag

# Step 2: Check for embedded files
binwalk challenge5.png

# Step 3: LSB analysis
zsteg challenge5.png

# Step 4: Bit plane analysis
java -jar Stegsolve.jar  # Visual inspection

# Step 5: Check appended data
python3 -c "from stego_toolkit import *; check_file_signature('challenge5.png')"
```

## Finding the Lab Flag

```python
from stego_toolkit import *

# The flag is hidden using LSB encoding
flag = "FLAG{h1dd3n_1n_pl41n_s1ght}"

# Create a stego image with the flag
from PIL import Image
img = Image.new('RGB', (200, 200), color='blue')
img.save('flag_cover.png')

lsb_encode('flag_cover.png', flag, 'flag_stego.png')

# Verify extraction
extracted = lsb_decode('flag_stego.png')
print(f"Flag: {extracted}")
```

## Summary

In this lab, you learned:

1. **LSB Encoding** - Hide data in least significant bits
2. **steghide** - Password-protected steganography
3. **zsteg** - LSB analysis for PNG/BMP
4. **Stegsolve** - Visual bit plane analysis
5. **binwalk** - Embedded file extraction
6. **exiftool** - Metadata analysis

## Next Lab

Continue to **Lab 08: Crypto Attacks** to learn about advanced attacks on cryptographic implementations.
