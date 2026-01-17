# Challenge 08 - Hidden Message

**Category:** Misc (Steganography)
**Difficulty:** Beginner
**Points:** 100
**Target:** Local (Image Analysis)

## Challenge Description

A picture is worth a thousand words... or in this case, a hidden flag! An innocent-looking image has been sent to you, but there's more to it than meets the eye.

Your mission is to extract the hidden data from the image file.

## Challenge Setup

Create the challenge image with this script:

```bash
#!/bin/bash
# Create a simple image with hidden data

# Create a basic image (requires ImageMagick)
convert -size 200x200 xc:blue -fill white -pointsize 20 \
        -draw "text 50,100 'Nothing Here'" /tmp/challenge08.png

# Hide the flag in the image using steghide (for JPEG) or append to PNG
echo "FLAG{st3g0_h1dd3n_1n_pl41n_s1ght}" >> /tmp/challenge08.png

echo "Challenge image created: /tmp/challenge08.png"
```

Or use the provided file: `curriculum/08-ctf-challenges/files/challenge08.png`

## Objectives

- Analyze image files for hidden data
- Use forensic tools to extract information
- Understand basic steganography techniques
- Find the flag

---

## Hints

<details>
<summary>Hint 1 (Cost: -10 points)</summary>

Start with basic analysis. The `strings` command can find printable text hidden in binary files:
```bash
strings /tmp/challenge08.png
```

</details>

<details>
<summary>Hint 2 (Cost: -20 points)</summary>

Check the file's metadata with `exiftool`:
```bash
exiftool /tmp/challenge08.png
```

Also try `binwalk` to look for embedded files:
```bash
binwalk /tmp/challenge08.png
```

</details>

<details>
<summary>Hint 3 (Cost: -30 points)</summary>

Sometimes data is simply appended to the end of image files. Use `strings` and grep for the flag format:
```bash
strings /tmp/challenge08.png | grep -i flag
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Basic File Analysis

```bash
# Check file type
file /tmp/challenge08.png
# Output: PNG image data, 200 x 200, ...

# Check file size - larger than expected for a simple image?
ls -la /tmp/challenge08.png
```

### Step 2: Extract Strings

```bash
strings /tmp/challenge08.png
# Look through output for anything interesting

# Grep for flag pattern
strings /tmp/challenge08.png | grep -i "flag"
# Output: FLAG{st3g0_h1dd3n_1n_pl41n_s1ght}
```

### Step 3: Alternative Methods

**Using xxd (hex dump):**
```bash
xxd /tmp/challenge08.png | tail -20
# Look at the end of the file for appended data
```

**Using binwalk:**
```bash
binwalk /tmp/challenge08.png
# Shows file structure and embedded data

binwalk -e /tmp/challenge08.png
# Extracts any embedded files
```

**Using exiftool:**
```bash
exiftool /tmp/challenge08.png
# Check metadata fields - flags sometimes hidden in comments
```

### Step 4: View Appended Data

```bash
# See what's after the PNG end marker (IEND)
cat /tmp/challenge08.png | xxd | grep -A5 "IEND"
```

### Result

```
FLAG{st3g0_h1dd3n_1n_pl41n_s1ght}
```

### Understanding Steganography

**Definition:** Hiding data within other data (images, audio, video, text)

**Common Techniques:**

| Technique | Description | Tools |
|-----------|-------------|-------|
| Appending | Add data to end of file | strings, xxd |
| LSB | Modify least significant bits | zsteg, steghide |
| Metadata | Hide in EXIF/comments | exiftool |
| Whitespace | Invisible characters | stegsnow |

### Steganography Detection Toolkit

```bash
# General analysis
file image.png
strings image.png | grep -i flag
binwalk image.png
exiftool image.png

# PNG specific
pngcheck image.png
zsteg image.png

# JPEG specific
steghide info image.jpg
stegseek image.jpg /usr/share/wordlists/rockyou.txt

# Audio files
sonic-visualiser audio.wav
audacity audio.wav  # Check spectrogram
```

### Python Analysis Script

```python
#!/usr/bin/env python3
"""Basic steganography detection script"""

import sys
from PIL import Image

def analyze_image(filepath):
    print(f"[*] Analyzing: {filepath}")

    # Read raw bytes
    with open(filepath, 'rb') as f:
        data = f.read()

    # Check for appended data after PNG IEND
    if b'IEND' in data:
        iend_pos = data.find(b'IEND') + 8
        if iend_pos < len(data):
            appended = data[iend_pos:]
            print(f"[+] Found {len(appended)} bytes after IEND!")
            print(f"[+] Appended data: {appended[:100]}")

    # Search for FLAG pattern
    if b'FLAG{' in data:
        start = data.find(b'FLAG{')
        end = data.find(b'}', start) + 1
        print(f"[+] Found flag: {data[start:end].decode()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <image>")
        sys.exit(1)
    analyze_image(sys.argv[1])
```

</details>

---

## Flag

```
FLAG{st3g0_h1dd3n_1n_pl41n_s1ght}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- File analysis and forensics
- Steganography detection
- Command-line forensic tools
- Pattern recognition

## Tools Used

- strings
- file
- xxd
- binwalk
- exiftool
- zsteg (for PNG LSB)
- steghide (for JPEG)

## Bonus Challenges

1. Create your own steganographic image
2. Hide a message using LSB encoding
3. Try extracting data from a password-protected steghide image

## Related Challenges

- [04 - What's in the Packet?](04-whats-in-the-packet.md) - Forensics basics
- [Memory Forensics (Advanced)](../advanced/03-memory-forensics.md) - Advanced forensics

## References

- [Steganography Tools List](https://0xrick.github.io/lists/stego/)
- [zsteg - PNG/BMP analysis](https://github.com/zed-0xff/zsteg)
- [steghide](http://steghide.sourceforge.net/)
- [Binwalk](https://github.com/ReFirmLabs/binwalk)
