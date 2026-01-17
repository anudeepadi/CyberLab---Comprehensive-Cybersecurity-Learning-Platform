# Lab 07 Hints - Steganography

Progressive hints for steganography challenges.

## Challenge 1: Basic Strings

Find the hidden flag in the image.

<details>
<summary>Hint 1</summary>

The simplest form of "hiding" data is just appending it to a file.

Try using the `strings` command to find readable text.

```bash
strings challenge1.png
```

</details>

<details>
<summary>Hint 2</summary>

Filter for likely flag formats:

```bash
strings challenge1.png | grep -i flag
strings challenge1.png | grep -i ctf
strings challenge1.png | grep "{"
```

</details>

<details>
<summary>Hint 3</summary>

If `strings` doesn't work, the text might be hidden at a specific location.

Try `xxd` or `hexdump` to view the raw bytes:

```bash
xxd challenge1.png | tail
hexdump -C challenge1.png | tail
```

Look for ASCII text near the end of the file.

</details>

<details>
<summary>Solution</summary>

```bash
strings challenge1.png | grep FLAG
# or
strings -n 4 challenge1.png | grep -E "(FLAG|flag|CTF)"
```

The flag is likely appended as plain text after the image data.

For PNG files, check after the IEND marker:
```bash
# Find offset of IEND
xxd challenge1.png | grep IEND

# Extract data after that offset
tail -c 100 challenge1.png
```

</details>

---

## Challenge 2: Metadata

A flag is hidden in the image metadata.

<details>
<summary>Hint 1</summary>

Image files can contain metadata (EXIF data) that includes:
- Camera information
- GPS coordinates
- Comments
- Custom fields

Use `exiftool` to examine metadata:

```bash
exiftool challenge2.jpg
```

</details>

<details>
<summary>Hint 2</summary>

Look specifically at comment fields:

```bash
exiftool challenge2.jpg | grep -i comment
exiftool challenge2.jpg | grep -i flag
exiftool challenge2.jpg | grep -i description
```

Common hiding spots:
- Comment
- XPComment
- UserComment
- ImageDescription

</details>

<details>
<summary>Hint 3</summary>

```bash
# Check all comment-like fields
exiftool -Comment -XPComment -UserComment -ImageDescription challenge2.jpg

# Or dump everything and search
exiftool challenge2.jpg | grep -i "flag\|secret\|ctf"
```

</details>

<details>
<summary>Solution</summary>

```bash
# View all metadata
exiftool challenge2.jpg

# The flag is typically in one of these fields:
exiftool -Comment challenge2.jpg
# or
exiftool -UserComment challenge2.jpg
# or
exiftool -ImageDescription challenge2.jpg
```

Common output:
```
Comment: FLAG{metadata_reveals_secrets}
```

</details>

---

## Challenge 3: LSB Encoding

Extract the LSB-encoded message from the image.

<details>
<summary>Hint 1</summary>

LSB (Least Significant Bit) encoding hides data in the lowest bits of pixel values.

For PNG images, use `zsteg`:

```bash
zsteg challenge3.png
```

</details>

<details>
<summary>Hint 2</summary>

Try different extraction modes:

```bash
# All possible extractions
zsteg -a challenge3.png

# Specific modes
zsteg -E "b1,rgb,lsb" challenge3.png
zsteg -E "b1,r,lsb" challenge3.png
```

</details>

<details>
<summary>Hint 3</summary>

If zsteg doesn't work, try Python:

```python
from PIL import Image
import numpy as np

img = Image.open('challenge3.png').convert('RGB')
pixels = np.array(img).flatten()

# Extract LSBs
bits = ''.join(str(p & 1) for p in pixels)

# Convert to text
text = ''
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) == 8:
        char = chr(int(byte, 2))
        if char.isprintable():
            text += char

print(text[:200])  # First 200 chars
```

</details>

<details>
<summary>Solution</summary>

```bash
# Using zsteg
zsteg challenge3.png
# Look for output like: b1,rgb,lsb .. text: "FLAG{...}"

# Extract specific payload
zsteg -E "b1,rgb,lsb" challenge3.png
```

Or with Python:
```python
from PIL import Image
import numpy as np

def lsb_decode(image_path):
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img).flatten()
    bits = ''.join(str(p & 1) for p in pixels)

    text = ''
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            char = chr(int(byte, 2))
            text += char

    # Find flag pattern
    if 'FLAG{' in text:
        start = text.find('FLAG{')
        end = text.find('}', start) + 1
        return text[start:end]
    return text[:100]

print(lsb_decode('challenge3.png'))
```

</details>

---

## Challenge 4: Steghide

The image was created with steghide. Password is "secret".

<details>
<summary>Hint 1</summary>

Steghide is a tool for hiding data in JPEG and BMP images.

Basic extraction:

```bash
steghide extract -sf challenge4.jpg -p "secret"
```

</details>

<details>
<summary>Hint 2</summary>

If "secret" doesn't work, try common passwords:

```bash
# Try without password first
steghide extract -sf challenge4.jpg -p ""

# Common passwords
for pw in secret password admin flag stego hidden 123456; do
    steghide extract -sf challenge4.jpg -p "$pw" 2>/dev/null && echo "Found: $pw"
done
```

</details>

<details>
<summary>Hint 3</summary>

Use stegcracker for dictionary attack:

```bash
# Install
pip install stegcracker

# Attack with wordlist
stegcracker challenge4.jpg /usr/share/wordlists/rockyou.txt
```

Or check file info first:

```bash
steghide info challenge4.jpg
```

</details>

<details>
<summary>Solution</summary>

```bash
# Extract with given password
steghide extract -sf challenge4.jpg -p "secret"

# Check extracted file
cat *.txt
```

The extracted file contains the flag.

If password cracking is needed:
```bash
# Create small wordlist
echo -e "secret\npassword\nadmin\nflag" > passwords.txt

# Try each
while read pw; do
    steghide extract -sf challenge4.jpg -p "$pw" 2>/dev/null && \
    echo "Password: $pw" && break
done < passwords.txt
```

</details>

---

## Challenge 5: Multi-Layer

The image contains multiple hidden elements. Find them all!

<details>
<summary>Hint 1</summary>

Multi-layer challenges often combine several techniques:
1. Plain text appended to file
2. Metadata
3. LSB encoding
4. Embedded files
5. Steghide

Start with the basics and work through each.

</details>

<details>
<summary>Hint 2</summary>

Systematic approach:

```bash
# 1. File info
file challenge5.png

# 2. Strings
strings challenge5.png | grep -i flag

# 3. Metadata
exiftool challenge5.png

# 4. Embedded files
binwalk challenge5.png

# 5. LSB
zsteg challenge5.png
```

</details>

<details>
<summary>Hint 3</summary>

Check for data after EOF marker:

```bash
# For PNG - check after IEND
xxd challenge5.png | grep -A5 IEND

# Extract appended data
python3 << 'EOF'
with open('challenge5.png', 'rb') as f:
    data = f.read()

# PNG ends with IEND chunk
iend = data.find(b'IEND')
if iend != -1:
    extra = data[iend+12:]  # 12 = IEND(4) + length(4) + CRC(4)
    if extra:
        print(f"Found {len(extra)} extra bytes:")
        print(extra[:200])
EOF
```

</details>

<details>
<summary>Solution</summary>

Complete analysis workflow:

```bash
# 1. Basic info
file challenge5.png
echo "---"

# 2. Strings search
strings challenge5.png | grep -E "(FLAG|flag|CTF)" || echo "No strings found"
echo "---"

# 3. Metadata
exiftool challenge5.png | grep -i -E "(flag|secret|comment)" || echo "No metadata flags"
echo "---"

# 4. Embedded files
binwalk challenge5.png
binwalk -e challenge5.png
ls _challenge5.png.extracted/ 2>/dev/null
echo "---"

# 5. LSB analysis
zsteg challenge5.png 2>/dev/null | head -20
echo "---"

# 6. Check EOF
python3 -c "
with open('challenge5.png', 'rb') as f:
    data = f.read()
iend = data.find(b'IEND')
if iend != -1:
    extra = data[iend+12:]
    if extra:
        print('EOF data:', extra[:100])
"
```

Flags might be in:
- Plain strings: `FLAG{part1}`
- Metadata comment: `FLAG{part2}`
- Embedded ZIP: `FLAG{part3}`
- LSB encoded: `FLAG{part4}`

</details>

---

## Lab Flag Hint

<details>
<summary>Hint 1</summary>

The lab flag `FLAG{h1dd3n_1n_pl41n_s1ght}` can be hidden using LSB encoding.

Try encoding it yourself to understand the process.

</details>

<details>
<summary>Hint 2</summary>

```python
from PIL import Image
import numpy as np

# Create a simple image
img = Image.new('RGB', (100, 100), 'white')
img.save('test.png')

# The flag to hide
flag = "FLAG{h1dd3n_1n_pl41n_s1ght}"
```

</details>

<details>
<summary>Solution</summary>

```python
from PIL import Image
import numpy as np

def encode(img_path, message, out_path):
    img = Image.open(img_path).convert('RGB')
    pixels = np.array(img)
    msg_bits = ''.join(format(ord(c), '08b') for c in message + '\x00')

    flat = pixels.flatten()
    for i, bit in enumerate(msg_bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)

    result = flat.reshape(pixels.shape)
    Image.fromarray(result.astype('uint8')).save(out_path)

def decode(img_path):
    img = Image.open(img_path).convert('RGB')
    pixels = np.array(img).flatten()
    bits = ''.join(str(p & 1) for p in pixels)

    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    text = ''
    for c in chars:
        if len(c) == 8:
            ch = chr(int(c, 2))
            if ch == '\x00':
                break
            text += ch
    return text

# Usage
flag = "FLAG{h1dd3n_1n_pl41n_s1ght}"
# encode('cover.png', flag, 'stego.png')
# print(decode('stego.png'))
print(f"Flag: {flag}")
```

</details>

---

## General Steganography Tips

### Quick Analysis Workflow

```bash
# Step 1: Basic info
file image.png
exiftool image.png

# Step 2: Search for strings
strings image.png | grep -iE "(flag|ctf|key)"

# Step 3: Check for embedded files
binwalk image.png

# Step 4: LSB analysis
zsteg image.png           # PNG/BMP
steghide info image.jpg   # JPEG

# Step 5: Visual analysis (Stegsolve)
java -jar Stegsolve.jar
```

### Common Hiding Places

| Location | Tool to Check |
|----------|---------------|
| Plain text | `strings` |
| Metadata | `exiftool` |
| LSB bits | `zsteg`, stegsolve |
| After EOF | `xxd`, binwalk |
| Embedded file | `binwalk` |
| Password protected | `steghide`, stegcracker |

### Password Guessing

Common steghide passwords:
- (empty)
- password
- secret
- admin
- flag
- stego
- hidden
- 123456
