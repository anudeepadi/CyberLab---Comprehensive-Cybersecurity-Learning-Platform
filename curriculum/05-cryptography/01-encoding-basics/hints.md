# Lab 01 Hints - Encoding Basics

Progressive hints for the encoding challenges. Try to solve them yourself first!

## Challenge 1: Simple Base64

<details>
<summary>Hint 1</summary>

The string ends with `=` which is a telltale sign of Base64 padding.

</details>

<details>
<summary>Hint 2</summary>

Use the `base64` command with the `-d` flag to decode:
```bash
echo "encoded_string" | base64 -d
```

</details>

<details>
<summary>Solution</summary>

```bash
echo "RkxBR3tiYXNlNjRfaXNfZWFzeX0=" | base64 -d
# FLAG{base64_is_easy}
```

</details>

---

## Challenge 2: Hex Encoded

<details>
<summary>Hint 1</summary>

Look at the characters - they're all 0-9 and a-f. This is hexadecimal!

</details>

<details>
<summary>Hint 2</summary>

The hex `46` = 'F', `4c` = 'L', `41` = 'A', `47` = 'G'... see the pattern?

</details>

<details>
<summary>Hint 3</summary>

Use `xxd` with `-r -p` flags to reverse hex to plaintext:
```bash
echo "hex_string" | xxd -r -p
```

</details>

<details>
<summary>Solution</summary>

```bash
echo "464c41477b6865785f6465636f64696e677d" | xxd -r -p
# FLAG{hex_decoding}
```

</details>

---

## Challenge 3: Nested Encoding

<details>
<summary>Hint 1</summary>

This has multiple layers. Start by identifying the outermost encoding.

The `=` at the end suggests Base64 as the outer layer.

</details>

<details>
<summary>Hint 2</summary>

After decoding Base64, look at what you get. Is it still encoded?

The result will be all hex characters (0-9, a-f).

</details>

<details>
<summary>Hint 3</summary>

The encoding layers are:
1. Base64 (outermost)
2. Hex
3. Base64 (innermost)

Decode in that order!

</details>

<details>
<summary>Hint 4</summary>

Use CyberChef with these operations in order:
1. From Base64
2. From Hex
3. From Base64

</details>

<details>
<summary>Solution</summary>

```python
import base64
from binascii import unhexlify

data = "NTI0NzRjNGI0ODM1NmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA=="

# Step 1: Base64 decode
layer1 = base64.b64decode(data).decode()
print(f"After Base64: {layer1}")

# Step 2: Hex decode
layer2 = unhexlify(layer1).decode()
print(f"After Hex: {layer2}")

# Step 3: Base64 decode
layer3 = base64.b64decode(layer2).decode()
print(f"Final: {layer3}")
```

</details>

---

## Challenge 4: Mixed Encoding

<details>
<summary>Hint 1</summary>

The string is very long. Start by looking for URL encoding patterns (`%XX`).

Wait - there are no `%` signs, so it might not be URL encoded at the outer layer.

</details>

<details>
<summary>Hint 2</summary>

It's Base64 encoded. Try decoding it first and see what you get.

The result will be another Base64 string!

</details>

<details>
<summary>Hint 3</summary>

Keep decoding Base64 until you get something different.

You'll need to decode Base64 multiple times.

</details>

<details>
<summary>Hint 4</summary>

Use CyberChef's "Magic" operation - it will auto-detect the layers!

</details>

<details>
<summary>Solution</summary>

This is multiple layers of Base64 encoding. Use CyberChef with "Magic" operation, or manually:

```python
import base64

data = "VkRKV2VtUklTbXhqTTFaNlpFaEtkbVJZVW14amJUVm9Xa2RXZVU1WFVubFpNamt4WW0xc2JHTnRWakJqU0Vwc1dtMDVNMlJIVm5OaU0wWXdZM2s0ZUU1dE9URmpiVlp6V2xkR2VtTXlWblZrUjFaNVRGaGtiRnBIVW5wTlIxWjVUR3hLY0dNelVteGhTRUV6VFdsM2VFOUVWWGhOUkdNMQ=="

result = data
for i in range(10):  # Try up to 10 layers
    try:
        result = base64.b64decode(result).decode()
        print(f"Layer {i+1}: {result[:50]}...")
    except:
        print(f"Final result: {result}")
        break
```

</details>

---

## Challenge 5: Binary Message

<details>
<summary>Hint 1</summary>

Each group of 8 bits (8 zeros and ones) represents one ASCII character.

</details>

<details>
<summary>Hint 2</summary>

`01000110` = 70 in decimal = 'F' in ASCII
`01001100` = 76 in decimal = 'L' in ASCII

See the pattern?

</details>

<details>
<summary>Hint 3</summary>

Split by spaces, convert each binary group to decimal, then to character:

```python
binary_str = "01000110 01001100 ..."
for byte in binary_str.split():
    decimal = int(byte, 2)
    char = chr(decimal)
    print(char, end='')
```

</details>

<details>
<summary>Solution</summary>

```python
binary = "01000110 01001100 01000001 01000111 01111011 01100010 00110001 01101110 01100001 01110010 01111001 01011111 01101101 00110000 01100100 00110011 01111101"

result = ''.join(chr(int(b, 2)) for b in binary.split())
print(result)
# FLAG{b1nary_m0d3}
```

Or use CyberChef: "From Binary" with delimiter "Space"

</details>

---

## Final Flag Hint

<details>
<summary>Hint 1</summary>

The lab flag is hidden in the walkthrough.md file.

It uses the same encoding pattern as Challenge 3.

</details>

<details>
<summary>Hint 2</summary>

Look for the "Encoded Flag" in the walkthrough.

Decode: Base64 -> Hex -> That's it!

</details>

<details>
<summary>Solution</summary>

```python
import base64
from binascii import unhexlify

encoded = "NTI0NzRjNGI0ODMzNmU2MzMwNjQzMTZlNjc1ZjZlMzA3NDVmMzM2ZTYzNzI3OTcwNzQzMTMwNmU3ZA=="

# Decode Base64
hex_data = base64.b64decode(encoded).decode()
# Decode Hex
flag = unhexlify(hex_data).decode()
print(flag)
# FLAG{3nc0d1ng_n0t_3ncrypt10n}
```

</details>

---

## General Tips

1. **Identify the encoding first** - Look for patterns:
   - Base64: A-Z, a-z, 0-9, +, /, ends with =
   - Hex: only 0-9, a-f
   - URL: contains %XX sequences
   - Binary: only 0s and 1s

2. **Use CyberChef's Magic** - It auto-detects most encodings

3. **Check for multiple layers** - If result still looks encoded, decode again

4. **Remember: encoding is NOT encryption** - No key needed!

5. **Common encoding chains in CTFs:**
   - Base64 -> Hex
   - Hex -> Base64
   - Multiple Base64 layers
   - URL -> Base64 -> Hex
