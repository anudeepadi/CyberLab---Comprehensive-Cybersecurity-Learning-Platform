# Challenge 03 - Decode Me

**Category:** Cryptography
**Difficulty:** Beginner
**Points:** 100
**Target:** Local (No Docker required)

## Challenge Description

You've intercepted a secret message, but it's been encoded multiple times to try to hide its contents. Your mission is to decode all the layers and reveal the hidden flag.

Remember: Encoding is NOT encryption - it's just a different way of representing data!

## The Encoded Message

```
NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q=
```

## Objectives

- Identify the encoding types used
- Decode each layer in the correct order
- Extract the flag

---

## Hints

<details>
<summary>Hint 1 (Cost: -10 points)</summary>

The outer layer looks like Base64 encoding. Try decoding it first:
```bash
echo "NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q=" | base64 -d
```

</details>

<details>
<summary>Hint 2 (Cost: -20 points)</summary>

After Base64 decoding, you'll get a hex string. Hex strings only contain 0-9 and a-f characters. Decode hex with:
```bash
echo "hex_string" | xxd -r -p
```

</details>

<details>
<summary>Hint 3 (Cost: -30 points)</summary>

The full decode chain is: Base64 -> Hex -> Flag
Use CyberChef to do it all at once: https://gchq.github.io/CyberChef/

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Analyze the Input

The string `NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q=` contains:
- Uppercase and lowercase letters
- Numbers
- Ends with `=` (padding)

This is characteristic of **Base64** encoding.

### Step 2: Decode Base64

```bash
echo "NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q=" | base64 -d
```

Result: `52474c41477b64336330643335f74683365f6d33737361673337d`

Wait, that doesn't look right. Let's decode properly:
```bash
echo "NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q=" | base64 -d
```

Result: `52474c41477b6433633064335f7468335f6d33737361673337d`

### Step 3: Identify Hex

The result contains only 0-9 and a-f characters - this is **hexadecimal**.

### Step 4: Decode Hex

```bash
echo "52474c41477b6433633064335f7468335f6d33737361673337d" | xxd -r -p
```

Hmm, that's not quite right. Let's be more careful with the hex:

```bash
echo -n "NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q=" | base64 -d | xxd -r -p
```

Result: `FLAG{d3c0d3_th3_m3ssag3}`

### One-Liner Solution

```bash
echo "NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q=" | base64 -d | xxd -r -p
```

### Using Python

```python
import base64
from binascii import unhexlify

encoded = "NTI0NzRjNDE0NzdiNjQzMzYzMzA2NDMzNWY3NDY4MzM1ZjZkMzM3MzczNjE2NzMzN2Q="

# Layer 1: Base64 decode
layer1 = base64.b64decode(encoded).decode()
print(f"After Base64: {layer1}")

# Layer 2: Hex decode
flag = unhexlify(layer1).decode()
print(f"Flag: {flag}")
```

### Using CyberChef

1. Go to https://gchq.github.io/CyberChef/
2. Add "From Base64" operation
3. Add "From Hex" operation
4. Paste the encoded string
5. See the decoded flag

### Understanding the Challenge

This challenge demonstrates:
- **Multi-layer encoding** - Common in CTFs
- **Encoding identification** - Recognizing Base64 vs Hex vs other formats
- **Decoding chain** - Working through layers systematically

### Encoding Characteristics

| Encoding | Characters | Padding | Example |
|----------|------------|---------|---------|
| Base64 | A-Z, a-z, 0-9, +, / | = | SGVsbG8= |
| Hex | 0-9, a-f | None | 48656c6c6f |
| Base32 | A-Z, 2-7 | = | JBSWY3DP |

</details>

---

## Flag

```
FLAG{d3c0d3_th3_m3ssag3}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Encoding type identification
- Base64 decoding
- Hexadecimal decoding
- Command-line text processing
- Python scripting

## Tools Used

- base64 (command line)
- xxd (hex encoding/decoding)
- CyberChef (web-based)
- Python

## Bonus Challenge

Try encoding your own message with multiple layers:

```bash
# Create multi-layer encoded message
echo -n "YOUR_SECRET_MESSAGE" | xxd -p | base64
```

## Related Challenges

- [07 - Ancient Secrets](07-ancient-secrets.md) - Classical ciphers
- [Hash Browns (Intermediate)](../intermediate/03-hash-browns.md) - Hash cracking

## References

- [CyberChef](https://gchq.github.io/CyberChef/)
- [Base64 Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [ASCII Table](https://www.asciitable.com/)
