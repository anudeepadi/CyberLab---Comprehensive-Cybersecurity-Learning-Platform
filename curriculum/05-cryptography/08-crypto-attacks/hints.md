# Lab 08 Hints - Crypto Attacks

Progressive hints for cryptographic attack challenges.

## Challenge 1: Padding Oracle

Exploit the padding oracle to decrypt the secret message.

<details>
<summary>Hint 1</summary>

A padding oracle tells you whether the decrypted data has valid PKCS#7 padding.

In CBC mode: `P[i] = Decrypt(C[i]) XOR C[i-1]`

By manipulating `C[i-1]`, you can control the final XOR and thus affect what padding the oracle sees.

</details>

<details>
<summary>Hint 2</summary>

To find the last byte of plaintext:
1. Create an attack block where you try all 256 values for the last byte
2. When padding is valid, you found a value that produces `\x01`
3. `intermediate_byte = guess XOR 0x01`
4. `plaintext_byte = intermediate_byte XOR original_prev_block_byte`

</details>

<details>
<summary>Hint 3</summary>

```python
def attack_last_byte(oracle, block, prev_block):
    for guess in range(256):
        attack_prev = bytearray(16)
        attack_prev[15] = guess
        test_data = bytes(attack_prev) + block

        if oracle.check_padding(test_data):
            intermediate = guess ^ 0x01
            plaintext = intermediate ^ prev_block[15]
            return plaintext
    return None
```

Continue for each byte, adjusting the padding value (0x02, 0x03, etc.)

</details>

<details>
<summary>Solution</summary>

```python
def padding_oracle_attack_block(oracle, block, prev_block):
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    for byte_pos in range(15, -1, -1):
        padding_value = 16 - byte_pos

        # Set known intermediate values for correct padding
        attack_block = bytearray(16)
        for i in range(byte_pos + 1, 16):
            attack_block[i] = intermediate[i] ^ padding_value

        # Brute force current byte
        for guess in range(256):
            attack_block[byte_pos] = guess
            if oracle.check_padding(bytes(attack_block) + block):
                intermediate[byte_pos] = guess ^ padding_value
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(plaintext)

# Apply to all blocks
```

</details>

---

## Challenge 2: CBC Bit Flip

Change "role=user" to "role=admin" using bit-flipping.

<details>
<summary>Hint 1</summary>

In CBC decryption:
```
P[i] = Decrypt(C[i]) XOR C[i-1]
```

If you flip a bit in `C[i-1]`, the same bit flips in `P[i]`!

(Note: `P[i-1]` becomes garbage, but `P[i]` has a predictable change)

</details>

<details>
<summary>Hint 2</summary>

To change character X to character Y at position P:
1. Find which block P is in (block N = P // 16)
2. Find byte position within block (byte = P % 16)
3. XOR the corresponding byte in the previous block:
   `C[N-1][byte] ^= ord(X) ^ ord(Y)`

</details>

<details>
<summary>Hint 3</summary>

```python
def cbc_bit_flip(ciphertext, position, old_char, new_char):
    ct = bytearray(ciphertext)

    # Target in block N -> modify block N-1
    block_num = position // 16
    byte_in_block = position % 16

    # Modify position in previous block
    modify_pos = block_num * 16 + byte_in_block
    ct[modify_pos] ^= ord(old_char) ^ ord(new_char)

    return bytes(ct)

# Find exact position of "user" in your plaintext string
```

</details>

<details>
<summary>Solution</summary>

```python
# Assuming plaintext: "...;role=user;..."
# We want: "...;role=admn;..." (or use 4-char replacement)

# If you control part of the plaintext, craft it for alignment:
plaintext = "comment=AAAAAAAA;admin=0;..."
#                            ^ position we can flip

# Find position of '0'
pos = plaintext.find("admin=0") + len("admin=")

# Flip '0' to '1'
modified = cbc_bit_flip(ciphertext, pos, '0', '1')

# The block before will be corrupted, but our target bit is flipped!
```

**Alternative:** If you need "user" -> "admin" (different lengths), you may need to:
1. Control the plaintext input
2. Use padding/alignment tricks
3. Accept corrupting previous block

</details>

---

## Challenge 3: RSA e=3

Decrypt a message encrypted with e=3 where m^3 < n.

<details>
<summary>Hint 1</summary>

With RSA:
```
c = m^e mod n
```

If `m^e < n`, then no modular reduction happens:
```
c = m^e  (exact)
```

So we can recover m by taking the e-th root of c!

</details>

<details>
<summary>Hint 2</summary>

For e=3, take the cube root:

```python
import gmpy2

c = 12345678901234567890  # ciphertext
e = 3

m, exact = gmpy2.iroot(c, e)
if exact:
    print(f"Message: {int(m)}")
```

</details>

<details>
<summary>Hint 3</summary>

If gmpy2 isn't available, use Newton's method for integer cube root:

```python
def integer_cube_root(n):
    if n < 0:
        return -integer_cube_root(-n)
    x = n
    while True:
        x_new = (2*x + n // (x*x)) // 3
        if x_new >= x:
            return x
        x = x_new

c = 1881676371789154860897069  # Example
m = integer_cube_root(c)
if m**3 == c:
    print(f"Found m: {m}")
```

</details>

<details>
<summary>Solution</summary>

```python
import gmpy2

# Given values
n = 1234567890...  # Large n (doesn't matter if m^3 < n)
e = 3
c = 123456789...   # ciphertext

# Take cube root
m, exact = gmpy2.iroot(c, e)

if exact:
    m = int(m)
    print(f"m = {m}")

    # Convert to text
    length = (m.bit_length() + 7) // 8
    plaintext = m.to_bytes(length, 'big')
    print(f"Plaintext: {plaintext}")
else:
    print("Not exact cube - try Coppersmith's attack or check if Hastad applies")
```

**Note:** If m^3 > n, you may need:
- Hastad's broadcast attack (same m to multiple n's)
- Coppersmith's method (partial knowledge of m)

</details>

---

## Challenge 4: Nonce Reuse

Two messages encrypted with the same nonce. Recover the second message.

<details>
<summary>Hint 1</summary>

In CTR or OFB mode:
```
C = P XOR Keystream
```

If the same keystream is used twice (nonce reuse):
```
C1 = P1 XOR K
C2 = P2 XOR K
```

Then:
```
C1 XOR C2 = P1 XOR P2
```

The keystream cancels out!

</details>

<details>
<summary>Hint 2</summary>

If you know (or can guess) P1:
```
P2 = (C1 XOR C2) XOR P1
```

```python
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

p1_xor_p2 = xor_bytes(c1, c2)
p2 = xor_bytes(p1_xor_p2, known_p1)
```

</details>

<details>
<summary>Hint 3</summary>

If you don't know P1, use **crib dragging**:
- XOR the ciphertexts to get P1 XOR P2
- Guess common words/phrases at each position
- If `(P1 XOR P2) XOR guess` produces readable text, you found part of P1

```python
def crib_drag(xored, crib):
    results = []
    for i in range(len(xored) - len(crib) + 1):
        result = xor_bytes(xored[i:i+len(crib)], crib)
        if all(32 <= b <= 126 for b in result):
            results.append((i, result.decode()))
    return results

# Try common words
for crib in [b"the ", b"FLAG", b" is ", b"secret"]:
    print(crib, crib_drag(c1_xor_c2, crib))
```

</details>

<details>
<summary>Solution</summary>

```python
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Given
c1 = bytes.fromhex("...")  # First ciphertext
c2 = bytes.fromhex("...")  # Second ciphertext
known_p1 = b"The first message text"  # Known or guessed

# XOR ciphertexts
c1_xor_c2 = xor_bytes(c1, c2)

# Recover P2
p2 = xor_bytes(c1_xor_c2, known_p1)
print(f"P2: {p2}")

# If partial knowledge, use crib dragging:
def crib_drag(xored, crib):
    for i in range(len(xored) - len(crib) + 1):
        result = xor_bytes(xored[i:i+len(crib)], crib)
        try:
            text = result.decode('ascii')
            if text.isprintable():
                print(f"Position {i}: XOR with '{crib}' gives '{text}'")
        except:
            pass

crib_drag(c1_xor_c2, b"FLAG{")
```

</details>

---

## Challenge 5: Weak PRNG

The server uses `random.randint()` seeded with current timestamp.

<details>
<summary>Hint 1</summary>

Python's `random` module uses the Mersenne Twister (MT19937).

If seeded with `time.time()`, the seed is predictable!

```python
import random
import time

# Server probably did something like:
# random.seed(int(time.time()))
```

</details>

<details>
<summary>Hint 2</summary>

If you know approximately when the server started:
1. Try all timestamps in that range
2. For each timestamp, seed the PRNG
3. Generate the same sequence
4. Compare with observed outputs

```python
for seed in range(start_time - 100, start_time + 100):
    random.seed(seed)
    test_output = random.randint(0, 1000000)
    if test_output == observed_output:
        print(f"Found seed: {seed}")
        break
```

</details>

<details>
<summary>Hint 3</summary>

For more advanced attacks (if you have 624 outputs):

```python
# pip install randcrack
from randcrack import RandCrack

rc = RandCrack()

# Submit 624 observed 32-bit outputs
for output in observed_outputs[:624]:
    rc.submit(output)

# Now predict future values
predicted = rc.predict_getrandbits(32)
```

</details>

<details>
<summary>Solution</summary>

```python
import random
import time

# Observed output from server
observed = 123456789

# Approximate time server started
current_time = int(time.time())

# Try seeds around current time
for offset in range(-3600, 3600):  # +-1 hour
    seed = current_time + offset
    random.seed(seed)
    test = random.randint(0, 2**32)

    if test == observed:
        print(f"Found seed: {seed}")

        # Generate future "random" values
        random.seed(seed)
        _ = random.randint(0, 2**32)  # Skip the first one
        next_value = random.randint(0, 2**32)
        print(f"Next value: {next_value}")
        break
```

**Key insight:** Never use `random` for cryptographic purposes. Use `secrets` or `os.urandom()` instead.

</details>

---

## Lab Flag Hint

<details>
<summary>Hint 1</summary>

The lab flag is `FLAG{crypt0_br34k3r}`.

Practice by implementing the attacks to recover it from various encryptions.

</details>

<details>
<summary>Hint 2</summary>

```python
# Try encrypting the flag with vulnerable methods and attacking:

# Padding Oracle
from crypto_attacks import PaddingOracle
oracle = PaddingOracle()
ct = oracle.encrypt("FLAG{crypt0_br34k3r}")
# Attack the oracle to recover...

# RSA e=3
m = int.from_bytes(b"FLAG{crypt0_br34k3r}", 'big')
c = pow(m, 3)  # No modulus needed if small
# Take cube root to recover...
```

</details>

<details>
<summary>Solution</summary>

The flag `FLAG{crypt0_br34k3r}` can be recovered using the techniques learned:

1. **Padding Oracle:** Decrypt CBC ciphertext byte-by-byte
2. **Bit Flip:** Modify ciphertext to change plaintext content
3. **RSA e=3:** Take cube root when message is small
4. **Nonce Reuse:** XOR ciphertexts to eliminate keystream

```python
flag = "FLAG{crypt0_br34k3r}"
print(f"Flag: {flag}")
```

</details>

---

## General Crypto Attack Tips

### Identifying Vulnerabilities

| Symptom | Likely Attack |
|---------|---------------|
| Server returns different errors for bad padding | Padding Oracle |
| Same IV/nonce used | Nonce Reuse |
| Small RSA exponent (e=3) | Cube root attack |
| Same message to multiple keys | Hastad broadcast |
| Timing differences | Timing attack |
| `random` module used | PRNG prediction |

### Useful Tools

```bash
# PadBuster for padding oracle
padbuster http://target/ $CT 16

# RsaCtfTool for RSA attacks
python RsaCtfTool.py --publickey pub.pem --unciphertext ct.txt

# xortool for XOR analysis
xortool ciphertext.bin
```

### Quick Python Helpers

```python
# XOR bytes
xor = lambda a, b: bytes(x^y for x,y in zip(a,b))

# Integer to bytes
int.to_bytes(n, (n.bit_length()+7)//8, 'big')

# Bytes to integer
int.from_bytes(b, 'big')

# Modular inverse (Python 3.8+)
pow(e, -1, phi)
```
