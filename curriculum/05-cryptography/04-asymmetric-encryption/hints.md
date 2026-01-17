# Lab 04 Hints - Asymmetric Encryption

Progressive hints for asymmetric encryption challenges.

## Challenge 1: Basic RSA

**Given:**
- n = 323
- e = 5
- c = 246

Decrypt to find the message.

<details>
<summary>Hint 1</summary>

To decrypt RSA, you need the private exponent `d`.

To find `d`, you need to factor `n` into its prime components `p` and `q`.

n = 323 is small enough to factor by trial division.

</details>

<details>
<summary>Hint 2</summary>

Try dividing 323 by small primes:
- 323 / 2 = 161.5 (not a factor)
- 323 / 3 = 107.67 (not a factor)
- ...
- 323 / 17 = 19 (exact!)

So n = 17 * 19

</details>

<details>
<summary>Hint 3</summary>

Now calculate:
1. phi(n) = (p-1) * (q-1) = 16 * 18 = 288
2. d = e^(-1) mod phi(n) = 5^(-1) mod 288

To find modular inverse, use extended Euclidean algorithm:
```python
def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x
    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi

d = mod_inverse(5, 288)
print(d)  # 173
```

</details>

<details>
<summary>Solution</summary>

```python
n = 323
e = 5
c = 246

# Factor n
p = 17
q = 19

# Calculate phi(n)
phi_n = (p - 1) * (q - 1)  # 288

# Calculate d
def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi

d = mod_inverse(e, phi_n)  # 173

# Decrypt
m = pow(c, d, n)
print(f"Decrypted: {m}")  # 70
print(f"As ASCII: {chr(m)}")  # 'F'
```

The message is the character 'F' (ASCII 70).

</details>

---

## Challenge 2: Factor n

**Given:**
- n = 7829873491387
- e = 65537
- c = 1234567890

Factor n and decrypt.

<details>
<summary>Hint 1</summary>

This n is too large for simple trial division but small enough for online factoring services.

Try FactorDB: http://factordb.com/

Or use the Python library:
```bash
pip install factordb-pycli
```

</details>

<details>
<summary>Hint 2</summary>

```python
from factordb.factordb import FactorDB

n = 7829873491387
f = FactorDB(n)
f.connect()
factors = f.get_factor_list()
print(factors)
```

</details>

<details>
<summary>Hint 3</summary>

Once you have p and q:

```python
p, q = factors[0], factors[1]
phi_n = (p - 1) * (q - 1)
d = mod_inverse(65537, phi_n)
m = pow(c, d, n)
```

</details>

<details>
<summary>Solution</summary>

```python
from factordb.factordb import FactorDB

n = 7829873491387
e = 65537
c = 1234567890

# Factor using FactorDB
f = FactorDB(n)
f.connect()
factors = f.get_factor_list()
# factors = [2742349, 2855263] (example factors)

p, q = factors[0], factors[1]
phi_n = (p - 1) * (q - 1)

def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi

d = mod_inverse(e, phi_n)
m = pow(c, d, n)

print(f"Decrypted integer: {m}")

# Convert to text if applicable
length = (m.bit_length() + 7) // 8
text = m.to_bytes(length, 'big')
print(f"As bytes: {text}")
```

</details>

---

## Challenge 3: Weak Random (Common Factor)

**Two RSA moduli share a prime factor:**
- n1 = 143
- n2 = 187

Find the shared factor and recover both private keys.

<details>
<summary>Hint 1</summary>

If two RSA moduli share a prime factor, we can find it using the Greatest Common Divisor (GCD).

```python
from math import gcd
shared = gcd(n1, n2)
```

</details>

<details>
<summary>Hint 2</summary>

```python
n1 = 143
n2 = 187

shared = gcd(n1, n2)
print(f"Shared factor: {shared}")  # 11

# Now factor both moduli
q1 = n1 // shared  # 13
q2 = n2 // shared  # 17

print(f"n1 = {shared} * {q1}")  # 11 * 13
print(f"n2 = {shared} * {q2}")  # 11 * 17
```

</details>

<details>
<summary>Hint 3</summary>

With the factors, calculate both private keys:

```python
e = 65537  # or whatever e is used

phi1 = (shared - 1) * (q1 - 1)
phi2 = (shared - 1) * (q2 - 1)

d1 = mod_inverse(e, phi1)
d2 = mod_inverse(e, phi2)
```

</details>

<details>
<summary>Solution</summary>

```python
from math import gcd

n1 = 143
n2 = 187

# Find shared factor
p = gcd(n1, n2)  # 11

# Factor both moduli
q1 = n1 // p  # 13
q2 = n2 // p  # 17

print(f"n1 = {p} * {q1} = {n1}")  # 11 * 13 = 143
print(f"n2 = {p} * {q2} = {n2}")  # 11 * 17 = 187

# Calculate private keys (assuming e=65537)
e = 65537
phi1 = (p - 1) * (q1 - 1)  # 10 * 12 = 120
phi2 = (p - 1) * (q2 - 1)  # 10 * 16 = 160

def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi

d1 = mod_inverse(e, phi1)
d2 = mod_inverse(e, phi2)

print(f"d1 = {d1}")
print(f"d2 = {d2}")
```

**Lesson:** Never generate RSA keys with poor random number generators! If two keys share a prime, both are compromised.

</details>

---

## Challenge 4: Signature Forgery

Verify a message was signed correctly, then forge a signature for a different message.

<details>
<summary>Hint 1</summary>

This challenge likely involves understanding how RSA signatures work.

RSA signature: signature = hash(message)^d mod n
Verification: hash(message) == signature^e mod n

Some implementations have vulnerabilities...

</details>

<details>
<summary>Hint 2</summary>

Common RSA signature vulnerabilities:
1. **No hashing** - If signature = message^d mod n directly, you can forge signatures for m1 * m2 from signatures of m1 and m2
2. **Bleichenbacher's attack** - Against PKCS#1 v1.5 padding
3. **Weak hash function** - MD5 collisions

</details>

<details>
<summary>Hint 3</summary>

If signatures are multiplicative (no hashing):

```python
# sig(m1) = m1^d mod n
# sig(m2) = m2^d mod n
# sig(m1 * m2) = sig(m1) * sig(m2) mod n

# To forge signature for m3 = m1 * m2:
forged_sig = (sig_m1 * sig_m2) % n
```

</details>

<details>
<summary>Solution</summary>

The solution depends on the specific vulnerability. For multiplicative property:

```python
# Given signatures for m1 and m2
n = 3233
e = 17
sig_m1 = 123  # signature of m1
sig_m2 = 456  # signature of m2
m1 = 10
m2 = 20

# Forge signature for m3 = m1 * m2 = 200
m3 = m1 * m2
forged_signature = (sig_m1 * sig_m2) % n

# Verify: signature^e mod n should equal m3
verified = pow(forged_signature, e, n)
print(f"Forged signature for {m3}: {forged_signature}")
print(f"Verification: {verified}")
```

**Lesson:** Always hash messages before signing!

</details>

---

## Challenge 5: Diffie-Hellman Intercept

**Given DH parameters and public values, compute the shared secret.**

- p = 23 (prime modulus)
- g = 5 (generator)
- A = 8 (Alice's public value)
- B = 19 (Bob's public value)

If you know one private value (a = 6), compute the shared secret.

<details>
<summary>Hint 1</summary>

In Diffie-Hellman:
- A = g^a mod p (Alice's public)
- B = g^b mod p (Bob's public)
- Shared secret = g^(ab) mod p

If you know `a`, you can compute the shared secret directly.

</details>

<details>
<summary>Hint 2</summary>

Alice computes: shared = B^a mod p
Bob computes: shared = A^b mod p

Both get the same result: g^(ab) mod p

```python
p = 23
g = 5
a = 6  # Alice's private (given)
B = 19  # Bob's public

shared = pow(B, a, p)
print(f"Shared secret: {shared}")
```

</details>

<details>
<summary>Hint 3</summary>

If you don't know a private value, you'd need to solve the discrete log problem:
- Find a such that g^a = A mod p

For small p, this can be brute-forced:

```python
def discrete_log(g, A, p):
    for a in range(p):
        if pow(g, a, p) == A:
            return a
    return None
```

</details>

<details>
<summary>Solution</summary>

```python
p = 23
g = 5
A = 8
B = 19
a = 6  # Given private value

# Compute shared secret
shared_secret = pow(B, a, p)
print(f"Shared secret: {shared_secret}")  # 2

# Verification: compute the other way
# First, find b by discrete log (only feasible for small p)
def discrete_log(g, pub, p):
    for x in range(p):
        if pow(g, x, p) == pub:
            return x
    return None

b = discrete_log(g, B, p)
print(f"Bob's private b: {b}")  # Some value

# Verify both methods give same shared secret
shared_from_bob = pow(A, b, p)
print(f"Shared secret (Bob's method): {shared_from_bob}")

# Both should match!
assert shared_secret == shared_from_bob
```

</details>

---

## Lab Flag Hint

<details>
<summary>Hint 1</summary>

The lab flag `FLAG{publ1c_k3y_m4st3r}` can be encrypted with RSA.

Try generating your own key pair and encrypting/decrypting it.

</details>

<details>
<summary>Hint 2</summary>

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Encrypt flag
flag = b"FLAG{publ1c_k3y_m4st3r}"
encrypted = public_key.encrypt(
    flag,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"Encrypted: {encrypted.hex()}")
```

</details>

<details>
<summary>Solution</summary>

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

flag = b"FLAG{publ1c_k3y_m4st3r}"

# Encrypt
encrypted = public_key.encrypt(
    flag,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt
decrypted = private_key.decrypt(
    encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Flag: {decrypted.decode()}")
# FLAG{publ1c_k3y_m4st3r}
```

</details>

---

## General RSA Tips

### Common Attack Scenarios

| Vulnerability | Attack Method |
|--------------|---------------|
| Small n | Factor with FactorDB, yafu, msieve |
| Common factor | GCD of multiple n values |
| Small e, small m | Integer root attack |
| Same m to multiple recipients | Hastad's broadcast attack |
| Small d | Wiener's attack (continued fractions) |
| Predictable p, q | Fermat factorization |

### Useful Tools

```bash
# FactorDB (Python)
pip install factordb-pycli

# RsaCtfTool (automated attacks)
git clone https://github.com/RsaCtfTool/RsaCtfTool

# OpenSSL for key inspection
openssl rsa -in key.pem -text -noout
```

### Quick Python Functions

```python
# Integer to bytes
n.to_bytes((n.bit_length() + 7) // 8, 'big')

# Bytes to integer
int.from_bytes(data, 'big')

# Modular inverse
pow(e, -1, phi_n)  # Python 3.8+

# GCD
from math import gcd

# Integer nth root (with gmpy2)
import gmpy2
root, exact = gmpy2.iroot(c, e)
```
