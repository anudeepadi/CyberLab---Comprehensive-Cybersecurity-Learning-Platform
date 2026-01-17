# Lab 05 Hints - Hashing

Progressive hints for hash function challenges.

## Challenge 1: Identify the Hash

**Hash:** `5d41402abc4b2a76b9719d911017c592`

What algorithm and what plaintext?

<details>
<summary>Hint 1</summary>

Count the characters in the hash string.

32 hexadecimal characters = 128 bits

What common hash algorithm produces 128-bit output?

</details>

<details>
<summary>Hint 2</summary>

32 hex characters suggests MD5.

This is a very common hash - it might be a simple word.

Try looking it up in an online hash database like CrackStation.

</details>

<details>
<summary>Hint 3</summary>

```python
import hashlib

# Try common words
common_words = ["hello", "world", "password", "test", "admin"]

for word in common_words:
    if hashlib.md5(word.encode()).hexdigest() == "5d41402abc4b2a76b9719d911017c592":
        print(f"Found: {word}")
        break
```

</details>

<details>
<summary>Solution</summary>

**Algorithm:** MD5 (128-bit = 32 hex characters)

**Plaintext:** "hello"

```python
import hashlib
print(hashlib.md5(b"hello").hexdigest())
# Output: 5d41402abc4b2a76b9719d911017c592
```

You can verify at https://crackstation.net/

</details>

---

## Challenge 2: Hash Collision

Two files have the same MD5 but different content. Why is this bad?

<details>
<summary>Hint 1</summary>

MD5 collisions were first demonstrated in 2004 by researchers.

A collision means: `MD5(file1) == MD5(file2)` but `file1 != file2`

Think about where MD5 hashes are used for verification...

</details>

<details>
<summary>Hint 2</summary>

Security implications:
- Digital signature forgery
- Certificate spoofing
- Malware disguised as legitimate files
- Version control manipulation

If you trust a file based on its MD5 hash, an attacker could substitute a malicious file with the same hash.

</details>

<details>
<summary>Hint 3</summary>

Real-world example: The "SHAttered" attack on SHA-1 (2017) allowed creating two different PDF files with identical SHA-1 hashes.

For MD5, researchers have created:
- Two different programs with same MD5
- Two different certificates with same MD5
- "Chosen-prefix" attacks for practical exploitation

</details>

<details>
<summary>Solution</summary>

**Why MD5 collisions are dangerous:**

1. **File Integrity:** Software downloads verified by MD5 can be replaced with malware
2. **Digital Signatures:** Attacker can create different document that validates against existing signature
3. **Certificates:** Rogue CA certificates can be created (demonstrated in 2008)
4. **Version Control:** Git uses SHA-1, theoretically vulnerable

**Example collision (hex bytes differ but same MD5):**
```python
# These produce the same MD5 hash:
# d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89...
# d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89...
#                                    ^^                           ^^ different!
```

**Mitigation:** Use SHA-256 or SHA-3 for security-critical applications.

</details>

---

## Challenge 3: Length Extension Attack

**Given:** `SHA256(secret || message) = <hash>`

Can you compute `SHA256(secret || message || padding || evil)` without knowing the secret?

<details>
<summary>Hint 1</summary>

This is called a "Length Extension Attack."

It exploits how Merkle-Damgard hash functions (MD5, SHA-1, SHA-256) work internally.

The final hash state contains enough information to continue hashing.

</details>

<details>
<summary>Hint 2</summary>

SHA-256 processes data in blocks. After processing, the internal state becomes the hash output.

If you know:
- The hash output (internal state after processing)
- The length of (secret + message)

You can continue from that state without knowing the secret!

</details>

<details>
<summary>Hint 3</summary>

```python
# pip install hashpumpy
import hashpumpy

# Known values
original_hash = "..."  # SHA256(secret || message)
original_message = "message"
secret_length = 16  # length of secret (you need to know/guess this)
data_to_add = "evil_data"

# Perform length extension
new_hash, new_message = hashpumpy.hashpump(
    original_hash,
    original_message,
    data_to_add,
    secret_length
)

# new_hash = SHA256(secret || original_message || padding || data_to_add)
# Without ever knowing the secret!
```

</details>

<details>
<summary>Solution</summary>

**Length Extension Attack explained:**

```
Original: SHA256(secret || message) = hash_1

Attack computes: SHA256(secret || message || padding || evil) = hash_2

Without knowing 'secret'!
```

**Vulnerable algorithms:** MD5, SHA-1, SHA-256, SHA-512 (Merkle-Damgard construction)

**Not vulnerable:** SHA-3, BLAKE2, HMAC

**Mitigation:** Use HMAC instead of raw hash:
```python
# WRONG (vulnerable):
hash = SHA256(secret + message)

# RIGHT (safe):
hash = HMAC-SHA256(secret, message)
```

**Tools:**
- hashpumpy (Python)
- hash_extender (C)
- hlextend (Python)

</details>

---

## Challenge 4: Rainbow Table Lookup

**Hash:** `5f4dcc3b5aa765d61d8327deb882cf99`

What is the original password?

<details>
<summary>Hint 1</summary>

This is an MD5 hash (32 hex characters).

Common passwords are pre-computed in "rainbow tables" - databases mapping hashes to plaintexts.

Try an online lookup service.

</details>

<details>
<summary>Hint 2</summary>

Online services to try:
- https://crackstation.net/
- https://md5decrypt.net/
- https://www.md5online.org/

This hash is one of the most common - it's definitely in any rainbow table.

</details>

<details>
<summary>Hint 3</summary>

```python
import hashlib

# Try the most common passwords
top_passwords = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine"
]

target = "5f4dcc3b5aa765d61d8327deb882cf99"

for pw in top_passwords:
    if hashlib.md5(pw.encode()).hexdigest() == target:
        print(f"Password: {pw}")
        break
```

</details>

<details>
<summary>Solution</summary>

**Password:** `password`

```python
import hashlib
print(hashlib.md5(b"password").hexdigest())
# Output: 5f4dcc3b5aa765d61d8327deb882cf99
```

This is literally the most common password hash in any rainbow table!

**Lesson:** Never store unsalted MD5 hashes of passwords. Use bcrypt, argon2, or PBKDF2 with a unique salt.

</details>

---

## Challenge 5: HMAC Verification

**Message:** "Transfer $1000 to account 12345"
**HMAC-SHA256:** `8a9f2b3c4d5e6f7a8b9c0d1e2f3a4b5c...`
**Key hint:** It's a common 8-letter word

<details>
<summary>Hint 1</summary>

HMAC combines a key with the message for authentication.

You need to find an 8-letter key that produces the given HMAC.

Since it's a "common" word, try a wordlist of common 8-letter words.

</details>

<details>
<summary>Hint 2</summary>

```python
import hmac
import hashlib

message = b"Transfer $1000 to account 12345"
target_hmac = "8a9f2b3c4d5e6f7a8b9c0d1e2f3a4b5c..."

# 8-letter words to try
words_8 = [
    "password", "security", "transfer", "accounts",
    "payments", "verified", "approved", "complete",
    "bankings", "finances"
]

for word in words_8:
    if len(word) == 8:
        h = hmac.new(word.encode(), message, hashlib.sha256).hexdigest()
        if h.startswith(target_hmac[:16]):
            print(f"Key: {word}")
```

</details>

<details>
<summary>Hint 3</summary>

If you have a larger wordlist:

```bash
# Get 8-letter words from a dictionary
grep -E '^.{8}$' /usr/share/dict/words > words8.txt
```

```python
with open('words8.txt') as f:
    for word in f:
        word = word.strip().lower()
        # Try as HMAC key...
```

</details>

<details>
<summary>Solution</summary>

The solution depends on the actual HMAC value provided. Here's the approach:

```python
import hmac
import hashlib

message = b"Transfer $1000 to account 12345"
# Replace with actual target HMAC from challenge
target_hmac = "your_target_hmac_here"

# Common 8-letter keys
candidates = [
    "password", "security", "secretss", "transfer",
    "keysecrt", "authcode", "bankkeys", "verified"
]

for key in candidates:
    calculated = hmac.new(key.encode(), message, hashlib.sha256).hexdigest()
    if calculated == target_hmac:
        print(f"Key found: {key}")
        print(f"HMAC: {calculated}")
        break
```

**Key takeaway:** HMAC security depends on key secrecy AND key strength. An 8-letter common word is weak!

</details>

---

## Lab Flag Hint

<details>
<summary>Hint 1</summary>

The lab flag is `FLAG{h4sh_1t_0ut}`.

Calculate its hash with different algorithms to verify.

</details>

<details>
<summary>Hint 2</summary>

```python
import hashlib

flag = "FLAG{h4sh_1t_0ut}"

print(f"MD5:    {hashlib.md5(flag.encode()).hexdigest()}")
print(f"SHA1:   {hashlib.sha1(flag.encode()).hexdigest()}")
print(f"SHA256: {hashlib.sha256(flag.encode()).hexdigest()}")
```

</details>

<details>
<summary>Solution</summary>

```python
import hashlib

flag = "FLAG{h4sh_1t_0ut}"

print(f"Flag: {flag}")
print(f"MD5:    {hashlib.md5(flag.encode()).hexdigest()}")
print(f"SHA1:   {hashlib.sha1(flag.encode()).hexdigest()}")
print(f"SHA256: {hashlib.sha256(flag.encode()).hexdigest()}")

# Output:
# Flag: FLAG{h4sh_1t_0ut}
# MD5:    (calculated value)
# SHA1:   (calculated value)
# SHA256: (calculated value)
```

</details>

---

## General Hashing Tips

### Hash Identification Cheat Sheet

| Length | Likely Algorithm |
|--------|------------------|
| 32 hex | MD5 |
| 40 hex | SHA-1 |
| 64 hex | SHA-256 |
| 128 hex | SHA-512 |
| Starts with $1$ | MD5crypt |
| Starts with $6$ | SHA-512crypt |
| Starts with $2a$ | bcrypt |

### Quick Commands

```bash
# Hash a string
echo -n "text" | md5sum
echo -n "text" | sha256sum

# Hash a file
sha256sum file.txt

# Verify hashes
sha256sum -c checksums.txt

# HMAC
echo -n "message" | openssl dgst -sha256 -hmac "key"
```

### Useful Online Tools

- **CrackStation** - Rainbow table lookup
- **Hashcat Example Hashes** - Hash format reference
- **CyberChef** - Hash calculation and analysis
- **hashID** - Hash type identification
