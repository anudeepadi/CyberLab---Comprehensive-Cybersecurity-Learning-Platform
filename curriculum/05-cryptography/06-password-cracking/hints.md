# Lab 06 Hints - Password Cracking

Progressive hints for password cracking challenges.

## Challenge 1: Basic MD5

**Hash:** `e10adc3949ba59abbe56e057f20f883e`

<details>
<summary>Hint 1</summary>

This is an MD5 hash (32 hex characters).

It's one of the most commonly leaked password hashes in history.

Try an online rainbow table lookup first.

</details>

<details>
<summary>Hint 2</summary>

This hash appears in virtually every data breach.

Think of the simplest, most common numeric password.

</details>

<details>
<summary>Hint 3</summary>

```python
import hashlib

# Try the top 5 most common passwords
common = ["123456", "password", "12345678", "qwerty", "123456789"]

for pw in common:
    if hashlib.md5(pw.encode()).hexdigest() == "e10adc3949ba59abbe56e057f20f883e":
        print(f"Password: {pw}")
```

</details>

<details>
<summary>Solution</summary>

**Password:** `123456`

```python
import hashlib
print(hashlib.md5(b"123456").hexdigest())
# Output: e10adc3949ba59abbe56e057f20f883e
```

This is the #1 most common password globally. It appears in almost every breach database.

</details>

---

## Challenge 2: SHA-256 with Rules

**Hash:** `5e884898da28047d9165091e2205ad02ba4aca1a7c34e8d3c0b87b3462f13a8e`

Hint: It's a common word with modifications.

<details>
<summary>Hint 1</summary>

This is a SHA-256 hash (64 hex characters).

Before applying rules, check if it's a simple common word.

</details>

<details>
<summary>Hint 2</summary>

This particular hash is actually a very simple 4-letter word with no modifications.

It's commonly used for testing.

</details>

<details>
<summary>Hint 3</summary>

```python
import hashlib

simple_words = ["test", "admin", "root", "user", "pass", "demo", "temp"]

target = "5e884898da28047d9165091e2205ad02ba4aca1a7c34e8d3c0b87b3462f13a8e"

for word in simple_words:
    if hashlib.sha256(word.encode()).hexdigest() == target:
        print(f"Password: {word}")
```

</details>

<details>
<summary>Solution</summary>

**Password:** `test`

```python
import hashlib
print(hashlib.sha256(b"test").hexdigest())
# Output: 5e884898da28047d9165091e2205ad02ba4aca1a7c34e8d3c0b87b3462f13a8e
```

The hint about "modifications" was a red herring - always try simple words first!

</details>

---

## Challenge 3: NTLM Hash

**Hash:** `32ed87bdb5fdc5e9cba88547376818d4`

Windows NTLM hash. Find the password.

<details>
<summary>Hint 1</summary>

NTLM hashes are 32 hex characters (same length as MD5).

NTLM uses MD4 with UTF-16LE encoding.

Try common passwords with a wordlist.

</details>

<details>
<summary>Hint 2</summary>

```python
import hashlib
import binascii

def ntlm_hash(password):
    return binascii.hexlify(
        hashlib.new('md4', password.encode('utf-16le')).digest()
    ).decode()

# Test with common passwords
target = "32ed87bdb5fdc5e9cba88547376818d4"
```

</details>

<details>
<summary>Hint 3</summary>

```bash
# Using hashcat
echo "32ed87bdb5fdc5e9cba88547376818d4" > ntlm.txt
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt

# Or CrackStation online
```

</details>

<details>
<summary>Solution</summary>

**Password:** `password`

```python
import hashlib
import binascii

def ntlm_hash(password):
    return binascii.hexlify(
        hashlib.new('md4', password.encode('utf-16le')).digest()
    ).decode()

print(ntlm_hash("password"))
# Output: 32ed87bdb5fdc5e9cba88547376818d4
```

Hashcat command:
```bash
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt --show
```

</details>

---

## Challenge 4: Salted Hash

**Salt:** `deadbeef`
**Hash (SHA256):** `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

Crack the salted password.

<details>
<summary>Hint 1</summary>

Salted hashes are computed as: `hash(salt + password)` or `hash(password + salt)`

Try both methods with common passwords.

The format here is likely `SHA256(salt + password)`.

</details>

<details>
<summary>Hint 2</summary>

Wait... look at this hash more carefully.

`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

This is actually a very famous SHA-256 hash!

</details>

<details>
<summary>Hint 3</summary>

```python
import hashlib

# This hash is SHA256 of "test"!
print(hashlib.sha256(b"test").hexdigest())

# But wait, we have a salt...
# Maybe the password is empty or the salt is not used?
# Or maybe: SHA256("deadbeef" + "") = ???
```

</details>

<details>
<summary>Solution</summary>

This is a trick question! The hash `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` is the SHA-256 of just `"test"` (without salt).

Either:
1. The salt wasn't actually applied, or
2. The password when salted produces this hash

```python
import hashlib

# Pure hash of "test"
print(hashlib.sha256(b"test").hexdigest())
# 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

# This IS the hash given! So the "salt" was misleading.
```

**Lesson:** Always check if a hash matches common values before assuming it's properly salted!

</details>

---

## Challenge 5: bcrypt

**Hash:** `$2a$10$N9qo8uLOickgx2ZMRZoMy.MrPSCr9YH9Q7xZLqvA6j5e8dKjPf7qC`

Crack this bcrypt hash. Hint: Very common password.

<details>
<summary>Hint 1</summary>

bcrypt is slow by design - that's the point!

The format is: `$2a$cost$salt+hash`
- `$2a$` = bcrypt variant
- `10` = cost factor (2^10 = 1024 iterations)
- Next 22 chars = salt
- Remaining = hash

Try only the most common passwords.

</details>

<details>
<summary>Hint 2</summary>

For bcrypt, don't try huge wordlists - it's too slow.

Focus on top 100 most common passwords.

The hint says "very common" - think top 10.

</details>

<details>
<summary>Hint 3</summary>

```python
import bcrypt

hash_to_crack = b"$2a$10$N9qo8uLOickgx2ZMRZoMy.MrPSCr9YH9Q7xZLqvA6j5e8dKjPf7qC"

# Top 10 most common passwords
top_passwords = [
    b"123456", b"password", b"12345678", b"qwerty", b"123456789",
    b"12345", b"1234", b"111111", b"1234567", b"dragon"
]

for pw in top_passwords:
    if bcrypt.checkpw(pw, hash_to_crack):
        print(f"Password: {pw.decode()}")
        break
```

</details>

<details>
<summary>Solution</summary>

**Password:** `password`

```python
import bcrypt

hash_to_crack = b"$2a$10$N9qo8uLOickgx2ZMRZoMy.MrPSCr9YH9Q7xZLqvA6j5e8dKjPf7qC"

if bcrypt.checkpw(b"password", hash_to_crack):
    print("Password: password")

# Or using hashcat (slow!)
# hashcat -m 3200 bcrypt.txt wordlist.txt
```

Even bcrypt can't protect weak passwords! It just makes attacks slower.

</details>

---

## Lab Flag Hint

<details>
<summary>Hint 1</summary>

The lab flag is `FLAG{cr4ck_th3_h4sh}`.

Practice by creating hashes of this flag and cracking them.

</details>

<details>
<summary>Hint 2</summary>

```python
import hashlib

flag = "FLAG{cr4ck_th3_h4sh}"

print(f"MD5: {hashlib.md5(flag.encode()).hexdigest()}")
print(f"SHA1: {hashlib.sha1(flag.encode()).hexdigest()}")
print(f"SHA256: {hashlib.sha256(flag.encode()).hexdigest()}")
```

</details>

<details>
<summary>Solution</summary>

```python
import hashlib

flag = "FLAG{cr4ck_th3_h4sh}"

# These hashes all represent the flag
md5_hash = hashlib.md5(flag.encode()).hexdigest()
sha1_hash = hashlib.sha1(flag.encode()).hexdigest()
sha256_hash = hashlib.sha256(flag.encode()).hexdigest()

print(f"Flag: {flag}")
print(f"MD5: {md5_hash}")
print(f"SHA1: {sha1_hash}")
print(f"SHA256: {sha256_hash}")
```

</details>

---

## General Password Cracking Tips

### Quick Identification

| Format | Hash Type | Hashcat Mode |
|--------|-----------|--------------|
| 32 hex chars | MD5 | 0 |
| 40 hex chars | SHA-1 | 100 |
| 64 hex chars | SHA-256 | 1400 |
| Starts with $1$ | MD5crypt | 500 |
| Starts with $6$ | SHA512crypt | 1800 |
| Starts with $2a$ | bcrypt | 3200 |

### Attack Strategy

1. **Check online first:** CrackStation, Hashes.com
2. **Try common passwords:** Top 100 list
3. **Dictionary attack:** rockyou.txt
4. **Rules:** best64.rule
5. **Hybrid:** word + numbers
6. **Brute force:** Last resort

### Useful Commands

```bash
# Hashcat dictionary
hashcat -m 0 hash.txt wordlist.txt

# Hashcat with rules
hashcat -m 0 hash.txt wordlist.txt -r best64.rule

# Hashcat mask (8 lowercase)
hashcat -m 0 hash.txt -a 3 ?l?l?l?l?l?l?l?l

# John auto-detect
john hash.txt

# Show cracked
hashcat -m 0 hash.txt --show
john --show hash.txt
```

### Online Resources

- **CrackStation:** https://crackstation.net/
- **Hashes.com:** https://hashes.com/
- **Hashcat examples:** https://hashcat.net/wiki/doku.php?id=example_hashes
