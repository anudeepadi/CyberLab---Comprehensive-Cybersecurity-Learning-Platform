# Challenge 06 - Binary Analysis

**Category:** Reverse Engineering
**Difficulty:** Intermediate
**Points:** 300
**Target:** ELF Binary (Linux)

## Challenge Description

You've obtained a suspicious binary file from a compromised system. The malware author tried to hide the command and control (C2) server address and a secret key inside the binary.

Your mission is to reverse engineer the binary, understand its functionality, and extract the hidden flag that's embedded within it.

## Objectives

- Use static analysis tools (strings, objdump, radare2)
- Use dynamic analysis tools (gdb, strace, ltrace)
- Understand basic assembly language
- Identify obfuscation techniques
- Extract hardcoded secrets

## Target Information

- **Binary:** challenge06-crackme
- **Architecture:** x86_64 ELF
- **Protections:** No PIE, No canary (for learning purposes)
- **Difficulty:** Basic obfuscation, no anti-debugging

## Getting Started

1. Create the challenge binary:

```c
/* challenge06-crackme.c - Compile with: gcc -o crackme challenge06-crackme.c */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// "Obfuscated" flag - each char XOR'd with 0x42
unsigned char obfuscated_flag[] = {
    0x04, 0x2e, 0x03, 0x09, 0x5b, 0x30, 0x21, 0x3c,
    0x25, 0x36, 0x33, 0x27, 0x75, 0x32, 0x2c, 0x21,
    0x2e, 0x37, 0x33, 0x21, 0x33, 0x5f, 0x19
};

// Decoy strings
const char* decoy1 = "FLAG{this_is_fake}";
const char* decoy2 = "FLAG{not_the_real_one}";
const char* c2_server = "evil.attacker.com";

void deobfuscate(unsigned char* data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int check_password(const char* input) {
    // Simple password check
    return strcmp(input, "s3cr3t_p4ss") == 0;
}

void print_flag() {
    unsigned char flag[32];
    memcpy(flag, obfuscated_flag, sizeof(obfuscated_flag));
    deobfuscate(flag, sizeof(obfuscated_flag), 0x42);
    printf("Congratulations! Flag: %s\n", flag);
}

int main(int argc, char** argv) {
    printf("=== CrackMe Challenge ===\n");
    printf("Enter the password: ");

    char input[64];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }
    input[strcspn(input, "\n")] = 0;

    if (check_password(input)) {
        print_flag();
    } else {
        printf("Wrong password! Try again.\n");
    }

    return 0;
}
```

2. Compile the binary:
   ```bash
   gcc -o crackme challenge06-crackme.c -no-pie -fno-stack-protector
   ```

3. Or download pre-compiled binary from challenge files

---

## Hints

<details>
<summary>Hint 1 (Cost: -30 points)</summary>

Start with basic static analysis:

```bash
# Check file type
file crackme

# Look for readable strings
strings crackme

# Check symbols
nm crackme

# Examine sections
objdump -h crackme
```

You'll find some "FLAG{...}" strings, but they might be decoys!

</details>

<details>
<summary>Hint 2 (Cost: -40 points)</summary>

The password check function is `check_password()`. Look at the disassembly:

```bash
objdump -d crackme | grep -A 20 "check_password"
```

Or use radare2:
```bash
r2 crackme
[0x00401000]> aaa
[0x00401000]> pdf @ sym.check_password
```

The password is compared using `strcmp()`. Find what string it's compared against!

</details>

<details>
<summary>Hint 3 (Cost: -60 points)</summary>

The real flag is XOR-obfuscated with key `0x42`.

Find the obfuscated data:
```bash
r2 crackme
[0x00401000]> iz~flag
[0x00401000]> px 32 @ obj.obfuscated_flag
```

Then decode it:
```python
data = bytes([0x04, 0x2e, 0x03, 0x09, 0x5b, 0x30, 0x21, 0x3c,
              0x25, 0x36, 0x33, 0x27, 0x75, 0x32, 0x2c, 0x21,
              0x2e, 0x37, 0x33, 0x21, 0x33, 0x5f, 0x19])
print(''.join(chr(b ^ 0x42) for b in data))
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Initial Reconnaissance

```bash
# File type
file crackme
# Output: crackme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked...

# Security features
checksec crackme
# No PIE, No canary, No RELRO, etc.

# Strings in binary
strings crackme | grep -i flag
# FLAG{this_is_fake}
# FLAG{not_the_real_one}
# ... (decoys!)
```

### Step 2: Find the Password (Static Analysis)

Using objdump:
```bash
objdump -d crackme | grep -A 30 "check_password"
```

Look for the `strcmp` call and the string it references.

Using radare2:
```bash
r2 -A crackme
[0x00401060]> pdf @ sym.check_password
```

Output shows:
```asm
mov esi, str.s3cr3t_p4ss    ; Compare with this string
call sym.imp.strcmp
```

Password: `s3cr3t_p4ss`

### Step 3: Find the Obfuscated Flag (Static Analysis)

```bash
r2 -A crackme
[0x00401060]> afl              ; List functions
[0x00401060]> pdf @ sym.print_flag
```

The `print_flag` function:
1. Copies data from `obfuscated_flag` to local buffer
2. Calls `deobfuscate()` with key `0x42`
3. Prints the result

Examine the obfuscated data:
```bash
[0x00401060]> px 32 @ obj.obfuscated_flag
```

### Step 4: Decode the Flag

```python
#!/usr/bin/env python3
"""Decode XOR-obfuscated flag"""

obfuscated = bytes([
    0x04, 0x2e, 0x03, 0x09, 0x5b, 0x30, 0x21, 0x3c,
    0x25, 0x36, 0x33, 0x27, 0x75, 0x32, 0x2c, 0x21,
    0x2e, 0x37, 0x33, 0x21, 0x33, 0x5f, 0x19
])

key = 0x42

decoded = ''.join(chr(b ^ key) for b in obfuscated)
print(f"Flag: {decoded}")
```

Output: `FLAG{r3v3rs3_3ng1n33r1ng}`

### Step 5: Dynamic Analysis (Alternative Method)

**Using GDB:**
```bash
gdb ./crackme

# Set breakpoint after deobfuscation
(gdb) break print_flag
(gdb) run
Enter the password: s3cr3t_p4ss

# Step through the function
(gdb) si
# ... until after deobfuscate() call

# Examine the flag buffer
(gdb) x/s $rbp-0x30    # Local buffer location
```

**Using ltrace:**
```bash
echo "s3cr3t_p4ss" | ltrace ./crackme
# Shows strcmp call with password, printf with flag
```

**Using strace:**
```bash
echo "s3cr3t_p4ss" | strace ./crackme 2>&1 | grep write
# Shows output being written
```

### Step 6: Automated Analysis with radare2

```bash
r2 -A crackme

# Find all strings
[0x00401060]> iz

# Find XOR operations
[0x00401060]> /c xor
[0x00401060]> pdf @ hit0_0

# Emulate the deobfuscation
[0x00401060]> aei              # Initialize emulation
[0x00401060]> aeim             # Initialize memory
[0x00401060]> s sym.print_flag # Seek to function
[0x00401060]> aecu <end_addr>  # Continue until address
[0x00401060]> px @ <flag_addr> # Print decoded flag
```

### Binary Analysis Cheat Sheet

| Tool | Purpose | Common Commands |
|------|---------|-----------------|
| `file` | Identify file type | `file binary` |
| `strings` | Extract strings | `strings -n 8 binary` |
| `objdump` | Disassembly | `objdump -d binary` |
| `nm` | List symbols | `nm binary` |
| `ltrace` | Library calls | `ltrace ./binary` |
| `strace` | System calls | `strace ./binary` |
| `gdb` | Debugger | `gdb ./binary` |
| `radare2` | RE framework | `r2 -A binary` |
| `ghidra` | Decompiler | GUI-based |

### XOR Obfuscation Detection

XOR is common for simple obfuscation. Detect it by:

1. **Known plaintext**: If you know part of the string (e.g., "FLAG{"), XOR encrypted and expected to find the key
2. **Frequency analysis**: XOR with single-byte key has patterns
3. **Disassembly**: Look for `xor` instructions in loops

```python
# Brute force single-byte XOR
def try_all_xor_keys(data):
    for key in range(256):
        decoded = ''.join(chr(b ^ key) for b in data)
        if decoded.startswith('FLAG'):
            return key, decoded
    return None, None
```

### Common Obfuscation Techniques

| Technique | Detection | Reversal |
|-----------|-----------|----------|
| XOR | `xor` in disasm | XOR with same key |
| Base64 | Charset pattern | Decode |
| ROT13 | Letter patterns | ROT13 again |
| String stacking | Push/mov chars | Concatenate |
| Control flow | Jump spaghetti | Trace execution |

### Prevention (As a Developer)

- Use proper encryption (AES) for sensitive data
- Don't hardcode secrets in binaries
- Use secure credential storage
- Apply binary protections (PIE, RELRO, Stack Canary)
- Consider commercial obfuscation for critical apps

</details>

---

## Flag

```
FLAG{r3v3rs3_3ng1n33r1ng}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Binary file analysis
- Static analysis with objdump/radare2
- Dynamic analysis with gdb/ltrace
- XOR deobfuscation
- x86_64 assembly reading

## Tools Used

- file, strings, nm, objdump
- radare2
- gdb
- ltrace/strace
- Python

## Related Challenges

- [03 - Decode Me (Beginner)](../beginner/03-decode-me.md) - Encoding basics
- [Heap Exploitation (Advanced)](../advanced/01-heap-exploitation.md) - Binary exploitation

## References

- [Radare2 Book](https://book.rada.re/)
- [GDB Tutorial](https://sourceware.org/gdb/current/onlinedocs/gdb/)
- [Reverse Engineering 101](https://malwareunicorn.org/workshops/re101.html)
- [x86 Assembly Guide](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)
