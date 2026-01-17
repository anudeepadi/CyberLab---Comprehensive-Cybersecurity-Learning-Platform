# Command Line Mastery - Walkthrough

This walkthrough guides you through advanced CLI exercises. Practice each command and understand what it does.

## Exercise 1: File Operations Practice

### Step 1: Create a Working Directory

Set up a practice environment:

```bash
mkdir -p ~/cli-practice
cd ~/cli-practice
```

### Step 2: Create Multiple Files

Use brace expansion to create multiple files:

```bash
touch file{1..5}.txt
touch report_{jan,feb,mar,apr}.log
```

Verify:

```bash
ls -la
```

### Step 3: Add Content to Files

```bash
echo "This is file 1" > file1.txt
echo "Error: Something went wrong" > file2.txt
echo "Warning: Low disk space" > file3.txt
echo "Error: Connection refused" > file4.txt
echo "Info: Process started" > file5.txt
```

### Step 4: Combine Files

Concatenate all files into one:

```bash
cat file*.txt > combined.txt
cat combined.txt
```

### Step 5: Organize into Directories

```bash
mkdir logs errors info
mv report_*.log logs/
```

Copy files matching pattern:

```bash
cp file*.txt info/
```

---

## Exercise 2: Permissions Workshop

### Step 1: Create Test Files

```bash
cd ~/cli-practice
echo '#!/bin/bash' > myscript.sh
echo 'echo "Hello from script"' >> myscript.sh
echo 'exit 0' >> myscript.sh
```

### Step 2: View Current Permissions

```bash
ls -l myscript.sh
```

Output: `-rw-r--r--` (no execute permission)

### Step 3: Try to Execute

```bash
./myscript.sh
```

You'll get: `Permission denied`

### Step 4: Add Execute Permission

```bash
chmod +x myscript.sh
ls -l myscript.sh
```

Output: `-rwxr-xr-x`

Now run it:

```bash
./myscript.sh
```

### Step 5: Experiment with Numeric Permissions

```bash
# Remove all permissions
chmod 000 myscript.sh
ls -l myscript.sh
# Output: ----------

# Set owner read/write only
chmod 600 myscript.sh
ls -l myscript.sh
# Output: -rw-------

# Set full permissions for owner, read/execute for others
chmod 755 myscript.sh
ls -l myscript.sh
# Output: -rwxr-xr-x
```

### Step 6: Create a "Secret" File

```bash
echo "Secret password: hunter2" > secret.txt
chmod 600 secret.txt
ls -l secret.txt
```

Only you can read this file now.

---

## Exercise 3: Text Processing Pipeline

### Step 1: Create Sample Data

Let's create a mock web access log:

```bash
cat > access.log << 'EOF'
192.168.1.100 - - [15/Jan/2024:10:15:32] "GET /index.html HTTP/1.1" 200 1234
192.168.1.101 - - [15/Jan/2024:10:15:33] "GET /login.php HTTP/1.1" 200 2345
192.168.1.100 - - [15/Jan/2024:10:15:34] "POST /login.php HTTP/1.1" 302 0
10.0.0.50 - - [15/Jan/2024:10:15:35] "GET /admin.php HTTP/1.1" 403 567
192.168.1.102 - - [15/Jan/2024:10:15:36] "GET /index.html HTTP/1.1" 200 1234
10.0.0.50 - - [15/Jan/2024:10:15:37] "GET /admin.php HTTP/1.1" 403 567
10.0.0.50 - - [15/Jan/2024:10:15:38] "GET /config.php HTTP/1.1" 404 234
192.168.1.100 - - [15/Jan/2024:10:15:39] "GET /dashboard.php HTTP/1.1" 200 5678
10.0.0.50 - - [15/Jan/2024:10:15:40] "GET /wp-admin HTTP/1.1" 404 234
10.0.0.50 - - [15/Jan/2024:10:15:41] "GET /.env HTTP/1.1" 404 234
EOF
```

### Step 2: Extract IP Addresses

```bash
awk '{print $1}' access.log
```

### Step 3: Count Requests per IP

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn
```

**Pipeline breakdown:**
1. `awk '{print $1}'` - Extract first column (IP)
2. `sort` - Sort IPs alphabetically
3. `uniq -c` - Count unique occurrences
4. `sort -rn` - Sort by count, descending

### Step 4: Find Suspicious Activity

Look for 403 and 404 responses (potential scanning):

```bash
grep -E '"[^"]*" (403|404)' access.log
```

Extract IPs generating errors:

```bash
grep -E '"[^"]*" (403|404)' access.log | awk '{print $1}' | sort | uniq -c
```

### Step 5: Find Most Requested Pages

```bash
awk '{print $7}' access.log | sort | uniq -c | sort -rn
```

---

## Exercise 4: Working with /etc/passwd

### Step 1: View User Information

```bash
cat /etc/passwd
```

### Step 2: Extract Only Usernames

```bash
cut -d':' -f1 /etc/passwd
```

### Step 3: Find Users with Bash Shell

```bash
grep "/bin/bash" /etc/passwd | cut -d':' -f1
```

### Step 4: Count System vs Regular Users

System users typically have UID < 1000:

```bash
# Count system users
awk -F':' '$3 < 1000 {count++} END {print "System users:", count}' /etc/passwd

# Count regular users
awk -F':' '$3 >= 1000 {count++} END {print "Regular users:", count}' /etc/passwd
```

### Step 5: Format User Information Nicely

```bash
awk -F':' '{printf "User: %-15s UID: %-5s Shell: %s\n", $1, $3, $7}' /etc/passwd | head -10
```

---

## Exercise 5: sed Transformations

### Step 1: Create Test Data

```bash
cat > config.txt << 'EOF'
SERVER_IP=192.168.1.1
SERVER_PORT=8080
DEBUG=false
DATABASE_HOST=localhost
DATABASE_PORT=3306
EOF
```

### Step 2: View Original

```bash
cat config.txt
```

### Step 3: Change a Value

Change debug to true:

```bash
sed 's/DEBUG=false/DEBUG=true/' config.txt
```

Note: This only displays the change, doesn't modify the file.

### Step 4: Make Permanent Change

```bash
sed -i 's/DEBUG=false/DEBUG=true/' config.txt
cat config.txt
```

### Step 5: Multiple Substitutions

```bash
sed -e 's/localhost/db.example.com/' -e 's/3306/5432/' config.txt
```

### Step 6: Delete Lines

Remove lines containing PORT:

```bash
sed '/PORT/d' config.txt
```

---

## Exercise 6: Building a Security Script

### Step 1: Create Script File

```bash
cat > security_check.sh << 'EOF'
#!/bin/bash

echo "========================================"
echo "      SECURITY INFORMATION SCRIPT      "
echo "========================================"
echo ""

echo "[*] Current User and Privileges"
echo "--------------------------------"
whoami
id
echo ""

echo "[*] System Information"
echo "----------------------"
uname -a
echo ""

echo "[*] Network Connections"
echo "-----------------------"
ss -tuln 2>/dev/null | head -15
echo ""

echo "[*] Last 5 Logins"
echo "-----------------"
last -5 2>/dev/null
echo ""

echo "[*] Writable Directories in PATH"
echo "---------------------------------"
echo $PATH | tr ':' '\n' | while read dir; do
    if [ -w "$dir" ] 2>/dev/null; then
        echo "WRITABLE: $dir"
    fi
done
echo ""

echo "[*] SUID Binaries (common locations)"
echo "-------------------------------------"
find /usr/bin /usr/sbin -perm -4000 2>/dev/null | head -10
echo ""

echo "========================================"
echo "             SCAN COMPLETE             "
echo "========================================"
EOF
```

### Step 2: Make Executable

```bash
chmod +x security_check.sh
```

### Step 3: Run the Script

```bash
./security_check.sh
```

### Step 4: Save Output to File

```bash
./security_check.sh > security_report.txt 2>&1
cat security_report.txt
```

---

## Exercise 7: Real-Time Log Monitoring

### Step 1: Open Two Terminals

In terminal 1, start watching auth log:

```bash
sudo tail -f /var/log/auth.log | grep --line-buffered "session"
```

### Step 2: Generate Log Entries

In terminal 2, create log activity:

```bash
su - nobody 2>/dev/null
sudo whoami
```

Watch terminal 1 for the logged entries.

### Step 3: Filter for Specific Events

```bash
sudo tail -f /var/log/auth.log | grep --line-buffered -E "(Failed|Accepted)"
```

Press `Ctrl+C` to stop.

---

## Challenge Exercises

### Challenge 1: Parse Apache Logs

Given an access log, find:
- Total number of requests
- Unique IP addresses
- Top 5 most requested resources
- All 404 errors

```bash
# Your solution pipeline here
```

### Challenge 2: User Audit

Create a command pipeline that:
1. Reads /etc/passwd
2. Filters for users with UID > 999
3. Extracts username and home directory
4. Formats output as "User X has home directory Y"

### Challenge 3: File Integrity

Write a script that:
1. Calculates MD5 hashes of all files in a directory
2. Saves to a baseline file
3. Can compare against baseline to detect changes

---

## Verification Checklist

Before proceeding, confirm you can:

- [ ] Create, copy, move, and delete files efficiently
- [ ] Set permissions using both symbolic and numeric notation
- [ ] Use grep with regex patterns
- [ ] Process columnar data with awk
- [ ] Modify text with sed
- [ ] Build multi-command pipelines
- [ ] Redirect stdout, stderr, and combine them
- [ ] Write and execute basic shell scripts

## Common Mistakes to Avoid

1. **Forgetting quotes around patterns with spaces**
   ```bash
   grep "error message" file.txt   # Correct
   grep error message file.txt     # Wrong - searches 'error' in 'message' and 'file.txt'
   ```

2. **Using `rm -rf` without double-checking path**
   - Always `echo` your path first
   - Use `rm -ri` for interactive mode when uncertain

3. **Overwriting files with `>`**
   - Use `>>` to append
   - Use `set -o noclobber` to prevent accidental overwrites

4. **Not escaping special characters in sed/grep**
   - Dots, asterisks, brackets need escaping: `\.` `\*` `\[`

## Next Steps

Continue to [Networking Fundamentals](../03-networking-fundamentals/README.md) to learn how networks operate.
