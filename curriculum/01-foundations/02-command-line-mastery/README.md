# Lab 02: Command Line Mastery

## Introduction

The command line interface (CLI) is the primary workspace for security professionals. While GUIs are convenient, the CLI offers unmatched power, automation capability, and precision. This lab transforms you from a casual CLI user into someone who thinks in commands and pipelines.

You'll master file operations, text processing, permissions, and the art of chaining commands together. These skills directly apply to log analysis, exploit development, and incident response.

## Learning Objectives

- Master essential file and directory operations
- Understand and manipulate file permissions
- Process text with grep, sed, awk, and other tools
- Create powerful command pipelines
- Redirect input/output and handle streams
- Write basic shell scripts

## Essential File Operations

### Creating and Managing Files

```bash
# Create empty file
touch newfile.txt

# Create file with content
echo "Hello World" > hello.txt

# Create multiple files
touch file{1..5}.txt

# Copy files
cp source.txt destination.txt
cp -r sourcedir/ destdir/    # Recursive (directories)

# Move/rename files
mv oldname.txt newname.txt
mv file.txt /new/location/

# Remove files
rm file.txt
rm -r directory/             # Remove directory recursively
rm -rf directory/            # Force remove (DANGEROUS)

# Create directories
mkdir newdir
mkdir -p parent/child/grandchild  # Create parents as needed
```

### Viewing File Contents

```bash
# View entire file
cat file.txt

# View with line numbers
cat -n file.txt

# View first/last lines
head file.txt           # First 10 lines
head -n 20 file.txt     # First 20 lines
tail file.txt           # Last 10 lines
tail -n 50 file.txt     # Last 50 lines
tail -f /var/log/syslog # Follow file in real-time

# Paginated viewing
less file.txt           # Navigate with arrows, q to quit
more file.txt           # Simpler pager

# Word/line/byte counts
wc file.txt             # Lines, words, bytes
wc -l file.txt          # Just line count
```

## File Permissions Deep Dive

Linux permissions control who can read, write, and execute files. Understanding them is critical for both defense and offense.

### Permission Structure

```
-rwxr-xr-- 1 kali kali 4096 Jan 15 10:30 script.sh
│└┬┘└┬┘└┬┘   │    │
│ │  │  │    │    └── Group owner
│ │  │  │    └─────── File owner
│ │  │  └──────────── Others permissions (r--)
│ │  └─────────────── Group permissions (r-x)
│ └────────────────── Owner permissions (rwx)
└──────────────────── File type (- = file, d = directory)
```

### Numeric Permissions

Each permission has a numeric value:
- Read (r) = 4
- Write (w) = 2
- Execute (x) = 1

Combine them for total permission:
- `rwx` = 4+2+1 = 7
- `r-x` = 4+0+1 = 5
- `r--` = 4+0+0 = 4

```bash
# Common permission sets
chmod 755 script.sh     # rwxr-xr-x (owner full, others read/execute)
chmod 644 file.txt      # rw-r--r-- (owner read/write, others read)
chmod 600 secret.txt    # rw------- (owner only)
chmod 777 public/       # rwxrwxrwx (everyone full - DANGEROUS)
```

### Special Permissions

```bash
# SUID - Execute as file owner (important for privesc!)
chmod u+s binary        # -rwsr-xr-x
chmod 4755 binary

# SGID - Execute as group owner
chmod g+s binary        # -rwxr-sr-x
chmod 2755 binary

# Sticky bit - Only owner can delete (common on /tmp)
chmod +t directory      # drwxrwxrwt
chmod 1777 directory

# Change ownership
chown user:group file.txt
chown -R user:group directory/
```

## Text Processing Power Tools

### grep - Pattern Searching

```bash
# Basic search
grep "error" logfile.txt

# Case insensitive
grep -i "error" logfile.txt

# Show line numbers
grep -n "error" logfile.txt

# Recursive search
grep -r "password" /var/log/

# Invert match (lines NOT containing)
grep -v "debug" logfile.txt

# Count matches
grep -c "error" logfile.txt

# Show context (lines before/after)
grep -B 3 -A 3 "error" logfile.txt

# Extended regex
grep -E "error|warning|critical" logfile.txt

# Only show matching part
grep -o "IP: [0-9.]+" access.log
```

### sed - Stream Editor

```bash
# Substitute first occurrence per line
sed 's/old/new/' file.txt

# Substitute all occurrences
sed 's/old/new/g' file.txt

# Edit file in place
sed -i 's/old/new/g' file.txt

# Delete lines containing pattern
sed '/pattern/d' file.txt

# Delete specific line
sed '5d' file.txt

# Print specific lines
sed -n '10,20p' file.txt

# Multiple operations
sed -e 's/foo/bar/g' -e 's/baz/qux/g' file.txt
```

### awk - Pattern Processing

```bash
# Print specific columns (space-separated)
awk '{print $1}' file.txt           # First column
awk '{print $1, $3}' file.txt       # First and third

# Custom field separator
awk -F':' '{print $1}' /etc/passwd  # Colon-separated

# Conditional printing
awk '$3 > 100 {print $1}' data.txt  # Print col1 if col3 > 100

# Print with formatting
awk '{printf "User: %s, ID: %s\n", $1, $3}' data.txt

# Sum a column
awk '{sum += $1} END {print sum}' numbers.txt

# Count lines
awk 'END {print NR}' file.txt
```

### cut and sort

```bash
# Extract columns
cut -d':' -f1 /etc/passwd           # First field, colon delimiter
cut -d',' -f1,3 data.csv            # Multiple fields

# Extract character positions
cut -c1-10 file.txt                 # First 10 characters

# Sort lines
sort file.txt                       # Alphabetical
sort -n numbers.txt                 # Numerical
sort -r file.txt                    # Reverse
sort -u file.txt                    # Unique only
sort -t':' -k3 -n /etc/passwd       # Sort by third field numerically
```

## Input/Output Redirection

Understanding streams is essential for chaining commands:

- **stdin (0)**: Standard input (keyboard by default)
- **stdout (1)**: Standard output (terminal by default)
- **stderr (2)**: Standard error (terminal by default)

```bash
# Redirect stdout to file (overwrite)
command > output.txt

# Redirect stdout to file (append)
command >> output.txt

# Redirect stderr to file
command 2> errors.txt

# Redirect both stdout and stderr
command > output.txt 2>&1
command &> output.txt               # Shorthand

# Discard output
command > /dev/null 2>&1

# Use file as stdin
command < input.txt

# Here document (multi-line input)
cat << EOF > file.txt
Line 1
Line 2
EOF
```

## Command Pipelines

Pipelines connect the output of one command to the input of another:

```bash
# Basic pipeline
cat /etc/passwd | grep bash

# Multiple pipes
cat access.log | grep "404" | wc -l

# Real-world examples

# Find top 10 IP addresses in access log
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Find users with bash shell
cat /etc/passwd | grep "/bin/bash" | cut -d':' -f1

# Monitor log for errors in real-time
tail -f /var/log/syslog | grep --line-buffered "error"

# Find large files
find / -type f -size +100M 2>/dev/null | xargs ls -lh

# Process list sorted by memory
ps aux | sort -k4 -rn | head -10
```

## Practical Security Examples

### Log Analysis

```bash
# Failed SSH login attempts
grep "Failed password" /var/log/auth.log | \
    awk '{print $11}' | sort | uniq -c | sort -rn

# Successful logins
grep "Accepted" /var/log/auth.log

# Find IPs with most requests
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head

# HTTP response codes summary
awk '{print $9}' access.log | sort | uniq -c | sort -rn
```

### File Analysis

```bash
# Find all SUID files (privilege escalation)
find / -perm -4000 -type f 2>/dev/null

# Find world-writable files
find / -perm -0002 -type f 2>/dev/null

# Find recently modified files
find /var -mtime -1 -type f 2>/dev/null

# Find files owned by root but writable by others
find / -user root -perm -002 -type f 2>/dev/null
```

### Network Information

```bash
# Active connections
netstat -tuln | grep LISTEN
ss -tuln | grep LISTEN

# Established connections
netstat -tunp | grep ESTABLISHED

# DNS lookups
cat /etc/resolv.conf
```

## Basic Shell Scripting

Create your first security script:

```bash
#!/bin/bash
# Simple system enumeration script

echo "=== System Information ==="
uname -a

echo -e "\n=== Current User ==="
whoami
id

echo -e "\n=== Network Interfaces ==="
ip addr | grep "inet "

echo -e "\n=== Listening Ports ==="
ss -tuln | grep LISTEN

echo -e "\n=== Running Processes ==="
ps aux | head -20

echo -e "\n=== SUID Binaries ==="
find /usr -perm -4000 -type f 2>/dev/null
```

Save as `enum.sh` and run:

```bash
chmod +x enum.sh
./enum.sh
```

## Hands-On Exercises

1. Create a file containing 100 random words, then count word frequency
2. Parse `/etc/passwd` to list only usernames and their shells
3. Find the 5 largest files in `/var/log`
4. Create a script that monitors a log file for specific keywords
5. Chain at least 4 commands to analyze web server access logs

## Summary

You've developed essential CLI skills:

- File operations (create, copy, move, delete)
- Permission management (chmod, chown)
- Text processing (grep, sed, awk, cut, sort)
- I/O redirection and pipelines
- Basic shell scripting

These tools combine to form the foundation of security work - from analyzing logs during incident response to crafting payloads during penetration tests.

## Next Steps

Continue to [Networking Fundamentals](../03-networking-fundamentals/README.md) to understand how data flows across networks.
