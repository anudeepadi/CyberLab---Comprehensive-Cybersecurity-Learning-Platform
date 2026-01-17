# Linux Basics - Walkthrough

This walkthrough provides step-by-step guidance through the Linux Basics exercises. Open a terminal and follow along, typing each command yourself.

## Exercise 1: File System Exploration

### Step 1: Navigate to /etc/

First, let's move to the `/etc/` directory, which contains system configuration files:

```bash
cd /etc
```

Verify your location:

```bash
pwd
```

You should see: `/etc`

### Step 2: List Contents of /etc/

List the contents of the current directory:

```bash
ls
```

For more detail, use the long format with hidden files:

```bash
ls -la
```

Notice the sheer number of configuration files. Each manages a different aspect of the system.

### Step 3: Find All .conf Files

Use the `find` command to locate configuration files:

```bash
find /etc -name "*.conf" 2>/dev/null
```

**Explanation:**
- `find /etc` - Search in /etc directory
- `-name "*.conf"` - Match files ending in .conf
- `2>/dev/null` - Hide permission denied errors

Alternative using `ls` with recursion:

```bash
ls -la /etc/*.conf
```

### Step 4: Read /etc/hostname

Display the system's hostname:

```bash
cat /etc/hostname
```

You should see your machine's name (e.g., `kali` or `cyberlab`).

---

## Exercise 2: User Investigation

### Step 1: List All Users

The `/etc/passwd` file contains user information:

```bash
cat /etc/passwd
```

Each line represents one user. Count total users:

```bash
wc -l /etc/passwd
```

### Step 2: Find Users with /bin/bash Shell

Filter for users who have bash as their login shell:

```bash
grep "/bin/bash" /etc/passwd
```

These are typically interactive user accounts. System accounts often use `/usr/sbin/nologin` or `/bin/false`.

### Step 3: Find Your User's UID and GID

Use the `id` command for your current user:

```bash
id
```

Output format:
```
uid=1000(kali) gid=1000(kali) groups=1000(kali),27(sudo),...
```

Or extract from `/etc/passwd`:

```bash
grep "^$(whoami):" /etc/passwd
```

### Step 4: Examine Root User

Compare with the root user:

```bash
grep "^root:" /etc/passwd
```

Notice root has UID and GID of 0.

---

## Exercise 3: Process Analysis

### Step 1: List All Running Processes

View all processes on the system:

```bash
ps aux
```

**Column meanings:**
- `USER` - Process owner
- `PID` - Process ID
- `%CPU` - CPU usage
- `%MEM` - Memory usage
- `COMMAND` - The command running

For a live view:

```bash
top
```

Press `q` to exit top.

### Step 2: Find Your Shell's PID

Your current shell has a PID stored in a special variable:

```bash
echo $$
```

Verify with ps:

```bash
ps -p $$
```

Or find by name:

```bash
pgrep -a bash
```

### Step 3: Background Process Management

Start a long-running process in the background:

```bash
sleep 300 &
```

The `&` runs it in the background. Note the job number `[1]` and PID.

List background jobs:

```bash
jobs
```

Bring job to foreground:

```bash
fg %1
```

Press `Ctrl+Z` to suspend it, then send back to background:

```bash
bg %1
```

Finally, terminate it:

```bash
kill %1
```

---

## Exercise 4: Package Management

### Step 1: Update Package Lists

Always update before installing:

```bash
sudo apt update
```

This downloads the latest package information from repositories.

### Step 2: Search for nmap

Find the nmap package:

```bash
apt search nmap
```

Get detailed information:

```bash
apt show nmap
```

### Step 3: Check for netcat

See if netcat is installed:

```bash
which nc
```

Or:

```bash
dpkg -l | grep netcat
```

If not installed:

```bash
sudo apt install netcat-openbsd
```

### Step 4: List Installed Security Tools

See what's already installed:

```bash
dpkg -l | grep -E "(nmap|wireshark|burp|metasploit)"
```

---

## Exercise 5: Service Management

### Step 1: Check SSH Service Status

View the SSH daemon status:

```bash
systemctl status ssh
```

Look for:
- `Active: active (running)` - Service is running
- `Active: inactive (dead)` - Service is stopped

### Step 2: Start Apache Web Server

Start the Apache2 web server:

```bash
sudo systemctl start apache2
```

Verify it started:

```bash
systemctl status apache2
```

### Step 3: Verify Port 80

Check if Apache is listening on port 80:

```bash
ss -tlnp | grep :80
```

Or:

```bash
sudo netstat -tlnp | grep :80
```

**Explanation:**
- `-t` - TCP connections
- `-l` - Listening ports
- `-n` - Numeric (don't resolve names)
- `-p` - Show process name

### Step 4: Test the Web Server

Use curl to make a request:

```bash
curl http://localhost
```

You should see Apache's default page HTML.

### Step 5: Stop the Service

When done, stop Apache:

```bash
sudo systemctl stop apache2
```

---

## Bonus Challenges

### Challenge 1: Find SUID Binaries

Search for files with the SUID bit set (important for privilege escalation):

```bash
find / -perm -4000 2>/dev/null
```

### Challenge 2: Check Login History

View recent login attempts:

```bash
last
```

View failed login attempts:

```bash
sudo lastb
```

### Challenge 3: Monitor System Logs

Watch authentication logs in real-time:

```bash
sudo tail -f /var/log/auth.log
```

Open another terminal and try logging in with a wrong password to see it logged.

### Challenge 4: Create a Test User

Create a new user:

```bash
sudo useradd -m testuser
sudo passwd testuser
```

Switch to that user:

```bash
su - testuser
```

Exit back to your user:

```bash
exit
```

Delete the test user:

```bash
sudo userdel -r testuser
```

---

## Verification Checklist

Before moving on, ensure you can:

- [ ] Navigate to any directory using `cd`
- [ ] List files with detailed information using `ls -la`
- [ ] Find files by name or pattern
- [ ] Identify your user's UID and GID
- [ ] List running processes and find specific ones
- [ ] Start, stop, and check status of services
- [ ] Update and search packages with apt

## Common Issues and Solutions

**"Permission denied" errors:**
- Add `sudo` before the command for privileged operations

**"Command not found" errors:**
- The tool may not be installed: `sudo apt install <package>`
- Or check if it's in a different location: `which <command>`

**Services won't start:**
- Check for port conflicts: `ss -tlnp`
- Check service logs: `journalctl -u service-name`

## Next Steps

Continue to the [Command Line Mastery](../02-command-line-mastery/README.md) walkthrough for advanced CLI techniques.
