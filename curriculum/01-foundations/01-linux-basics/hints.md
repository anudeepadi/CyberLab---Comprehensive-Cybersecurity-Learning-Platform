# Linux Basics - Hints

Use these hints when you're stuck. Try to solve problems yourself first - the struggle helps learning!

## General Navigation Hints

### Hint: I'm lost in the file system
- Use `pwd` to print your current directory
- Use `cd ~` or just `cd` to return to your home directory
- Use `cd /` to go to the root of the file system
- Use `cd ..` to go up one directory level
- Use `cd -` to return to the previous directory

### Hint: I can't see hidden files
- Hidden files start with a dot (.)
- Use `ls -a` to show hidden files
- Use `ls -la` for detailed listing including hidden files

### Hint: I don't know what a command does
- Use `man <command>` to read the manual page
- Use `<command> --help` for quick help
- Use `which <command>` to find where a command is located
- Use `type <command>` to see if it's a builtin, alias, or file

---

## User and Permission Hints

### Hint: "Permission denied" error
- You likely need root privileges
- Prefix the command with `sudo`
- Example: `sudo cat /etc/shadow`

### Hint: I can't run a file I created
- Check if it has execute permission: `ls -l filename`
- Add execute permission: `chmod +x filename`

### Hint: Understanding permission notation
- `rwx` = read (4), write (2), execute (1)
- First set = owner, second = group, third = others
- Example: `chmod 755 file` = rwxr-xr-x

### Hint: Finding information about a user
- Use `id username` to see UID, GID, and groups
- Check `/etc/passwd` for basic user info
- Check `/etc/group` for group memberships

---

## Process Management Hints

### Hint: Finding a specific process
- Use `pgrep processname` to get PID(s)
- Use `pgrep -a processname` to see full command
- Use `ps aux | grep processname` for detailed search
- Use `pidof processname` for exact name match

### Hint: A process won't die with `kill`
- Try `kill -9 PID` for force kill (SIGKILL)
- Check if you own the process or need sudo
- Zombie processes (Z state) need parent cleanup

### Hint: I want to see what a process is doing
- Use `strace -p PID` to trace system calls
- Use `lsof -p PID` to see open files
- Use `top -p PID` to monitor that specific process

### Hint: My terminal is frozen/hung
- Press `Ctrl+C` to interrupt current process
- Press `Ctrl+Z` to suspend (then `bg` or `kill %1`)
- Press `Ctrl+D` to send EOF (end of input)

---

## Package Management Hints

### Hint: Package not found when installing
- Run `sudo apt update` first
- Check spelling of package name
- Search with `apt search keyword`

### Hint: I need to find which package provides a file
- Use `apt-file search filename` (install apt-file first)
- Or use `dpkg -S filename` for installed packages

### Hint: Installation is broken/stuck
- Try `sudo dpkg --configure -a`
- Then `sudo apt --fix-broken install`
- Clear cache if needed: `sudo apt clean`

### Hint: I want to see package dependencies
- Use `apt depends packagename`
- Use `apt rdepends packagename` for reverse dependencies

---

## Service Management Hints

### Hint: Service won't start
- Check status for error details: `systemctl status servicename`
- Check logs: `journalctl -u servicename -n 50`
- Look for port conflicts: `ss -tlnp | grep PORT`

### Hint: I need to see all available services
- List all: `systemctl list-units --type=service`
- List enabled: `systemctl list-unit-files --type=service --state=enabled`
- List failed: `systemctl list-units --type=service --state=failed`

### Hint: Changes to config files aren't taking effect
- Reload the service: `sudo systemctl reload servicename`
- Or restart: `sudo systemctl restart servicename`
- Some services need daemon-reload: `sudo systemctl daemon-reload`

### Hint: I need to start a service at boot
- Enable it: `sudo systemctl enable servicename`
- Enable and start now: `sudo systemctl enable --now servicename`

---

## File System Hints

### Hint: I need to find a file but don't know where
- Use `find / -name "filename" 2>/dev/null`
- Use wildcards: `find / -name "*.conf" 2>/dev/null`
- Use `locate filename` (faster, but uses database)

### Hint: I want to search file contents
- Use `grep "search term" filename`
- Search recursively: `grep -r "term" /path/`
- Case insensitive: `grep -i "term" filename`

### Hint: I need to see file type
- Use `file filename` to identify file type
- Check for text: `file filename | grep text`

### Hint: I ran out of disk space
- Check usage: `df -h`
- Find large directories: `du -sh /*`
- Find large files: `find / -type f -size +100M 2>/dev/null`

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| Where am I? | `pwd` |
| Go home | `cd ~` or `cd` |
| List everything | `ls -la` |
| Who am I? | `whoami` |
| What groups? | `id` |
| All processes | `ps aux` |
| Find process | `pgrep -a name` |
| Kill process | `kill PID` |
| Service status | `systemctl status name` |
| Install package | `sudo apt install name` |
| Read manual | `man command` |
| Find file | `find / -name "name" 2>/dev/null` |
| Search in file | `grep "text" file` |

---

## Still Stuck?

1. Read the error message carefully - it often tells you exactly what's wrong
2. Search the error message online
3. Check the man page: `man <command>`
4. Try running with `--help` flag
5. Check if you need sudo/root privileges
6. Ask in CyberLab Discord or forums

Remember: Every error is a learning opportunity!
