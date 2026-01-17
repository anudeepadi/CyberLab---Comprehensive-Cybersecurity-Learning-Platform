# Lab 01: Linux Basics

## Introduction

Linux is the dominant operating system in cybersecurity for good reason. Most servers, embedded devices, and security tools run on Linux. Kali Linux, the distribution included in CyberLab, comes pre-loaded with hundreds of security tools. Mastering Linux fundamentals is your first step toward becoming a proficient security professional.

This lab introduces core Linux concepts: the file system hierarchy, user management, processes, and basic system administration. By the end, you'll navigate Linux with confidence.

## Learning Objectives

- Understand the Linux file system hierarchy
- Navigate directories and manage files
- Understand users, groups, and permissions
- Manage processes and services
- Use package managers to install software

## The Linux File System Hierarchy

Unlike Windows with its drive letters (C:, D:), Linux uses a single unified tree starting from the root directory `/`. Understanding this hierarchy is essential:

```
/               # Root of the entire file system
├── bin/        # Essential user binaries (ls, cp, cat)
├── boot/       # Boot loader files, kernel
├── dev/        # Device files (hard drives, USB, etc.)
├── etc/        # System configuration files
├── home/       # User home directories
│   └── kali/   # Your home directory in Kali Linux
├── lib/        # Shared libraries
├── opt/        # Optional/third-party software
├── proc/       # Virtual filesystem for process info
├── root/       # Root user's home directory
├── sbin/       # System binaries (admin commands)
├── tmp/        # Temporary files (cleared on reboot)
├── usr/        # User programs and data
│   ├── bin/    # User binaries
│   ├── lib/    # Libraries
│   └── share/  # Shared data
└── var/        # Variable data (logs, databases)
    └── log/    # System log files
```

### Key Directories for Security Professionals

| Directory | Purpose | Security Relevance |
|-----------|---------|-------------------|
| `/etc/passwd` | User account information | User enumeration |
| `/etc/shadow` | Encrypted passwords | Password cracking |
| `/var/log/` | System logs | Forensics, intrusion detection |
| `/tmp/` | Temporary files | Often world-writable, attack vector |
| `/home/` | User directories | Data exfiltration targets |

## Users and Groups

Linux is a multi-user system with a robust permission model.

### Key Concepts

- **root**: The superuser with unlimited privileges (UID 0)
- **Regular users**: Limited privileges, isolated home directories
- **Groups**: Collections of users sharing permissions
- **sudo**: Execute commands as root temporarily

### Essential Commands

```bash
# Display current user
whoami

# Display user ID and group memberships
id

# Switch to root user
sudo su

# Execute single command as root
sudo <command>

# Add new user
sudo useradd -m newuser

# Set user password
sudo passwd newuser

# Add user to group
sudo usermod -aG groupname username
```

### Understanding /etc/passwd

Each line in `/etc/passwd` represents a user:

```
kali:x:1000:1000:Kali,,,:/home/kali:/bin/bash
```

Format: `username:password:UID:GID:comment:home:shell`

- `x` means password is stored in `/etc/shadow`
- UID 0 = root, 1-999 = system users, 1000+ = regular users

## Process Management

A process is a running instance of a program. Understanding processes helps you identify malicious activity and manage system resources.

### Viewing Processes

```bash
# List all processes (full format)
ps aux

# Interactive process viewer
top

# Better interactive viewer (if installed)
htop

# Find process by name
pgrep -a firefox

# Show process tree
pstree
```

### Process Control

```bash
# Run process in background
command &

# List background jobs
jobs

# Bring job to foreground
fg %1

# Send to background
bg %1

# Terminate process by PID
kill 1234

# Force kill
kill -9 1234

# Kill by name
pkill firefox
killall firefox
```

### Process States

| State | Description |
|-------|-------------|
| R | Running or runnable |
| S | Sleeping (waiting for event) |
| D | Uninterruptible sleep (I/O) |
| Z | Zombie (terminated, not reaped) |
| T | Stopped |

## Package Management

Kali Linux uses APT (Advanced Package Tool) based on Debian.

### Essential APT Commands

```bash
# Update package lists
sudo apt update

# Upgrade installed packages
sudo apt upgrade

# Install package
sudo apt install nmap

# Remove package
sudo apt remove nmap

# Search for packages
apt search wireshark

# Show package info
apt show nmap

# Clean up unused packages
sudo apt autoremove
```

### Important Tips

1. **Always update before installing**: Run `apt update` first
2. **Don't blindly upgrade**: In security contexts, specific versions may be needed
3. **Check what's installed**: `dpkg -l | grep package-name`

## Services and Daemons

Services (daemons) are background processes that start at boot.

```bash
# List all services
systemctl list-units --type=service

# Check service status
systemctl status ssh

# Start/stop/restart service
sudo systemctl start ssh
sudo systemctl stop ssh
sudo systemctl restart ssh

# Enable/disable at boot
sudo systemctl enable ssh
sudo systemctl disable ssh
```

### Common Services in CyberLab

| Service | Purpose | Port |
|---------|---------|------|
| ssh | Secure shell access | 22 |
| apache2 | Web server | 80, 443 |
| mysql | Database server | 3306 |
| postgresql | Database server | 5432 |

## Hands-On Exercises

Complete these exercises to solidify your understanding:

1. **File System Exploration**
   - Navigate to `/etc/` and list its contents
   - Find all `.conf` files in `/etc/`
   - Read the contents of `/etc/hostname`

2. **User Investigation**
   - List all users on the system from `/etc/passwd`
   - Identify which users have `/bin/bash` as their shell
   - Find your user's UID and GID

3. **Process Analysis**
   - List all running processes
   - Find the PID of your shell process
   - Start a process in the background and bring it to foreground

4. **Package Management**
   - Update your package lists
   - Search for the `nmap` package
   - Check if `netcat` is installed

5. **Service Management**
   - Check the status of the SSH service
   - Start the Apache web server
   - Verify it's running by checking port 80

## Security Implications

Understanding Linux fundamentals has direct security applications:

- **User enumeration**: Reading `/etc/passwd` reveals usernames for attacks
- **Privilege escalation**: Misconfigured permissions allow privilege escalation
- **Persistence**: Attackers create users or modify services to maintain access
- **Forensics**: Log analysis in `/var/log/` reveals attacker activity
- **Defense**: Proper user/group configuration limits attack surface

## Summary

You've learned the foundational Linux concepts needed for cybersecurity:

- The hierarchical file system starting from `/`
- Users, groups, and the root superuser
- Process management and control
- Package installation with APT
- Service management with systemctl

These fundamentals underpin everything else in cybersecurity. In the next lab, you'll build on this foundation with advanced command-line techniques.

## Next Steps

Proceed to [Command Line Mastery](../02-command-line-mastery/README.md) to develop your CLI skills.
