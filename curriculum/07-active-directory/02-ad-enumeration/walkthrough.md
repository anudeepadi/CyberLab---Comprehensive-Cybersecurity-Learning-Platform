# AD Enumeration Walkthrough

Step-by-step guide for enumerating Active Directory environments.

## Phase 1: Initial Discovery

### Finding Domain Controllers

```bash
# DNS SRV record lookup
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local
nslookup -type=SRV _kerberos._tcp.domain.local

# Using nmap
nmap -p 389,636,88,53 -sV 192.168.1.0/24

# Using crackmapexec
crackmapexec smb 192.168.1.0/24

# Linux - find DC via LDAP
ldapsearch -x -H ldap://192.168.1.10 -s base namingContexts
```

```powershell
# PowerShell - Current domain
$env:USERDNSDOMAIN
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Find all DCs
nltest /dclist:domain.local
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
```

### Domain Information

```bash
# Using ldapsearch
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" -s base "(objectClass=*)"

# Using rpcclient
rpcclient -U 'domain\user%password' dc01.domain.local -c "querydominfo"

# Using enum4linux-ng
enum4linux-ng -A dc01.domain.local -u user -p password
```

```powershell
# PowerView
Get-Domain
Get-DomainController
Get-DomainPolicy

# Native PowerShell
Get-ADDomain
Get-ADDomainController -Filter *
```

## Phase 2: User Enumeration

### List All Users

```bash
# ldapsearch - all users
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(&(objectCategory=person)(objectClass=user))" \
  sAMAccountName userPrincipalName memberOf description

# Using GetADUsers.py (Impacket)
GetADUsers.py -all domain.local/user:password -dc-ip 192.168.1.10

# Using crackmapexec
crackmapexec smb dc01.domain.local -u user -p password --users

# Using rpcclient
rpcclient -U 'domain\user%password' dc01.domain.local -c "enumdomusers"
```

```powershell
# PowerView - All users
Get-DomainUser | Select-Object samaccountname, description, memberof

# Users with specific property
Get-DomainUser -Properties samaccountname, description, pwdlastset, lastlogon

# Find admin users
Get-DomainUser -AdminCount | Select-Object samaccountname

# Check for interesting descriptions (often contain passwords!)
Get-DomainUser -Properties samaccountname, description |
  Where-Object { $_.description -ne $null } |
  Select-Object samaccountname, description
```

### Find Specific User Types

```powershell
# Users with no password required
Get-DomainUser -UACFilter PASSWD_NOTREQD

# Users with password never expires
Get-DomainUser -UACFilter DONT_EXPIRE_PASSWORD

# Users with Kerberos pre-auth disabled (AS-REP roastable)
Get-DomainUser -UACFilter DONT_REQ_PREAUTH

# Disabled accounts
Get-DomainUser -UACFilter ACCOUNTDISABLE

# Users with unconstrained delegation
Get-DomainUser -TrustedToAuth
```

```bash
# AS-REP roastable users with ldapsearch
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName
```

## Phase 3: Group Enumeration

### List All Groups

```bash
# ldapsearch
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(objectCategory=group)" cn description member

# rpcclient
rpcclient -U 'domain\user%password' dc01.domain.local -c "enumdomgroups"
```

```powershell
# PowerView
Get-DomainGroup | Select-Object samaccountname, description

# Find privileged groups
Get-DomainGroup -Identity "Domain Admins" -Recurse
Get-DomainGroup -Identity "Enterprise Admins"
Get-DomainGroup -AdminCount

# Group members
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

### High-Value Groups to Enumerate

```powershell
# Key groups for privilege escalation
$groups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Remote Desktop Users",
    "Remote Management Users"
)

foreach ($group in $groups) {
    Write-Host "`n=== $group ===" -ForegroundColor Yellow
    Get-DomainGroupMember -Identity $group -Recurse 2>$null |
      Select-Object MemberName, MemberObjectClass
}
```

## Phase 4: Computer Enumeration

### List All Computers

```bash
# ldapsearch
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(objectCategory=computer)" \
  cn operatingSystem operatingSystemVersion dNSHostName

# crackmapexec
crackmapexec smb dc01.domain.local -u user -p password --computers
```

```powershell
# PowerView
Get-DomainComputer | Select-Object dnshostname, operatingsystem

# Find specific OS
Get-DomainComputer -OperatingSystem "*Server 2019*"
Get-DomainComputer -OperatingSystem "*Windows 10*"

# Computers with unconstrained delegation
Get-DomainComputer -Unconstrained

# Computers with constrained delegation
Get-DomainComputer -TrustedToAuth
```

### Check Live Hosts

```bash
# Quick ping sweep
nmap -sn 192.168.1.0/24

# Check specific ports
nmap -p 445,135,5985 -Pn 192.168.1.0/24

# crackmapexec SMB check
crackmapexec smb 192.168.1.0/24 -u user -p password --shares
```

## Phase 5: Service Principal Names (SPNs)

Finding Kerberoastable accounts:

```bash
# Using GetUserSPNs.py (Impacket)
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10

# Just list SPNs (no tickets)
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10 -request

# ldapsearch
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName
```

```powershell
# PowerView - Find all users with SPNs
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# With Rubeus
.\Rubeus.exe kerberoast /stats

# Native PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

## Phase 6: ACL Enumeration

Understanding who has what permissions:

```powershell
# PowerView - Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# ACLs for specific user
Get-DomainObjectAcl -Identity "target_user" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite|Self" }

# Who can reset password
Get-DomainObjectAcl -Identity "target_user" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "ExtendedRight" -and $_.ObjectAceType -match "00299570-246d-11d0-a768-00aa006e0529" }

# Find principals with DCSync rights
Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -SearchScope Base -ResolveGUIDs |
  Where-Object { ($_.ObjectAceType -match 'DS-Replication-Get-Changes') -or ($_.ActiveDirectoryRights -match 'GenericAll') }
```

### Common ACL Abuses

| Right | Abuse |
|-------|-------|
| GenericAll | Full control - reset password, modify attributes |
| GenericWrite | Modify attributes - add SPN, logon script |
| WriteDacl | Modify permissions - grant yourself more rights |
| WriteOwner | Take ownership - then modify permissions |
| Self | Self-write - add yourself to group |
| AllExtendedRights | Includes force password change |
| ForceChangePassword | Reset password without knowing current |
| AddMember | Add members to group |

## Phase 7: Trust Enumeration

```bash
# ldapsearch for trusts
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "CN=System,DC=domain,DC=local" "(objectClass=trustedDomain)"
```

```powershell
# PowerView
Get-DomainTrust
Get-DomainTrustMapping

# Forest trusts
Get-ForestTrust

# Foreign group members
Get-DomainForeignUser
Get-DomainForeignGroupMember
```

## Phase 8: BloodHound Data Collection

### Using SharpHound (Windows)

```powershell
# Basic collection
.\SharpHound.exe -c All

# Stealth mode (slower, less noise)
.\SharpHound.exe -c All --stealth

# Specific collection methods
.\SharpHound.exe -c DCOnly
.\SharpHound.exe -c Session,LoggedOn
.\SharpHound.exe -c ObjectProps,Container

# Output options
.\SharpHound.exe -c All -o C:\Temp --zipfilename data.zip
```

### Using bloodhound-python (Linux)

```bash
# Basic collection
bloodhound-python -d domain.local -u user -p password -dc dc01.domain.local -c All

# Specific collection
bloodhound-python -d domain.local -u user -p password -dc dc01.domain.local -c Group,LocalAdmin,Session

# Using NTLM hash
bloodhound-python -d domain.local -u user -hashes :NTLM_HASH -dc dc01.domain.local -c All

# Using Kerberos ticket
export KRB5CCNAME=/path/to/ticket.ccache
bloodhound-python -d domain.local -dc dc01.domain.local -c All -k --auth-method kerberos
```

### BloodHound Queries

After ingesting data, use these built-in queries:

```
Pre-built Queries:
├── Find all Domain Admins
├── Find Shortest Paths to Domain Admins
├── Find Principals with DCSync Rights
├── Users with Foreign Domain Group Membership
├── Groups with Foreign Domain Group Membership
├── Find Computers where Domain Users are Local Admin
├── Shortest Paths to High Value Targets
├── Find Kerberoastable Users
├── Find AS-REP Roastable Users
├── Shortest Paths to Unconstrained Delegation Systems
└── Shortest Paths from Kerberoastable Users
```

Custom Cypher queries:

```cypher
// Find all Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u.name

// Find AS-REP roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// Find path from owned user to DA
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

// Find users with DCSync rights
MATCH p=(u:User)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p

// Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

## Output Formatting

### Export User List

```bash
# Create clean user list
GetADUsers.py -all domain.local/user:password -dc-ip 192.168.1.10 2>/dev/null | \
  grep -v "^#" | awk '{print $1}' > users.txt
```

```powershell
# PowerView - Export users
Get-DomainUser | Select-Object samaccountname | Export-Csv -Path users.csv
```

### Create Enumeration Report

```bash
# Example enumeration script
#!/bin/bash
DOMAIN="domain.local"
USER="user"
PASS="password"
DC="192.168.1.10"

echo "=== Domain Controllers ==="
crackmapexec smb $DC -u $USER -p $PASS --dc

echo -e "\n=== Domain Users ==="
GetADUsers.py -all $DOMAIN/$USER:$PASS -dc-ip $DC

echo -e "\n=== SPNs (Kerberoastable) ==="
GetUserSPNs.py $DOMAIN/$USER:$PASS -dc-ip $DC

echo -e "\n=== AS-REP Roastable ==="
GetNPUsers.py $DOMAIN/$USER:$PASS -dc-ip $DC -usersfile users.txt

echo -e "\n=== Shares ==="
crackmapexec smb $DC -u $USER -p $PASS --shares
```

## Summary Checklist

- [ ] Identified all Domain Controllers
- [ ] Enumerated domain structure (domains, forests, trusts)
- [ ] Listed all users and their properties
- [ ] Identified privileged groups and members
- [ ] Found service accounts with SPNs
- [ ] Discovered AS-REP roastable accounts
- [ ] Enumerated all computers and their OS
- [ ] Identified delegation configurations
- [ ] Analyzed ACLs for abuse opportunities
- [ ] Collected and analyzed BloodHound data
- [ ] Identified shortest paths to Domain Admin
- [ ] Documented all findings
