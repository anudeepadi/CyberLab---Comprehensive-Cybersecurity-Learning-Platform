# AD Fundamentals Study Guide

Quick reference for Active Directory concepts, terminology, and key security implications.

## Core Concepts Quick Reference

### AD Hierarchy
```
Forest (contoso.com)
├── Domain (corp.contoso.com)
│   ├── Organizational Unit (OU=Sales)
│   │   ├── User (jsmith)
│   │   ├── Computer (WS01$)
│   │   └── Group (Sales-Users)
│   └── Organizational Unit (OU=IT)
│       └── User (admin)
└── Child Domain (eu.corp.contoso.com)
    └── ...
```

### Object Types and Attack Relevance

| Object | Identifier | Attack Relevance |
|--------|-----------|------------------|
| User | sAMAccountName, UPN | Password spray, Kerberoast, AS-REP roast |
| Computer | sAMAccountName$ | Machine account abuse, delegation |
| Group | Name, SID | ACL abuse, membership modification |
| GPO | GUID, Name | Script execution, settings modification |
| Trust | Name, Direction | Cross-domain attacks, SID history |

### Important SIDs

```
S-1-5-21-<domain>-500     : Built-in Administrator
S-1-5-21-<domain>-501     : Guest
S-1-5-21-<domain>-502     : krbtgt (Kerberos ticket account)
S-1-5-21-<domain>-512     : Domain Admins
S-1-5-21-<domain>-513     : Domain Users
S-1-5-21-<domain>-514     : Domain Guests
S-1-5-21-<domain>-515     : Domain Computers
S-1-5-21-<domain>-516     : Domain Controllers
S-1-5-21-<domain>-518     : Schema Admins
S-1-5-21-<domain>-519     : Enterprise Admins
S-1-5-21-<domain>-520     : Group Policy Creator Owners
S-1-5-21-<domain>-521     : Read-only Domain Controllers
S-1-5-21-<domain>-522     : Cloneable Domain Controllers
S-1-5-21-<domain>-525     : Protected Users
S-1-5-21-<domain>-526     : Key Admins
S-1-5-21-<domain>-527     : Enterprise Key Admins

Well-Known SIDs:
S-1-5-32-544              : Administrators (Built-in)
S-1-5-32-545              : Users (Built-in)
S-1-5-32-548              : Account Operators
S-1-5-32-549              : Server Operators
S-1-5-32-550              : Print Operators
S-1-5-32-551              : Backup Operators
```

### User Account Control (UAC) Flags

```python
# Common userAccountControl flags
SCRIPT                          = 0x0001  # 1
ACCOUNTDISABLE                  = 0x0002  # 2
HOMEDIR_REQUIRED               = 0x0008  # 8
LOCKOUT                        = 0x0010  # 16
PASSWD_NOTREQD                 = 0x0020  # 32
PASSWD_CANT_CHANGE             = 0x0040  # 64
ENCRYPTED_TEXT_PWD_ALLOWED     = 0x0080  # 128
NORMAL_ACCOUNT                 = 0x0200  # 512
INTERDOMAIN_TRUST_ACCOUNT      = 0x0800  # 2048
WORKSTATION_TRUST_ACCOUNT      = 0x1000  # 4096
SERVER_TRUST_ACCOUNT           = 0x2000  # 8192
DONT_EXPIRE_PASSWORD           = 0x10000 # 65536
MNS_LOGON_ACCOUNT              = 0x20000 # 131072
SMARTCARD_REQUIRED             = 0x40000 # 262144
TRUSTED_FOR_DELEGATION         = 0x80000 # 524288 (Unconstrained)
NOT_DELEGATED                  = 0x100000 # 1048576
USE_DES_KEY_ONLY               = 0x200000 # 2097152
DONT_REQ_PREAUTH               = 0x400000 # 4194304 (AS-REP roastable)
PASSWORD_EXPIRED               = 0x800000 # 8388608
TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 # 16777216 (Constrained)
```

### LDAP Attribute Reference

| Attribute | Description | Attack Use |
|-----------|-------------|------------|
| `sAMAccountName` | Logon name | User enumeration |
| `userPrincipalName` | UPN (user@domain) | User enumeration |
| `servicePrincipalName` | SPN for Kerberos | Kerberoasting |
| `memberOf` | Group membership | Privilege mapping |
| `member` | Group members | Target identification |
| `adminCount` | AdminSDHolder protected | High-value targets |
| `lastLogon` | Last authentication | Active accounts |
| `pwdLastSet` | Password change time | Stale passwords |
| `userAccountControl` | Account flags | Misconfigurations |
| `msDS-AllowedToDelegateTo` | Constrained delegation | Delegation abuse |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD | RBCD attacks |
| `description` | Often contains passwords! | Credential harvesting |
| `info` | Notes field | Info disclosure |

### Kerberos Ticket Structure

```
TGT (Ticket Granting Ticket):
┌────────────────────────────────────────────────┐
│ Encrypted with: krbtgt NTLM hash              │
├────────────────────────────────────────────────┤
│ - User SID                                     │
│ - Group memberships                            │
│ - Timestamp (validity period)                  │
│ - Session key                                  │
│ - PAC (Privilege Attribute Certificate)        │
└────────────────────────────────────────────────┘

Service Ticket (TGS):
┌────────────────────────────────────────────────┐
│ Encrypted with: Service account NTLM hash     │
├────────────────────────────────────────────────┤
│ - User SID                                     │
│ - Group memberships                            │
│ - Session key                                  │
│ - PAC                                          │
│ - Target service SPN                           │
└────────────────────────────────────────────────┘
```

### Trust Types Summary

| Trust Type | Transitive | Direction | Created |
|------------|------------|-----------|---------|
| Parent-Child | Yes | Two-way | Automatic |
| Tree-Root | Yes | Two-way | Automatic |
| Shortcut | Yes | One or Two-way | Manual |
| External | No | One or Two-way | Manual |
| Forest | Yes | One or Two-way | Manual |
| Realm (MIT) | Yes or No | One or Two-way | Manual |

### Group Policy Preference (GPP) Passwords

Historical vulnerability (MS14-025) - passwords stored in SYSVOL:

```
Locations:
\\domain\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
\\domain\SYSVOL\domain\Policies\{GUID}\User\Preferences\Groups\Groups.xml

The AES-256 key is publicly known, making decryption trivial.
```

### NTLM Hash Formats

```
LM Hash (legacy, disabled by default):
AAD3B435B51404EEAAD3B435B51404EE (empty)

NTLM Hash (NT Hash):
32 hex characters, e.g., 32ED87BDB5FDC5E9CBA88547376818D4

Format in SAM/NTDS.dit:
username:RID:LM_HASH:NT_HASH:::

Net-NTLM v1/v2 (network authentication):
username::domain:challenge:response:challenge
```

### Key Files and Locations

```
Domain Controller:
C:\Windows\NTDS\ntds.dit     : AD database (encrypted)
C:\Windows\System32\config\SYSTEM  : Contains boot key for ntds.dit

SYSVOL (replicated across DCs):
\\domain\SYSVOL\domain\Policies\  : Group Policy Objects
\\domain\SYSVOL\domain\scripts\   : Logon scripts

Important Registry:
HKLM\SECURITY\SAM              : Local account hashes
HKLM\SECURITY\CACHE            : Cached domain credentials
HKLM\SECURITY\POLICY\SECRETS   : LSA secrets
```

### Service Principal Name (SPN) Format

```
service_class/host:port/service_name

Examples:
MSSQLSvc/sql01.corp.local:1433
HTTP/web01.corp.local
LDAP/dc01.corp.local
HOST/ws01.corp.local
```

### Quick Commands Reference

```bash
# Find Domain Controllers
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.com

# LDAP query example
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Kerberos ticket request
kinit username@DOMAIN.COM

# List tickets
klist

# SMB null session check
smbclient -L //dc01.corp.local -N
rpcclient -U "" dc01.corp.local -N
```

```powershell
# PowerShell AD queries
Get-ADUser -Filter * -Properties *
Get-ADGroup -Filter * -Properties *
Get-ADComputer -Filter * -Properties *
Get-ADDomain
Get-ADForest
Get-ADTrust -Filter *
```

### Security Descriptor Flags

```
Access Rights:
GenericAll        : Full control
GenericWrite      : Write properties
WriteDacl         : Modify permissions
WriteOwner        : Take ownership
Self              : Self-write
AllExtendedRights : All extended rights
ForceChangePassword : Reset password
AddMember         : Add to group
```

### Attack Surface Summary

| Component | Potential Attacks |
|-----------|-------------------|
| LDAP (389/636) | Enumeration, credential harvesting |
| Kerberos (88) | Kerberoast, AS-REP roast, ticket attacks |
| SMB (445) | Relay, enumeration, lateral movement |
| RPC (135) | SAM enumeration, password spraying |
| WinRM (5985/5986) | Remote execution |
| DNS (53) | Zone transfer, ADIDNS poisoning |
| NTDS.dit | Offline credential extraction |
| SYSVOL | GPP passwords, script analysis |

## Key Takeaways

1. **krbtgt hash is the keys to the kingdom** - Protect it, monitor it
2. **SPNs expose service accounts** - Minimize user account SPNs
3. **Delegation is dangerous** - Audit and minimize delegation
4. **ACLs are complex** - Regularly review permissions
5. **Trusts extend attack surface** - Map and monitor all trusts
6. **NTLM is still used** - Even when Kerberos is preferred
7. **Group Policy can be weaponized** - Monitor GPO changes
8. **Everything is enumerable** - Assume attackers can see your AD
