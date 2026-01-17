# Module 07: Active Directory Security

Master Active Directory attack techniques used in real-world penetration tests and red team operations.

## Module Overview

Active Directory (AD) is the backbone of enterprise Windows networks, making it a primary target for attackers. This module covers AD enumeration, Kerberos attacks, credential theft, delegation abuse, and domain dominance techniques.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Active Directory Attack Chain                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   Initial    │ →  │  Enumeration │ →  │  Credential  │                   │
│  │   Access     │    │  & Recon     │    │   Attacks    │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│         ↓                   ↓                   ↓                            │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │  Lateral     │ →  │   Privilege  │ →  │   Domain     │                   │
│  │  Movement    │    │  Escalation  │    │  Dominance   │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│                                                 ↓                            │
│                                          ┌──────────────┐                   │
│                                          │ Persistence  │                   │
│                                          └──────────────┘                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Important Note: Lab Environment

**This module is theory-focused** because full Active Directory labs require Windows infrastructure that cannot be easily containerized. For hands-on practice, we recommend:

### Recommended Practice Environments

| Platform | Labs | Cost |
|----------|------|------|
| [HackTheBox Pro Labs](https://www.hackthebox.com/hacker/pro-labs) | Dante, Offshore, RastaLabs | Subscription |
| [TryHackMe](https://tryhackme.com) | Attacktive Directory, Post-Exploitation Basics | Free/Subscription |
| [DVAD - Damn Vulnerable Active Directory](https://github.com/WazeHell/vulnerable-AD) | Self-hosted | Free |
| [GOAD - Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) | Self-hosted (5 VMs) | Free |
| [PentesterLab](https://pentesterlab.com) | AD exercises | Subscription |
| [Virtual Hacking Labs](https://www.virtualhackinglabs.com) | AD network | Subscription |

### Building Your Own Lab

For self-hosted practice, you need:

```
Minimum Requirements:
- 16GB RAM (32GB recommended)
- 200GB disk space
- VMware/VirtualBox/Proxmox

Suggested Setup:
┌─────────────────────────────────────────────────┐
│                    Your Lab                      │
├─────────────────────────────────────────────────┤
│  DC01 (Windows Server 2019/2022)                │
│  - Domain Controller                            │
│  - DNS Server                                   │
│  - Certificate Authority (optional)             │
├─────────────────────────────────────────────────┤
│  WS01 (Windows 10/11)                           │
│  - Domain-joined workstation                    │
│  - Standard user account                        │
├─────────────────────────────────────────────────┤
│  Kali Linux                                     │
│  - Attack machine                               │
│  - All AD attack tools pre-installed            │
└─────────────────────────────────────────────────┘
```

## Lab Series

### Lab 1: AD Fundamentals
**Difficulty:** Beginner | **Duration:** 2 hrs | **Type:** Theory + Study

Understanding Active Directory architecture:
- Domains, forests, and trusts
- Objects: Users, Groups, Computers, OUs
- Group Policy Objects (GPOs)
- Authentication protocols (NTLM, Kerberos)

### Lab 2: AD Enumeration
**Difficulty:** Intermediate | **Duration:** 2.5 hrs | **Type:** Hands-on (with external lab)

Reconnaissance and enumeration:
- BloodHound data collection and analysis
- PowerView enumeration techniques
- LDAP queries with ldapsearch
- Identifying attack paths

### Lab 3: Kerberos Attacks
**Difficulty:** Intermediate | **Duration:** 2.5 hrs | **Type:** Hands-on (with external lab)

Exploiting Kerberos protocol:
- Kerberoasting service accounts
- AS-REP roasting accounts without pre-auth
- Ticket extraction and cracking
- Using Impacket and Rubeus

### Lab 4: Credential Attacks
**Difficulty:** Advanced | **Duration:** 3 hrs | **Type:** Hands-on (with external lab)

Credential theft and reuse:
- Pass-the-Hash (PtH)
- Pass-the-Ticket (PtT)
- Overpass-the-Hash
- Mimikatz and secretsdump

### Lab 5: Delegation Attacks
**Difficulty:** Advanced | **Duration:** 2.5 hrs | **Type:** Hands-on (with external lab)

Exploiting delegation misconfigurations:
- Unconstrained delegation
- Constrained delegation
- Resource-Based Constrained Delegation (RBCD)
- S4U2Self and S4U2Proxy abuse

### Lab 6: Domain Dominance
**Difficulty:** Advanced | **Duration:** 2.5 hrs | **Type:** Hands-on (with external lab)

Achieving domain admin and beyond:
- Golden Ticket attacks
- Silver Ticket attacks
- DCSync for credential extraction
- Enterprise Admin escalation

## Essential Tools

### Linux Tools (Kali)
```bash
# Impacket Suite
GetUserSPNs.py    # Kerberoasting
GetNPUsers.py     # AS-REP roasting
secretsdump.py    # DCSync, credential extraction
psexec.py         # Remote execution
wmiexec.py        # WMI execution
smbexec.py        # SMB execution

# BloodHound
bloodhound-python  # Data collection from Linux
neo4j              # Graph database
bloodhound         # GUI analysis

# Other Essential Tools
crackmapexec       # Swiss army knife for AD
ldapsearch         # LDAP enumeration
rpcclient          # RPC enumeration
enum4linux-ng      # SMB/NetBIOS enumeration
kerbrute           # Kerberos user enumeration
```

### Windows Tools
```powershell
# PowerView (PowerSploit)
Import-Module .\PowerView.ps1

# Rubeus (C# Kerberos toolkit)
Rubeus.exe kerberoast
Rubeus.exe asreproast

# Mimikatz
mimikatz.exe "sekurlsa::logonpasswords"
mimikatz.exe "lsadump::dcsync"

# SharpHound (BloodHound collector)
SharpHound.exe -c All
```

## Attack Methodology

### Phase 1: Enumeration
```
1. Identify domain controllers and domain name
2. Enumerate users, groups, and computers
3. Find service accounts and their SPNs
4. Map trust relationships
5. Identify delegation configurations
6. Discover Group Policy settings
7. Use BloodHound to visualize attack paths
```

### Phase 2: Initial Credential Access
```
1. Password spraying against user accounts
2. Kerberoasting service accounts
3. AS-REP roasting vulnerable accounts
4. Credential harvesting from compromised systems
5. LLMNR/NBT-NS poisoning
```

### Phase 3: Privilege Escalation
```
1. Analyze BloodHound paths to Domain Admin
2. Exploit delegation misconfigurations
3. Abuse Group Policy
4. Exploit ACL misconfigurations
5. Target high-value groups (Domain Admins, Backup Operators, etc.)
```

### Phase 4: Domain Dominance
```
1. DCSync to extract all credentials
2. Create Golden Ticket for persistent access
3. Forge Silver Tickets for targeted access
4. Compromise trust relationships
5. Target Enterprise Admins in forest
```

## Common Attack Paths

```
Standard User → Service Account (Kerberoast) → Local Admin → Domain Admin
                                                     ↓
Standard User → Computer with Unconstrained Delegation → Domain Admin
                                                     ↓
Standard User → RBCD Attack → Computer Account → Domain Admin
                                                     ↓
Standard User → ACL Abuse → Password Reset → Domain Admin
```

## Module Prerequisites

Before starting this module:
- [x] Complete Module 01: Foundations
- [x] Complete Module 02: Network Analysis (especially SMB/NetBIOS)
- [x] Basic Windows command line familiarity
- [x] Understanding of Windows authentication (NTLM basics)
- [x] Familiarity with PowerShell

## Certification Relevance

This module aligns with:
- **OSCP** - Active Directory exploitation (new syllabus)
- **OSEP** - Advanced evasion and AD attacks
- **CRTO** - Certified Red Team Operator
- **PNPT** - Practical Network Penetration Tester
- **HTB CPTS** - Certified Penetration Testing Specialist

## References

- [HackTricks - Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [The Hacker Recipes](https://www.thehacker.recipes/ad/)
- [PayloadsAllTheThings - AD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [ired.team - Red Team Notes](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)
- [SpecterOps Blog](https://posts.specterops.io/)
- [Harmj0y's Blog](https://blog.harmj0y.net/)
