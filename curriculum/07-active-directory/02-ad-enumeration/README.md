# Lab 2: Active Directory Enumeration

**Difficulty:** Intermediate | **Duration:** 2.5 hours | **Type:** Hands-on (External Lab Required)

## Overview

Enumeration is the foundation of any successful Active Directory attack. Before exploiting misconfigurations, you must understand the environment. This lab covers essential enumeration techniques using BloodHound, PowerView, and native tools.

## Learning Objectives

By the end of this lab, you will:
- Collect and analyze AD data with BloodHound
- Enumerate users, groups, and computers with PowerView
- Use LDAP queries for reconnaissance
- Identify attack paths and high-value targets
- Map trust relationships and ACL misconfigurations

## Prerequisites

- Access to an AD lab environment (HackTheBox, TryHackMe, or self-hosted)
- Kali Linux with tools installed
- Domain user credentials (any level)

## Lab Environment Setup

For this lab, use one of these environments:

| Platform | Lab Name | Notes |
|----------|----------|-------|
| TryHackMe | Attacktive Directory | Free, guided |
| TryHackMe | Post-Exploitation Basics | Subscription |
| HackTheBox | Forest, Sauna, Cascade | Retired machines |
| GOAD | Game of Active Directory | Self-hosted, 5 VMs |
| DVAD | Damn Vulnerable AD | Self-hosted |

## Enumeration Phases

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Enumeration Methodology                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 1: Discovery                                                  │
│  └─→ Domain Controllers, DNS, Network Layout                        │
│                                                                      │
│  Phase 2: User & Group Enumeration                                   │
│  └─→ Users, Groups, Memberships, Descriptions                       │
│                                                                      │
│  Phase 3: Computer Enumeration                                       │
│  └─→ Workstations, Servers, DCs, Operating Systems                  │
│                                                                      │
│  Phase 4: Service Account Discovery                                  │
│  └─→ SPNs, Service Accounts, Kerberoastable Targets                 │
│                                                                      │
│  Phase 5: ACL & Permission Analysis                                  │
│  └─→ Who can do what to whom?                                       │
│                                                                      │
│  Phase 6: Trust Enumeration                                          │
│  └─→ Domain Trusts, Forest Trusts, Direction                        │
│                                                                      │
│  Phase 7: Attack Path Identification                                 │
│  └─→ BloodHound Analysis, Shortest Paths to DA                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Tools

### BloodHound / SharpHound

BloodHound uses graph theory to reveal attack paths in AD environments.

```bash
# Install BloodHound on Kali
sudo apt install bloodhound neo4j

# Start neo4j database
sudo neo4j start
# Access: http://localhost:7474 (neo4j:neo4j, change password)

# Start BloodHound
bloodhound --no-sandbox

# Python collector (from Linux)
bloodhound-python -d domain.local -u username -p password -dc dc01.domain.local -c All
```

### PowerView (PowerSploit)

PowerView is the definitive PowerShell AD enumeration tool.

```powershell
# Load PowerView
Import-Module .\PowerView.ps1

# Or dot-source
. .\PowerView.ps1
```

### ldapsearch

Native LDAP queries from Linux.

```bash
# Basic syntax
ldapsearch -x -H ldap://dc01.domain.local -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(filter)" attributes
```

### CrackMapExec

Swiss army knife for AD pentesting.

```bash
# Basic authentication test
crackmapexec smb dc01.domain.local -u user -p password -d domain.local
```

## Tasks

### Task 1: Identify Domain Controllers and Domain Information

**Objective:** Find the Domain Controllers and gather basic domain information.

### Task 2: Enumerate All Domain Users

**Objective:** Create a list of all domain users with relevant attributes.

### Task 3: Identify High-Value Groups and Members

**Objective:** Find privileged groups and their members.

### Task 4: Discover Service Accounts (SPNs)

**Objective:** Find accounts with SPNs (Kerberoasting targets).

### Task 5: Collect BloodHound Data

**Objective:** Run SharpHound/bloodhound-python and ingest data.

### Task 6: Analyze Attack Paths

**Objective:** Use BloodHound to identify paths to Domain Admin.

## Resources

- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [PowerView Documentation](https://powersploit.readthedocs.io/en/latest/Recon/)
- [HackTricks AD Enumeration](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [ired.team AD Recon](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)

## Next Steps

After completing enumeration:
- Proceed to **Lab 3: Kerberos Attacks** to exploit discovered SPNs
- Use BloodHound paths to guide your attack strategy
- Document all findings for the assessment report
