# Lab 7: Active Directory Persistence

**Difficulty:** Advanced | **Duration:** 2-3 hours | **Type:** Study + Hands-on (External Lab Required)

## Overview

After achieving domain dominance, attackers establish persistence mechanisms to maintain long-term access. This lab covers various Active Directory persistence techniques, from simple (service accounts, scheduled tasks) to advanced (AdminSDHolder, DCShadow). Understanding these techniques is essential for both red team operations and blue team detection.

## Learning Objectives

By the end of this lab, you will:
- Understand the importance and risks of AD persistence
- Implement Golden Ticket and Silver Ticket persistence
- Abuse AdminSDHolder for automated privilege restoration
- Create persistence via Group Policy Objects (GPOs)
- Establish persistence through Security Support Providers (SSPs)
- Understand DCShadow attacks for stealthy persistence
- Know how to detect and remediate persistence mechanisms

## Prerequisites

- Completion of Labs 1-6 (AD Fundamentals through Domain Dominance)
- Domain Admin or Enterprise Admin access
- Understanding of Group Policy and Active Directory structure
- Familiarity with Windows services and scheduled tasks

## Persistence Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      AD Persistence Taxonomy                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Credential-Based Persistence                                         │   │
│  │  ├─→ Golden Ticket: Valid for 10 years (until krbtgt reset)          │   │
│  │  ├─→ Silver Ticket: Valid for service account password lifetime       │   │
│  │  ├─→ Skeleton Key: Master password (until DC reboot)                 │   │
│  │  └─→ Custom SSP: Capture all authentications                         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  ACL-Based Persistence                                                │   │
│  │  ├─→ AdminSDHolder: Auto-restore admin rights every 60 minutes       │   │
│  │  ├─→ DCSync Rights: Permanent credential extraction                  │   │
│  │  └─→ Object ACL Modification: Hidden permissions                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Object-Based Persistence                                             │   │
│  │  ├─→ Hidden Admin Accounts: Accounts not in Domain Admins           │   │
│  │  ├─→ Machine Account Abuse: Privileged computer accounts             │   │
│  │  └─→ Service Accounts: Kerberoastable backdoors                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Configuration-Based Persistence                                      │   │
│  │  ├─→ GPO Abuse: Malicious group policies                             │   │
│  │  ├─→ Scheduled Tasks: Recurring code execution                       │   │
│  │  ├─→ Registry Modifications: Auto-run entries                        │   │
│  │  └─→ Service Installation: Malicious services                        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Advanced Persistence                                                 │   │
│  │  ├─→ DCShadow: Rogue Domain Controller                               │   │
│  │  ├─→ SID History Injection: Hidden group membership                  │   │
│  │  └─→ Primary Group ID: Alternative admin membership                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Persistence Comparison

| Technique | Stealth | Durability | Detection Difficulty | Requires |
|-----------|---------|------------|---------------------|----------|
| Golden Ticket | High | High (until krbtgt reset) | Medium | krbtgt hash |
| Silver Ticket | Very High | Medium | Very High | Service hash |
| AdminSDHolder | Medium | High | Medium | DA access |
| DCSync Rights | Medium | High | Low-Medium | DA access |
| GPO Persistence | Low | High | Low | DA access |
| Skeleton Key | Low | Low (reboot) | Medium | DC access |
| DCShadow | Very High | Variable | Very High | DA access |
| Custom SSP | Medium | High | Medium | DC access |
| SID History | High | High | Medium | DA access |

## Key Concepts

### AdminSDHolder

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AdminSDHolder Mechanism                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  AdminSDHolder is a container object that protects privileged groups:       │
│                                                                              │
│  Protected Groups:                                                           │
│  ├─→ Domain Admins                                                          │
│  ├─→ Enterprise Admins                                                      │
│  ├─→ Schema Admins                                                          │
│  ├─→ Administrators                                                         │
│  ├─→ Account Operators                                                      │
│  ├─→ Backup Operators                                                       │
│  ├─→ Server Operators                                                       │
│  ├─→ Print Operators                                                        │
│  ├─→ Domain Controllers                                                     │
│  └─→ Read-only Domain Controllers                                           │
│                                                                              │
│  SDProp Process (runs every 60 minutes):                                    │
│  1. Reads ACL from AdminSDHolder container                                  │
│  2. Applies this ACL to all protected objects                               │
│  3. Overwrites any changes made to protected object ACLs                    │
│                                                                              │
│  Attack: Add permissions to AdminSDHolder → Auto-applied to all admins!    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### DCShadow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DCShadow Attack                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DCShadow registers a rogue Domain Controller to push malicious changes:    │
│                                                                              │
│  1. Register attacker machine as DC in AD                                   │
│  2. Push arbitrary changes via replication                                  │
│  3. Changes appear to come from legitimate replication                      │
│  4. Unregister fake DC                                                      │
│                                                                              │
│  Capabilities:                                                               │
│  ├─→ Modify any AD object                                                   │
│  ├─→ Add SID History                                                        │
│  ├─→ Modify group memberships                                               │
│  ├─→ Change passwords without logging                                       │
│  └─→ Inject backdoors stealthily                                            │
│                                                                              │
│  Detection Challenge:                                                        │
│  - Changes appear as normal DC replication                                   │
│  - Limited logging on the fake DC                                           │
│  - Quick registration/unregistration                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Tools

| Tool | Platform | Purpose |
|------|----------|---------|
| Mimikatz | Windows | Ticket forging, SSP, DCShadow |
| PowerView | Windows | ACL manipulation, enumeration |
| SharpGPOAbuse | Windows | GPO exploitation |
| Rubeus | Windows | Ticket operations |
| Impacket | Linux | Remote operations |
| BloodHound | Both | Attack path visualization |

## Topics Covered

### Topic 1: Golden Ticket Persistence

Golden Tickets remain valid until the krbtgt password is reset (twice).

**Persistence Duration:** Years (until krbtgt rotation)
**Detection:** Difficult without specialized monitoring

### Topic 2: AdminSDHolder Abuse

Modify AdminSDHolder ACL to gain automatic privilege restoration.

**Persistence Duration:** Indefinite (until ACL cleaned)
**Detection:** Monitor AdminSDHolder ACL changes

### Topic 3: DCSync Rights Persistence

Grant DCSync rights to a controlled account for permanent credential access.

**Persistence Duration:** Until rights revoked
**Detection:** Audit DS-Replication rights

### Topic 4: GPO-Based Persistence

Create or modify GPOs to execute code, add users, or modify security settings.

**Persistence Duration:** Until GPO removed
**Detection:** GPO auditing

### Topic 5: Custom SSP Installation

Install a malicious Security Support Provider to capture credentials.

**Persistence Duration:** Until SSP removed or DC rebuilt
**Detection:** Registry and file monitoring

### Topic 6: SID History Injection

Add privileged SIDs to a user's SID History for hidden admin access.

**Persistence Duration:** Until SID History cleared
**Detection:** Audit SID History on accounts

### Topic 7: DCShadow Attack

Register rogue DC to push stealthy AD changes.

**Persistence Duration:** Variable (used for modification)
**Detection:** Monitor DC registration events

## Defense Considerations

### Detecting Persistence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Persistence Detection Methods                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Golden Ticket:                                                              │
│  ├─→ Monitor for TGTs with very long lifetimes                             │
│  ├─→ Watch for TGTs of non-existent users                                  │
│  └─→ Event ID 4769 with unusual encryption types                           │
│                                                                              │
│  AdminSDHolder:                                                              │
│  ├─→ Monitor changes to CN=AdminSDHolder                                   │
│  ├─→ Event ID 5136 - Directory service object modification                 │
│  └─→ Regular ACL audits                                                     │
│                                                                              │
│  DCSync Rights:                                                              │
│  ├─→ Event ID 4662 with replication GUIDs                                  │
│  ├─→ Monitor non-DC replication requests                                   │
│  └─→ Audit DS-Replication rights on domain object                          │
│                                                                              │
│  GPO Persistence:                                                            │
│  ├─→ Event ID 5136/5137 for GPO changes                                    │
│  ├─→ Monitor SYSVOL for modifications                                      │
│  └─→ Regular GPO audits                                                     │
│                                                                              │
│  Custom SSP:                                                                 │
│  ├─→ Monitor HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages   │
│  ├─→ Watch for new DLLs in System32                                        │
│  └─→ LSASS integrity monitoring                                             │
│                                                                              │
│  SID History:                                                                │
│  ├─→ Event ID 4765/4766 - SID History modification                         │
│  ├─→ Query users with non-empty SID History                                │
│  └─→ Flag admin SIDs in non-admin user's history                           │
│                                                                              │
│  DCShadow:                                                                   │
│  ├─→ Event ID 4742 - Computer account changes                              │
│  ├─→ Monitor for new DC registrations                                      │
│  └─→ SPN monitoring for GC and E3514235 SPNs                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Remediation Steps

| Technique | Remediation |
|-----------|-------------|
| Golden Ticket | Reset krbtgt password TWICE |
| Silver Ticket | Reset service account password |
| AdminSDHolder | Remove unauthorized ACEs, run SDProp |
| DCSync Rights | Remove replication rights |
| GPO Persistence | Delete/restore malicious GPOs |
| Skeleton Key | Reboot DC |
| Custom SSP | Remove from registry, delete DLL |
| SID History | Clear SID History attribute |
| DCShadow | Remove rogue DC objects |

## Resources

- [ADSecurity - AD Persistence](https://adsecurity.org/?p=1929)
- [The Hacker Recipes - Persistence](https://www.thehacker.recipes/ad/persistence)
- [SpecterOps - AdminSDHolder](https://posts.specterops.io/shadow-admins-the-stealthy-accounts-that-you-should-fear-most-in-your-organization-2e75c98dd466)
- [DCShadow Paper](https://www.dcshadow.com/)
- [SANS - Detecting AD Persistence](https://www.sans.org/white-papers/detecting-active-directory-persistence-attacks/)

## Important Notes

**Red Team/Pentest Considerations:**
- Always document persistence mechanisms installed
- Have a removal plan before deployment
- Consider detection risk vs. operational need
- Persistence should be proportional to engagement scope

**Blue Team Considerations:**
- Regular AD security assessments
- Monitor for unauthorized changes
- Implement tiered administration
- Maintain incident response procedures

## Next Steps

After completing this module:
- Review the complete AD attack chain from enumeration to persistence
- Practice detection techniques in a lab environment
- Study trust attacks for multi-domain/forest scenarios
- Learn about modern defenses (Credential Guard, PAM, etc.)
