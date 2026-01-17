# Lab 6: Domain Dominance

**Difficulty:** Advanced | **Duration:** 3-4 hours | **Type:** Hands-on (External Lab Required)

## Overview

Domain Dominance represents the pinnacle of Active Directory attacks. Once you achieve Domain Admin or equivalent privileges, you can extract all domain credentials via DCSync, forge tickets for unlimited access, and establish deep persistence. This lab covers the "endgame" techniques: DCSync, Golden Tickets, Silver Tickets, and Skeleton Key attacks.

## Learning Objectives

By the end of this lab, you will:
- Perform DCSync attacks to extract any account's credentials
- Forge Golden Tickets for unrestricted domain access
- Create Silver Tickets for targeted service access
- Understand the differences between ticket forgery techniques
- Learn about Skeleton Key attacks for universal authentication
- Understand the prerequisites and detection of each technique

## Prerequisites

- Completion of Labs 1-5 (AD Fundamentals through Delegation Attacks)
- Domain Admin or equivalent access (or DCSync rights)
- Understanding of Kerberos ticket structure
- Familiarity with Mimikatz and Impacket tools

## Domain Dominance Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Domain Dominance Attack Taxonomy                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  DCSync                                                               │   │
│  │  ├─→ Mimics Domain Controller replication                            │   │
│  │  ├─→ Extracts password data for any account                          │   │
│  │  └─→ Requires: DS-Replication-Get-Changes[-All] rights               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Golden Ticket                                                        │   │
│  │  ├─→ Forged TGT using krbtgt hash                                    │   │
│  │  ├─→ Valid for any user, any service, any time                       │   │
│  │  └─→ Requires: krbtgt NTLM hash + Domain SID                         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Silver Ticket                                                        │   │
│  │  ├─→ Forged Service Ticket (no KDC interaction)                      │   │
│  │  ├─→ Access specific service as any user                             │   │
│  │  └─→ Requires: Service account hash + Domain SID                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Skeleton Key                                                         │   │
│  │  ├─→ Patches LSASS on DC to accept master password                   │   │
│  │  ├─→ Any account authenticates with skeleton password                │   │
│  │  └─→ Requires: Domain Admin on DC (temporary)                        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### DCSync Rights

DCSync requires these rights on the domain object:

| Right | Description |
|-------|-------------|
| DS-Replication-Get-Changes | Replicate directory changes |
| DS-Replication-Get-Changes-All | Replicate directory changes including secrets |
| DS-Replication-Get-Changes-In-Filtered-Set | Optional, for filtered attribute set |

Default members with DCSync rights:
- Domain Admins
- Enterprise Admins
- Administrators
- Domain Controllers

### Ticket Comparison

| Attribute | Golden Ticket | Silver Ticket |
|-----------|---------------|---------------|
| Ticket Type | TGT | Service Ticket (TGS) |
| Required Hash | krbtgt | Service account |
| Scope | Any service in domain | Single service |
| KDC Contact | Yes (for TGS) | No |
| Detection | Medium | Very Low |
| Validity | Up to 10 years | Up to 10 years |
| PAC Validation | N/A | Can be bypassed |

### Domain Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Account Hierarchy & Access                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Enterprise Admins (Forest-wide)                                            │
│  └─→ Full control over entire forest                                        │
│                                                                              │
│  Domain Admins (Domain-wide)                                                │
│  └─→ Full control over domain, DCSync rights                               │
│                                                                              │
│  krbtgt Account (Special)                                                   │
│  └─→ Signs all TGTs - compromise = Golden Ticket                           │
│                                                                              │
│  Computer Accounts (DC01$, WS01$, etc.)                                     │
│  └─→ Own hash signs Silver Tickets for their services                      │
│                                                                              │
│  Service Accounts (svc_sql, svc_web, etc.)                                  │
│  └─→ Hash can be used for Silver Tickets to their services                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Tools

| Tool | Platform | Purpose |
|------|----------|---------|
| secretsdump.py | Linux | DCSync and credential extraction |
| Mimikatz | Windows | DCSync, ticket forging, injection |
| ticketer.py | Linux | Golden/Silver ticket creation |
| Rubeus | Windows | Ticket manipulation |
| lookupsid.py | Linux | Get Domain SID |
| rpcclient | Linux | Domain SID lookup |

## Tasks

### Task 1: DCSync Attack

**Objective:** Use DCSync to extract credentials for any domain account.

**Requirements:**
- DCSync rights (Domain Admin, or explicit grant)
- Network access to Domain Controller

### Task 2: Golden Ticket Attack

**Objective:** Create a forged TGT that provides access to any service as any user.

**Requirements:**
- krbtgt NTLM hash (from DCSync)
- Domain SID
- Domain FQDN

### Task 3: Silver Ticket Attack

**Objective:** Create a forged service ticket for targeted access without KDC interaction.

**Requirements:**
- Target service account hash
- Domain SID
- Target SPN

### Task 4: Skeleton Key Attack

**Objective:** Install a backdoor on the Domain Controller that allows authentication with a master password.

**Requirements:**
- Domain Admin access to DC
- Physical or remote code execution on DC

## Attack Chains

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Complete Domain Compromise Chain                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Step 1: Achieve Domain Admin (via any previous technique)                  │
│  └─→ Credential attacks, delegation abuse, ACL abuse, etc.                 │
│                                                                              │
│  Step 2: DCSync all credentials                                             │
│  └─→ secretsdump.py or Mimikatz lsadump::dcsync                           │
│  └─→ Extract: krbtgt, Administrator, computer accounts, etc.               │
│                                                                              │
│  Step 3: Create Golden Ticket                                               │
│  └─→ Valid for 10 years, survives password changes (except krbtgt)         │
│                                                                              │
│  Step 4: Create Silver Tickets (optional, for stealth)                      │
│  └─→ No KDC logs, harder to detect                                         │
│                                                                              │
│  Step 5: Establish Persistence (see Lab 7)                                  │
│  └─→ AdminSDHolder, GPO, scheduled tasks, etc.                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Golden Ticket Persistence

Golden Tickets provide powerful persistence because:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Golden Ticket Persistence Power                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Survives:                                                                   │
│  ├─→ User password changes                                                  │
│  ├─→ User account disable                                                   │
│  ├─→ User account deletion (ticket still valid!)                           │
│  └─→ Normal security monitoring                                             │
│                                                                              │
│  Does NOT survive:                                                           │
│  ├─→ krbtgt password reset (must be done TWICE)                            │
│  └─→ Domain trust destruction                                               │
│                                                                              │
│  Detection challenges:                                                       │
│  ├─→ Ticket appears legitimate                                              │
│  ├─→ PAC is properly signed                                                 │
│  └─→ Only krbtgt reset invalidates it                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Silver Ticket Stealth

Silver Tickets are stealthier because:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Silver Ticket Advantages                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  No KDC Interaction:                                                         │
│  ├─→ Ticket created offline                                                 │
│  ├─→ No TGS-REQ to domain controller                                       │
│  └─→ No Event ID 4769 generated                                             │
│                                                                              │
│  Targeted Access:                                                            │
│  ├─→ Only works for specific service                                        │
│  └─→ Limits blast radius if detected                                        │
│                                                                              │
│  PAC Validation Bypass:                                                      │
│  ├─→ Many services don't validate PAC with DC                              │
│  └─→ Can impersonate non-existent users                                    │
│                                                                              │
│  Common SPNs for Silver Tickets:                                            │
│  ├─→ CIFS/hostname - File share access                                     │
│  ├─→ HOST/hostname - WMI, PSRemoting, Scheduled Tasks                      │
│  ├─→ HTTP/hostname - Web services, WinRM                                   │
│  ├─→ MSSQLSvc/hostname - SQL Server access                                 │
│  └─→ LDAP/hostname - Directory queries                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Defense Considerations

### DCSync Detection

- Event ID 4662 - Directory service access
- Monitor for non-DC systems making replication requests
- Watch for DS-Replication-Get-Changes operations

### Golden Ticket Detection

- Event ID 4769 with unexpected encryption types
- TGT lifetime > 10 hours (default)
- TGT for non-existent users
- Domain field mismatch

### Silver Ticket Detection

- Very difficult - no KDC interaction
- Service account password rotation
- PAC validation enforcement
- Monitor for impossible travel

### Mitigation

- **krbtgt Rotation:** Reset twice (allows replication)
- **Protected Users:** Prevents certain ticket attacks
- **Credential Guard:** Protects LSASS
- **LAPS:** Unique local admin passwords
- **Tiered Administration:** Separate admin accounts

## Resources

- [ADSecurity - Golden Ticket](https://adsecurity.org/?p=1640)
- [ADSecurity - Silver Ticket](https://adsecurity.org/?p=2011)
- [The Hacker Recipes - Domain Dominance](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets)
- [SpecterOps - Detecting Forged Tickets](https://posts.specterops.io/detecting-forged-tickets-leveraging-the-kerberos-pac-structure-a7c23e8b7b4f)
- [Microsoft - Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)

## Next Steps

After completing this lab:
- Proceed to **Lab 7: AD Persistence** for maintaining long-term access
- Practice detection and response techniques
- Study forest trust attacks for multi-domain environments
