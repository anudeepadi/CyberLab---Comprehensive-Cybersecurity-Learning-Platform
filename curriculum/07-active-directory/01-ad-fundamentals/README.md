# Lab 1: Active Directory Fundamentals

**Difficulty:** Beginner | **Duration:** 2 hours | **Type:** Theory + Study

## Overview

Before attacking Active Directory, you must understand how it works. This lab covers the core architecture, components, and authentication mechanisms that make AD the foundation of enterprise Windows networks.

## Learning Objectives

By the end of this lab, you will:
- Understand AD structure (domains, forests, trusts)
- Know the key AD objects and their purposes
- Comprehend Kerberos and NTLM authentication
- Recognize common security misconfigurations
- Identify high-value targets in an AD environment

## What is Active Directory?

Active Directory Domain Services (AD DS) is Microsoft's directory service for Windows domain networks. It stores information about network resources and provides:

- **Centralized Authentication** - Single sign-on for users
- **Authorization** - Access control through permissions and group membership
- **Policy Management** - Group Policy for configuration management
- **Resource Discovery** - Locate resources via LDAP queries

## Active Directory Structure

### Logical Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                           FOREST                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      Root Domain                           │  │
│  │                    (corp.local)                            │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │
│  │  │   Domain    │  │   Domain    │  │   Domain    │        │  │
│  │  │ Controllers │  │   Users     │  │  Computers  │        │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│              ┌───────────────┼───────────────┐                  │
│              ↓               ↓               ↓                  │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │  Child Domain   │ │  Child Domain   │ │  Child Domain   │   │
│  │ (us.corp.local) │ │(eu.corp.local)  │ │(asia.corp.local)│   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Terminology

| Term | Definition |
|------|------------|
| **Forest** | Top-level container; collection of domains sharing a schema |
| **Domain** | Administrative boundary for objects; has its own security policies |
| **Tree** | Collection of domains sharing contiguous namespace |
| **Organizational Unit (OU)** | Container for organizing objects within a domain |
| **Site** | Physical network location; affects replication |
| **Trust** | Relationship allowing cross-domain authentication |

### Physical Structure

```
Domain Controller (DC)
├── NTDS.dit          # AD database (contains all objects and credentials)
├── SYSVOL            # Shared folder with GPOs and scripts
├── DNS               # Usually integrated with AD
└── Global Catalog    # Partial replica of all domains in forest
```

## Active Directory Objects

### Users
```
Attributes of interest:
- sAMAccountName     : Username (pre-Windows 2000)
- userPrincipalName  : UPN (user@domain.com format)
- memberOf           : Group memberships
- servicePrincipalName (SPN) : Kerberoasting target if set
- userAccountControl : Account flags (disabled, no pre-auth, etc.)
- adminCount         : Protected by AdminSDHolder if = 1
- lastLogon          : Activity indicator
- pwdLastSet         : Password age
```

### Groups
```
Types:
- Domain Local  : Can have members from any domain, used in same domain
- Global        : Members from same domain, used anywhere in forest
- Universal     : Members from any domain, used anywhere in forest

Scope:
- Security Groups     : Used for permissions
- Distribution Groups : Used for email (no security function)
```

### High-Value Groups
```
Critical Groups (Target These):
├── Domain Admins           # Full control of domain
├── Enterprise Admins       # Full control of forest (root domain only)
├── Schema Admins           # Can modify AD schema
├── Administrators          # Built-in admin group
├── Backup Operators        # Can backup/restore files
├── Account Operators       # Can manage accounts (except admins)
├── Server Operators        # Can logon to DCs
├── Print Operators         # Can load drivers (can lead to code execution)
├── DnsAdmins              # Can load DLL on DC (privesc vector)
└── Group Policy Creator Owners  # Can create GPOs
```

### Computers
```
Every domain-joined computer has:
- Machine account (COMPUTERNAME$)
- Password (auto-rotated every 30 days by default)
- SPN for services (HOST/computer.domain.com)

Domain Controllers have additional:
- LDAP/hostname
- Kerberos/hostname
- GC (Global Catalog) services
```

## Authentication Protocols

### NTLM Authentication

```
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  1. NEGOTIATE (request auth)            │
     │ ─────────────────────────────────────→  │
     │                                         │
     │  2. CHALLENGE (server sends nonce)      │
     │ ←─────────────────────────────────────  │
     │                                         │
     │  3. RESPONSE (hash of password+nonce)   │
     │ ─────────────────────────────────────→  │
     │                                         │
     │  4. Server verifies with DC             │
     │                                         │
```

**NTLM Weaknesses:**
- Hash is sent over network (can be relayed or cracked)
- No mutual authentication (client doesn't verify server)
- Supports pass-the-hash attacks
- Vulnerable to NTLM relay attacks

### Kerberos Authentication

```
┌──────────┐     ┌─────────────────┐     ┌──────────┐
│  Client  │     │   KDC (on DC)   │     │  Server  │
└────┬─────┘     │ ┌─────────────┐ │     └────┬─────┘
     │           │ │     AS      │ │          │
     │           │ │   (Auth     │ │          │
     │           │ │   Service)  │ │          │
     │           │ └─────────────┘ │          │
     │           │ ┌─────────────┐ │          │
     │           │ │     TGS     │ │          │
     │           │ │  (Ticket    │ │          │
     │           │ │   Granting) │ │          │
     │           └─┴─────────────┴─┘          │
     │                   │                    │
     │ 1. AS-REQ (user hash as auth)          │
     │ ─────────────────→│                    │
     │                   │                    │
     │ 2. AS-REP (TGT encrypted with krbtgt)  │
     │ ←─────────────────│                    │
     │                   │                    │
     │ 3. TGS-REQ (TGT + target service)      │
     │ ─────────────────→│                    │
     │                   │                    │
     │ 4. TGS-REP (Service Ticket)            │
     │ ←─────────────────│                    │
     │                   │                    │
     │ 5. AP-REQ (Service Ticket)             │
     │ ──────────────────────────────────────→│
     │                   │                    │
     │ 6. AP-REP (optional mutual auth)       │
     │ ←──────────────────────────────────────│
```

**Kerberos Components:**
| Component | Encryption Key | Purpose |
|-----------|---------------|---------|
| TGT (Ticket Granting Ticket) | krbtgt hash | Proves user authenticated |
| Service Ticket | Service account hash | Access to specific service |
| Authenticator | Session key | Proves ticket holder is ticket owner |

**Kerberos Weaknesses:**
- Tickets are encrypted with hashes (can be cracked offline)
- krbtgt hash = Golden Ticket (forge any TGT)
- Service hash = Silver Ticket (forge service ticket)
- SPNs are enumerable (Kerberoasting)
- Pre-auth can be disabled (AS-REP roasting)

## Group Policy

Group Policy Objects (GPOs) define configuration settings:

```
Common GPO Settings:
├── Password Policy
│   ├── Minimum length
│   ├── Complexity requirements
│   └── Maximum age
├── Account Lockout Policy
├── Kerberos Policy
├── Audit Policy
├── User Rights Assignment
│   ├── SeDebugPrivilege
│   ├── SeBackupPrivilege
│   └── SeImpersonatePrivilege
├── Software Deployment
├── Logon Scripts
└── Security Options
```

**Attack Relevance:**
- GPOs can deploy malicious scripts
- Scheduled tasks via GPO = persistence
- GPO permissions = privilege escalation
- SYSVOL contains GPO files (sometimes with passwords)

## Trusts

```
Trust Types:
├── Parent-Child Trust    : Automatic, transitive
├── Tree-Root Trust       : Automatic, transitive
├── Shortcut Trust        : Manually created, transitive
├── External Trust        : To non-AD or different forest, non-transitive
└── Forest Trust          : Between forests, transitive

Trust Direction:
┌────────────┐  trusts   ┌────────────┐
│  Domain A  │ ────────→ │  Domain B  │
│ (trusting) │           │ (trusted)  │
└────────────┘           └────────────┘
     ↑                         │
     │                         │
Users from Domain B CAN access resources in Domain A
```

## Common Misconfigurations

| Misconfiguration | Risk | Attack |
|-----------------|------|--------|
| SPNs on user accounts | Kerberoastable | Extract TGS, crack password |
| Pre-auth disabled | AS-REP roastable | Request AS-REP, crack password |
| Unconstrained delegation | Token capture | Capture TGTs of connecting users |
| Weak ACLs | Privilege escalation | Modify objects (password, membership) |
| AdminCount = 1 orphans | Stale permissions | May have residual privileges |
| Password in SYSVOL | Credential exposure | Read Group Policy Preferences |
| LLMNR/NBT-NS enabled | Credential capture | Responder poisoning |
| SMB Signing disabled | Relay attacks | NTLM relay |

## Ports and Protocols

| Port | Protocol | Service |
|------|----------|---------|
| 53 | TCP/UDP | DNS |
| 88 | TCP/UDP | Kerberos |
| 135 | TCP | RPC Endpoint Mapper |
| 139 | TCP | NetBIOS Session |
| 389 | TCP/UDP | LDAP |
| 445 | TCP | SMB |
| 464 | TCP/UDP | Kerberos Password Change |
| 636 | TCP | LDAPS (LDAP over SSL) |
| 3268 | TCP | Global Catalog |
| 3269 | TCP | Global Catalog over SSL |
| 5985 | TCP | WinRM (HTTP) |
| 5986 | TCP | WinRM (HTTPS) |

## Study Questions

1. What is the difference between a domain and a forest?
2. Explain why the krbtgt account is so critical to AD security.
3. What is the purpose of the AdminSDHolder container?
4. How does Kerberos delegation work and why is it dangerous?
5. What is the Global Catalog and why is it important?

## Practice Activities

1. **Build a Lab**: Set up a Windows Server as a Domain Controller
2. **Explore AD**: Use ADUC (Active Directory Users and Computers) to examine objects
3. **Query LDAP**: Use ldapsearch or PowerShell to enumerate AD
4. **Analyze GPOs**: Examine default domain policy settings
5. **Map Trusts**: If you have multiple domains, explore trust relationships

## Next Steps

- Proceed to **Lab 2: AD Enumeration** to learn reconnaissance techniques
- Set up a practice environment from the recommendations in the module overview
- Review the study guide for key terminology and concepts
