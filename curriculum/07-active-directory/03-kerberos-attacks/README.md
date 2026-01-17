# Lab 3: Kerberos Attacks

**Difficulty:** Intermediate | **Duration:** 4-6 hours | **Type:** Hands-on (External Lab Required)

## Overview

Kerberos is the primary authentication protocol in Active Directory environments. While more secure than NTLM, Kerberos has inherent design weaknesses that attackers exploit. This lab covers the most common Kerberos-based attacks: Kerberoasting, AS-REP Roasting, and ticket-based attacks.

## Learning Objectives

By the end of this lab, you will:
- Understand how Kerberos authentication works and its weaknesses
- Perform Kerberoasting attacks against service accounts
- Execute AS-REP Roasting against misconfigured accounts
- Create and use Golden Tickets
- Create and use Silver Tickets
- Understand Overpass-the-Hash techniques

## Prerequisites

- Completion of Lab 1 (AD Fundamentals) and Lab 2 (AD Enumeration)
- Access to an AD lab environment
- Understanding of Kerberos protocol basics
- Familiarity with hash cracking tools

## Attack Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Kerberos Attack Taxonomy                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Pre-Authentication Attacks                                           │   │
│  │  └─→ AS-REP Roasting: Exploit accounts without pre-auth required     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Service Ticket Attacks                                               │   │
│  │  └─→ Kerberoasting: Request and crack service account tickets        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Ticket Forgery                                                       │   │
│  │  ├─→ Golden Ticket: Forge TGT using krbtgt hash                      │   │
│  │  └─→ Silver Ticket: Forge service ticket using service hash          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Pass-the-Ticket                                                      │   │
│  │  ├─→ Overpass-the-Hash: Use NTLM hash to get Kerberos tickets        │   │
│  │  └─→ Pass-the-Ticket: Use stolen tickets for authentication          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Kerberos Recap

```
Normal Authentication Flow:

User ─────[1]─────> KDC (AS-REQ)
     Password hash

User <────[2]───── KDC (AS-REP)
     TGT (encrypted with krbtgt hash)

User ─────[3]─────> KDC (TGS-REQ)
     TGT + Target service SPN

User <────[4]───── KDC (TGS-REP)
     Service Ticket (encrypted with service account hash)

User ─────[5]─────> Service (AP-REQ)
     Service Ticket
```

## Key Tools

| Tool | Platform | Purpose |
|------|----------|---------|
| GetUserSPNs.py | Linux | Kerberoasting |
| GetNPUsers.py | Linux | AS-REP Roasting |
| Rubeus | Windows | All-in-one Kerberos toolkit |
| Mimikatz | Windows | Ticket extraction and forgery |
| Impacket | Linux | Multiple Kerberos attacks |
| hashcat | Both | Hash cracking |
| john | Both | Hash cracking |

## Tasks

### Task 1: Kerberoasting

**Objective:** Find accounts with SPNs and crack their passwords.

**Why it works:** Any domain user can request a TGS for any service. The TGS is encrypted with the service account's password hash, allowing offline cracking.

### Task 2: AS-REP Roasting

**Objective:** Find and exploit accounts with pre-authentication disabled.

**Why it works:** Accounts without pre-auth send encrypted AS-REP without proving identity, allowing offline cracking.

### Task 3: Golden Ticket

**Objective:** Forge a TGT using the krbtgt hash.

**Why it works:** TGTs are encrypted with the krbtgt hash. With this hash, you can forge tickets for any user.

### Task 4: Silver Ticket

**Objective:** Forge a service ticket for a specific service.

**Why it works:** Service tickets are encrypted with the service account hash. With this hash, you can forge tickets for that service.

### Task 5: Overpass-the-Hash

**Objective:** Use an NTLM hash to obtain Kerberos tickets.

**Why it works:** The AS-REQ authentication uses the user's password hash, not the password itself.

## Attack Comparison

| Attack | Requires | Provides | Detection Difficulty |
|--------|----------|----------|---------------------|
| Kerberoasting | Any domain user | Service account password | Medium |
| AS-REP Roasting | List of usernames | User password | Low |
| Golden Ticket | krbtgt hash | Domain-wide access | High |
| Silver Ticket | Service account hash | Service-specific access | Very High |
| Pass-the-Ticket | Stolen ticket | Same access as original | Medium |
| Overpass-the-Hash | NTLM hash | Kerberos tickets | Medium |

## Defense Considerations

Throughout this lab, consider these defensive measures:

- **Kerberoasting Defense:**
  - Use Group Managed Service Accounts (gMSA)
  - Long, complex passwords (25+ characters)
  - Monitor for unusual TGS requests

- **AS-REP Roasting Defense:**
  - Require Kerberos pre-authentication
  - Monitor 4768 events without pre-auth

- **Golden Ticket Defense:**
  - Reset krbtgt password twice
  - Use Protected Users group
  - Enable Credential Guard

- **Silver Ticket Defense:**
  - PAC validation
  - Rotate service account passwords
  - Use gMSA for services

## Resources

- [Kerberoasting - harmj0y](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [Rubeus Documentation](https://github.com/GhostPack/Rubeus)
- [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples)
- [The Hacker Recipes - Kerberos](https://www.thehacker.recipes/ad/movement/kerberos)

## Next Steps

After completing this lab:
- Proceed to **Lab 4: Credential Attacks** for LSASS extraction and Pass-the-Hash
- Practice cracking captured hashes efficiently
- Review detection mechanisms for these attacks
