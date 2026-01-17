# Lab 5: Delegation Attacks

**Difficulty:** Advanced | **Duration:** 3-4 hours | **Type:** Hands-on (External Lab Required)

## Overview

Kerberos delegation allows services to impersonate users when accessing other resources. While designed for legitimate use cases like multi-tier applications, delegation is frequently misconfigured, creating powerful privilege escalation paths. This lab covers Unconstrained Delegation, Constrained Delegation, and Resource-Based Constrained Delegation (RBCD) attacks.

## Learning Objectives

By the end of this lab, you will:
- Understand the three types of Kerberos delegation
- Identify delegation misconfigurations using BloodHound and PowerView
- Exploit Unconstrained Delegation to capture TGTs
- Abuse Constrained Delegation with S4U2Self and S4U2Proxy
- Perform Resource-Based Constrained Delegation attacks
- Understand the prerequisites and impact of each delegation attack

## Prerequisites

- Completion of Labs 1-4 (AD Fundamentals through Credential Attacks)
- Understanding of Kerberos protocol and ticket types
- Familiarity with BloodHound attack path analysis
- Access to an AD lab with delegation configurations

## Delegation Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Kerberos Delegation Types                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Unconstrained Delegation (TrustedForDelegation)                      │   │
│  │  ├─→ Service can impersonate users to ANY service                    │   │
│  │  ├─→ Stores user's TGT in memory                                     │   │
│  │  └─→ Most dangerous - full domain compromise possible                │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Constrained Delegation (msDS-AllowedToDelegateTo)                    │   │
│  │  ├─→ Service can impersonate users to SPECIFIC services only         │   │
│  │  ├─→ Uses S4U2Self and S4U2Proxy extensions                          │   │
│  │  └─→ Dangerous if configured to sensitive services                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOf) │   │
│  │  ├─→ Target resource controls who can delegate TO it                 │   │
│  │  ├─→ Configured on the target, not the service                       │   │
│  │  └─→ Exploitable if you can modify the target's attribute            │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Why Delegation Exists

Delegation solves the "double-hop" problem in multi-tier applications:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           Double-Hop Problem                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  User authenticates to Web Server, which needs to access SQL as that user:   │
│                                                                               │
│  ┌────────┐     ┌────────────┐     ┌────────────┐                            │
│  │  User  │ ──> │ Web Server │ ──> │ SQL Server │                            │
│  │ (TGT)  │     │            │     │            │                            │
│  └────────┘     └────────────┘     └────────────┘                            │
│                       │                  │                                    │
│                       │                  │                                    │
│               "I need to access        "Who are you?                         │
│                SQL as this user"        I see the web server,                │
│                                         not the user"                        │
│                                                                               │
│  Solution: Delegation allows Web Server to impersonate User to SQL Server   │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Key Tools

| Tool | Platform | Purpose |
|------|----------|---------|
| BloodHound | Both | Identify delegation configurations |
| PowerView | Windows | Enumerate delegation settings |
| Rubeus | Windows | S4U attacks, ticket manipulation |
| getST.py | Linux | Request service tickets via S4U |
| findDelegation.py | Linux | Find delegation configurations |
| Impacket Suite | Linux | Remote exploitation tools |
| krbrelayx | Linux | Unconstrained delegation exploitation |

## Tasks

### Task 1: Enumerate Delegation Configurations

**Objective:** Find all accounts with delegation enabled using BloodHound and PowerView.

**What to look for:**
- Computers with TrustedForDelegation (Unconstrained)
- Accounts with msDS-AllowedToDelegateTo (Constrained)
- Accounts with msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)

### Task 2: Unconstrained Delegation Attack

**Objective:** Compromise a computer with unconstrained delegation and capture TGTs.

**Attack flow:**
1. Compromise computer with unconstrained delegation
2. Wait for or coerce high-value user authentication
3. Extract their TGT from memory
4. Use TGT for impersonation

### Task 3: Constrained Delegation Attack

**Objective:** Abuse constrained delegation to access unauthorized services.

**Attack flow:**
1. Compromise account with constrained delegation
2. Use S4U2Self to get service ticket for target user
3. Use S4U2Proxy to get ticket for allowed service
4. Exploit "service name is just a formality" for alternative services

### Task 4: Resource-Based Constrained Delegation (RBCD)

**Objective:** Create RBCD relationship to compromise a target computer.

**Attack flow:**
1. Find target computer where you can modify RBCD attribute
2. Create or control a computer account
3. Configure RBCD to allow your computer to delegate to target
4. Use S4U to impersonate admin to target

## Attack Comparison

| Attack Type | Requires | Provides | Difficulty |
|-------------|----------|----------|------------|
| Unconstrained | Compromise computer with delegation | Any user's TGT who authenticates | Medium |
| Constrained | Control account with delegation | Access to allowed services | Medium |
| RBCD | Write access to target's msDS-AllowedToActOnBehalfOf | Admin on target | Medium-High |

## Delegation Attack Chains

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Unconstrained Delegation Attack Chain                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Identify target: Computer with TRUSTED_FOR_DELEGATION                   │
│     └─→ BloodHound query: MATCH (c:Computer {unconstraineddelegation:true}) │
│                                                                              │
│  2. Compromise the computer (any method)                                    │
│     └─→ Exploit vulnerability, credential reuse, etc.                       │
│                                                                              │
│  3. Coerce authentication from high-value target                            │
│     └─→ PrinterBug, PetitPotam, or wait for natural auth                   │
│                                                                              │
│  4. Extract TGT from memory                                                  │
│     └─→ Mimikatz sekurlsa::tickets or Rubeus dump                          │
│                                                                              │
│  5. Pass-the-Ticket to target services                                       │
│     └─→ DC TGT = Domain Compromise                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    Constrained Delegation Attack Chain                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Identify target: Account with msDS-AllowedToDelegateTo                  │
│     └─→ PowerView: Get-DomainUser -TrustedToAuth                           │
│                                                                              │
│  2. Obtain credential for that account (hash or password)                   │
│     └─→ Kerberoast, credential theft, etc.                                 │
│                                                                              │
│  3. Request TGT for the delegating account                                  │
│     └─→ getTGT.py or Rubeus asktgt                                         │
│                                                                              │
│  4. Use S4U2Self: Get ticket for target user to own service                │
│     └─→ "I want a ticket for admin@domain to my service"                   │
│                                                                              │
│  5. Use S4U2Proxy: Get ticket for target user to allowed service           │
│     └─→ "Now give me that as a ticket to CIFS/target"                      │
│                                                                              │
│  6. Access target service as impersonated user                              │
│     └─→ Full access to the allowed service                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         RBCD Attack Chain                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Identify target: Computer you can write to                              │
│     └─→ GenericAll, GenericWrite, WriteProperty on computer                │
│                                                                              │
│  2. Create or control a computer account                                    │
│     └─→ Default: Any user can add up to 10 computers                       │
│     └─→ addcomputer.py or PowerMad                                         │
│                                                                              │
│  3. Set RBCD: Allow your computer to delegate to target                    │
│     └─→ Modify msDS-AllowedToActOnBehalfOfOtherIdentity                    │
│                                                                              │
│  4. S4U2Self: Get ticket for admin to your service                         │
│     └─→ Rubeus s4u or getST.py                                             │
│                                                                              │
│  5. S4U2Proxy: Get ticket for admin to target's service                    │
│     └─→ CIFS ticket = file share access = admin                            │
│                                                                              │
│  6. Access target as admin                                                   │
│     └─→ psexec, smbclient, etc.                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## S4U Protocol Extensions

Understanding S4U is essential for constrained delegation attacks:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    S4U2Self and S4U2Proxy Flow                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  S4U2Self (Service for User to Self):                                       │
│  ├─→ Service requests ticket for any user to ITSELF                        │
│  ├─→ Does NOT require user's password or TGT                               │
│  └─→ Ticket is marked as "not forwardable" by default                      │
│                                                                              │
│  S4U2Proxy (Service for User to Proxy):                                     │
│  ├─→ Service uses S4U2Self ticket to request ticket to ANOTHER service     │
│  ├─→ Only works for services in msDS-AllowedToDelegateTo                   │
│  └─→ Requires forwardable ticket OR RBCD configuration                     │
│                                                                              │
│  Attack Flow:                                                                │
│                                                                              │
│  1. Attacker → KDC: "Give me TGT for service_account"                      │
│     └─→ Using password, hash, or key                                        │
│                                                                              │
│  2. Attacker → KDC: "Give me ticket for Administrator to my service"       │
│     └─→ S4U2Self - gets service ticket for admin                           │
│                                                                              │
│  3. Attacker → KDC: "Now convert that to ticket for CIFS/target"           │
│     └─→ S4U2Proxy - gets ticket for admin to target service                │
│                                                                              │
│  4. Attacker → Target: Present admin's CIFS ticket                         │
│     └─→ Authenticated as admin!                                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Defense Considerations

- **Protected Users Group:**
  - Members cannot be delegated
  - Prevents TGT caching on non-DCs
  - Add high-value accounts

- **Account is Sensitive and Cannot Be Delegated:**
  - UserAccountControl flag
  - Prevents impersonation of this account
  - Set on admin accounts

- **Minimize Delegation:**
  - Remove unconstrained delegation where possible
  - Use constrained delegation with minimal scope
  - Audit msDS-AllowedToDelegateTo regularly

- **Machine Account Quota:**
  - Default: Any user can add 10 computers
  - Set ms-DS-MachineAccountQuota to 0
  - Mitigates RBCD attacks

- **Monitoring:**
  - Event ID 4769 - Service ticket requests
  - Monitor for S4U2Self/S4U2Proxy patterns
  - Watch for new computer account creation

## Resources

- [The Hacker Recipes - Delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations)
- [HackTricks - Delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-delegation)
- [SpecterOps - Delegation](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
- [Elad Shamir - RBCD](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [harmj0y - S4U2Pwnage](https://blog.harmj0y.net/activedirectory/s4u2pwnage/)

## Next Steps

After completing this lab:
- Proceed to **Lab 6: Domain Dominance** for Golden Ticket and DCSync
- Practice chaining delegation with other attack vectors
- Study coercion techniques (PrinterBug, PetitPotam)
