# Lab 4: Credential Attacks

**Difficulty:** Advanced | **Duration:** 3-4 hours | **Type:** Hands-on (External Lab Required)

## Overview

Credential attacks are the backbone of lateral movement in Active Directory environments. Once you have valid credentials (passwords or hashes), you can authenticate to other systems without needing to crack passwords. This lab covers the essential credential theft and reuse techniques: Pass-the-Hash (PtH), Pass-the-Ticket (PtT), and Overpass-the-Hash.

## Learning Objectives

By the end of this lab, you will:
- Extract credentials from compromised Windows systems
- Perform Pass-the-Hash attacks using NTLM hashes
- Execute Pass-the-Ticket attacks with stolen Kerberos tickets
- Conduct Overpass-the-Hash to obtain Kerberos tickets from NTLM hashes
- Use Mimikatz for credential extraction and manipulation
- Use Impacket's secretsdump for remote credential dumping
- Understand the differences between credential attack techniques

## Prerequisites

- Completion of Labs 1-3 (AD Fundamentals, Enumeration, Kerberos Attacks)
- Access to an AD lab environment with local admin on at least one machine
- Understanding of NTLM and Kerberos authentication
- Familiarity with Windows credential storage

## Attack Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Credential Attack Taxonomy                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Credential Extraction                                                │   │
│  │  ├─→ LSASS Memory Dump: Extract credentials from memory              │   │
│  │  ├─→ SAM Database: Local account hashes                              │   │
│  │  ├─→ NTDS.dit: Domain database with all hashes                       │   │
│  │  └─→ DCSync: Remote extraction via replication protocol              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Credential Reuse Attacks                                             │   │
│  │  ├─→ Pass-the-Hash: Authenticate using NTLM hash                     │   │
│  │  ├─→ Pass-the-Ticket: Use stolen Kerberos tickets                    │   │
│  │  └─→ Overpass-the-Hash: Convert NTLM hash to Kerberos ticket         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Lateral Movement with Credentials                                    │   │
│  │  ├─→ PsExec: Remote service creation and execution                   │   │
│  │  ├─→ WMI: Windows Management Instrumentation                         │   │
│  │  ├─→ WinRM: PowerShell Remoting                                      │   │
│  │  └─→ SMB: File share and admin share access                          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Windows Credential Storage

Understanding where Windows stores credentials is essential:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Windows Credential Storage Locations                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  LSASS Memory (lsass.exe)                                                   │
│  ├─→ NTLM hashes of logged-on users                                        │
│  ├─→ Kerberos tickets (TGT, service tickets)                               │
│  ├─→ Plaintext passwords (WDigest if enabled)                              │
│  └─→ Cached credentials                                                     │
│                                                                              │
│  SAM Database (%SystemRoot%\system32\config\SAM)                            │
│  └─→ Local account password hashes                                          │
│                                                                              │
│  NTDS.dit (Domain Controller only)                                          │
│  └─→ All domain account password hashes                                     │
│                                                                              │
│  Registry                                                                    │
│  ├─→ LSA Secrets: Service account passwords, auto-logon                    │
│  └─→ Cached Domain Credentials: Last 10 domain logons                      │
│                                                                              │
│  Credential Manager                                                          │
│  └─→ Saved passwords for websites and network resources                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Tools

| Tool | Platform | Purpose |
|------|----------|---------|
| Mimikatz | Windows | Credential extraction and manipulation |
| secretsdump.py | Linux | Remote credential dumping |
| psexec.py | Linux | Remote execution with credentials/hash |
| wmiexec.py | Linux | WMI-based remote execution |
| smbexec.py | Linux | SMB-based remote execution |
| crackmapexec | Linux | Multi-purpose AD attack tool |
| Rubeus | Windows | Kerberos ticket manipulation |
| SharpDump | Windows | LSASS memory dump to file |

## Tasks

### Task 1: Credential Extraction with Mimikatz

**Objective:** Extract credentials from a compromised Windows system using Mimikatz.

**Techniques:**
- Dump LSASS memory for NTLM hashes and Kerberos tickets
- Extract SAM database for local account hashes
- Retrieve cached domain credentials
- Extract LSA secrets

### Task 2: Remote Credential Dumping with secretsdump

**Objective:** Remotely extract credentials using Impacket's secretsdump.

**Techniques:**
- Dump SAM, LSA secrets, and cached credentials remotely
- Perform DCSync to extract domain hashes
- Extract NTDS.dit contents

### Task 3: Pass-the-Hash (PtH)

**Objective:** Authenticate to remote systems using NTLM hashes without cracking passwords.

**Why it works:** NTLM authentication uses the hash directly for authentication, not the plaintext password. If you have the hash, you can authenticate.

### Task 4: Pass-the-Ticket (PtT)

**Objective:** Use stolen Kerberos tickets to authenticate as another user.

**Why it works:** Kerberos tickets are bearer tokens - whoever presents a valid ticket is authenticated. Stolen tickets can be injected and used.

### Task 5: Overpass-the-Hash

**Objective:** Use an NTLM hash to request Kerberos tickets, enabling Kerberos-based lateral movement.

**Why it works:** The Kerberos AS-REQ uses the user's password hash to prove identity. You can substitute the actual password with the hash.

## Attack Comparison

| Attack | Requires | Authentication Method | Detection Difficulty |
|--------|----------|----------------------|---------------------|
| Pass-the-Hash | NTLM hash | NTLM | Medium |
| Pass-the-Ticket | Kerberos ticket | Kerberos | Medium |
| Overpass-the-Hash | NTLM hash | Kerberos | Higher (looks like normal Kerberos) |
| DCSync | Domain Replication rights | N/A | High (legitimate protocol) |

## Attack Chain Example

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Credential Attack Chain Example                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Step 1: Initial Access                                                      │
│  ├─→ Compromise workstation via phishing/exploit                            │
│  └─→ Gain local administrator access                                        │
│                                                                              │
│  Step 2: Credential Extraction                                               │
│  ├─→ Run Mimikatz sekurlsa::logonpasswords                                  │
│  └─→ Obtain Domain Admin NTLM hash from memory                              │
│                                                                              │
│  Step 3: Lateral Movement                                                    │
│  ├─→ Pass-the-Hash to Domain Controller                                     │
│  └─→ psexec.py domain/admin@dc01 -hashes :NTLM_HASH                        │
│                                                                              │
│  Step 4: Domain Dominance                                                    │
│  ├─→ DCSync to extract all domain hashes                                    │
│  └─→ secretsdump.py domain/admin@dc01 -hashes :HASH -just-dc              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Lateral Movement Methods

### Method Comparison

| Method | Port | Protocol | Notes |
|--------|------|----------|-------|
| PsExec | 445 | SMB | Creates service, very noisy |
| WMI | 135, 445 | DCOM/WMI | Stealthier than PsExec |
| WinRM | 5985, 5986 | HTTP(S) | PowerShell Remoting |
| SMBExec | 445 | SMB | Uses temp batch file |
| DCOM | 135 | DCOM | Multiple execution methods |
| SSH | 22 | SSH | If OpenSSH is installed |

### Impacket Lateral Movement Suite

```bash
# All support -hashes for Pass-the-Hash
psexec.py domain/user@target -hashes :NTLM_HASH
wmiexec.py domain/user@target -hashes :NTLM_HASH
smbexec.py domain/user@target -hashes :NTLM_HASH
atexec.py domain/user@target -hashes :NTLM_HASH "command"
dcomexec.py domain/user@target -hashes :NTLM_HASH

# With Kerberos tickets
export KRB5CCNAME=ticket.ccache
psexec.py domain/user@target -k -no-pass
```

## Defense Considerations

Throughout this lab, consider these defensive measures:

- **Credential Guard:**
  - Protects LSASS using virtualization-based security
  - Prevents extraction of credentials from memory

- **Protected Users Group:**
  - Prevents NTLM authentication
  - Prevents credential caching
  - Enforces Kerberos AES encryption

- **Local Administrator Password Solution (LAPS):**
  - Unique passwords for local admin on each machine
  - Limits lateral movement with local admin hashes

- **Privileged Access Workstations (PAWs):**
  - Dedicated workstations for admin tasks
  - Isolates admin credentials from user workstations

- **Monitoring:**
  - Event ID 4624 - Logon events (Type 3 = Network)
  - Event ID 4648 - Explicit credential use
  - Event ID 4672 - Special privileges assigned

## Resources

- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Impacket Documentation](https://github.com/fortra/impacket)
- [The Hacker Recipes - Credentials](https://www.thehacker.recipes/ad/movement/credentials)
- [HackTricks - LSASS Dumping](https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz)
- [ired.team - Credential Access](https://www.ired.team/offensive-security/credential-access-and-credential-dumping)

## Next Steps

After completing this lab:
- Proceed to **Lab 5: Delegation Attacks** for advanced privilege escalation
- Practice identifying high-value targets for credential theft
- Study defensive mechanisms and how to bypass them
