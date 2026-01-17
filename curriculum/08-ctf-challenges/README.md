# Module 08 - CTF Challenges

Master your cybersecurity skills through hands-on Capture The Flag challenges.

## Overview

This module contains 22+ CTF challenges across multiple categories and difficulty levels. Each challenge is designed to test specific skills learned throughout the CyberLab curriculum.

```
     ┌───────────────────────────────────────────────────────┐
     │                   CTF CHALLENGES                       │
     │                                                        │
     │   ┌─────────┐   ┌──────────────┐   ┌──────────┐       │
     │   │BEGINNER │ → │ INTERMEDIATE │ → │ ADVANCED │       │
     │   │ 8 Chall │   │   8 Chall    │   │  6 Chall │       │
     │   └─────────┘   └──────────────┘   └──────────┘       │
     │                                                        │
     │   Categories: Web | Crypto | Forensics | Misc | Pwn   │
     └───────────────────────────────────────────────────────┘
```

## Challenge Statistics

| Difficulty | Count | Estimated Time | Skills Required |
|------------|-------|----------------|-----------------|
| Beginner | 8 | 4-6 hrs | Basic Linux, Web fundamentals |
| Intermediate | 8 | 8-12 hrs | SQLi, XSS, Network analysis |
| Advanced | 6 | 12-20 hrs | Binary exploitation, Advanced techniques |

## Categories

### Web Security
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Authentication Bypass
- IDOR Vulnerabilities

### Cryptography
- Encoding/Decoding
- Classical Ciphers
- Hash Cracking
- Steganography

### Forensics
- Network Packet Analysis
- File Carving
- Metadata Analysis
- Memory Forensics

### Misc
- OSINT
- Scripting Challenges
- Logic Puzzles

### Pwn (Binary Exploitation)
- Buffer Overflows
- Format String Vulnerabilities
- Return-Oriented Programming

## How to Use This Module

### Prerequisites

1. **Complete Earlier Modules**: Challenges assume knowledge from Modules 01-07
2. **Docker Services Running**: Start CyberLab Docker environment
   ```bash
   cd docker && docker-compose up -d
   ```
3. **Tools Ready**: Ensure you have access to:
   - Burp Suite / OWASP ZAP
   - Wireshark / tshark
   - Python 3.x
   - netcat, curl, wget
   - John the Ripper / Hashcat

### Challenge Structure

Each challenge file includes:

1. **Challenge Description** - What you need to accomplish
2. **Target Information** - Docker service, port, URL
3. **Hints** - Progressive hints (spoiler-tagged)
4. **Solution Walkthrough** - Step-by-step solution
5. **Flag Format** - Expected flag format

### Difficulty Progression

```
BEGINNER                    INTERMEDIATE                 ADVANCED
────────                    ────────────                 ────────
• Single vulnerability      • Chained exploits           • Complex multi-stage
• Clear hints available     • Less guidance              • Minimal hints
• Common techniques         • Tool proficiency           • Custom exploitation
• 30-45 min each           • 1-2 hrs each               • 2-4 hrs each
```

## Challenge Index

### Beginner Challenges (beginner/)

| # | Name | Category | Target | Flag Points |
|---|------|----------|--------|-------------|
| 01 | Hidden in Plain Sight | Web | DVWA | 100 |
| 02 | Cookie Monster | Web | DVWA | 100 |
| 03 | Decode Me | Crypto | Local | 100 |
| 04 | What's in the Packet? | Forensics | PCAP | 100 |
| 05 | Robots Aren't Welcome | Web | Juice Shop | 100 |
| 06 | The Classic Injection | Web | DVWA | 150 |
| 07 | Ancient Secrets | Crypto | Local | 100 |
| 08 | Hidden Message | Misc | Local | 100 |

### Intermediate Challenges (intermediate/)

| # | Name | Category | Target | Flag Points |
|---|------|----------|--------|-------------|
| 01 | Union Station | Web | DVWA | 200 |
| 02 | Command & Control | Web | DVWA | 200 |
| 03 | Hash Browns | Crypto | Local | 200 |
| 04 | Stealthy Transfer | Forensics | PCAP | 250 |
| 05 | Broken Access | Web | Juice Shop | 200 |
| 06 | DNS Tunneling | Forensics | PCAP | 250 |
| 07 | Filter Bypass | Web | DVWA | 200 |
| 08 | API Mayhem | Web | Juice Shop | 250 |

### Advanced Challenges (advanced/)

| # | Name | Category | Target | Flag Points |
|---|------|----------|--------|-------------|
| 01 | Stack Smasher | Pwn | Buffer Overflow Server | 400 |
| 02 | Blind Injection | Web | DVWA | 350 |
| 03 | Memory Forensics | Forensics | Memory Dump | 400 |
| 04 | Token Trouble | Web | Juice Shop | 350 |
| 05 | Crypto Cascade | Crypto | Local | 350 |
| 06 | The Final Boss | Multi | All Services | 500 |

## Flag Format

All flags follow this format:
```
FLAG{descriptive_flag_text}
```

Examples:
- `FLAG{sql_1nj3ct10n_m4st3r}`
- `FLAG{xss_c00k13_th13f}`
- `FLAG{h4sh_cr4ck3d}`

## Scoring System

| Difficulty | Base Points | Time Bonus | First Blood |
|------------|-------------|------------|-------------|
| Beginner | 100-150 | +25% if <30min | +50 |
| Intermediate | 200-250 | +25% if <1hr | +100 |
| Advanced | 350-500 | +25% if <2hr | +150 |

## Tips for Success

### General Approach
1. **Read Carefully** - Challenge descriptions contain clues
2. **Enumerate First** - Gather information before attacking
3. **Use Hints Sparingly** - Try on your own first
4. **Take Notes** - Document your methodology
5. **Try Multiple Approaches** - One technique may not work

### Common Mistakes to Avoid
- Skipping reconnaissance
- Not checking robots.txt and source code
- Forgetting to URL encode payloads
- Missing obvious clues in challenge names
- Not trying default credentials

### Useful Resources
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io/)
- [CyberChef](https://gchq.github.io/CyberChef/)

## Docker Services Reference

| Service | URL | Purpose |
|---------|-----|---------|
| DVWA | http://localhost:8081 | Web vulnerabilities |
| Juice Shop | http://localhost:8082 | Modern web challenges |
| WebGoat | http://localhost:8083 | Guided lessons |
| MySQL | localhost:3307 | Database access |
| Buffer Overflow | nc localhost 9999 | Binary exploitation |

## Progress Tracking

Track your progress using the checkboxes in each challenge file:

- [ ] Complete challenge without hints
- [ ] Complete challenge with 1 hint
- [ ] Complete challenge with walkthrough
- [ ] Understand the underlying vulnerability
- [ ] Document your own solution

## Competition Mode

For group practice, you can run these challenges in competition mode:

1. Set a time limit per difficulty tier
2. Disable access to solution sections
3. Award points based on completion time
4. First to solve gets bonus points

## Next Steps

After completing CTF challenges:
- Practice on [HackTheBox](https://www.hackthebox.eu/)
- Try [TryHackMe](https://tryhackme.com/) rooms
- Participate in live CTF competitions
- Build your own CTF challenges

## Contributing

Found a bug or want to add a challenge? See the main repository CONTRIBUTING.md.

---

**Total Challenges:** 22+
**Total Points Available:** 4,600+
**Estimated Completion Time:** 25-40 hours
