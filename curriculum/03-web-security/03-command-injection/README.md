# OS Command Injection Labs

Master command injection attacks from basic payloads to blind exploitation and filter bypass techniques.

## What is Command Injection?

OS Command Injection (also known as shell injection) is a vulnerability that allows attackers to execute arbitrary operating system commands on the server. This occurs when an application passes unsafe user-supplied data to a system shell.

Command injection can lead to:
- Full server compromise
- Data exfiltration
- Privilege escalation
- Lateral movement in networks
- Denial of Service
- Cryptocurrency mining

## How Command Injection Works

### Attack Flow

1. **Application accepts user input** (filename, IP address, etc.)
2. **Input is passed to system command** without sanitization
3. **Attacker injects command separator** and malicious command
4. **Shell executes both** original and injected commands
5. **Attacker gains** command execution on server

### Command Separators

| Operator | Description | Example |
|----------|-------------|---------|
| `;` | Command separator (Unix) | `ping 127.0.0.1; id` |
| `&&` | Execute if previous succeeds | `ping 127.0.0.1 && id` |
| `\|\|` | Execute if previous fails | `ping invalid \|\| id` |
| `\|` | Pipe output | `ping 127.0.0.1 \| id` |
| `` ` `` | Command substitution | `ping \`id\`` |
| `$()` | Command substitution | `ping $(id)` |
| `&` | Background execution (Unix) | `ping 127.0.0.1 & id` |
| `\n` | Newline separator | `ping 127.0.0.1%0aid` |

## Types of Command Injection

### 1. In-Band Command Injection
Output of injected command is returned in the response

### 2. Blind Command Injection
No visible output, must use time delays or out-of-band techniques

### 3. Out-of-Band Command Injection
Data exfiltrated via DNS, HTTP, or other protocols

## Lab Series

### Lab 1: Basic Command Injection
**Difficulty:** Beginner | **Duration:** 30 min | **Target:** DVWA

Learn the fundamentals:
- Understanding command separators
- Injecting simple commands
- Reading files via injection

### Lab 2: Ping Utility Exploitation
**Difficulty:** Beginner | **Duration:** 30 min | **Target:** bWAPP

Common vulnerable patterns:
- Network utilities as targets
- IP address input fields
- System diagnostic pages

### Lab 3: Blind Command Injection
**Difficulty:** Intermediate | **Duration:** 1 hr | **Target:** WebGoat

No output techniques:
- Time-based detection
- DNS exfiltration
- HTTP callbacks

### Lab 4: Filter Bypass Techniques
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Multiple

Evading protections:
- Character encoding
- Alternate command syntax
- Whitespace bypass
- Quote manipulation

### Lab 5: Out-of-Band Exploitation
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Custom

Data exfiltration:
- DNS tunneling
- HTTP exfiltration
- Reverse shells

## Basic Payloads

### Unix/Linux

```bash
# Command chaining
; id
; cat /etc/passwd
; whoami
&& id
|| id
| id

# Command substitution
`id`
$(id)

# Newline injection
%0aid
%0a%0did
```

### Windows

```cmd
# Command chaining
& whoami
&& whoami
| whoami

# For loop technique
& for /f "tokens=*" %a in ('whoami') do echo %a
```

## Tools

```bash
# Commix - Automated command injection
commix --url="http://target.com/page?param=INJECT_HERE"

# Burp Suite - Manual testing
# Use Intruder with command injection wordlists

# Manual testing
curl "http://target.com/ping?ip=127.0.0.1;id"
```

## Defense Techniques (Know Your Enemy)

Understanding defenses helps identify weaknesses:

1. **Input Validation** - Whitelist allowed characters
2. **Avoid Shell Commands** - Use language APIs instead
3. **Parameterized Calls** - Separate data from commands
4. **Least Privilege** - Run with minimal permissions
5. **Sandbox Execution** - Isolate command execution

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 - Basic Injection | `FLAG{cmd_1nj3ct_b4s1c}` |
| Lab 2 - Ping Exploitation | `FLAG{p1ng_p0ng_pwn3d}` |
| Lab 3 - Blind Injection | `FLAG{bl1nd_cmd_t1m3}` |
| Lab 4 - Filter Bypass | `FLAG{byp4ss_f1lt3rs}` |
| Lab 5 - Out-of-Band | `FLAG{00b_3xf1ltr4t10n}` |

## OWASP References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP Testing for Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)

## Additional Resources

- [PortSwigger Command Injection](https://portswigger.net/web-security/os-command-injection)
- [PayloadsAllTheThings Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [HackTricks Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
