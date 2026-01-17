# File Upload Vulnerabilities Labs

Master file upload attacks from basic extension bypass to advanced polyglot files and webshell deployment.

## What are File Upload Vulnerabilities?

File upload vulnerabilities occur when a web application allows users to upload files without properly validating the file type, content, or name. Attackers can exploit this to upload malicious files that execute code on the server.

File upload attacks can lead to:
- Remote Code Execution (RCE)
- Server compromise
- Defacement
- Data theft
- Malware distribution
- Denial of Service

## How File Upload Attacks Work

### Attack Flow

1. Identify upload functionality (profile pictures, documents, etc.)
2. Analyze validation mechanisms (client-side, server-side)
3. Craft malicious file (webshell, executable)
4. Bypass upload restrictions (extension, MIME type, content)
5. Locate uploaded file (guess path, retrieve from response)
6. Execute malicious code (access webshell, trigger execution)

### Common Validation Bypasses

| Validation Type | Bypass Technique |
|-----------------|------------------|
| Extension blacklist | Use .php5, .phtml, .phar |
| Extension whitelist | Double extension: file.php.jpg |
| MIME type check | Modify Content-Type header |
| Content check | Add valid image header (magic bytes) |
| File size limit | Minimize payload |

## Lab Series

### Lab 1: Basic File Upload
Difficulty: Beginner | Duration: 30 min | Target: DVWA

Learn the fundamentals:
- Understanding file upload mechanisms
- Uploading basic webshells
- Finding uploaded file location

### Lab 2: Extension Bypass
Difficulty: Intermediate | Duration: 45 min | Target: bWAPP

Defeating extension filters:
- Alternative PHP extensions
- Double extensions
- Null byte injection
- Case manipulation

### Lab 3: MIME Type Bypass
Difficulty: Intermediate | Duration: 30 min | Target: Multiple

Content-Type manipulation:
- Changing MIME types
- Adding magic bytes
- Polyglot files

### Lab 4: Content Validation Bypass
Difficulty: Advanced | Duration: 1 hr | Target: Juice Shop

Bypassing content checks:
- Image header injection
- Polyglot file creation
- GIF89a technique

### Lab 5: Webshell Deployment
Difficulty: Advanced | Duration: 1 hr | Target: Multiple

Advanced exploitation:
- Minimal webshells
- Obfuscated shells
- Reverse shell uploads

## Extension Variations

PHP alternatives:
- .php, .php3, .php4, .php5, .php7
- .pht, .phtml, .phar
- .phps, .phpt

Double Extensions:
- file.php.jpg
- file.php.png
- file.jpg.php

## Tools

Burp Suite - Intercept and modify uploads, use Repeater to test payloads

Weevely - Generate obfuscated PHP backdoors

msfvenom - Generate various payloads

## Defense Techniques (Know Your Enemy)

Understanding defenses helps identify weaknesses:

1. Whitelist Extensions - Only allow specific safe extensions
2. Validate MIME Type - Check Content-Type header
3. Validate Content - Verify file magic bytes
4. Rename Files - Use random names, strip extensions
5. Store Outside Webroot - Prevent direct execution
6. Use CDN - Serve files from separate domain
7. Antivirus Scanning - Scan uploaded files

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 - Basic Upload | FLAG{f1l3_upl04d_b4s1c} |
| Lab 2 - Extension Bypass | FLAG{3xt3ns10n_byp4ss} |
| Lab 3 - MIME Bypass | FLAG{m1m3_typ3_pwn3d} |
| Lab 4 - Content Bypass | FLAG{c0nt3nt_v4l1d4t10n} |
| Lab 5 - Webshell | FLAG{w3bsh3ll_d3pl0y3d} |

## OWASP References

- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

## Additional Resources

- PortSwigger File Upload: https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings File Upload: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- HackTricks File Upload: https://book.hacktricks.xyz/pentesting-web/file-upload
