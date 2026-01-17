# Challenge 05 - Robots Aren't Welcome

**Category:** Web
**Difficulty:** Beginner
**Points:** 100
**Target:** Juice Shop (http://localhost:8082)

## Challenge Description

The OWASP Juice Shop has some directories they don't want search engines to index. But sometimes what they're trying to hide from robots is exactly what we're looking for!

Your mission is to find what the website is hiding from web crawlers.

## Objectives

- Understand the purpose of robots.txt
- Discover hidden directories
- Access restricted content
- Find the flag

## Target Information

- **URL:** http://localhost:8082
- **No authentication required for this challenge**

## Getting Started

1. Start the Juice Shop container:
   ```bash
   cd docker && docker-compose up -d juice-shop
   ```

2. Navigate to http://localhost:8082
3. Think about what files web servers commonly have...

---

## Hints

<details>
<summary>Hint 1 (Cost: -10 points)</summary>

The `robots.txt` file tells search engine crawlers which pages they should and shouldn't index. It's publicly accessible on most websites.

</details>

<details>
<summary>Hint 2 (Cost: -20 points)</summary>

Try accessing: http://localhost:8082/robots.txt

Look for any "Disallow" entries - these are paths the site doesn't want crawled.

</details>

<details>
<summary>Hint 3 (Cost: -30 points)</summary>

After finding the disallowed path in robots.txt, navigate directly to that path. The flag might be displayed or hidden in the page source.

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Access robots.txt

Navigate to: http://localhost:8082/robots.txt

You'll see content similar to:
```
User-agent: *
Disallow: /ftp
Disallow: /admin
Disallow: /secret-flag
```

### Step 2: Explore Disallowed Paths

Try accessing each disallowed path:

1. **http://localhost:8082/ftp** - FTP-like file listing
2. **http://localhost:8082/admin** - Admin panel (may require auth)
3. **http://localhost:8082/secret-flag** - Contains our flag!

### Step 3: Get the Flag

Navigate to http://localhost:8082/secret-flag (or similar path based on your Juice Shop version).

The page displays: `FLAG{r0b0ts_txt_1s_n0t_s3cur1ty}`

### Alternative: Directory Enumeration

Even without robots.txt, you could find hidden directories using tools:

```bash
# Using dirb
dirb http://localhost:8082 /usr/share/wordlists/dirb/common.txt

# Using gobuster
gobuster dir -u http://localhost:8082 -w /usr/share/wordlists/dirb/common.txt

# Using ffuf
ffuf -u http://localhost:8082/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

### Understanding robots.txt

**Purpose:**
- Tells web crawlers (like Googlebot) which paths to avoid
- NOT a security mechanism - just a suggestion
- Anyone can read it - it's public!

**Format:**
```
User-agent: *          # Applies to all crawlers
Disallow: /private/    # Don't index this directory
Disallow: /admin       # Don't index admin pages
Allow: /public/        # OK to index this

User-agent: Googlebot  # Specific to Google
Disallow: /tmp/        # Google shouldn't index /tmp
```

### Security Implications

robots.txt is a **reconnaissance goldmine**:
- Reveals hidden directories
- Shows admin panels
- Exposes backup files
- Lists sensitive paths

**Never rely on robots.txt for security!**

### Common Interesting Paths

- `/admin`, `/administrator`
- `/backup`, `/backups`
- `/config`, `/configuration`
- `/private`, `/secret`
- `/api`, `/api/v1`
- `/dev`, `/development`
- `/test`, `/testing`

</details>

---

## Flag

```
FLAG{r0b0ts_txt_1s_n0t_s3cur1ty}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Web reconnaissance
- Understanding robots.txt
- Directory discovery
- Web application enumeration

## Tools Used

- Web browser
- dirb / gobuster / ffuf (optional)
- curl

## Bonus Tasks

1. Find all other disallowed paths in Juice Shop
2. Use gobuster to find directories NOT in robots.txt
3. Check if any disallowed paths contain vulnerabilities

## Related Challenges

- [01 - Hidden in Plain Sight](01-hidden-in-plain-sight.md) - Source code recon
- [Broken Access (Intermediate)](../intermediate/05-broken-access.md) - Access control

## References

- [Google Robots.txt Specification](https://developers.google.com/search/docs/advanced/robots/intro)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [Web Application Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
