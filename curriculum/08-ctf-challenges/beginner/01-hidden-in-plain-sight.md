# Challenge 01 - Hidden in Plain Sight

**Category:** Web
**Difficulty:** Beginner
**Points:** 100
**Target:** DVWA (http://localhost:8081)

## Challenge Description

The developers of this web application thought they could hide sensitive information in plain sight. Your mission is to find the hidden flag that's been carelessly left in the application.

Sometimes the best hiding spots are the ones nobody thinks to check.

## Objectives

- Explore the web application thoroughly
- Find hidden or commented information
- Extract the flag

## Target Information

- **URL:** http://localhost:8081
- **Credentials:** admin / password
- **Security Level:** Low

## Getting Started

1. Start the DVWA container:
   ```bash
   cd docker && docker-compose up -d dvwa
   ```

2. Navigate to http://localhost:8081
3. Login with the provided credentials
4. Begin your exploration!

---

## Hints

<details>
<summary>Hint 1 (Cost: -10 points)</summary>

Developers often leave comments in HTML source code that shouldn't be visible to end users.

</details>

<details>
<summary>Hint 2 (Cost: -20 points)</summary>

Try viewing the page source (Ctrl+U or Right-click > View Page Source). Look for HTML comments that start with `<!--` and end with `-->`.

</details>

<details>
<summary>Hint 3 (Cost: -30 points)</summary>

Check the main login page source code before logging in. There's a comment with developer notes.

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Access DVWA

Navigate to http://localhost:8081 in your browser.

### Step 2: View Page Source

Before logging in, right-click on the page and select "View Page Source" (or press Ctrl+U).

### Step 3: Search for Comments

Look through the HTML source code for comments. You can use Ctrl+F to search for `<!--` or `FLAG`.

### Step 4: Find the Flag

In the source code, you'll find:

```html
<!-- Developer notes: Remember to remove test credentials
     Also, don't forget about: FLAG{s0urc3_c0d3_1s_publ1c} -->
```

### Understanding the Vulnerability

This is an example of **Information Disclosure** - sensitive information exposed through:
- HTML comments
- JavaScript comments
- Error messages
- Debug information

### Prevention

- Remove all comments containing sensitive data before deployment
- Use server-side comments that don't render to clients
- Implement proper code review processes
- Use automated tools to scan for sensitive data in source code

</details>

---

## Flag

```
FLAG{s0urc3_c0d3_1s_publ1c}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Web reconnaissance
- Source code analysis
- Information disclosure detection

## Related Challenges

- [02 - Cookie Monster](02-cookie-monster.md) - More web exploration
- [05 - Robots Aren't Welcome](05-robots-arent-welcome.md) - Hidden files

## References

- [OWASP - Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
