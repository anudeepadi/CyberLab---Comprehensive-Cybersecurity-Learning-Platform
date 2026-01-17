# Command Line Mastery - Hints

Use these hints when stuck on CLI exercises. Each section provides progressive hints.

## File Operations Hints

### Hint: Creating files with specific content
- `echo "text" > file.txt` creates/overwrites file
- `echo "text" >> file.txt` appends to file
- `cat > file.txt` then type content, end with Ctrl+D
- `touch file.txt` creates empty file

### Hint: Copying multiple files
- Use wildcards: `cp *.txt destination/`
- Use brace expansion: `cp file{1,2,3}.txt dest/`
- Recursive copy: `cp -r sourcedir/ destdir/`

### Hint: Finding files to operate on
- `find . -name "*.log"` finds by name
- `find . -type f -mtime -1` finds files modified today
- `find . -size +10M` finds files over 10MB

### Hint: Safe deletion
- `rm -i file.txt` asks before deleting
- `rm -ri directory/` recursive with prompts
- Consider moving to trash: `mv file ~/.trash/`

---

## Permission Hints

### Hint: Understanding permission denied
- Check file permissions: `ls -l filename`
- Check if you own the file: compare with `whoami`
- Try with sudo if appropriate

### Hint: Making a script executable
```bash
chmod +x script.sh      # Add execute for all
chmod u+x script.sh     # Add execute for owner only
chmod 755 script.sh     # Standard for scripts
```

### Hint: Permission number calculation
```
r = 4, w = 2, x = 1

Owner  Group  Others
rwx    r-x    r-x
7      5      5      = 755

rw-    r--    r--
6      4      4      = 644
```

### Hint: Special permissions
- SUID (4xxx): File runs as owner, not executor
- SGID (2xxx): File runs as group owner
- Sticky (1xxx): Only owner can delete in directory

### Hint: Changing ownership
- Need root: `sudo chown user:group file`
- Recursive: `sudo chown -R user:group directory/`

---

## grep Hints

### Hint: Basic patterns not working
- Check case: use `-i` for case insensitive
- Check for regex characters: escape with backslash
- Try `-E` for extended regex (OR, +, ?)

### Hint: Searching multiple patterns
```bash
grep -E "pattern1|pattern2" file       # OR
grep -e "pattern1" -e "pattern2" file  # Alternative
grep "pattern1" file | grep "pattern2" # AND
```

### Hint: Getting context around matches
- `-B 3` shows 3 lines before match
- `-A 3` shows 3 lines after match
- `-C 3` shows 3 lines before and after

### Hint: Searching recursively
```bash
grep -r "pattern" directory/     # Recursive
grep -rn "pattern" directory/    # With line numbers
grep -rl "pattern" directory/    # Only filenames
```

### Hint: Inverting results
- `grep -v "pattern"` shows lines NOT matching
- Useful for filtering out noise

---

## sed Hints

### Hint: Substitution not working
- Check if pattern exists: `grep "pattern" file`
- Remember: `s/old/new/` only replaces first occurrence
- Use `s/old/new/g` for global (all occurrences)

### Hint: Making changes permanent
- `sed 's/a/b/' file` only prints, doesn't change
- `sed -i 's/a/b/' file` edits in place
- `sed -i.bak 's/a/b/' file` creates backup first

### Hint: Deleting lines
- `sed '/pattern/d' file` deletes matching lines
- `sed '5d' file` deletes line 5
- `sed '1,10d' file` deletes lines 1-10

### Hint: Special characters in sed
- Use different delimiter if pattern contains `/`:
  ```bash
  sed 's|/path/to/old|/path/to/new|g' file
  ```
- Escape special chars: `\.` `\*` `\[` `\]`

---

## awk Hints

### Hint: Wrong columns being printed
- Default separator is whitespace
- For CSV: `awk -F',' '{print $1}'`
- For /etc/passwd: `awk -F':' '{print $1}'`

### Hint: Combining columns
- Print with space: `awk '{print $1, $2}'`
- Print without space: `awk '{print $1 $2}'`
- Custom separator: `awk '{print $1 ":" $2}'`

### Hint: Conditional processing
```bash
awk '$3 > 100'          # Print lines where col3 > 100
awk '$1 == "root"'      # Print lines where col1 is "root"
awk 'NR > 1'            # Skip header (line 1)
```

### Hint: Calculations
```bash
awk '{sum += $1} END {print sum}'        # Sum
awk '{sum += $1} END {print sum/NR}'     # Average
awk 'BEGIN {max=0} $1>max {max=$1} END {print max}'  # Max
```

---

## Pipeline Hints

### Hint: Pipeline not giving expected results
- Test each command separately first
- Add `| head` to see first few results
- Use `| tee debug.txt` to save intermediate output

### Hint: Common pipeline patterns
```bash
# Count unique occurrences
... | sort | uniq -c | sort -rn

# Top N results
... | head -n 10

# Filter then count
... | grep "pattern" | wc -l
```

### Hint: Debugging pipelines
```bash
# See what each step produces
cat file | tee step1.txt | grep "x" | tee step2.txt | wc -l
```

---

## Redirection Hints

### Hint: Output disappearing
- `>` overwrites, `>>` appends
- stderr goes to terminal by default
- Capture stderr: `command 2> errors.txt`

### Hint: Capturing all output
```bash
command > output.txt 2>&1     # stdout and stderr to file
command &> output.txt         # Shorthand (bash)
```

### Hint: Discarding output
```bash
command > /dev/null           # Discard stdout
command 2> /dev/null          # Discard stderr
command &> /dev/null          # Discard all
```

### Hint: Using file as input
```bash
command < input.txt           # File as stdin
while read line; do echo "$line"; done < file.txt
```

---

## Script Hints

### Hint: Script won't execute
1. Check shebang line: `#!/bin/bash` at top
2. Check execute permission: `chmod +x script.sh`
3. Run with: `./script.sh` or `bash script.sh`

### Hint: Variables not expanding
- Use double quotes: `"$variable"`
- No spaces around `=`: `var=value`
- Use braces for clarity: `${variable}`

### Hint: Command output in variable
```bash
result=$(command)
result=`command`    # Older syntax
```

### Hint: Script debugging
```bash
bash -x script.sh   # Print each command before execution
set -x              # Enable debug mode in script
set +x              # Disable debug mode
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Find text in files | `grep -r "text" directory/` |
| Replace text | `sed -i 's/old/new/g' file` |
| Extract column | `awk '{print $N}' file` |
| Count occurrences | `sort \| uniq -c` |
| First N lines | `head -n N` |
| Last N lines | `tail -n N` |
| Line count | `wc -l` |
| Unique lines | `sort \| uniq` |
| Sort numerically | `sort -n` |
| Reverse sort | `sort -r` |

---

## Still Stuck?

1. Break the problem into smaller steps
2. Test each command individually
3. Read the man page: `man command`
4. Search online: "linux command [what you want to do]"
5. Check if you need sudo for the operation
6. Verify file paths and permissions

Remember: Building complex pipelines takes practice. Start simple and add complexity gradually!
