# CyberLab - Quick Start Reference Card

## 🚀 After Git Pull (3 Steps)

### 1. Start Docker Containers
```bash
cd docker
docker-compose up -d
```

### 2. Start the UI
```bash
cd ui
npm run dev
```

### 3. Open in Browser
- **UI Dashboard:** http://localhost:5173
- **DVWA:** http://localhost:8081 (admin:password)

---

## 📦 All Services

| Service | URL | Login |
|---------|-----|-------|
| **CyberLab UI** | http://localhost:5173 | - |
| **DVWA** | http://localhost:8081 | admin:password |
| **Juice Shop** | http://localhost:8082 | - |
| **WebGoat** | http://localhost:8083 | - |
| **bWAPP** | http://localhost:8084 | bee:bug |
| **Mutillidae** | http://localhost:8085 | - |

---

## 🎯 Quick Commands

### Docker
```bash
# Start all
cd docker && docker-compose up -d

# Stop all
docker-compose down

# View status
docker ps

# View logs
docker-compose logs -f
```

### UI
```bash
# Development mode
cd ui && npm run dev

# Build production
npm run build
```

---

## 📚 Your First Lab

1. Open UI: http://localhost:5173
2. Go to **Labs** → **SQL Injection - Basics**
3. Open DVWA: http://localhost:8081
4. Login: admin:password
5. Set Security: LOW
6. Complete tasks and check them off in UI
7. Find flag: `FLAG{sql_1nj3ct10n_m4st3r}`

---

## 💾 Backup Progress

In UI → **Progress** page:
- Click **Export** → Save JSON file
- Click **Import** → Restore from JSON

---

## 🔧 Common Issues

**Containers won't start:**
```bash
docker-compose down -v
docker-compose up -d --force-recreate
```

**DVWA database error:**
- Go to http://localhost:8081
- Click "Create / Reset Database"

**Port already in use:**
```bash
# Find what's using port 8081
sudo lsof -i :8081

# Kill the process or change port in docker-compose.yml
```

---

## 📖 Full Documentation

For detailed walkthrough, see: **GETTING-STARTED.md**

---

## 🎓 Curriculum Structure

**52 Labs across 8 Modules:**

1. **Foundations** (5 labs) - Linux, CLI, networking
2. **Network Analysis** (6 labs) - Packets, MITM, scanning
3. **Web Security** (8 labs) - SQLi, XSS, CSRF, XXE
4. **System Exploitation** (6 labs) - Shells, privesc, buffer overflow
5. **Cryptography** (8 labs) - Hashing, encoding, crypto attacks
6. **Wireless** (8 labs) - WPA, WEP, evil twin
7. **Active Directory** (7 labs) - Kerberos, mimikatz, golden ticket
8. **CTF Challenges** (4 labs) - Mixed difficulty challenges

---

## ⚡ Pro Tips

- ✅ Check off tasks in UI as you complete them
- 🚩 Submit flags to track progress
- 💾 Export progress regularly (it's in browser localStorage)
- 📚 Read curriculum markdown files for detailed guidance
- 🔍 Check `hints.md` if stuck
- 📖 Read `walkthrough.md` for complete solutions

---

**Happy Hacking! 🔐**
