# BountyRecon Pro v2.5.0 - Premium Bug Bounty Recon Platform

![Version](https://img.shields.io/badge/version-2.5.0-red)
![License](https://img.shields.io/badge/license-MIT-green)
![React](https://img.shields.io/badge/React-18-blue)

Professional bug bounty reconnaissance dashboard with 18 premium modules, Burp Suite BApp Store integration, and POC Studio.

**Live Demo:** https://bountyrecon-pro.vercel.app  
**Author:** Mhotasin Munna

---

## ⚠️ Legal Disclaimer

> **Only scan targets you own or have explicit permission to test.**
> This tool is for educational and authorized bug bounty purposes only. The frontend runs in DEMO_MODE (simulated findings). Real scanning requires backend deployment with proper authorization.

## 🚀 Features

### 18 Premium Modules
- **Takeover:** Subjack
- **Discovery:** Feroxbuster, FFUF, Dirb, WhatWeb, Dmitry
- **Fuzzing:** Arjun, WFuzz, Nuclei
- **Injection:** SSRF Lab, CSRF Lab, XSS Auto Payload, Commix, SQLi
- **Auth:** Hydra, Ike-scan
- **CMS:** WPScan, Nikto, Nmap

### Burp Suite BApp Store (8 BApps)
Active Scan++, Param Miner, Autorize, Logger++, Collaborator Everywhere, Backslash Scanner, Software Vuln Scanner, JS Link Finder

### POC Studio
- HD Screenshot 1920x1080 (Canvas API)
- Video POC HTML Export
- HackerOne Ready Markdown Report (CVSS, OWASP, Impact)

### Core Engine
- `Sm()` - Subdomain enumeration simulation
- `Em()` - Endpoint discovery
- `km()` - Knowledge map correlation
- Out-of-Scope wildcard filtering `*.example.com`
- Dark/Light theme with localStorage persistence

## 📦 Installation

```bash
# Clone
git clone https://github.com/mhotasin24/bountyrecon-pro.git
cd bountyrecon-pro

# Frontend
npm install
cp .env.example .env
# Edit .env - set VITE_GOOGLE_CLIENT_ID if needed
npm run dev   # http://localhost:5173

# Build
npm run build
```

## 🔧 Backend (Optional Real Scanning)

Real scanning API is in `/backend` - requires Kali Linux tools.

```bash
cd backend
npm install
cp .env.example .env
# Edit .env: FRONTEND_URL, API_KEY, ALLOWED_DOMAINS
npm start  # http://localhost:3001
```

See `backend/README.md` for full deployment guide.

## 🌐 Deploy to Vercel

1. Push to GitHub
2. Vercel -> New Project -> Import `bountyrecon-pro`
3. Framework: Vite, Build Command: `npm run build`, Output: `dist`
4. Add env vars: `VITE_DEMO_MODE=true`
5. Deploy

`vercel.json` already includes security headers (CSP, HSTS, X-Frame).

## 🔐 Environment Variables

Frontend `.env.example`:
```
VITE_DEMO_MODE=true
VITE_API_URL=http://localhost:3001
VITE_GOOGLE_CLIENT_ID=your_id_here
```

Never commit `.env` - only `.env.example`.

## 🛡️ Security Updates in v2.5.0

- Removed hardcoded OAuth Client ID from README
- Added .gitignore (node_modules, dist, .env)
- Added helmet, rate-limit, CORS in backend
- Input validation for target URL (prevents command injection)
- Added CSP, HSTS, X-Frame-Options headers in vercel.json
- Removed Netlify HUD debug script from production
- Added Legal Disclaimer
- Theme persistence via localStorage

## 📄 License

MIT - See LICENSE file.

## 🤝 Contributing

PRs welcome! Please read CONTRIBUTING.md (coming soon).
