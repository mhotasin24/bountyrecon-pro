# BountyRecon Backend - Real Scanning API

## Deploy

Requires Node.js + Kali tools (nmap, whatweb, nuclei)

```bash
npm install
cp .env.example .env
node server.js
```

## API

- GET /health
- GET /api/tools
- POST /api/scan { target, tools[], outOfScope[] }
- GET /api/scan/:id

## Security

- helmet, cors, rate-limit (30 req / 15 min)
- validateTarget() prevents command injection
- MAX_CONCURRENT_SCANS limit
- Optional API_KEY protection
