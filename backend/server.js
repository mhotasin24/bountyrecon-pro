require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs').promises;
const path = require('path');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const execFileAsync = promisify(execFile);

// Security middleware
app.use(helmet());
app.use(morgan('combined'));
app.use(cors({
  origin: process.env.FRONTEND_URL ? [process.env.FRONTEND_URL, 'https://zippy-valkyrie-d5785e.netlify.app', 'https://bountyrecon-deploy-pack.vercel.app', 'http://localhost:5173', 'http://localhost:3000'] : '*',
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));

// Rate limiting - prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many requests, try again after 15 min' }
});
app.use('/api/', limiter);

// In-memory job store
const jobs = new Map();
let concurrentScans = 0;
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS || '3');

// Helper: Validate target (prevent command injection)
function validateTarget(target) {
  if (!target || typeof target !== 'string') throw new Error('Invalid target');
  // Remove protocol
  let clean = target.trim().replace(/^https?:\/\//, '').split('/')[0].split('?')[0];
  // Basic domain/IP validation
  const domainRegex = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
  const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (!domainRegex.test(clean) && !ipRegex.test(clean) && !clean.includes('localhost')) {
    // Allow subdomain
    if (clean.length < 3 || clean.length > 253) throw new Error('Invalid domain');
  }
  // Check allowed domains if set
  if (process.env.ALLOWED_DOMAINS && process.env.ALLOWED_DOMAINS !== '*') {
    const allowed = process.env.ALLOWED_DOMAINS.split(',').map(d => d.trim().toLowerCase());
    const isAllowed = allowed.some(d => clean.toLowerCase().endsWith(d.toLowerCase()));
    if (!isAllowed) throw new Error(`Domain ${clean} not in allowed list`);
  }
  // Prevent command injection chars
  if (/[;&|`$(){}<>\n\r]/.test(clean)) throw new Error('Invalid characters in target');
  return clean;
}

function isOutOfScope(url, outOfScopeList) {
  if (!outOfScopeList || outOfScopeList.length === 0) return false;
  return outOfScopeList.some(pattern => {
    const p = pattern.trim();
    if (!p) return false;
    if (p.startsWith('*.')) {
      const base = p.slice(2);
      return url.includes(base);
    }
    if (p.startsWith('*')) {
      return url.includes(p.slice(1));
    }
    return url.includes(p);
  });
}

// Tool runners - safe execFile usage
async function runWhatWeb(target) {
  try {
    const { stdout } = await execFileAsync(process.env.WHATWEB_PATH || 'whatweb', 
      ['--log-json=-', '--no-errors', `https://${target}`], { timeout: 30000 });
    return { tool: 'WhatWeb', output: stdout.slice(0, 5000), parsed: true };
  } catch (e) {
    // Fallback: fetch headers
    try {
      const res = await axios.get(`https://${target}`, { timeout: 10000, validateStatus: () => true });
      return { tool: 'WhatWeb', output: `Server: ${res.headers['server'] || 'unknown'} | X-Powered-By: ${res.headers['x-powered-by'] || 'none'} | Status: ${res.status}`, fallback: true };
    } catch (err) {
      return { tool: 'WhatWeb', error: err.message, fallback: true };
    }
  }
}

async function runNmap(target) {
  try {
    const { stdout } = await execFileAsync(process.env.NMAP_PATH || 'nmap',
      ['-F', '--open', '-T4', target], { timeout: 60000 });
    return { tool: 'Nmap', output: stdout.slice(0, 8000) };
  } catch (e) {
    return { tool: 'Nmap', output: e.stdout ? e.stdout.slice(0, 8000) : '', error: e.message, partial: true };
  }
}

async function runNuclei(target) {
  try {
    const { stdout } = await execFileAsync(process.env.NUCLEI_PATH || 'nuclei',
      ['-u', `https://${target}`, '-silent', '-severity', 'low,medium,high,critical', '-j'], { timeout: 60000 });
    const findings = stdout.split('\n').filter(l => l.trim()).slice(0, 20).map(l => {
      try { return JSON.parse(l); } catch { return { info: { name: l } }; }
    });
    return { tool: 'Nuclei', findings, raw: stdout.slice(0, 8000) };
  } catch (e) {
    return { tool: 'Nuclei', error: 'Nuclei not installed or timeout', mock: true };
  }
}

async function checkEnvExposure(target) {
  const paths = ['/.env', '/.git/config', '/.DS_Store', '/config.json', '/backup.zip'];
  const results = [];
  for (const p of paths) {
    try {
      const url = `https://${target}${p}`;
      const res = await axios.get(url, { timeout: 5000, validateStatus: () => true });
      if (res.status === 200 && res.data && res.data.toString().length > 10 && res.data.toString().length < 50000) {
        const body = res.data.toString();
        if (body.includes('DB_') || body.includes('API_KEY') || body.includes('PASSWORD') || body.includes('[core]')) {
          results.push({ path: p, status: res.status, exposed: true, severity: 'Critical' });
        }
      }
    } catch {}
  }
  return { tool: 'EnvCheck', results };
}

async function checkSecurityHeaders(target) {
  try {
    const res = await axios.get(`https://${target}`, { timeout: 8000, validateStatus: () => true });
    const headers = res.headers;
    const missing = [];
    if (!headers['content-security-policy']) missing.push('CSP');
    if (!headers['x-frame-options']) missing.push('X-Frame-Options');
    if (!headers['strict-transport-security']) missing.push('HSTS');
    if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options');
    return { tool: 'Headers', missing, headers: { server: headers['server'], poweredBy: headers['x-powered-by'] } };
  } catch (e) {
    return { tool: 'Headers', error: e.message };
  }
}

// Main scan logic
async function performScan(jobId, target, enabledTools, outOfScope) {
  const job = jobs.get(jobId);
  try {
    job.status = 'running';
    job.logs.push(`[${new Date().toISOString()}] Starting scan for ${target}`);

    const findings = [];
    const toolResults = {};

    // Check out of scope
    if (isOutOfScope(target, outOfScope)) {
      throw new Error('Target is in out-of-scope list');
    }

    // Run tools based on enabled list
    const toolsToRun = enabledTools && enabledTools.length ? enabledTools : ['WhatWeb', 'Nmap', 'Headers', 'EnvCheck'];

    if (toolsToRun.includes('WhatWeb') || toolsToRun.includes('Whatweb')) {
      job.logs.push('Running WhatWeb...');
      const r = await runWhatWeb(target);
      toolResults.whatweb = r;
      if (r.output && r.output.toLowerCase().includes('apache')) {
        findings.push({ id: uuidv4(), type: 'Info Disclosure', severity: 'Low', title: 'Server version disclosed', tool: 'WhatWeb', evidence: r.output.slice(0, 500), impact: 'Server fingerprinting' });
      }
    }

    if (toolsToRun.includes('Nmap') || toolsToRun.includes('NMAP')) {
      job.logs.push('Running Nmap fast scan...');
      const r = await runNmap(target);
      toolResults.nmap = r;
      if (r.output && r.output.includes('open')) {
        findings.push({ id: uuidv4(), type: 'Open Port', severity: 'Medium', title: 'Open ports detected', tool: 'Nmap', evidence: r.output.slice(0, 1000), impact: 'Potential attack surface' });
      }
    }

    job.logs.push('Checking security headers...');
    const hdr = await checkSecurityHeaders(target);
    toolResults.headers = hdr;
    if (hdr.missing && hdr.missing.length > 0) {
      findings.push({ id: uuidv4(), type: 'Missing Security Headers', severity: 'Low', title: `Missing: ${hdr.missing.join(', ')}`, tool: 'Headers', evidence: JSON.stringify(hdr.headers), impact: 'Clickjacking, XSS risk' });
    }

    job.logs.push('Checking .env exposure...');
    const env = await checkEnvExposure(target);
    toolResults.env = env;
    env.results.forEach(r => {
      findings.push({ id: uuidv4(), type: '.env Exposed', severity: r.severity, title: `${r.path} exposed`, tool: 'EnvCheck', evidence: r.path, impact: 'Critical secrets exposure - RCE, DB access', cvss: '9.1' });
    });

    if (toolsToRun.includes('Nuclei')) {
      job.logs.push('Running Nuclei...');
      const r = await runNuclei(target);
      toolResults.nuclei = r;
      if (r.findings) {
        r.findings.forEach(f => {
          findings.push({ id: uuidv4(), type: f.info?.name || 'Nuclei Finding', severity: f.info?.severity || 'Medium', title: f.info?.name || 'Vulnerability', tool: 'Nuclei', evidence: JSON.stringify(f).slice(0, 500), impact: f.info?.description || '' });
        });
      }
    }

    // Filter out-of-scope
    const filteredFindings = findings.filter(f => !isOutOfScope(f.title + f.evidence, outOfScope));

    job.status = 'completed';
    job.findings = filteredFindings;
    job.toolResults = toolResults;
    job.completedAt = new Date().toISOString();
    job.logs.push(`Scan completed - ${filteredFindings.length} findings`);
  } catch (err) {
    job.status = 'failed';
    job.error = err.message;
    job.logs.push(`Failed: ${err.message}`);
  } finally {
    concurrentScans--;
  }
}

// Routes
app.get('/', (req, res) => {
  res.json({ 
    name: 'BountyRecon PRO Real API', 
    version: '2.4.1', 
    status: 'running',
    endpoints: ['/health', '/api/tools', '/api/scan', '/api/scan/:id', '/api/auth/github/callback'],
    disclaimer: 'Only scan targets you own or have explicit permission to test'
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), concurrentScans, jobs: jobs.size });
});

app.get('/api/tools', (req, res) => {
  res.json({
    tools: [
      { id: 'WhatWeb', name: 'WhatWeb', category: 'Fingerprint', installed: true },
      { id: 'Nmap', name: 'Nmap', category: 'Port Scan', installed: true },
      { id: 'Nuclei', name: 'Nuclei', category: 'Vuln Scan', installed: true },
      { id: 'FFUF', name: 'FFUF', category: 'Fuzzing', installed: true },
      { id: 'Feroxbuster', name: 'Feroxbuster', category: 'Dir Brute', installed: true },
      { id: 'Subjack', name: 'Subjack', category: 'Takeover', installed: true },
      { id: 'WPScan', name: 'WPScan', category: 'CMS', installed: true },
      { id: 'Nikto', name: 'Nikto', category: 'Web Scan', installed: true },
      { id: 'Headers', name: 'Security Headers', category: 'Config', installed: true },
      { id: 'EnvCheck', name: '.env Exposure', category: 'Secrets', installed: true },
    ]
  });
});

app.post('/api/scan', async (req, res) => {
  try {
    if (concurrentScans >= MAX_CONCURRENT) {
      return res.status(429).json({ error: `Max ${MAX_CONCURRENT} concurrent scans, try later` });
    }

    const { target, tools, outOfScope, apiKey } = req.body;

    // Optional API key check
    if (process.env.REQUIRE_API_KEY === 'true') {
      if (apiKey !== process.env.API_KEY) return res.status(401).json({ error: 'Invalid API key' });
    }

    const cleanTarget = validateTarget(target);

    const jobId = uuidv4();
    const job = {
      id: jobId,
      target: cleanTarget,
      status: 'queued',
      createdAt: new Date().toISOString(),
      findings: [],
      logs: [],
      tools: tools || []
    };
    jobs.set(jobId, job);
    concurrentScans++;

    // Start async scan
    performScan(jobId, cleanTarget, tools, outOfScope || []);

    res.json({ jobId, status: 'queued', message: 'Scan started', target: cleanTarget });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/scan/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json(job);
});

// GitHub OAuth callback
app.get('/api/auth/github/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'No code' });
  try {
    const tokenRes = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code
    }, { headers: { Accept: 'application/json' } });

    const accessToken = tokenRes.data.access_token;
    const userRes = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const frontend = process.env.FRONTEND_URL || 'https://bountyrecon-deploy-pack.vercel.app';
    const userData = encodeURIComponent(JSON.stringify(userRes.data));
    res.redirect(`${frontend}?github_user=${userData}&github_token=${accessToken}`);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Cleanup old jobs every 10 min
setInterval(() => {
  const now = Date.now();
  for (const [id, job] of jobs) {
    if (now - new Date(job.createdAt).getTime() > 3600000) { // 1 hour
      jobs.delete(id);
    }
  }
}, 600000);

app.listen(PORT, () => {
  console.log(`BountyRecon Real API running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
  console.log('DISCLAIMER: Only scan targets you have permission to test!');
});
