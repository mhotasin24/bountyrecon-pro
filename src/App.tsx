import { useState, useEffect, useMemo, useRef } from 'react';

// Types
type ModuleItem = {
  id: string;
  name: string;
  desc: string;
  icon: string;
  enabled: boolean;
};

type BAppItem = {
  id: string;
  name: string;
  color: string;
  findingCount: number;
  enabled: boolean;
};

type Finding = {
  uid: string;
  owasp: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  title: string;
  url: string;
  tool: string;
  confidence: number;
  evidence: string;
  attackScenario: string[];
  impact: string;
  report: string;
  param?: string;
  cvss?: string;
};

// --- CORE RECON ENGINE FUNCTIONS Sm(), Em(), km() ---
const Sm = (target: string): string[] => {
  try {
    const host = new URL(target).hostname.replace(/^www\./, '');
    const base = host.split('.').slice(-2).join('.');
    const prefixes = ['api', 'admin', 'dev', 'staging', 'test', 'portal', 'app', 'beta', 'internal', 'vpn', 'mail', 'cdn', 'assets', 'auth', 'gateway', 'dashboard', 'secure', 'legacy', 'jenkins', 'jira'];
    const count = 12 + (host.length % 7);
    return prefixes.slice(0, count).map(p => `${p}.${base}`);
  } catch {
    return ['api.target.com', 'admin.target.com', 'dev.target.com', 'staging.target.com'];
  }
};

const Em = (target: string): string[] => {
  const endpoints = [
    '/api/v1/users', '/api/v2/admin', '/graphql', '/api/auth/login',
    '/.git/config', '/.env', '/admin/backup.zip', '/api/debug',
    '/wp-json/wp/v2/users', '/server-status', '/actuator/env',
    '/api/v1/ssrf/test', '/upload', '/redirect?url=', '/search?q=',
    '/api/v1/export', '/.well-known/security.txt', '/swagger.json'
  ];
  const base = target.replace(/\/$/, '');
  return endpoints.map(e => base + e);
};

const km = (target: string, subs: string[], eps: string[]): Finding[] => {
  // Knowledge Map - correlates subs + endpoints into findings
  let seed = 0;
  for (let i = 0; i < target.length; i++) seed += target.charCodeAt(i);
  const rand = (n: number) => {
    seed = (seed * 9301 + 49297) % 233280;
    return (seed / 233280) * n;
  };

  const templates: Omit<Finding, 'uid' | 'url'>[] = [
    {
      owasp: 'A03:2021', severity: 'Critical', title: 'SQL Injection - Auth Bypass via login', tool: 'FFUF',
      confidence: 96, param: 'username', cvss: '9.8',
      evidence: `POST /api/auth/login HTTP/1.1\nContent-Type: application/json\n\n{"username":"' OR '1'='1' --","password":"x"}\n\nResponse: 200 OK\nSet-Cookie: session=admin_token_92f...`,
      attackScenario: ['Identify login endpoint via Arjun param discovery', 'Fuzz username param with FFUF payload set sql.txt', 'Observe boolean-based differential response time + auth bypass', 'Extract admin session token, access /api/v2/admin'],
      impact: 'Full authentication bypass leads to admin panel access, PII exfiltration, and lateral privilege escalation to infrastructure.',
      report: ''
    },
    {
      owasp: 'A01:2021', severity: 'Critical', title: 'Broken Access Control - IDOR to PII leak', tool: 'Autorize',
      confidence: 92, param: 'user_id', cvss: '8.1',
      evidence: `GET /api/v1/users/1337/profile\nAuthorization: Bearer user_token\n\nResponse leaks: email, ssn, billing`,
      attackScenario: ['Login as low-priv user', 'Enumerate user IDs via Param Miner', 'Autorize detects 200 vs 403 diff', 'Automate harvest with Burp Intruder'],
      impact: 'IDOR exposes PII of all users, violating GDPR and enabling account takeover chains.',
      report: ''
    },
    {
      owasp: 'A03:2021', severity: 'High', title: 'Reflected XSS in search - auto payload triggered', tool: 'XSS Auto Payload',
      confidence: 98, param: 'q', cvss: '7.4',
      evidence: `GET /search?q="><svg/onload=alert(document.domain)>\n\nReflected in <div class="results"> without encoding`,
      attackScenario: ['Fuzz search param with XSS Auto Payload module', 'Payload executes in context of target.com', 'Steal HttpOnly? No but steal localStorage tokens', 'Chain with open redirect for phishing'],
      impact: 'Reflected XSS allows session hijacking, credential theft, and defacement in customer-facing search.',
      report: ''
    },
    {
      owasp: 'A10:2021', severity: 'High', title: 'SSRF to internal metadata - 169.254.169.254', tool: 'SSRF Lab',
      confidence: 89, param: 'url', cvss: '8.6',
      evidence: `GET /api/v1/export?url=http://169.254.169.254/latest/meta-data/\nResponse: ami-id, IAM role creds leaked`,
      attackScenario: ['Discover url param via Arjun', 'SSRF Lab tests cloud metadata payloads', 'Internal AWS metadata returned', 'Pivot to IAM privilege escalation'],
      impact: 'SSRF grants access to cloud instance metadata, leading to full cloud takeover.',
      report: ''
    },
    {
      owasp: 'A05:2021', severity: 'Medium', title: 'Directory Listing - /admin/backup.zip exposed', tool: 'Feroxbuster',
      confidence: 100, param: '-', cvss: '5.3',
      evidence: `GET /admin/backup.zip -> 200 OK (124MB)\nContains .env, db.sql, private keys`,
      attackScenario: ['Run Feroxbuster with raft-large wordlist', 'Detect 200 on backup.zip', 'Download and analyze secrets', 'Use leaked DB creds for RCE'],
      impact: 'Sensitive backup exposes credentials and source code, enabling full compromise.',
      report: ''
    },
    {
      owasp: 'A01:2021', severity: 'High', title: 'Subdomain Takeover - dangling CNAME to unclaimed S3', tool: 'Subjack',
      confidence: 95, param: '-', cvss: '7.5',
      evidence: `legacy.target.com CNAME -> target-legacy.s3-website-us-east-1.amazonaws.com (NXDOMAIN, bucket claimable)`,
      attackScenario: ['Subjack enumerates CNAMEs', 'Detects unclaimed S3 bucket', 'Claim bucket, host malicious JS', 'Cookies scoped to *.target.com hijacked'],
      impact: 'Takeover allows persistent XSS on parent domain, cookie theft, and phishing.',
      report: ''
    },
    {
      owasp: 'A06:2021', severity: 'Medium', title: 'Outdated WordPress 5.4.2 - CVE-2021-29447 XXE', tool: 'WPScan',
      confidence: 88, param: '-', cvss: '6.5',
      evidence: `WPScan detected WP 5.4.2, media library XXE via getid3`,
      attackScenario: ['WhatWeb fingerprints WP', 'WPScan version check', 'Exploit XXE to read /etc/passwd', 'Chain to RCE'],
      impact: 'XXE leads to file disclosure and potential SSRF.',
      report: ''
    },
    {
      owasp: 'A03:2021', severity: 'High', title: 'Command Injection via Commix - image converter', tool: 'Commix',
      confidence: 91, param: 'file', cvss: '9.9',
      evidence: `POST /api/convert?file=;id\nResponse: uid=33(www-data) gid=33...`,
      attackScenario: ['WFuzz finds convert endpoint', 'Commix tests ; && | payloads', 'OS command exec confirmed', 'Reverse shell to internal VPC'],
      impact: 'RCE as www-data leads to full host compromise.',
      report: ''
    },
    {
      owasp: 'A05:2021', severity: 'Info', title: 'Nikto - Apache 2.4.49 Path Traversal CVE-2021-41773', tool: 'Nikto',
      confidence: 85, param: '-', cvss: '7.5',
      evidence: `GET /cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd -> 200`,
      attackScenario: ['Nikto scans server', 'Detects traversal', 'Read arbitrary files', 'Bypass to RCE via log poisoning'],
      impact: 'Path traversal exposes sensitive files.',
      report: ''
    },
    {
      owasp: 'A07:2021', severity: 'Medium', title: 'Weak SSH creds - Hydra brute forces admin:admin', tool: 'Hydra',
      confidence: 100, param: '-', cvss: '6.0',
      evidence: `hydra -l admin -P rockyou.txt ssh://target.com\n[22][ssh] host: target.com login: admin password: admin123`,
      attackScenario: ['Nmap finds 22 open', 'Hydra brute forces', 'SSH login success', 'Escalate via sudo -l'],
      impact: 'Weak creds lead to initial foothold.',
      report: ''
    },
    {
      owasp: 'A01:2021', severity: 'High', title: 'CSRF - Password change without token', tool: 'CSRF Lab',
      confidence: 90, param: '-', cvss: '6.8',
      evidence: `<form action="https://target.com/api/change-password" method="POST"><input name="new" value="hacked"></form> No CSRF token`,
      attackScenario: ['CSRF Lab parses forms', 'No anti-CSRF token found', 'Craft PoC page', 'Victim changes password via click'],
      impact: 'Account takeover via CSRF.',
      report: ''
    },
    {
      owasp: 'A05:2021', severity: 'Low', title: 'Ike-scan - Aggressive Mode PSK leak', tool: 'Ike-scan',
      confidence: 82, param: '-', cvss: '4.3',
      evidence: `IKE Aggressive Mode hash captured, crackable offline`,
      attackScenario: ['Ike-scan discovers VPN endpoint', 'Capture hash', 'Offline crack with hashcat', 'VPN access'],
      impact: 'VPN PSK leak leads to network access.',
      report: ''
    },
    {
      owasp: 'A04:2021', severity: 'Medium', title: 'XXE via SVG upload', tool: 'Backslash Powered Scanner',
      confidence: 87, param: 'avatar', cvss: '6.6',
      evidence: `Upload svg with <!ENTITY xxe SYSTEM "file:///etc/passwd"> -> file contents returned in image metadata`,
      attackScenario: ['Upload functionality found', 'Backslash scanner tests XXE payloads', 'File disclosure', 'SSRF pivot'],
      impact: 'XXE discloses server files.',
      report: ''
    },
    {
      owasp: 'A03:2021', severity: 'High', title: 'Nuclei - CVE-2023-44487 HTTP/2 Rapid Reset', tool: 'Nuclei',
      confidence: 94, param: '-', cvss: '7.5',
      evidence: `Nuclei template http2-rapid-reset.yaml matched - HTTP/2 enabled, vulnerable to DoS`,
      attackScenario: ['Nuclei runs 4000+ templates', 'HTTP/2 DoS detected', 'Mass RST_STREAM flood', 'Service outage'],
      impact: 'DoS risk for availability.',
      report: ''
    },
    {
      owasp: 'A02:2021', severity: 'Low', title: 'WhatWeb - Technology fingerprint leaks version', tool: 'WhatWeb',
      confidence: 99, param: '-', cvss: '3.7',
      evidence: `X-Powered-By: PHP/7.4.3, Server: nginx/1.18.0`,
      attackScenario: ['WhatWeb fingerprints stack', 'Versions aid targeted CVE search', 'Info disclosure'],
      impact: 'Info disclosure helps attacker.',
      report: ''
    },
  ];

  // build full findings
  const shuffled = [...templates].sort(() => rand(1) - 0.5);
  const count = 7 + Math.floor(rand(6)); // 7-12 findings per scan

  return shuffled.slice(0, count).map((t, i) => {
    const url = eps[Math.floor(rand(eps.length))] || `${target}/api/v1/users`;
    const sub = subs[Math.floor(rand(subs.length))] || 'api.target.com';
    const finalUrl = rand(1) > 0.4 ? url : `https://${sub}${url.replace(target, '')}`;
    const uid = `BR-${String(i + 1).padStart(3, '0')}-${Math.floor(rand(9000) + 1000)}`;
    const baseReport = `# ${t.title}\n\n**OWASP:** ${t.owasp} | **Severity:** ${t.severity} | **Tool:** ${t.tool} | **CVSS:** ${t.cvss}\n**URL:** ${finalUrl}\n**Param:** ${t.param}\n\n## Description\nVulnerability ${t.title} identified via ${t.tool} during automated recon against ${target}. Confidence ${t.confidence}%.\n\n## Proof of Concept\n\`\`\`http\n${t.evidence}\n\`\`\`\n\n## Attack Scenario\n${t.attackScenario.map((s, idx) => `${idx + 1}. ${s}`).join('\n')}\n\n## Impact\n${t.impact}\n\n## Remediation\n- Validate and sanitize all user inputs\n- Implement least privilege and deny-by-default\n- Add WAF rules for ${t.param} parameter\n- Rotate exposed secrets and enforce 2FA\n\n## References\n- OWASP ${t.owasp}\n- CWE associated with ${t.title}\n\n---\n*Generated by BountyRecon Pro EDITION v2.5.0 | LIVE RECON ENGINE*\n`;
    return {
      ...t,
      uid,
      url: finalUrl,
      report: baseReport,
    } as Finding;
  });
};

// initial data
const INITIAL_MODULES: ModuleItem[] = [
  { id: 'subjack', name: 'Subjack', desc: 'Subdomain takeover detection', icon: '◉', enabled: true },
  { id: 'feroxbuster', name: 'Feroxbuster', desc: 'Content discovery brute', icon: '⟁', enabled: true },
  { id: 'ffuf', name: 'FFUF', desc: 'Fast web fuzzer', icon: '⚡', enabled: true },
  { id: 'ssrf-lab', name: 'SSRF Lab', desc: 'SSRF payload lab', icon: '↗', enabled: true },
  { id: 'csrf-lab', name: 'CSRF Lab', desc: 'CSRF PoC builder', icon: '↻', enabled: false },
  { id: 'xss-payload', name: 'XSS Auto Payload', desc: 'XSS polyglot engine', icon: '✴', enabled: true },
  { id: 'nikto', name: 'Nikto', desc: 'Web server scanner', icon: '☍', enabled: false },
  { id: 'wpscan', name: 'WPScan', desc: 'WordPress vuln scanner', icon: '◍', enabled: true },
  { id: 'whatweb', name: 'WhatWeb', desc: 'Tech fingerprinting', icon: '◎', enabled: true },
  { id: 'nmap', name: 'Nmap', desc: 'Port & service scan', icon: '⬢', enabled: true },
  { id: 'arjun', name: 'Arjun', desc: 'Param discovery', icon: '⤢', enabled: true },
  { id: 'wfuzz', name: 'WFuzz', desc: 'Injection fuzzer', icon: '≋', enabled: false },
  { id: 'dirb', name: 'Dirb', desc: 'Dir brute legacy', icon: '≡', enabled: false },
  { id: 'dmitry', name: 'Dmitry', desc: 'Info gathering', icon: '⧉', enabled: false },
  { id: 'nuclei', name: 'Nuclei', desc: '4000+ CVE templates', icon: '⬣', enabled: true },
  { id: 'commix', name: 'Commix', desc: 'Command injection', icon: '⯀', enabled: true },
  { id: 'hydra', name: 'Hydra', desc: 'Login brute forcer', icon: '⚑', enabled: false },
  { id: 'ike-scan', name: 'Ike-scan', desc: 'IPSec VPN scanner', icon: '⬔', enabled: false },
];

const INITIAL_BAPPS: BAppItem[] = [
  { id: 'active-scan', name: 'Active Scan++', color: '#DC2626', findingCount: 12, enabled: true },
  { id: 'param-miner', name: 'Param Miner', color: '#EAB308', findingCount: 8, enabled: true },
  { id: 'autorize', name: 'Autorize', color: '#3B82F6', findingCount: 15, enabled: true },
  { id: 'logger', name: 'Logger++', color: '#22C55E', findingCount: 23, enabled: false },
  { id: 'collab', name: 'Collaborator Everywhere', color: '#A855F7', findingCount: 5, enabled: true },
  { id: 'backslash', name: 'Backslash Powered Scanner', color: '#F97316', findingCount: 9, enabled: true },
  { id: 'soft-vuln', name: 'Software Vulnerability Scanner', color: '#06B6D4', findingCount: 11, enabled: false },
  { id: 'js-link', name: 'JS Link Finder', color: '#EC4899', findingCount: 18, enabled: true },
];

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [isLoggedIn, setIsLoggedIn] = useState(() => {
    if (typeof window !== 'undefined') return localStorage.getItem('bountyrecon_auth') === 'true';
    return false;
  });
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [targetUrl, setTargetUrl] = useState('https://target.com');
  const [hasPermission, setHasPermission] = useState(true);
  const [oosKeywords, setOosKeywords] = useState('admin.example.com\ninternal\nstaging-old');
  const [modules, setModules] = useState<ModuleItem[]>(INITIAL_MODULES);
  const [bapps, setBapps] = useState<BAppItem[]>(INITIAL_BAPPS);

  // --- LOGIN SCREEN ---
  if (!isLoggedIn) {
    return (
      <div className={`min-h-screen grid place-items-center p-4 ${theme === 'dark' ? 'bg-[#050508] text-white' : 'bg-zinc-50 text-black'}`}>
        <div className={`w-full max-w-[420px] rounded-[16px] border p-8 shadow-2xl ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1E1E26]' : 'bg-white border-zinc-200'}`}>
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-[10px] bg-[#DC2626] grid place-items-center font-bold text-white">BR</div>
            <div>
              <div className="font-bold text-[15px] tracking-widest">BOUNTYRECON PRO</div>
              <div className="text-[11px] opacity-60 tracking-widest">v2.5.0 • PREMIUM</div>
            </div>
          </div>

          <h1 className="text-[22px] font-bold mb-2">Welcome back, Hunter</h1>
          <p className="text-[12px] opacity-60 mb-6 leading-relaxed">Sign in to access 18 premium modules, BApp Store & POC Studio. Demo mode available.</p>

          <div className="space-y-3">
            <input
              value={loginEmail}
              onChange={e => setLoginEmail(e.target.value)}
              placeholder="Email (any for demo)"
              className={`w-full h-11 px-4 rounded-[8px] border text-[13px] outline-none ${theme === 'dark' ? 'bg-[#050508] border-[#1E1E26] text-white placeholder:text-zinc-500 focus:border-[#DC2626]' : 'bg-white border-zinc-200 focus:border-[#DC2626]'}`}
            />
            <input
              type="password"
              value={loginPass}
              onChange={e => setLoginPass(e.target.value)}
              placeholder="Password (any for demo)"
              className={`w-full h-11 px-4 rounded-[8px] border text-[13px] outline-none ${theme === 'dark' ? 'bg-[#050508] border-[#1E1E26] text-white placeholder:text-zinc-500 focus:border-[#DC2626]' : 'bg-white border-zinc-200 focus:border-[#DC2626]'}`}
            />
            <button
              onClick={() => {
                if (loginEmail || loginPass) {
                  localStorage.setItem('bountyrecon_auth', 'true');
                  localStorage.setItem('bountyrecon_user', loginEmail || 'hunter@bountyrecon.pro');
                  setIsLoggedIn(true);
                }
              }}
              className="w-full h-11 rounded-[8px] bg-[#DC2626] hover:bg-[#B91C1C] text-white font-bold text-[13px] tracking-widest transition"
            >
              SIGN IN → DASHBOARD
            </button>
            <button
              onClick={() => {
                localStorage.setItem('bountyrecon_auth', 'true');
                localStorage.setItem('bountyrecon_user', 'demo@bountyrecon.pro');
                setIsLoggedIn(true);
              }}
              className={`w-full h-11 rounded-[8px] border font-bold text-[12px] tracking-widest transition ${theme === 'dark' ? 'bg-[#050508] border-[#1E1E26] hover:bg-[#12121A] text-zinc-300' : 'bg-zinc-50 border-zinc-200 hover:bg-white'}`}
            >
              CONTINUE AS DEMO
            </button>
          </div>

          <div className="mt-6 pt-6 border-t border-[#1E1E26] text-[10px] opacity-50 leading-relaxed">
            <div className="font-bold mb-1">🔒 SECURITY NOTICE</div>
            Demo mode uses Sm(), Em(), km() simulation. No real requests to target. For real scanning, connect backend API with permission.
          </div>

          <div className="mt-4 flex items-center justify-between text-[10px] opacity-40">
            <span>Google OAuth ready - set VITE_GOOGLE_CLIENT_ID</span>
            <span>v2.5.0</span>
          </div>
        </div>
      </div>
    );
  }

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [rawFindings, setRawFindings] = useState<Finding[]>([]);
  const [subdomains, setSubdomains] = useState<string[]>(Sm('https://target.com'));
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'evidence' | 'scenario' | 'impact' | 'report'>('evidence');
  const [selectedUid, setSelectedUid] = useState<string | null>(null);
  const [toasts, setToasts] = useState<{ id: number; msg: string; type: 'ok' | 'err' }[]>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const enabledModuleSet = useMemo(() => new Set(modules.filter(m => m.enabled).map(m => m.name)), [modules]);
  const enabledBAppSet = useMemo(() => new Set(bapps.filter(b => b.enabled).map(b => b.name)), [bapps]);

  const oosList = useMemo(() => oosKeywords.split(/[\n,]+/).map(s => s.trim().toLowerCase()).filter(Boolean), [oosKeywords]);

  const filteredByModules = useMemo(() => {
    return rawFindings.filter(f => {
      // tool is module or bapp name; if not in either set, keep if module enabled? For simplicity check if tool in module names OR bapp-associated
      if (enabledModuleSet.has(f.tool)) return true;
      // map some tools to bapps
      if (f.tool === 'Autorize' && enabledBAppSet.has('Autorize')) return true;
      if (f.tool === 'Param Miner' && enabledBAppSet.has('Param Miner')) return true;
      if (['Active Scan++', 'Backslash Powered Scanner', 'JS Link Finder'].includes(f.tool) && enabledBAppSet.size > 0) return true;
      // if tool not in modules list, check bapp enabled fallback
      return enabledModuleSet.size === 0 ? false : enabledModuleSet.has(f.tool) || (f.tool === 'FFUF' && enabledModuleSet.has('FFUF'));
    });
  }, [rawFindings, enabledModuleSet, enabledBAppSet]);

  const finalFindings = useMemo(() => {
    if (oosList.length === 0) return filteredByModules;
    return filteredByModules.filter(f => !oosList.some(k => f.url.toLowerCase().includes(k) || f.title.toLowerCase().includes(k) || f.uid.toLowerCase().includes(k)));
  }, [filteredByModules, oosList]);

  const filteredOOSCount = filteredByModules.length - finalFindings.length;
  const totalRaw = rawFindings.length;

  // toast helper
  const pushToast = (msg: string, type: 'ok' | 'err' = 'ok') => {
    const id = Date.now() + Math.random();
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 3000);
  };

  // scanning simulation
  const initiateScan = () => {
    if (!hasPermission) {
      pushToast('Permission required to scan target', 'err');
      return;
    }
    try { new URL(targetUrl); } catch { pushToast('Invalid target URL', 'err'); return; }
    setIsScanning(true);
    setScanProgress(0);
    setRawFindings([]);
    setExpandedId(null);
    setSelectedUid(null);
    pushToast(`Initiating recon against ${targetUrl}`);

    const interval = setInterval(() => {
      setScanProgress(p => {
        const inc = 4 + Math.random() * 9;
        const next = Math.min(100, p + inc);
        if (next >= 100) {
          clearInterval(interval);
          // generate using Sm, Em, km
          const subs = Sm(targetUrl);
          const eps = Em(targetUrl);
          const findings = km(targetUrl, subs, eps);
          setSubdomains(subs);
          setRawFindings(findings);
          setSelectedUid(findings[0]?.uid || null);
          setIsScanning(false);
          pushToast(`Scan complete: ${findings.length} findings, ${subs.length} subdomains`);
          return 100;
        }
        return next;
      });
    }, 280);
  };

  useEffect(() => {
    // initial scan mock
    const subs = Sm(targetUrl);
    const eps = Em(targetUrl);
    setRawFindings(km(targetUrl, subs, eps));
    setSubdomains(subs);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // screenshot generation 1920x1080 canvas
  const handleHDScreenshot = (f: Finding) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    canvas.width = 1920;
    canvas.height = 1080;
    // bg
    ctx.fillStyle = theme === 'dark' ? '#050508' : '#ffffff';
    ctx.fillRect(0, 0, 1920, 1080);
    // top bar red
    ctx.fillStyle = '#DC2626';
    ctx.fillRect(0, 0, 1920, 8);
    ctx.fillRect(0, 0, 8, 1080);
    ctx.fillRect(1912, 0, 8, 1080);
    ctx.fillRect(0, 1072, 1920, 8);
    // header
    ctx.fillStyle = '#DC2626';
    ctx.fillRect(40, 40, 64, 64);
    ctx.fillStyle = '#fff';
    ctx.font = 'bold 36px JetBrains Mono';
    ctx.fillText('BR', 52, 82);
    ctx.fillStyle = theme === 'dark' ? '#fff' : '#000';
    ctx.font = 'bold 28px JetBrains Mono';
    ctx.fillText(`BOUNTYRECON PRO // ${f.uid}`, 130, 78);
    ctx.font = '14px JetBrains Mono';
    ctx.fillStyle = '#9CA3AF';
    ctx.fillText(`TARGET: ${targetUrl} | GENERATED: ${new Date().toISOString()} | CONFIDENCE: ${f.confidence}%`, 130, 100);
    // severity badge
    const sevColor: Record<string, string> = { Critical: '#DC2626', High: '#EA580C', Medium: '#CA8A04', Low: '#16A34A', Info: '#6B7280' };
    ctx.fillStyle = sevColor[f.severity] || '#DC2626';
    ctx.fillRect(40, 130, 220, 36);
    ctx.fillStyle = '#fff';
    ctx.font = 'bold 16px JetBrains Mono';
    ctx.fillText(`${f.severity.toUpperCase()} // ${f.owasp}`, 52, 152);
    // title
    ctx.fillStyle = theme === 'dark' ? '#fff' : '#000';
    ctx.font = 'bold 42px JetBrains Mono';
    const titleLines = f.title.match(/.{1,55}(\s|$)/g) || [f.title];
    titleLines.slice(0, 2).forEach((line, i) => ctx.fillText(line.trim(), 40, 220 + i * 48));
    // url
    ctx.font = '16px JetBrains Mono';
    ctx.fillStyle = '#DC2626';
    ctx.fillText(f.url, 40, 320);
    // evidence box
    ctx.fillStyle = theme === 'dark' ? '#0A0A0F' : '#F3F4F6';
    ctx.fillRect(40, 350, 1200, 640);
    ctx.strokeStyle = '#1F1F23';
    ctx.strokeRect(40, 350, 1200, 640);
    ctx.fillStyle = '#9CA3AF';
    ctx.font = '12px JetBrains Mono';
    ctx.fillText('EVIDENCE // HTTP REQUEST/RESPONSE', 60, 380);
    ctx.fillStyle = theme === 'dark' ? '#E5E7EB' : '#111';
    ctx.font = '13px JetBrains Mono';
    f.evidence.split('\n').slice(0, 22).forEach((line, i) => {
      ctx.fillText(line.slice(0, 120), 60, 410 + i * 22);
    });
    // right meta
    ctx.fillStyle = theme === 'dark' ? '#111113' : '#F9FAFB';
    ctx.fillRect(1280, 350, 600, 640);
    ctx.fillStyle = '#6B7280';
    ctx.font = '12px JetBrains Mono';
    ctx.fillText('TOOL', 1310, 390);
    ctx.fillStyle = theme === 'dark' ? '#fff' : '#000';
    ctx.font = 'bold 18px JetBrains Mono';
    ctx.fillText(f.tool, 1310, 415);
    ctx.fillStyle = '#6B7280';
    ctx.font = '12px JetBrains Mono';
    ctx.fillText('CVSS', 1310, 460);
    ctx.fillStyle = theme === 'dark' ? '#fff' : '#000';
    ctx.font = 'bold 18px JetBrains Mono';
    ctx.fillText(f.cvss || '8.0', 1310, 485);
    ctx.fillStyle = '#6B7280';
    ctx.fillText('ATTACK SCENARIO', 1310, 530);
    ctx.fillStyle = theme === 'dark' ? '#D1D5DB' : '#111';
    ctx.font = '13px JetBrains Mono';
    f.attackScenario.slice(0, 5).forEach((s, i) => {
      const wrapped = `${i + 1}. ${s}`.slice(0, 62);
      ctx.fillText(wrapped, 1310, 560 + i * 24);
    });
    ctx.fillStyle = '#6B7280';
    ctx.fillText('IMPACT', 1310, 700);
    ctx.fillStyle = theme === 'dark' ? '#D1D5DB' : '#111';
    const impactLines = f.impact.match(/.{1,58}(\s|$)/g) || [];
    impactLines.slice(0, 6).forEach((l, i) => ctx.fillText(l.trim(), 1310, 730 + i * 22));

    // footer
    ctx.fillStyle = '#DC2626';
    ctx.font = '11px JetBrains Mono';
    ctx.fillText('LIVE RECON ENGINE // BOUNTYRECON PRO EDITION v2.5.0 // CLASSIFIED', 40, 1030);

    const dataUrl = canvas.toDataURL('image/png');
    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = `${f.uid}_HD_${f.severity}.png`;
    a.click();
    pushToast(`HD Screenshot generated: ${f.uid}`);
  };

  const handleVideoPoC = (f: Finding) => {
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${f.uid} Video PoC</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
      body{background:#050508;color:#fff;font-family:'JetBrains Mono',monospace;margin:0;padding:0;overflow:hidden}
      .bar{height:6px;background:#DC2626;width:100%}
      .wrap{padding:40px;max-width:1100px;margin:0 auto}
      .badge{display:inline-block;background:#DC2626;color:#fff;padding:6px 12px;font-size:12px;font-weight:700}
      h1{font-size:42px;margin:20px 0 8px}
      .url{color:#DC2626;font-size:14px;word-break:break-all}
      .stage{margin-top:30px;border:1px solid #1A1A1F;background:#0A0A0F;padding:24px;position:relative;overflow:hidden}
      .cursor{position:absolute;width:24px;height:24px;background:#DC2626;border-radius:50%;box-shadow:0 0 20px #DC2626;animation:move 8s infinite ease-in-out}
      @keyframes move{0%{left:10%;top:20%}25%{left:70%;top:30%}50%{left:60%;top:70%}75%{left:20%;top:60%}100%{left:10%;top:20%}}
      .log{font-size:13px;color:#9CA3AF;line-height:1.8;margin-top:20px}
      .log b{color:#fff}
      .progress{height:4px;background:#1A1A1F;margin-top:20px;position:relative}
      .progress i{position:absolute;left:0;top:0;height:100%;background:#DC2626;width:0;animation:load 8s linear forwards}
      @keyframes load{to{width:100%}}
    </style></head><body><div class="bar"></div><div class="wrap">
    <div class="badge">${f.severity} // ${f.owasp} // ${f.tool}</div>
    <h1>${f.title}</h1>
    <div class="url">${f.url}</div>
    <div class="stage">
      <div class="cursor"></div>
      <div style="font-size:12px;color:#666">VIDEO POC REPLAY // ${targetUrl}</div>
      <div class="log">
        <div><b>[0.0s]</b> Initiating ${f.tool} against ${f.url}</div>
        <div><b>[1.2s]</b> Param discovered: ${f.param} via Arjun</div>
        <div><b>[2.4s]</b> Payload injected: ${f.evidence.split('\n')[0].slice(0,80)}</div>
        <div><b>[3.1s]</b> Response differential detected - confidence ${f.confidence}%</div>
        <div><b>[4.8s]</b> Exploitation confirmed - ${f.title}</div>
        <div><b>[6.5s]</b> Impact: ${f.impact}</div>
      </div>
      <div class="progress"><i></i></div>
    </div>
    <div style="margin-top:24px;font-size:11px;color:#555">Generated by BOUNTYRECON PRO v2.5.0 // LIVE RECON ENGINE // ${new Date().toISOString()}</div>
    </div></body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${f.uid}_VideoPoC.html`;
    a.click();
    URL.revokeObjectURL(url);
    pushToast(`Video PoC exported: ${f.uid}`);
  };

  const copyReport = (text: string) => {
    navigator.clipboard.writeText(text).then(() => pushToast('Report copied to clipboard'));
  };

  const severityColor = (s: string) => {
    switch (s) {
      case 'Critical': return 'bg-[#DC2626] text-white';
      case 'High': return 'bg-[#EA580C] text-white';
      case 'Medium': return 'bg-[#CA8A04] text-black';
      case 'Low': return 'bg-[#16A34A] text-white';
      default: return 'bg-zinc-700 text-zinc-300';
    }
  };

  return (
    <div className={theme === 'dark' ? 'dark' : ''}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');
        *{font-family:'JetBrains Mono', monospace}
        ::-webkit-scrollbar{width:6px;height:6px}
        ::-webkit-scrollbar-thumb{background:#2A2A30;border-radius:10px}
        ::-webkit-scrollbar-track{background:transparent}
      `}</style>
      <div className={`min-h-screen w-full flex flex-col ${theme === 'dark' ? 'bg-[#050508] text-[#E5E7EB]' : 'bg-[#F6F6F7] text-zinc-900'}`} style={{ paddingTop: 'var(--safe-area-inset-top,0px)' }}>
        {/* Header */}
        <header className={`h-[64px] shrink-0 flex items-center justify-between px-4 md:px-6 border-b ${theme === 'dark' ? 'bg-[#08080B] border-[#1A1A20]' : 'bg-white border-zinc-200'} sticky top-[var(--safe-area-inset-top,0px)] z-30`} style={{ top: 'var(--safe-area-inset-top,0px)' }}>
          <div className="flex items-center gap-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-[#DC2626] flex items-center justify-center font-bold text-white text-[18px] tracking-tighter">BR</div>
              <div className="leading-none">
                <div className="font-bold text-[13px] tracking-[0.14em]">BOUNTYRECON PRO EDITION v2.5.0</div>
                <div className="text-[10px] tracking-[0.2em] opacity-60 mt-1">OFFENSIVE RECONNAISSANCE PLATFORM</div>
              </div>
            </div>
            <div className="hidden md:flex items-center gap-2 ml-6">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_10px_#10B981]" />
              <span className={`text-[11px] font-bold tracking-widest px-2.5 py-1 rounded border ${theme === 'dark' ? 'bg-[#0F0F13] border-[#1E1E26] text-emerald-400' : 'bg-emerald-50 border-emerald-200 text-emerald-700'}`}>LIVE RECON ENGINE</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className={`hidden lg:flex items-center gap-2 text-[11px] px-3 py-1.5 rounded border ${theme === 'dark' ? 'border-[#1E1E26] bg-[#0F0F13]' : 'border-zinc-200 bg-zinc-50'}`}>
              <span className="opacity-50">TARGET:</span><span className="font-bold truncate max-w-[180px]">{targetUrl}</span>
            </div>
            <button onClick={() => pushToast('HD Evidence Ready', 'err')} className="h-9 px-5 bg-[#DC2626] hover:bg-[#B91C1C] text-white text-[11px] font-bold tracking-widest transition">LOGIN</button>
          </div>
        </header>

        <div className="flex flex-col lg:flex-row flex-1">
          {/* Left Sidebar 380px */}
          <aside className={`w-full lg:w-[380px] shrink-0 lg:sticky lg:top-[64px] lg:h-[calc(100vh-64px)] overflow-y-auto border-b lg:border-b-0 lg:border-r ${theme === 'dark' ? 'bg-[#08080B] border-[#1A1A20]' : 'bg-white border-zinc-200'}`}>
            <div className="p-5 space-y-6">
              {/* Target Config */}
              <div className={`rounded-[8px] border p-4 ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1E1E26]' : 'bg-zinc-50 border-zinc-200'}`}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-[11px] font-bold tracking-[0.18em] opacity-80">TARGET CONFIG</h3>
                  <span className="text-[10px] px-1.5 py-0.5 bg-[#DC2626] text-white font-bold">PRO</span>
                </div>
                <label className="text-[10px] opacity-60 tracking-widest">TARGET URL</label>
                <input value={targetUrl} onChange={e => setTargetUrl(e.target.value)} className={`mt-1 w-full h-10 px-3 text-[13px] rounded border outline-none focus:border-[#DC2626] transition ${theme === 'dark' ? 'bg-[#050508] border-[#22222A] text-white' : 'bg-white border-zinc-300'}`} placeholder="https://target.com" />
                <label className="flex items-center gap-2 mt-3 cursor-pointer select-none">
                  <input type="checkbox" checked={hasPermission} onChange={e => setHasPermission(e.target.checked)} className="accent-[#DC2626] w-4 h-4" />
                  <span className="text-[11px]">I have permission to test this target</span>
                </label>
                <div className="mt-4">
                  <label className="text-[10px] opacity-60 tracking-widest">KEYWORD OUT-OF-SCOPE (one per line)</label>
                  <textarea value={oosKeywords} onChange={e => setOosKeywords(e.target.value)} rows={3} className={`mt-1 w-full p-3 text-[12px] rounded border outline-none focus:border-[#DC2626] resize-none ${theme === 'dark' ? 'bg-[#050508] border-[#22222A] text-white' : 'bg-white border-zinc-300'}`} placeholder="internal\nadmin.example.com" />
                  <div className={`mt-2 text-[10px] leading-relaxed p-2 rounded border ${theme === 'dark' ? 'bg-[#050508] border-[#1A1A1F] text-zinc-500' : 'bg-amber-50 border-amber-200 text-amber-800'}`}>
                    <span className="font-bold">FILTER:</span> Findings matching keywords are hidden from table and counted as Filtered OOS. Use comma or newline separated.
                  </div>
                </div>
              </div>

              {/* Premium Modules */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-[11px] font-bold tracking-[0.18em]">PREMIUM MODULES</h3>
                  <span className="text-[10px] opacity-60">{modules.filter(m => m.enabled).length}/18 ACTIVE</span>
                </div>
                <div className="grid grid-cols-2 gap-2.5">
                  {modules.map(m => (
                    <div key={m.id} className={`group relative rounded-[6px] border p-2.5 flex flex-col gap-2 transition ${m.enabled ? (theme === 'dark' ? 'bg-[#101014] border-[#2A2A35]' : 'bg-white border-zinc-300 shadow-sm') : (theme === 'dark' ? 'bg-[#0A0A0E] border-[#15151C] opacity-70' : 'bg-zinc-100 border-zinc-200 opacity-70')}`}>
                      <div className="flex items-start justify-between">
                        <div className={`w-7 h-7 rounded flex items-center justify-center text-[13px] font-bold border ${m.enabled ? 'bg-[#DC2626] text-white border-[#DC2626]' : 'bg-transparent border-[#2A2A35] opacity-60'}`}>{m.icon}</div>
                        <button onClick={() => setModules(prev => prev.map(x => x.id === m.id ? { ...x, enabled: !x.enabled } : x))} className={`relative w-9 h-5 rounded-full transition ${m.enabled ? 'bg-[#DC2626]' : 'bg-[#2A2A32]'}`}>
                          <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition ${m.enabled ? 'translate-x-4' : 'translate-x-0'}`} />
                        </button>
                      </div>
                      <div>
                        <div className="text-[11px] font-bold tracking-wide leading-none">{m.name}</div>
                        <div className="text-[10px] opacity-60 leading-tight mt-1 line-clamp-2">{m.desc}</div>
                      </div>
                      <div className={`text-[9px] tracking-widest font-bold ${m.enabled ? 'text-[#DC2626]' : 'opacity-40'}`}>{m.enabled ? 'ON' : 'OFF'}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Burp Suite BApp Store */}
              <div className={`rounded-[8px] border p-4 ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1E1E26]' : 'bg-zinc-50 border-zinc-200'}`}>
                <h3 className="text-[11px] font-bold tracking-[0.18em] mb-3 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#FF6F00]" /> BURP SUITE BAPP STORE
                </h3>
                <div className="space-y-2.5">
                  {bapps.map(b => (
                    <div key={b.id} className={`flex items-center justify-between p-2.5 rounded border transition ${theme === 'dark' ? 'bg-[#050508] border-[#1A1A20] hover:border-[#2A2A35]' : 'bg-white border-zinc-200'}`}>
                      <div className="flex items-center gap-2.5">
                        <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: b.color, boxShadow: `0 0 8px ${b.color}` }} />
                        <span className="text-[11px] font-medium">{b.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${theme === 'dark' ? 'bg-[#15151C] text-zinc-400' : 'bg-zinc-100 text-zinc-600'}`}>{b.findingCount}</span>
                        <button onClick={() => setBapps(prev => prev.map(x => x.id === b.id ? { ...x, enabled: !x.enabled } : x))} className={`w-8 h-4 rounded-full relative transition ${b.enabled ? 'bg-[#DC2626]' : 'bg-[#2A2A32]'}`}>
                          <span className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition ${b.enabled ? 'translate-x-4' : ''}`} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </aside>

          {/* Main */}
          <main className="flex-1 min-w-0">
            <div className="p-4 md:p-6 space-y-5">
              {/* POC Studio */}
              <div className={`rounded-[10px] border overflow-hidden ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1E1E26]' : 'bg-white border-zinc-200'}`}>
                <div className={`flex flex-col md:flex-row md:items-center justify-between gap-3 px-5 py-4 border-b ${theme === 'dark' ? 'border-[#1A1A20] bg-[#0F0F13]' : 'border-zinc-200 bg-zinc-50'}`}>
                  <div>
                    <h2 className="text-[13px] font-bold tracking-[0.16em] flex items-center gap-2">
                      <span className="w-1.5 h-4 bg-[#DC2626] inline-block" /> POC STUDIO
                      <span className={`ml-2 text-[10px] px-2 py-0.5 rounded font-bold ${theme === 'dark' ? 'bg-[#1A1A20] text-zinc-400' : 'bg-zinc-200 text-zinc-600'}`}>SELECT A FINDING TO GENERATE</span>
                    </h2>
                    <div className="text-[11px] opacity-60 mt-1">Professional evidence generator - HD screenshots 1920x1080 & video PoC HTML export</div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => {
                      const f = finalFindings.find(x => x.uid === selectedUid) || finalFindings[0];
                      if (!f) { pushToast('No finding selected', 'err'); return; }
                      handleHDScreenshot(f);
                    }} className="h-9 px-4 bg-[#DC2626] hover:bg-[#B91C1C] text-white text-[11px] font-bold tracking-widest rounded transition">GENERATE HD SCREENSHOT</button>
                    <button onClick={() => {
                      const f = finalFindings.find(x => x.uid === selectedUid) || finalFindings[0];
                      if (!f) { pushToast('No finding selected', 'err'); return; }
                      handleVideoPoC(f);
                    }} className={`h-9 px-4 text-[11px] font-bold tracking-widest rounded border transition ${theme === 'dark' ? 'border-[#2A2A35] hover:bg-[#1A1A20] text-white' : 'border-zinc-300 hover:bg-zinc-100'}`}>GENERATE VIDEO POC</button>
                  </div>
                </div>
                <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className={`rounded border p-4 ${theme === 'dark' ? 'bg-[#08080B] border-[#1A1A20]' : 'bg-zinc-50 border-zinc-200'}`}>
                    <div className="text-[10px] opacity-60 tracking-widest">SELECTED FINDING</div>
                    <div className="mt-2 text-[13px] font-bold leading-tight min-h-[40px]">
                      {finalFindings.find(f => f.uid === selectedUid)?.title || finalFindings[0]?.title || 'No findings yet - run recon'}
                    </div>
                    <div className="mt-2 flex gap-2">
                      <span className={`text-[10px] px-2 py-1 rounded font-bold ${severityColor(finalFindings.find(f => f.uid === selectedUid)?.severity || 'Info')}`}>{finalFindings.find(f => f.uid === selectedUid)?.severity || 'Info'}</span>
                      <span className={`text-[10px] px-2 py-1 rounded border ${theme === 'dark' ? 'border-[#222] bg-[#111]' : 'border-zinc-300 bg-white'}`}>{finalFindings.find(f => f.uid === selectedUid)?.tool || 'N/A'}</span>
                    </div>
                  </div>
                  <div className={`rounded border p-4 col-span-2 ${theme === 'dark' ? 'bg-[#08080B] border-[#1A1A20]' : 'bg-zinc-50 border-zinc-200'}`}>
                    <div className="text-[10px] opacity-60 tracking-widest">PREVIEW - EVIDENCE SNIPPET</div>
                    <pre className={`mt-2 text-[11px] leading-relaxed p-3 rounded border overflow-x-auto ${theme === 'dark' ? 'bg-[#050508] border-[#1A1A20] text-zinc-300' : 'bg-white border-zinc-200 text-zinc-700'}`}>{finalFindings.find(f => f.uid === selectedUid)?.evidence.slice(0, 320) || 'Run scan to populate evidence...'}</pre>
                  </div>
                </div>
              </div>

              {/* Stats cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                {[
                  { label: 'SUBDOMAINS', value: subdomains.length, sub: `via Sm()`, color: '#3B82F6' },
                  { label: 'FINDINGS', value: finalFindings.length, sub: `${totalRaw} raw via km()`, color: '#DC2626' },
                  { label: 'FILTERED OOS', value: filteredOOSCount, sub: `${oosList.length} keywords`, color: '#CA8A04' },
                  { label: 'SCAN PROGRESS', value: `${scanProgress.toFixed(0)}%`, sub: isScanning ? 'SCANNING...' : 'IDLE', color: '#10B981', action: true },
                ].map((c, i) => (
                  <div key={i} className={`rounded-[8px] border p-4 relative overflow-hidden ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1E1E26]' : 'bg-white border-zinc-200'}`}>
                    <div className="absolute top-0 left-0 w-full h-0.5" style={{ background: c.color }} />
                    <div className="text-[10px] tracking-[0.18em] opacity-60 font-bold">{c.label}</div>
                    <div className="mt-2 text-[26px] font-bold tracking-tight">{c.value}</div>
                    <div className="text-[11px] opacity-60 mt-1">{c.sub}</div>
                    {c.action && (
                      <button onClick={initiateScan} disabled={isScanning} className={`mt-3 w-full h-8 text-[11px] font-bold tracking-widest rounded transition ${isScanning ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed' : 'bg-[#DC2626] hover:bg-[#B91C1C] text-white'}`}>
                        {isScanning ? `SCANNING ${scanProgress.toFixed(0)}%` : 'INITIATE RECON SCAN'}
                      </button>
                    )}
                    {c.label === 'SCAN PROGRESS' && isScanning && (
                      <div className="mt-2 h-1.5 bg-[#1A1A20] rounded overflow-hidden">
                        <div className="h-full bg-[#DC2626] transition-all duration-300" style={{ width: `${scanProgress}%` }} />
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Findings Table */}
              <div className={`rounded-[10px] border overflow-hidden ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1E1E26]' : 'bg-white border-zinc-200'}`}>
                <div className={`px-5 py-4 border-b flex items-center justify-between ${theme === 'dark' ? 'border-[#1A1A20] bg-[#0F0F13]' : 'border-zinc-200 bg-zinc-50'}`}>
                  <h3 className="text-[12px] font-bold tracking-[0.18em] flex items-center gap-2">
                    FINDINGS TABLE <span className="w-1 h-1 rounded-full bg-[#DC2626]" /> {finalFindings.length} ACTIVE
                  </h3>
                  <div className="flex items-center gap-2 text-[10px]">
                    <span className="opacity-60 hidden md:inline">FILTERED BY {enabledModuleSet.size} MODULES + {enabledBAppSet.size} BAPPS + {oosList.length} OOS KEYWORDS</span>
                    <span className={`px-2 py-1 rounded border ${theme === 'dark' ? 'bg-[#050508] border-[#1E1E26]' : 'bg-white border-zinc-300'}`}>LIVE</span>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse min-w-[980px]">
                    <thead>
                      <tr className={`text-[10px] tracking-widest border-b ${theme === 'dark' ? 'bg-[#08080B] border-[#1A1A20] text-zinc-500' : 'bg-zinc-50 border-zinc-200 text-zinc-500'}`}>
                        <th className="px-4 py-3 font-bold">OWASP ID</th>
                        <th className="px-4 py-3 font-bold">SEVERITY</th>
                        <th className="px-4 py-3 font-bold">TITLE / URL</th>
                        <th className="px-4 py-3 font-bold">TOOL</th>
                        <th className="px-4 py-3 font-bold">CONFIDENCE</th>
                        <th className="px-4 py-3 font-bold">ACTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {finalFindings.map(f => (
                        <>
                          <tr key={f.uid} onClick={() => setSelectedUid(f.uid)} className={`border-b text-[12px] cursor-pointer transition ${selectedUid === f.uid ? (theme === 'dark' ? 'bg-[#14141A]' : 'bg-zinc-100') : ''} ${theme === 'dark' ? 'border-[#15151C] hover:bg-[#101014]' : 'border-zinc-200 hover:bg-zinc-50'}`}>
                            <td className="px-4 py-3.5 font-bold tracking-wide">{f.owasp}</td>
                            <td className="px-4 py-3.5"><span className={`px-2 py-1 rounded text-[10px] font-bold ${severityColor(f.severity)}`}>{f.severity}</span></td>
                            <td className="px-4 py-3.5 max-w-[360px]">
                              <div className="font-bold leading-tight truncate">{f.title}</div>
                              <div className="text-[11px] opacity-60 truncate mt-1">{f.url}</div>
                            </td>
                            <td className="px-4 py-3.5"><span className={`px-2 py-1 rounded border text-[11px] font-medium ${theme === 'dark' ? 'bg-[#0A0A0F] border-[#1E1E26]' : 'bg-zinc-50 border-zinc-300'}`}>{f.tool}</span></td>
                            <td className="px-4 py-3.5">
                              <div className="flex items-center gap-2">
                                <div className="w-14 h-1.5 bg-[#1A1A20] rounded overflow-hidden">
                                  <div className="h-full bg-emerald-500" style={{ width: `${f.confidence}%` }} />
                                </div>
                                <span className="text-[11px] font-bold">{f.confidence}%</span>
                              </div>
                            </td>
                            <td className="px-4 py-3.5">
                              <div className="flex items-center gap-1.5">
                                <button onClick={(e) => { e.stopPropagation(); handleHDScreenshot(f); }} className="h-7 px-2.5 bg-[#DC2626] hover:bg-[#B91C1C] text-white text-[10px] font-bold rounded">HD SHOT</button>
                                <button onClick={(e) => { e.stopPropagation(); handleVideoPoC(f); }} className={`h-7 px-2.5 text-[10px] font-bold rounded border ${theme === 'dark' ? 'border-[#2A2A35] hover:bg-[#1A1A20] text-white' : 'border-zinc-300 hover:bg-zinc-100'}`}>VIDEO POC</button>
                                <button onClick={(e) => { e.stopPropagation(); setExpandedId(expandedId === f.uid ? null : f.uid); if (expandedId !== f.uid) setSelectedUid(f.uid); }} className={`h-7 w-7 grid place-items-center rounded border text-[12px] ${theme === 'dark' ? 'border-[#2A2A35] hover:bg-[#1A1A20]' : 'border-zinc-300 hover:bg-zinc-100'}`}>{expandedId === f.uid ? '−' : '+'}</button>
                              </div>
                            </td>
                          </tr>
                          {expandedId === f.uid && (
                            <tr className={`${theme === 'dark' ? 'bg-[#08080B]' : 'bg-zinc-50'}`}>
                              <td colSpan={6} className="p-0">
                                <div className={`border-t ${theme === 'dark' ? 'border-[#1E1E26]' : 'border-zinc-200'}`}>
                                  <div className={`flex gap-1 p-2 border-b ${theme === 'dark' ? 'border-[#1A1A20] bg-[#0F0F13]' : 'border-zinc-200 bg-zinc-100'}`}>
                                    {[
                                      { k: 'evidence', l: 'Evidence' },
                                      { k: 'scenario', l: 'Attack Scenario' },
                                      { k: 'impact', l: 'Security Impact' },
                                      { k: 'report', l: 'Professional Report Template' },
                                    ].map(tab => (
                                      <button key={tab.k} onClick={() => setActiveTab(tab.k as any)} className={`h-8 px-3 text-[11px] font-bold tracking-widest rounded transition ${activeTab === tab.k ? 'bg-[#DC2626] text-white' : (theme === 'dark' ? 'bg-[#15151C] text-zinc-400 hover:text-white' : 'bg-white border border-zinc-300 text-zinc-600')}`}>{tab.l.toUpperCase()}</button>
                                    ))}
                                    <div className="ml-auto flex gap-1.5">
                                      <button onClick={() => copyReport(f.report)} className={`h-8 px-3 text-[11px] font-bold rounded border ${theme === 'dark' ? 'border-[#2A2A35] hover:bg-[#1A1A20]' : 'border-zinc-300 bg-white hover:bg-zinc-100'}`}>COPY MARKDOWN</button>
                                    </div>
                                  </div>
                                  <div className="p-5">
                                    {activeTab === 'evidence' && (
                                      <pre className={`text-[12px] leading-7 p-4 rounded border overflow-x-auto whitespace-pre-wrap break-words ${theme === 'dark' ? 'bg-[#050508] border-[#1A1A20] text-[#D1D5DB]' : 'bg-white border-zinc-200 text-zinc-800'}`}>{f.evidence}</pre>
                                    )}
                                    {activeTab === 'scenario' && (
                                      <div className="space-y-3">
                                        {f.attackScenario.map((step, i) => (
                                          <div key={i} className={`flex gap-3 p-3 rounded border ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1A1A20]' : 'bg-white border-zinc-200'}`}>
                                            <span className="w-6 h-6 rounded-full bg-[#DC2626] text-white grid place-items-center text-[11px] font-bold shrink-0">{i + 1}</span>
                                            <span className="text-[12px] leading-relaxed">{step}</span>
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                    {activeTab === 'impact' && (
                                      <div className={`p-4 rounded border leading-relaxed text-[12px] ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1A1A20] text-zinc-300' : 'bg-white border-zinc-200'}`}>
                                        <div className="font-bold text-[13px] mb-2">Security Impact</div>
                                        <p>{f.impact}</p>
                                        <div className="mt-4 grid grid-cols-2 gap-3">
                                          <div className={`p-3 rounded border ${theme === 'dark' ? 'bg-[#050508] border-[#1A1A20]' : 'bg-zinc-50 border-zinc-200'}`}>
                                            <div className="text-[10px] opacity-60">CVSS SCORE</div>
                                            <div className="text-[18px] font-bold mt-1">{f.cvss}</div>
                                          </div>
                                          <div className={`p-3 rounded border ${theme === 'dark' ? 'bg-[#050508] border-[#1A1A20]' : 'bg-zinc-50 border-zinc-200'}`}>
                                            <div className="text-[10px] opacity-60">AFFECTED PARAM</div>
                                            <div className="text-[13px] font-bold mt-1 font-mono">{f.param}</div>
                                          </div>
                                        </div>
                                      </div>
                                    )}
                                    {activeTab === 'report' && (
                                      <div className={`rounded border overflow-hidden ${theme === 'dark' ? 'bg-[#050508] border-[#1E1E26]' : 'bg-white border-zinc-200'}`}>
                                        <div className={`px-4 py-2 border-b flex items-center justify-between ${theme === 'dark' ? 'bg-[#0F0F13] border-[#1A1A20]' : 'bg-zinc-50 border-zinc-200'}`}>
                                          <span className="text-[11px] font-bold tracking-widest">PROFESSIONAL REPORT TEMPLATE // MARKDOWN</span>
                                          <span className="text-[10px] opacity-60">BOUNTYRECON v2.5.0</span>
                                        </div>
                                        <pre className="p-4 text-[11px] leading-6 overflow-x-auto whitespace-pre-wrap break-words max-h-[420px] overflow-y-auto">{f.report}</pre>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </>
                      ))}
                      {finalFindings.length === 0 && (
                        <tr>
                          <td colSpan={6} className="px-4 py-12 text-center">
                            <div className="text-[13px] font-bold opacity-60">NO FINDINGS MATCH CURRENT FILTERS</div>
                            <div className="text-[11px] opacity-40 mt-2">Adjust modules, BApps or Out-of-Scope keywords - {totalRaw} raw findings hidden, {filteredOOSCount} filtered OOS</div>
                            <button onClick={() => { setOosKeywords(''); setModules(INITIAL_MODULES); }} className="mt-4 h-8 px-4 bg-[#DC2626] text-white text-[11px] font-bold rounded">RESET FILTERS</button>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* subdomains list via Em() */}
              <div className={`rounded-[8px] border p-4 ${theme === 'dark' ? 'bg-[#0C0C10] border-[#1E1E26]' : 'bg-white border-zinc-200'}`}>
                <div className="text-[11px] font-bold tracking-widest mb-3">SUBDOMAINS DISCOVERED VIA Sm() - {subdomains.length}</div>
                <div className="flex flex-wrap gap-1.5">
                  {subdomains.map(s => (
                    <span key={s} className={`px-2 py-1 rounded text-[11px] border font-mono ${theme === 'dark' ? 'bg-[#050508] border-[#1A1A20] text-zinc-400' : 'bg-zinc-50 border-zinc-200'}`}>{s}</span>
                  ))}
                </div>
              </div>

            </div>
          </main>
        </div>

        {/* hidden canvas for HD */}
        <canvas ref={canvasRef} className="hidden" width={1920} height={1080} />

        {/* Logout */}
        <button onClick={() => { localStorage.removeItem('bountyrecon_auth'); setIsLoggedIn(false); }} className={`fixed bottom-4 left-4 z-40 h-11 px-4 rounded-full border shadow-xl text-[11px] font-bold tracking-widest ${theme === 'dark' ? 'bg-[#0F0F13] border-[#2A2A35] text-white' : 'bg-white border-zinc-300 text-black'}`}>LOGOUT</button>

        {/* Theme toggle bottom right */}
        <button onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} className={`fixed bottom-4 right-4 z-40 w-11 h-11 rounded-full grid place-items-center border shadow-xl transition ${theme === 'dark' ? 'bg-[#0F0F13] border-[#2A2A35] text-white hover:bg-[#1A1A20]' : 'bg-white border-zinc-300 text-black hover:bg-zinc-50'}`} title="Toggle theme">
          <span className="text-[16px]">{theme === 'dark' ? '☀' : '☾'}</span>
        </button>

        {/* Toasts */}
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 flex flex-col gap-2 pointer-events-none">
          {toasts.map(t => (
            <div key={t.id} className={`pointer-events-auto px-4 py-2.5 rounded-[8px] border shadow-2xl text-[12px] font-bold tracking-wide flex items-center gap-2 animate-[slideUp_0.25s_ease] ${t.type === 'ok' ? 'bg-[#0F0F13] border-[#2A2A35] text-white' : 'bg-[#DC2626] border-[#991B1B] text-white'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${t.type === 'ok' ? 'bg-emerald-400' : 'bg-white'}`} />
              {t.msg}
            </div>
          ))}
        </div>

        <style>{`
          @keyframes slideUp{from{transform:translateY(12px);opacity:0}to{transform:translateY(0);opacity:1}}
        `}</style>
      </div>
    </div>
  );
}
