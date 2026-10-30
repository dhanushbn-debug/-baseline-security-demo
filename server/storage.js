// server/storage.js
// Persistent file-backed storage layer for scans, findings, and benchmark imports.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../data');
const DB_FILE = path.join(DATA_DIR, 'baseline_demo.json');

const INITIAL_SEEDED_SCANS = [
  {
    id: "scan-seed-001",
    name: "Sample 1: Web App API Gateway",
    fixtureId: "fixture-ecommerce-api",
    target: "bundled://fixtures/ecommerce-api/v1",
    status: "completed",
    startedAt: "2026-10-30T10:15:00.000Z",
    completedAt: "2026-10-30T10:15:04.250Z",
    elapsedMs: 4250,
    isSimulated: true,
    stages: {
      scannerAgent: {
        status: "completed",
        startedAt: "2026-10-30T10:15:00.000Z",
        completedAt: "2026-10-30T10:15:02.100Z",
        elapsedMs: 2100,
        rulesChecked: 8,
        candidateFindingsCount: 2,
        logs: [
          "[Scanner Agent] Initialized static pattern engine against bundled fixture.",
          "[Scanner Agent] Parsed 2 source files (57 total lines).",
          "[Scanner Agent] Rule RULE-SEC-001 triggered: Detected raw string concatenation in SQL query.",
          "[Scanner Agent] Rule RULE-SEC-007 triggered: Authentication endpoint missing rate-limit guard.",
          "[Scanner Agent] Scanner completed. Passing 2 candidate findings to Report Agent."
        ]
      },
      reportAgent: {
        status: "completed",
        startedAt: "2026-10-30T10:15:02.100Z",
        completedAt: "2026-10-30T10:15:04.250Z",
        elapsedMs: 2150,
        findingsGrouped: 2,
        logs: [
          "[Report Agent] Received candidate findings from Scanner Agent.",
          "[Report Agent] Assigned static severity: RULE-SEC-001 -> High, RULE-SEC-007 -> Medium.",
          "[Report Agent] Attached generic manual remediation guidelines (no patch generated).",
          "[Report Agent] Flagged: Independent exploit verification NOT performed.",
          "[Report Agent] Generated final scan summary report."
        ]
      }
    },
    findings: [
      {
        id: "find-seed-001",
        scanId: "scan-seed-001",
        ruleId: "RULE-SEC-001",
        title: "SQL String Concatenation Pattern",
        severity: "High",
        confidence: "Low (Static Heuristic)",
        status: "Needs manual verification",
        category: "Input Validation",
        targetFile: "src/controllers/userController.js",
        line: 24,
        evidence: "const query = \"SELECT id, username, role FROM users WHERE email = '\" + req.body.email + \"' AND status = 'active'\";",
        whyMatched: "Found regex pattern db.query with direct string concatenation without prepared statement parameters.",
        limitations: "Candidate finding only. Baseline demo does not verify exploitability dynamically, execute payloads, or test database dialect defenses. Manual verification required.",
        genericRemediation: "Replace inline string concatenation with parameterized SQL queries or an ORM prepared statement mechanism. Ensure all user inputs undergo strict type casting.",
        verified: false,
        patchAvailable: false
      },
      {
        id: "find-seed-002",
        scanId: "scan-seed-001",
        ruleId: "RULE-SEC-007",
        title: "Unthrottled Authentication Endpoint",
        severity: "Medium",
        confidence: "Low (Static Inspection)",
        status: "Needs manual verification",
        category: "Rate Limiting & DoS",
        targetFile: "src/routes/authRoutes.js",
        line: 12,
        evidence: "router.post('/api/v1/auth/login', authController.login);",
        whyMatched: "Endpoint POST /api/v1/auth/login does not reference rate-limiter middleware.",
        limitations: "Static check only. Does not simulate brute-force load or test cloud WAF rate-limiting rules.",
        genericRemediation: "Apply IP and account-based rate limiting to authentication routes. Return HTTP 429 Too Many Requests when threshold is exceeded.",
        verified: false,
        patchAvailable: false
      }
    ]
  },
  {
    id: "scan-seed-002",
    name: "Sample 2: Public Cloud Portal",
    fixtureId: "fixture-cloud-portal",
    target: "bundled://fixtures/cloud-portal/web",
    status: "completed",
    startedAt: "2026-10-30T11:20:00.000Z",
    completedAt: "2026-10-30T11:20:03.900Z",
    elapsedMs: 3900,
    isSimulated: true,
    stages: {
      scannerAgent: {
        status: "completed",
        startedAt: "2026-10-30T11:20:00.000Z",
        completedAt: "2026-10-30T11:20:01.850Z",
        elapsedMs: 1850,
        rulesChecked: 8,
        candidateFindingsCount: 3,
        logs: [
          "[Scanner Agent] Initialized HTTP header check against static config.",
          "[Scanner Agent] Inspected nginx/conf.d/default.conf.",
          "[Scanner Agent] Rule RULE-SEC-002 triggered: Missing Content-Security-Policy header.",
          "[Scanner Agent] Rule RULE-SEC-003 triggered: Missing Strict-Transport-Security header.",
          "[Scanner Agent] Rule RULE-SEC-004 triggered: Missing X-Frame-Options header.",
          "[Scanner Agent] Scanner completed. Passing 3 candidate findings to Report Agent."
        ]
      },
      reportAgent: {
        status: "completed",
        startedAt: "2026-10-30T11:20:01.850Z",
        completedAt: "2026-10-30T11:20:03.900Z",
        elapsedMs: 2050,
        findingsGrouped: 3,
        logs: [
          "[Report Agent] Received candidate findings from Scanner Agent.",
          "[Report Agent] Categorized header findings under Transport & Client Security.",
          "[Report Agent] Attached generic manual remediation guidelines (no patch generated).",
          "[Report Agent] Generated final scan summary report."
        ]
      }
    },
    findings: [
      {
        id: "find-seed-003",
        scanId: "scan-seed-002",
        ruleId: "RULE-SEC-002",
        title: "Missing Content-Security-Policy (CSP)",
        severity: "Medium",
        confidence: "Medium (Header Scan)",
        status: "Needs manual verification",
        category: "Security Headers",
        targetFile: "nginx/conf.d/default.conf",
        line: 5,
        evidence: "location / { proxy_pass http://portal_upstream; }",
        whyMatched: "Inspection of HTTP response header map returned null for 'Content-Security-Policy'.",
        limitations: "Header presence check only. Scanner Agent cannot evaluate whether downstream CDNs inject headers dynamically.",
        genericRemediation: "Configure the web server or reverse proxy to emit a restrictive Content-Security-Policy header directive.",
        verified: false,
        patchAvailable: false
      },
      {
        id: "find-seed-004",
        scanId: "scan-seed-002",
        ruleId: "RULE-SEC-003",
        title: "Missing HTTP Strict-Transport-Security (HSTS)",
        severity: "Medium",
        confidence: "Medium (Header Scan)",
        status: "Needs manual verification",
        category: "Transport Security",
        targetFile: "nginx/conf.d/default.conf",
        line: 6,
        evidence: "listen 80; server_name portal.example.internal;",
        whyMatched: "HTTP response headers omitted 'Strict-Transport-Security'.",
        limitations: "Static check only. Does not verify browser HSTS preload list status.",
        genericRemediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
        verified: false,
        patchAvailable: false
      },
      {
        id: "find-seed-005",
        scanId: "scan-seed-002",
        ruleId: "RULE-SEC-004",
        title: "Clickjacking Exposure (Missing X-Frame-Options)",
        severity: "Low",
        confidence: "Medium (Header Scan)",
        status: "Needs manual verification",
        category: "Security Headers",
        targetFile: "public/index.html",
        line: 3,
        evidence: "<title>Cloud Management Console</title>",
        whyMatched: "Header 'X-Frame-Options' was not returned by the mock server endpoint.",
        limitations: "Does not verify CSP frame-ancestors equivalence or client side frame-busting scripts.",
        genericRemediation: "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
        verified: false,
        patchAvailable: false
      }
    ]
  }
];

// In-memory cache synced to disk
let dbCache = null;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

export function initStorage() {
  ensureDataDir();
  if (fs.existsSync(DB_FILE)) {
    try {
      const content = fs.readFileSync(DB_FILE, 'utf-8');
      dbCache = JSON.parse(content);
      return;
    } catch (err) {
      console.warn("Could not read db.json, reinitializing seed:", err.message);
    }
  }

  dbCache = {
    scans: INITIAL_SEEDED_SCANS,
    benchmarks: [] // Empty by default: "No benchmark data yet"
  };
  saveStorage();
}

export function saveStorage() {
  ensureDataDir();
  try {
    const tmpFile = DB_FILE + '.tmp';
    fs.writeFileSync(tmpFile, JSON.stringify(dbCache, null, 2), 'utf-8');
    fs.renameSync(tmpFile, DB_FILE);
  } catch (err) {
    console.error("Failed to write database file:", err.message);
  }
}

export function getScans() {
  if (!dbCache) initStorage();
  return dbCache.scans || [];
}

export function getScanById(scanId) {
  const scans = getScans();
  return scans.find((s) => s.id === scanId) || null;
}

export function addScan(scan) {
  if (!dbCache) initStorage();
  dbCache.scans.unshift(scan);
  saveStorage();
  return scan;
}

export function updateScan(scanId, updates) {
  if (!dbCache) initStorage();
  const index = dbCache.scans.findIndex((s) => s.id === scanId);
  if (index !== -1) {
    dbCache.scans[index] = { ...dbCache.scans[index], ...updates };
    saveStorage();
    return dbCache.scans[index];
  }
  return null;
}

export function getAllFindings() {
  const scans = getScans();
  const allFindings = [];
  for (const s of scans) {
    if (Array.isArray(s.findings)) {
      for (const f of s.findings) {
        allFindings.push({
          ...f,
          scanName: s.name,
          fixtureId: s.fixtureId,
          scanStartedAt: s.startedAt
        });
      }
    }
  }
  return allFindings;
}

export function getBenchmarks() {
  if (!dbCache) initStorage();
  return dbCache.benchmarks || [];
}

export function saveBenchmarks(benchmarksArray) {
  if (!dbCache) initStorage();
  dbCache.benchmarks = benchmarksArray;
  saveStorage();
  return dbCache.benchmarks;
}

export function resetToSeed() {
  dbCache = {
    scans: JSON.parse(JSON.stringify(INITIAL_SEEDED_SCANS)),
    benchmarks: []
  };
  saveStorage();
  return dbCache;
}
