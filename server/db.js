// server/db.js
// Native SQLite Database layer using Node.js built-in `node:sqlite` (DatabaseSync).
// Zero external dependencies required.

import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../data');
const DB_PATH = path.join(DATA_DIR, 'baseline_demo.sqlite');

let db = null;

export function getDb() {
  if (!db) {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    db = new DatabaseSync(DB_PATH);
    initTables();
  }
  return db;
}

function initTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      fixture_id TEXT NOT NULL,
      target TEXT NOT NULL,
      status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      completed_at TEXT,
      elapsed_ms INTEGER DEFAULT 0,
      is_simulated INTEGER DEFAULT 1,
      stages_json TEXT,
      error TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      cwe TEXT,
      severity TEXT NOT NULL,
      confidence TEXT NOT NULL,
      status TEXT NOT NULL,
      target_file TEXT NOT NULL,
      line INTEGER DEFAULT 1,
      evidence TEXT NOT NULL,
      why_matched TEXT NOT NULL,
      limitations TEXT NOT NULL,
      generic_remediation TEXT NOT NULL,
      remediation_type TEXT NOT NULL,
      verified INTEGER DEFAULT 0,
      patch_available INTEGER DEFAULT 0,
      FOREIGN KEY(scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS benchmarks (
      id TEXT PRIMARY KEY,
      test_id TEXT NOT NULL,
      target_name TEXT NOT NULL,
      expected_finding TEXT NOT NULL,
      baseline_result TEXT NOT NULL,
      aegis_result TEXT,
      baseline_time_ms INTEGER DEFAULT 0,
      aegis_time_ms INTEGER DEFAULT 0,
      baseline_tp INTEGER DEFAULT 0,
      baseline_fp INTEGER DEFAULT 0,
      baseline_fn INTEGER DEFAULT 0,
      aegis_tp INTEGER DEFAULT 0,
      aegis_fp INTEGER DEFAULT 0,
      aegis_fn INTEGER DEFAULT 0,
      notes TEXT
    );
  `);

  // Check if scans table is empty, if so, seed initial DEMO data
  const countRow = db.prepare('SELECT count(*) as count FROM scans').get();
  if (countRow.count === 0) {
    seedInitialDemoData();
  }
}

function seedInitialDemoData() {
  const insertScan = db.prepare(`
    INSERT INTO scans (id, name, fixture_id, target, status, started_at, completed_at, elapsed_ms, is_simulated, stages_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertFinding = db.prepare(`
    INSERT INTO findings (
      id, scan_id, rule_id, title, category, cwe, severity, confidence,
      status, target_file, line, evidence, why_matched, limitations,
      generic_remediation, remediation_type, verified, patch_available
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Seed Scan 1: E-Commerce API Gateway
  const scan1Stages = {
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
  };

  insertScan.run(
    "scan-seed-001",
    "Sample 1: Web App API Gateway",
    "fixture-ecommerce-api",
    "bundled://fixtures/ecommerce-api/v1",
    "completed",
    "2026-10-30T10:15:00.000Z",
    "2026-10-30T10:15:04.250Z",
    4250,
    1,
    JSON.stringify(scan1Stages)
  );

  insertFinding.run(
    "find-seed-001",
    "scan-seed-001",
    "RULE-SEC-001",
    "SQL String Concatenation Pattern",
    "Input Validation",
    "CWE-89: SQL Injection",
    "High",
    "Low (Static Heuristic)",
    "Needs manual verification",
    "src/controllers/userController.js",
    24,
    "const query = \"SELECT id, username, role FROM users WHERE email = '\" + req.body.email + \"' AND status = 'active'\";",
    "Found regex pattern db.query with direct string concatenation without prepared statement parameters.",
    "Candidate finding only. Baseline demo does not verify exploitability dynamically, execute payloads, or test database dialect defenses. Manual verification required.",
    "Replace inline string concatenation with parameterized SQL queries or an ORM prepared statement mechanism. Ensure all user inputs undergo strict type casting.",
    "Generic Manual Guidance (No patch generated)",
    0,
    0
  );

  insertFinding.run(
    "find-seed-002",
    "scan-seed-001",
    "RULE-SEC-007",
    "Unthrottled Authentication Endpoint",
    "Rate Limiting & DoS",
    "CWE-307: Improper Restriction of Excessive Authentication Attempts",
    "Medium",
    "Low (Static Inspection)",
    "Needs manual verification",
    "src/routes/authRoutes.js",
    12,
    "router.post('/api/v1/auth/login', authController.login);",
    "Endpoint POST /api/v1/auth/login does not reference rate-limiter middleware.",
    "Static check only. Does not simulate brute-force load or test cloud WAF rate-limiting rules.",
    "Apply IP and account-based rate limiting to authentication routes. Return HTTP 429 Too Many Requests when threshold is exceeded.",
    "Generic Manual Guidance (No patch generated)",
    0,
    0
  );

  // Seed Scan 2: Public Cloud Portal
  const scan2Stages = {
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
  };

  insertScan.run(
    "scan-seed-002",
    "Sample 2: Public Cloud Portal",
    "fixture-cloud-portal",
    "bundled://fixtures/cloud-portal/web",
    "completed",
    "2026-10-30T11:20:00.000Z",
    "2026-10-30T11:20:03.900Z",
    3900,
    1,
    JSON.stringify(scan2Stages)
  );

  insertFinding.run(
    "find-seed-003",
    "scan-seed-002",
    "RULE-SEC-002",
    "Missing Content-Security-Policy (CSP)",
    "Security Headers",
    "CWE-1021: Improper Restriction of Rendered UI Layers",
    "Medium",
    "Medium (Header Scan)",
    "Needs manual verification",
    "nginx/conf.d/default.conf",
    5,
    "location / { proxy_pass http://portal_upstream; }",
    "Inspection of HTTP response header map returned null for 'Content-Security-Policy'.",
    "Header presence check only. Scanner Agent cannot evaluate whether downstream CDNs inject headers dynamically.",
    "Configure the web server or reverse proxy to emit a restrictive Content-Security-Policy header directive.",
    "Generic Manual Guidance (No patch generated)",
    0,
    0
  );

  insertFinding.run(
    "find-seed-004",
    "scan-seed-002",
    "RULE-SEC-003",
    "Missing HTTP Strict-Transport-Security (HSTS)",
    "Transport Security",
    "CWE-319: Cleartext Transmission of Sensitive Information",
    "Medium",
    "Medium (Header Scan)",
    "Needs manual verification",
    "nginx/conf.d/default.conf",
    6,
    "listen 80; server_name portal.example.internal;",
    "HTTP response headers omitted 'Strict-Transport-Security'.",
    "Static check only. Does not verify browser HSTS preload list status.",
    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
    "Generic Manual Guidance (No patch generated)",
    0,
    0
  );

  insertFinding.run(
    "find-seed-005",
    "scan-seed-002",
    "RULE-SEC-004",
    "Clickjacking Exposure (Missing X-Frame-Options)",
    "Security Headers",
    "CWE-1021: Clickjacking / Framing",
    "Low",
    "Medium (Header Scan)",
    "Needs manual verification",
    "public/index.html",
    3,
    "<title>Cloud Management Console</title>",
    "Header 'X-Frame-Options' was not returned by the mock server endpoint.",
    "Does not verify CSP frame-ancestors equivalence or client side frame-busting scripts.",
    "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
    "Generic Manual Guidance (No patch generated)",
    0,
    0
  );
}

// Scans Queries
export function getAllScans() {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM scans ORDER BY started_at DESC').all();
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    fixtureId: r.fixture_id,
    target: r.target,
    status: r.status,
    startedAt: r.started_at,
    completedAt: r.completed_at,
    elapsedMs: r.elapsed_ms,
    isSimulated: Boolean(r.is_simulated),
    stages: r.stages_json ? JSON.parse(r.stages_json) : null,
    error: r.error,
    findings: getFindingsByScanId(r.id)
  }));
}

export function getScanById(scanId) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    fixtureId: row.fixture_id,
    target: row.target,
    status: row.status,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    elapsedMs: row.elapsed_ms,
    isSimulated: Boolean(row.is_simulated),
    stages: row.stages_json ? JSON.parse(row.stages_json) : null,
    error: row.error,
    findings: getFindingsByScanId(row.id)
  };
}

export function insertScan(scan) {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO scans (id, name, fixture_id, target, status, started_at, completed_at, elapsed_ms, is_simulated, stages_json, error)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    scan.id,
    scan.name,
    scan.fixtureId,
    scan.target,
    scan.status,
    scan.startedAt,
    scan.completedAt,
    scan.elapsedMs || 0,
    scan.isSimulated ? 1 : 0,
    scan.stages ? JSON.stringify(scan.stages) : null,
    scan.error || null
  );
  return scan;
}

export function updateScanRecord(scanId, updates) {
  const db = getDb();
  const existing = getScanById(scanId);
  if (!existing) return null;

  const merged = { ...existing, ...updates };
  const stmt = db.prepare(`
    UPDATE scans
    SET name = ?, fixture_id = ?, target = ?, status = ?, started_at = ?,
        completed_at = ?, elapsed_ms = ?, is_simulated = ?, stages_json = ?, error = ?
    WHERE id = ?
  `);
  stmt.run(
    merged.name,
    merged.fixtureId,
    merged.target,
    merged.status,
    merged.startedAt,
    merged.completedAt,
    merged.elapsedMs || 0,
    merged.isSimulated ? 1 : 0,
    merged.stages ? JSON.stringify(merged.stages) : null,
    merged.error || null,
    scanId
  );
  return merged;
}

// Findings Queries
export function getFindingsByScanId(scanId) {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM findings WHERE scan_id = ?').all(scanId);
  return rows.map(formatFindingRow);
}

export function getAllFindingsList() {
  const db = getDb();
  const rows = db.prepare(`
    SELECT f.*, s.name as scan_name, s.fixture_id, s.started_at as scan_started_at
    FROM findings f
    JOIN scans s ON f.scan_id = s.id
    ORDER BY s.started_at DESC
  `).all();
  return rows.map((r) => ({
    ...formatFindingRow(r),
    scanName: r.scan_name,
    fixtureId: r.fixture_id,
    scanStartedAt: r.scan_started_at
  }));
}

export function insertFinding(finding) {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO findings (
      id, scan_id, rule_id, title, category, cwe, severity, confidence,
      status, target_file, line, evidence, why_matched, limitations,
      generic_remediation, remediation_type, verified, patch_available
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    finding.id,
    finding.scanId,
    finding.ruleId,
    finding.title,
    finding.category,
    finding.cwe || null,
    finding.severity,
    finding.confidence,
    finding.status || 'Needs manual verification',
    finding.targetFile,
    finding.line || 1,
    finding.evidence,
    finding.whyMatched,
    finding.limitations,
    finding.genericRemediation,
    finding.remediationType || 'Generic Manual Guidance (No patch generated)',
    finding.verified ? 1 : 0,
    finding.patchAvailable ? 1 : 0
  );
  return finding;
}

function formatFindingRow(r) {
  return {
    id: r.id,
    scanId: r.scan_id,
    ruleId: r.rule_id,
    title: r.title,
    category: r.category,
    cwe: r.cwe,
    severity: r.severity,
    confidence: r.confidence,
    status: r.status,
    targetFile: r.target_file,
    line: r.line,
    evidence: r.evidence,
    whyMatched: r.why_matched,
    limitations: r.limitations,
    genericRemediation: r.generic_remediation,
    remediationType: r.remediation_type,
    verified: Boolean(r.verified),
    patchAvailable: Boolean(r.patch_available)
  };
}

// Benchmark Queries
export function getAllBenchmarkTestCases() {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM benchmarks ORDER BY test_id ASC').all();
  return rows.map((r) => ({
    id: r.id,
    testId: r.test_id,
    targetName: r.target_name,
    expectedFinding: r.expected_finding,
    baselineResult: r.baseline_result,
    aegisResult: r.aegis_result,
    baselineTimeMs: r.baseline_time_ms,
    aegisTimeMs: r.aegis_time_ms,
    baselineTP: r.baseline_tp,
    baselineFP: r.baseline_fp,
    baselineFN: r.baseline_fn,
    aegisTP: r.aegis_tp,
    aegisFP: r.aegis_fp,
    aegisFN: r.aegis_fn,
    notes: r.notes
  }));
}

export function saveBenchmarkTestCases(testCases) {
  const db = getDb();
  db.exec('DELETE FROM benchmarks');
  const stmt = db.prepare(`
    INSERT INTO benchmarks (
      id, test_id, target_name, expected_finding, baseline_result, aegis_result,
      baseline_time_ms, aegis_time_ms, baseline_tp, baseline_fp, baseline_fn,
      aegis_tp, aegis_fp, aegis_fn, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const tc of testCases) {
    const id = tc.id || `tc-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    stmt.run(
      id,
      tc.testId || tc.test_id || 'TC-NEW',
      tc.targetName || tc.target_name || 'Test Case',
      tc.expectedFinding || tc.expected_finding || 'Finding',
      tc.baselineResult || tc.baseline_result || 'Unknown',
      tc.aegisResult || tc.aegis_result || 'N/A',
      Number(tc.baselineTimeMs || tc.baseline_time_ms || 0),
      Number(tc.aegisTimeMs || tc.aegis_time_ms || 0),
      Number(tc.baselineTP || tc.baseline_tp || 0),
      Number(tc.baselineFP || tc.baseline_fp || 0),
      Number(tc.baselineFN || tc.baseline_fn || 0),
      Number(tc.aegisTP || tc.aegis_tp || 0),
      Number(tc.aegisFP || tc.aegis_fp || 0),
      Number(tc.aegisFN || tc.aegis_fn || 0),
      tc.notes || ''
    );
  }
  return getAllBenchmarkTestCases();
}

export function resetDatabase() {
  const db = getDb();
  db.exec(`
    DELETE FROM findings;
    DELETE FROM scans;
    DELETE FROM benchmarks;
  `);
  seedInitialDemoData();
  return { success: true };
}
