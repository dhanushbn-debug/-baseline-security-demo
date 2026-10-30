// server.js
// Baseline Security Demo — High-Performance Native Node.js Server & SQLite Backend
// Zero external runtime dependencies required.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  getAllScans,
  getScanById,
  insertScan,
  updateScanRecord,
  getFindingsByScanId,
  getAllFindingsList,
  insertFinding,
  getAllBenchmarkTestCases,
  saveBenchmarkTestCases,
  resetDatabase
} from './server/db.js';
import { SAMPLE_FIXTURES, getFixtureById } from './server/fixtures.js';
import { PREDEFINED_RULES, getRuleById } from './server/rules.js';
import { runScannerAgent, isTargetAuthorized } from './server/scanner.js';
import {
  runReportAgent,
  generateHtmlReport,
  generateJsonReport,
  generateCsvReport
} from './server/reporter.js';
import {
  FEATURE_MATRIX,
  STANDARDIZED_LAB_DATASET,
  calculateMetrics
} from './server/benchmarks.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, 'public');
const PORT = process.env.PORT || 5000;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8',
  '.pdf': 'application/pdf'
};

// Helper to parse JSON request body
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) {
        // 5MB limit
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('Invalid JSON payload: ' + err.message));
      }
    });
    req.on('error', reject);
  });
}

// Helper to send JSON responses
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Demo-Notice': 'Baseline-Security-Demo-Comparator'
  });
  res.end(JSON.stringify(data));
}

// Helper to serve static files
function serveStatic(req, res, pathname) {
  let relativePath = pathname === '/' ? 'index.html' : pathname;
  // Prevent directory traversal
  const safePath = path.normalize(relativePath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err) {
      if (err.code === 'ENOENT') {
        // Fallback to index.html for SPA client-side routes
        const indexPath = path.join(PUBLIC_DIR, 'index.html');
        fs.readFile(indexPath, (err2, content) => {
          if (err2) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
            return;
          }
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(content);
        });
        return;
      }
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('500 Server Error');
      return;
    }

    if (stats.isDirectory()) {
      serveStatic(req, res, path.join(pathname, 'index.html'));
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err3, data) => {
      if (err3) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Error reading file');
        return;
      }
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(data);
    });
  });
}

// Request Router
const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = urlObj.pathname;
  const method = req.method;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    });
    res.end();
    return;
  }

  // --- API ROUTES ---

  // Health Check
  if (pathname === '/api/health' && method === 'GET') {
    return sendJson(res, 200, {
      status: 'ok',
      app: 'Baseline Security Demo',
      subtitle: 'Fictional baseline workflow for controlled product comparison',
      version: '1.0.0',
      uptimeSeconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    });
  }

  // Fixtures
  if (pathname === '/api/fixtures' && method === 'GET') {
    return sendJson(res, 200, SAMPLE_FIXTURES);
  }

  if (pathname.startsWith('/api/fixtures/') && method === 'GET') {
    const fixtureId = pathname.replace('/api/fixtures/', '');
    const fixture = getFixtureById(fixtureId);
    if (!fixture) return sendJson(res, 404, { error: 'Fixture not found' });
    return sendJson(res, 200, fixture);
  }

  // Rules Catalog
  if (pathname === '/api/rules' && method === 'GET') {
    return sendJson(res, 200, PREDEFINED_RULES);
  }

  // Scans: List
  if (pathname === '/api/scans' && method === 'GET') {
    const scans = getAllScans();
    return sendJson(res, 200, scans);
  }

  // Scans: Trigger New Scan
  if (pathname === '/api/scans' && method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const { fixtureId, customTarget, authorizedConfirmed } = body;

      if (!authorizedConfirmed) {
        return sendJson(res, 400, {
          error: 'Scope Authorization Required: You must confirm the scan target before proceeding.'
        });
      }

      const fixture = fixtureId ? getFixtureById(fixtureId) : null;
      const target = fixture ? fixture.targetUri : (customTarget || '').trim();

      // Enforce strict safety boundary: Only allow bundled fixtures or local loopback
      if (!isTargetAuthorized(target)) {
        return sendJson(res, 400, {
          error: 'Safety Guardrail Triggered: Arbitrary internet scanning is disabled. You may only scan approved bundled demo fixtures or local loopback training targets (localhost / 127.0.0.1).'
        });
      }

      const scanId = `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const scanName = fixture ? fixture.name : `Local Target Scan (${target})`;
      const startedAt = new Date().toISOString();

      const newScan = {
        id: scanId,
        name: scanName,
        fixtureId: fixtureId || 'custom-local',
        target,
        status: 'running',
        startedAt,
        completedAt: null,
        elapsedMs: 0,
        isSimulated: fixture ? true : false,
        stages: {
          scannerAgent: {
            status: 'running',
            startedAt,
            completedAt: null,
            elapsedMs: 0,
            rulesChecked: 0,
            candidateFindingsCount: 0,
            logs: [`[Scanner Agent] Stage started at ${new Date().toLocaleTimeString()}`]
          },
          reportAgent: {
            status: 'pending',
            startedAt: null,
            completedAt: null,
            elapsedMs: 0,
            findingsGrouped: 0,
            logs: []
          }
        },
        error: null,
        findings: []
      };

      insertScan(newScan);

      // Return scan record immediately so UI can show the live timeline
      sendJson(res, 201, newScan);

      // Asynchronous sequential 2-agent execution
      (async () => {
        try {
          const startTime = Date.now();

          // Stage 1: Scanner Agent
          const scannerResult = await runScannerAgent({
            fixtureId,
            customTarget: target,
            onProgress: (p) => {
              newScan.stages.scannerAgent.logs.push(p.message);
              updateScanRecord(scanId, { stages: newScan.stages });
            }
          });

          const scannerEndTime = Date.now();
          newScan.stages.scannerAgent.status = 'completed';
          newScan.stages.scannerAgent.completedAt = new Date().toISOString();
          newScan.stages.scannerAgent.elapsedMs = scannerEndTime - startTime;
          newScan.stages.scannerAgent.rulesChecked = scannerResult.rulesChecked;
          newScan.stages.scannerAgent.candidateFindingsCount = scannerResult.candidateFindings.length;
          newScan.stages.scannerAgent.logs = scannerResult.logs;

          // Stage 2: Report Agent
          newScan.stages.reportAgent.status = 'running';
          newScan.stages.reportAgent.startedAt = new Date().toISOString();
          updateScanRecord(scanId, { stages: newScan.stages });

          const reportResult = await runReportAgent({
            candidateFindings: scannerResult.candidateFindings,
            scanInfo: newScan,
            onProgress: (p) => {
              newScan.stages.reportAgent.logs.push(p.message);
              updateScanRecord(scanId, { stages: newScan.stages });
            }
          });

          const finishTime = Date.now();
          newScan.stages.reportAgent.status = 'completed';
          newScan.stages.reportAgent.completedAt = new Date().toISOString();
          newScan.stages.reportAgent.elapsedMs = finishTime - scannerEndTime;
          newScan.stages.reportAgent.findingsGrouped = reportResult.finalFindings.length;
          newScan.stages.reportAgent.logs = reportResult.logs;

          newScan.status = 'completed';
          newScan.completedAt = new Date().toISOString();
          newScan.elapsedMs = finishTime - startTime;

          // Insert findings into SQLite
          for (const finding of reportResult.finalFindings) {
            insertFinding(finding);
          }

          updateScanRecord(scanId, {
            status: 'completed',
            completedAt: newScan.completedAt,
            elapsedMs: newScan.elapsedMs,
            stages: newScan.stages
          });
        } catch (err) {
          console.error(`Error in scan ${scanId}:`, err);
          updateScanRecord(scanId, {
            status: 'failed',
            error: err.message
          });
        }
      })();

      return;
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // Scans: Get Scan Details
  if (pathname.startsWith('/api/scans/') && method === 'GET' && !pathname.endsWith('/findings')) {
    const scanId = pathname.replace('/api/scans/', '');
    const scan = getScanById(scanId);
    if (!scan) return sendJson(res, 404, { error: 'Scan not found' });
    return sendJson(res, 200, scan);
  }

  // Scans: Reset Demo Seeds
  if (pathname === '/api/scans/reset' && method === 'POST') {
    resetDatabase();
    return sendJson(res, 200, {
      message: 'Demo history reset to initial seed.',
      scans: getAllScans()
    });
  }

  // Findings: Filterable List
  if (pathname === '/api/findings' && method === 'GET') {
    let findings = getAllFindingsList();
    const severity = urlObj.searchParams.get('severity');
    const query = urlObj.searchParams.get('query');
    const ruleId = urlObj.searchParams.get('ruleId');
    const scanId = urlObj.searchParams.get('scanId');

    if (scanId) {
      findings = findings.filter((f) => f.scanId === scanId);
    }
    if (severity && severity !== 'ALL') {
      findings = findings.filter((f) => f.severity.toLowerCase() === severity.toLowerCase());
    }
    if (ruleId) {
      findings = findings.filter((f) => f.ruleId === ruleId);
    }
    if (query) {
      const q = query.toLowerCase();
      findings = findings.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.targetFile.toLowerCase().includes(q) ||
          f.ruleId.toLowerCase().includes(q) ||
          f.whyMatched.toLowerCase().includes(q)
      );
    }

    return sendJson(res, 200, findings);
  }

  // Findings: Single Finding Detail
  if (pathname.startsWith('/api/findings/') && method === 'GET') {
    const findingId = pathname.replace('/api/findings/', '');
    const all = getAllFindingsList();
    const finding = all.find((f) => f.id === findingId);
    if (!finding) return sendJson(res, 404, { error: 'Finding not found' });
    return sendJson(res, 200, finding);
  }

  // Reports: Download (HTML, JSON, CSV)
  if (pathname.startsWith('/api/reports/') && pathname.endsWith('/download') && method === 'GET') {
    const parts = pathname.split('/');
    const reportId = parts[3];
    const scan = getScanById(reportId);
    if (!scan) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Report not found');
    }

    const format = (urlObj.searchParams.get('format') || 'html').toLowerCase();

    if (format === 'json') {
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${scan.id}-report.json"`,
        'X-Content-Type-Options': 'nosniff'
      });
      return res.end(generateJsonReport(scan));
    }

    if (format === 'csv') {
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${scan.id}-report.csv"`,
        'X-Content-Type-Options': 'nosniff'
      });
      return res.end(generateCsvReport(scan));
    }

    // Default HTML
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Disposition': `attachment; filename="${scan.id}-report.html"`,
      'X-Content-Type-Options': 'nosniff'
    });
    return res.end(generateHtmlReport(scan));
  }

  // Reports: Get Report Metadata
  if (pathname.startsWith('/api/reports/') && method === 'GET') {
    const reportId = pathname.replace('/api/reports/', '');
    const scan = getScanById(reportId);
    if (!scan) return sendJson(res, 404, { error: 'Report not found' });
    return sendJson(res, 200, {
      scanId: scan.id,
      scanName: scan.name,
      target: scan.target,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      elapsedMs: scan.elapsedMs,
      findingsCount: (scan.findings || []).length,
      findings: scan.findings || [],
      stages: scan.stages
    });
  }

  // Comparison: Feature Matrix
  if (pathname === '/api/comparison/matrix' && method === 'GET') {
    return sendJson(res, 200, FEATURE_MATRIX);
  }

  // Benchmarks: Get Current Measured Results
  if (pathname === '/api/benchmarks' && method === 'GET') {
    const testCases = getAllBenchmarkTestCases();
    const metrics = calculateMetrics(testCases);
    return sendJson(res, 200, {
      benchmarks: testCases,
      metrics,
      hasData: testCases && testCases.length > 0
    });
  }

  // Benchmarks: Import Measured Results
  if (pathname === '/api/benchmarks' && method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const testCases = body.testCases;
      if (!Array.isArray(testCases) || testCases.length === 0) {
        return sendJson(res, 400, { error: 'Invalid benchmark data: testCases array required.' });
      }
      const saved = saveBenchmarkTestCases(testCases);
      const metrics = calculateMetrics(saved);
      return sendJson(res, 200, {
        message: `Successfully imported ${saved.length} benchmark test case(s).`,
        benchmarks: saved,
        metrics,
        hasData: true
      });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // Benchmarks: Load Standardized N=10 Lab Suite
  if (pathname === '/api/benchmarks/load-sample' && method === 'POST') {
    const saved = saveBenchmarkTestCases(STANDARDIZED_LAB_DATASET.testCases);
    const metrics = calculateMetrics(saved);
    return sendJson(res, 200, {
      message: 'Standardized lab benchmark dataset loaded (N=10 test cases).',
      datasetInfo: STANDARDIZED_LAB_DATASET.metadata,
      benchmarks: saved,
      metrics,
      hasData: true
    });
  }

  // Benchmarks: Reset to Empty ("No benchmark data yet")
  if (pathname === '/api/benchmarks/reset' && method === 'POST') {
    saveBenchmarkTestCases([]);
    return sendJson(res, 200, {
      message: 'Benchmark dataset cleared. Status: No benchmark data yet.',
      benchmarks: [],
      metrics: null,
      hasData: false
    });
  }

  // --- STATIC FILES / SPA ROUTING ---
  serveStatic(req, res, pathname);
});

// Start Server with Port Auto-fallback
function startServer(portToTry) {
  server.listen(portToTry, '0.0.0.0', () => {
    console.log('================================================================');
    console.log('  BASELINE SECURITY DEMO — Comparator Server');
    console.log('  Fictional baseline workflow for controlled product comparison');
    console.log('----------------------------------------------------------------');
    console.log(`  Local URL:   http://localhost:${portToTry}`);
    console.log(`  Health API:  http://localhost:${portToTry}/api/health`);
    console.log('  Database:    SQLite (data/baseline_demo.sqlite)');
    console.log('  Agents:      Scanner Agent (Stage 1) -> Report Agent (Stage 2)');
    console.log('  Scope:       Bundled Demo Fixtures & Local Targets Only');
    console.log('================================================================');
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      const nextPort = Number(portToTry) + 1;
      console.warn(`Port ${portToTry} in use, attempting port ${nextPort}...`);
      startServer(nextPort);
    } else {
      console.error('Server error:', err);
    }
  });
}

// Only launch listener if run directly (not imported during tests)
const isTestEnv = process.env.NODE_ENV === 'test' || process.argv.some((arg) => arg.includes('test'));
if (!isTestEnv) {
  startServer(PORT);
}

export default server;
