// server/index.js
// Main entry point for Baseline Security Demo backend server

import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

import { SAMPLE_FIXTURES, getFixtureById } from './fixtures.js';
import { PREDEFINED_RULES, getRuleById } from './rules.js';
import {
  initStorage,
  getScans,
  getScanById,
  addScan,
  updateScan,
  getAllFindings,
  getBenchmarks,
  saveBenchmarks,
  resetToSeed
} from './storage.js';
import { runScannerAgent, isTargetAuthorized } from './scanner.js';
import {
  runReportAgent,
  generateHtmlReport,
  generateJsonReport,
  generateCsvReport
} from './reporter.js';
import {
  FEATURE_MATRIX,
  STANDARDIZED_LAB_DATASET,
  calculateMetrics
} from './benchmarks.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize persistent storage
initStorage();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'Baseline Security Demo',
    subtitle: 'Fictional baseline workflow for controlled product comparison',
    version: '1.0.0',
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

// Fixtures
app.get('/api/fixtures', (req, res) => {
  res.json(SAMPLE_FIXTURES);
});

app.get('/api/fixtures/:id', (req, res) => {
  const fixture = getFixtureById(req.params.id);
  if (!fixture) {
    return res.status(404).json({ error: 'Fixture not found' });
  }
  res.json(fixture);
});

// Predefined Rules
app.get('/api/rules', (req, res) => {
  res.json(PREDEFINED_RULES);
});

// Scans API
app.get('/api/scans', (req, res) => {
  res.json(getScans());
});

app.get('/api/scans/:id', (req, res) => {
  const scan = getScanById(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  res.json(scan);
});

// Trigger a new Scan (Sequential 2-Agent Workflow)
app.post('/api/scans', async (req, res) => {
  const { fixtureId, customTarget, authorizedConfirmed } = req.body;

  if (!authorizedConfirmed) {
    return res.status(400).json({
      error: 'Authorization Required: You must confirm the scan scope before launching.'
    });
  }

  const fixture = fixtureId ? getFixtureById(fixtureId) : null;
  const target = fixture ? fixture.targetUri : (customTarget || '').trim();

  // Safety constraint: Reject arbitrary external internet targets
  if (!isTargetAuthorized(target)) {
    return res.status(400).json({
      error: 'Safety Guardrail Triggered: Arbitrary internet scanning is strictly disabled. You may only scan approved bundled demo fixtures or local loopback training targets (localhost / 127.0.0.1).'
    });
  }

  const scanId = `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const scanName = fixture ? fixture.name : `Local Target Scan (${target})`;
  const startedAt = new Date().toISOString();

  // Initialize new scan record
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
    findings: []
  };

  addScan(newScan);

  // Return scan id immediately so frontend can navigate to progress view
  res.status(201).json(newScan);

  // Execute two-agent workflow asynchronously with realistic stage timings
  (async () => {
    try {
      const startTime = Date.now();

      // Stage 1: Scanner Agent
      const scannerResult = await runScannerAgent({
        fixtureId,
        customTarget: target,
        onProgress: (p) => {
          newScan.stages.scannerAgent.logs.push(p.message);
          updateScan(scanId, { stages: newScan.stages });
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
      updateScan(scanId, { stages: newScan.stages });

      const reportResult = await runReportAgent({
        candidateFindings: scannerResult.candidateFindings,
        scanInfo: newScan,
        onProgress: (p) => {
          newScan.stages.reportAgent.logs.push(p.message);
          updateScan(scanId, { stages: newScan.stages });
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
      newScan.findings = reportResult.finalFindings;

      updateScan(scanId, newScan);
    } catch (err) {
      console.error(`Error during scan ${scanId}:`, err);
      newScan.status = 'failed';
      newScan.error = err.message;
      updateScan(scanId, newScan);
    }
  })();
});

// Reset scan history back to demo seed
app.post('/api/scans/reset', (req, res) => {
  const resetDb = resetToSeed();
  res.json({ message: 'Database reset to initial demo seeds.', scans: resetDb.scans });
});

// Findings API
app.get('/api/findings', (req, res) => {
  const { severity, query, ruleId, scanId } = req.query;
  let findings = getAllFindings();

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

  res.json(findings);
});

app.get('/api/findings/:id', (req, res) => {
  const all = getAllFindings();
  const finding = all.find((f) => f.id === req.params.id);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }
  res.json(finding);
});

// Reports & Downloads (HTML, JSON, CSV)
app.get('/api/reports/:id', (req, res) => {
  const scan = getScanById(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Report not found' });
  }
  res.json({
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
});

app.get('/api/reports/:id/download', (req, res) => {
  const scan = getScanById(req.params.id);
  if (!scan) {
    return res.status(404).send('Report not found');
  }

  const format = (req.query.format || 'html').toLowerCase();

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${scan.id}-report.json"`);
    return res.send(generateJsonReport(scan));
  }

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${scan.id}-report.csv"`);
    return res.send(generateCsvReport(scan));
  }

  // Default: HTML
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${scan.id}-report.html"`);
  return res.send(generateHtmlReport(scan));
});

// Comparison & Benchmarks API
app.get('/api/comparison/matrix', (req, res) => {
  res.json(FEATURE_MATRIX);
});

app.get('/api/benchmarks', (req, res) => {
  const benchmarks = getBenchmarks();
  const metrics = calculateMetrics(benchmarks);
  res.json({
    benchmarks,
    metrics,
    hasData: benchmarks && benchmarks.length > 0
  });
});

// Import benchmark test results (JSON array of test cases)
app.post('/api/benchmarks', (req, res) => {
  const { testCases } = req.body;
  if (!Array.isArray(testCases) || testCases.length === 0) {
    return res.status(400).json({ error: 'Invalid benchmark data: testCases array required.' });
  }

  saveBenchmarks(testCases);
  const metrics = calculateMetrics(testCases);
  res.json({
    message: `Successfully imported ${testCases.length} benchmark test case(s).`,
    benchmarks: testCases,
    metrics,
    hasData: true
  });
});

// Load pre-measured standardized lab dataset (N=10)
app.post('/api/benchmarks/load-sample', (req, res) => {
  saveBenchmarks(STANDARDIZED_LAB_DATASET.testCases);
  const metrics = calculateMetrics(STANDARDIZED_LAB_DATASET.testCases);
  res.json({
    message: 'Loaded standardized lab benchmark dataset (N=10).',
    datasetInfo: STANDARDIZED_LAB_DATASET.metadata,
    benchmarks: STANDARDIZED_LAB_DATASET.testCases,
    metrics,
    hasData: true
  });
});

// Reset benchmarks back to empty state: "No benchmark data yet"
app.post('/api/benchmarks/reset', (req, res) => {
  saveBenchmarks([]);
  res.json({
    message: 'Benchmark dataset reset. Status: No benchmark data yet.',
    benchmarks: [],
    metrics: null,
    hasData: false
  });
});

// Serve frontend static assets in production
const clientDistPath = path.resolve(__dirname, '../dist');
if (fs.existsSync(clientDistPath)) {
  app.use(express.static(clientDistPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(clientDistPath, 'index.html'));
  });
}

// Start Server
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`Baseline Security Demo server listening on http://localhost:${PORT}`);
  });
}

export default app;
