// test/api.test.js
// Automated verification tests using native Node.js test runner (`node:test`).
// Zero test dependencies required.

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

process.env.NODE_ENV = 'test';
process.env.PORT = '5099';

// Import server
import server from '../server.js';
import { getDb } from '../server/db.js';

function request(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 5099,
        ...options
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch (e) {
            // not json
          }
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: data,
            json
          });
        });
      }
    );

    req.on('error', reject);

    if (postData) {
      if (typeof postData === 'object') {
        req.setHeader('Content-Type', 'application/json');
        req.write(JSON.stringify(postData));
      } else {
        req.write(postData);
      }
    }
    req.end();
  });
}

test('Baseline Security Demo Server Test Suite', async (t) => {
  // Start server on test port
  await new Promise((resolve) => server.listen(5099, '127.0.0.1', resolve));

  t.after(() => {
    server.close();
  });

  await t.test('1. Health check returns 200 OK and expected app metadata', async () => {
    const res = await request({ path: '/api/health', method: 'GET' });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json.status, 'ok');
    assert.equal(res.json.app, 'Baseline Security Demo');
    assert.equal(res.json.subtitle, 'Fictional baseline workflow for controlled product comparison');
    assert.ok(res.json.uptimeSeconds >= 0);
  });

  await t.test('2. Fixtures endpoint returns bundled educational fixtures', async () => {
    const res = await request({ path: '/api/fixtures', method: 'GET' });
    assert.equal(res.statusCode, 200);
    assert.ok(Array.isArray(res.json));
    assert.ok(res.json.length >= 3);
    const ecommerce = res.json.find((f) => f.id === 'fixture-ecommerce-api');
    assert.ok(ecommerce);
    assert.equal(ecommerce.name, 'Sample 1: Web App API Gateway');
  });

  await t.test('3. Rules endpoint returns safe predefined check catalog', async () => {
    const res = await request({ path: '/api/rules', method: 'GET' });
    assert.equal(res.statusCode, 200);
    assert.ok(Array.isArray(res.json));
    assert.ok(res.json.some((r) => r.id === 'RULE-SEC-001'));
  });

  await t.test('4. Safety Guardrail: Rejects scans without authorization confirmation', async () => {
    const res = await request(
      { path: '/api/scans', method: 'POST' },
      { fixtureId: 'fixture-ecommerce-api', authorizedConfirmed: false }
    );
    assert.equal(res.statusCode, 400);
    assert.match(res.json.error, /Authorization Required/i);
  });

  await t.test('5. Safety Guardrail: Rejects arbitrary public internet targets', async () => {
    const res = await request(
      { path: '/api/scans', method: 'POST' },
      {
        customTarget: 'https://example.com/exploit',
        authorizedConfirmed: true
      }
    );
    assert.equal(res.statusCode, 400);
    assert.match(res.json.error, /Safety Guardrail Triggered/i);
  });

  await t.test('6. Fixture Workflow: Creates and executes a 2-stage fixture scan', async () => {
    const res = await request(
      { path: '/api/scans', method: 'POST' },
      { fixtureId: 'fixture-internal-admin', authorizedConfirmed: true }
    );
    assert.equal(res.statusCode, 201);
    assert.ok(res.json.id);
    assert.equal(res.json.fixtureId, 'fixture-internal-admin');
    assert.equal(res.json.isSimulated, true);
    assert.ok(res.json.stages.scannerAgent);
    assert.ok(res.json.stages.reportAgent);

    // Give asynchronous execution worker 100ms to persist findings to SQLite
    await new Promise((r) => setTimeout(r, 150));

    // Retrieve scan details
    const scanDetail = await request({ path: `/api/scans/${res.json.id}`, method: 'GET' });
    assert.equal(scanDetail.statusCode, 200);
    assert.equal(scanDetail.json.status, 'completed');
    assert.ok(scanDetail.json.findings.length > 0);

    // Verify all findings have 'Needs manual verification' status
    for (const f of scanDetail.json.findings) {
      assert.equal(f.status, 'Needs manual verification');
      assert.equal(f.verified, false);
      assert.equal(f.patchAvailable, false);
    }
  });

  await t.test('7. Findings API: Lists and filters findings', async () => {
    const res = await request({ path: '/api/findings?severity=High', method: 'GET' });
    assert.equal(res.statusCode, 200);
    assert.ok(Array.isArray(res.json));
    for (const item of res.json) {
      assert.equal(item.severity.toLowerCase(), 'high');
    }
  });

  await t.test('8. Report Export: Downloads HTML, JSON, and CSV formats', async () => {
    // HTML Download
    const htmlRes = await request({ path: '/api/reports/scan-seed-001/download?format=html', method: 'GET' });
    assert.equal(htmlRes.statusCode, 200);
    assert.match(htmlRes.headers['content-type'], /text\/html/);
    assert.match(htmlRes.body, /BASELINE SECURITY DEMO/);
    assert.match(htmlRes.body, /Candidate Findings/);
    assert.match(htmlRes.body, /Needs Manual Verification/);

    // JSON Download
    const jsonRes = await request({ path: '/api/reports/scan-seed-001/download?format=json', method: 'GET' });
    assert.equal(jsonRes.statusCode, 200);
    assert.match(jsonRes.headers['content-type'], /application\/json/);
    assert.equal(jsonRes.json.scanSummary.runId, 'scan-seed-001');
    assert.ok(Array.isArray(jsonRes.json.findings));

    // CSV Download
    const csvRes = await request({ path: '/api/reports/scan-seed-001/download?format=csv', method: 'GET' });
    assert.equal(csvRes.statusCode, 200);
    assert.match(csvRes.headers['content-type'], /text\/csv/);
    assert.match(csvRes.body, /"Scan ID","Scan Name","Target"/);
    assert.match(csvRes.body, /"RULE-SEC-001"/);
  });

  await t.test('9. Benchmark & Comparison: Handles empty state and sample dataset', async () => {
    // Reset benchmarks
    const resetRes = await request({ path: '/api/benchmarks/reset', method: 'POST' });
    assert.equal(resetRes.statusCode, 200);
    assert.equal(resetRes.json.hasData, false);

    // Verify empty state message
    const emptyRes = await request({ path: '/api/benchmarks', method: 'GET' });
    assert.equal(emptyRes.statusCode, 200);
    assert.equal(emptyRes.json.hasData, false);
    assert.equal(emptyRes.json.metrics, null);

    // Load standardized lab suite (N=10)
    const loadRes = await request({ path: '/api/benchmarks/load-sample', method: 'POST' });
    assert.equal(loadRes.statusCode, 200);
    assert.equal(loadRes.json.hasData, true);
    assert.equal(loadRes.json.metrics.sampleSize, 10);
    assert.ok(loadRes.json.metrics.baseline.precision >= 0);
    assert.ok(loadRes.json.metrics.baseline.recall >= 0);
  });

  await t.test('10. Static Assets & SPA Routing: Serves UI and falls back for deep links', async () => {
    // Index page
    const indexRes = await request({ path: '/', method: 'GET' });
    assert.equal(indexRes.statusCode, 200);
    assert.match(indexRes.headers['content-type'], /text\/html/);
    assert.match(indexRes.body, /Baseline Security Demo/);

    // CSS file
    const cssRes = await request({ path: '/css/styles.css', method: 'GET' });
    assert.equal(cssRes.statusCode, 200);
    assert.match(cssRes.headers['content-type'], /text\/css/);
    assert.match(cssRes.body, /--bg-app/);

    // JavaScript app
    const jsRes = await request({ path: '/js/app.js', method: 'GET' });
    assert.equal(jsRes.statusCode, 200);
    assert.match(jsRes.headers['content-type'], /text\/javascript/);
    assert.match(jsRes.body, /initApp/);

    // SPA deep routing fallback (e.g. /findings or /comparison on refresh)
    const deepRes = await request({ path: '/comparison', method: 'GET' });
    assert.equal(deepRes.statusCode, 200);
    assert.match(deepRes.headers['content-type'], /text\/html/);
    assert.match(deepRes.body, /Baseline Security Demo/);
  });
});
