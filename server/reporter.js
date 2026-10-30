// server/reporter.js
// Report Agent: Groups candidate findings, maps severities, formats generic remediation guidance,
// and generates exportable HTML, JSON, and CSV reports.

export async function runReportAgent({ candidateFindings, scanInfo, onProgress }) {
  const logs = [];
  function log(msg) {
    logs.push(msg);
    if (onProgress) onProgress({ agent: 'Report Agent', message: msg });
  }

  log(`[Report Agent] Received ${candidateFindings.length} candidate finding(s) from Scanner Agent.`);
  log(`[Report Agent] Normalizing severity levels based on predefined rule catalog.`);

  const finalFindings = candidateFindings.map((finding) => {
    log(`[Report Agent] Processing ${finding.ruleId} (${finding.title}) -> Severity: ${finding.severity}`);
    return {
      ...finding,
      scanId: scanInfo.id,
      status: "Needs manual verification",
      verified: false,
      patchAvailable: false,
      remediationSummary: `[Manual Action Required] ${finding.genericRemediation}`
    };
  });

  log(`[Report Agent] Grouped findings: ${finalFindings.length} issue(s) cataloged.`);
  log(`[Report Agent] Limitations recorded: No exploit verification, no patch generation, no regression tests executed.`);
  log(`[Report Agent] Scan report generated and persisted.`);

  return {
    finalFindings,
    logs,
    summary: {
      total: finalFindings.length,
      critical: finalFindings.filter((f) => f.severity === 'Critical').length,
      high: finalFindings.filter((f) => f.severity === 'High').length,
      medium: finalFindings.filter((f) => f.severity === 'Medium').length,
      low: finalFindings.filter((f) => f.severity === 'Low').length,
      info: finalFindings.filter((f) => f.severity === 'Info').length
    }
  };
}

// Generate Downloadable Reports: HTML, JSON, CSV

export function generateHtmlReport(scan) {
  const findingsRows = (scan.findings || [])
    .map(
      (f, idx) => `
      <tr style="border-bottom: 1px solid #e2e8f0;">
        <td style="padding: 12px; font-weight: 600; color: #1e293b;">#${idx + 1}</td>
        <td style="padding: 12px;">
          <span style="display:inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: ${
            f.severity === 'Critical' ? '#fee2e2; color: #991b1b;' :
            f.severity === 'High' ? '#ffedd5; color: #9a3412;' :
            f.severity === 'Medium' ? '#fef3c7; color: #92400e;' :
            '#e0e7ff; color: #3730a3;'
          }">${f.severity}</span>
        </td>
        <td style="padding: 12px;">
          <div style="font-weight: 600; color: #0f172a;">${escapeHtml(f.title)}</div>
          <div style="font-size: 12px; color: #64748b;">${escapeHtml(f.ruleId)} &bull; ${escapeHtml(f.cwe || '')}</div>
        </td>
        <td style="padding: 12px; font-family: monospace; font-size: 12px; color: #334155;">${escapeHtml(f.targetFile)}:${f.line || 1}</td>
        <td style="padding: 12px; font-size: 12px; color: #64748b;">
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 6px; font-family: monospace; max-height: 80px; overflow: hidden; margin-bottom: 6px;">
            ${escapeHtml(f.evidence)}
          </div>
          <div style="margin-top: 4px; color: #475569;"><strong>Manual Guidance:</strong> ${escapeHtml(f.genericRemediation)}</div>
        </td>
        <td style="padding: 12px;">
          <span style="background: #f1f5f9; color: #475569; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">Needs Manual Verification</span>
        </td>
      </tr>
    `
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scan Report: ${escapeHtml(scan.name)} | Baseline Security Demo</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 40px; background: #f8fafc; color: #0f172a; }
    .container { max-width: 1000px; margin: 0 auto; background: #ffffff; padding: 36px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
    .badge-fictional { background: #eff6ff; color: #1d4ed8; padding: 6px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; display: inline-block; border: 1px solid #bfdbfe; margin-bottom: 16px; }
    h1 { margin: 0 0 8px 0; font-size: 24px; color: #0f172a; }
    .meta { color: #64748b; font-size: 14px; margin-bottom: 24px; }
    .limitation-box { background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; padding: 16px; margin: 24px 0; font-size: 13px; color: #92400e; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th { text-align: left; padding: 12px; background: #f1f5f9; font-size: 12px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 2px solid #cbd5e1; }
    .footer { margin-top: 36px; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #f1f5f9; padding-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="badge-fictional">BASELINE SECURITY DEMO &bull; FICTIONAL COMPARATOR</div>
    <h1>Security Scan Report: ${escapeHtml(scan.name)}</h1>
    <div class="meta">
      <strong>Run ID:</strong> ${escapeHtml(scan.id)} &bull; 
      <strong>Target:</strong> ${escapeHtml(scan.target)} &bull; 
      <strong>Timestamp:</strong> ${escapeHtml(scan.startedAt || new Date().toISOString())} &bull; 
      <strong>Execution Mode:</strong> ${scan.isSimulated ? 'Simulated Fixture Run' : 'Live Local Target'} &bull; 
      <strong>Total Elapsed:</strong> ${(scan.elapsedMs / 1000).toFixed(2)}s
    </div>

    <div class="limitation-box">
      <strong>Demo Boundaries & Transparency Notice:</strong><br>
      This report was generated by a fictional, intentionally limited 2-agent baseline comparator (Scanner Agent & Report Agent). 
      Exploitability has <strong>NOT</strong> been autonomously verified. No code patches have been generated, and no regression tests were executed. 
      All findings require manual engineering verification.
    </div>

    <h3>Candidate Findings (${(scan.findings || []).length})</h3>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Severity</th>
          <th>Finding & Rule</th>
          <th>File/Location</th>
          <th>Evidence & Guidance</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${findingsRows || '<tr><td colspan="6" style="padding: 24px; text-align:center; color:#94a3b8;">No findings detected.</td></tr>'}
      </tbody>
    </table>

    <div class="footer">
      Generated by Baseline Security Demo &bull; Controlled Comparator for AEGIS-AGENT Demonstrations &bull; Safe Educational Fixtures
    </div>
  </div>
</body>
</html>`;
}

export function generateJsonReport(scan) {
  return JSON.stringify(
    {
      reportMetadata: {
        generator: "Baseline Security Demo (Fictional 2-Agent Comparator)",
        version: "1.0.0",
        purpose: "Controlled baseline comparison for AEGIS-AGENT demonstrations",
        notice: "Simulated fixture scan. No autonomous exploit verification, patch generation, or PR creation performed.",
        generatedAt: new Date().toISOString()
      },
      scanSummary: {
        runId: scan.id,
        scanName: scan.name,
        target: scan.target,
        fixtureId: scan.fixtureId,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
        elapsedSeconds: (scan.elapsedMs / 1000).toFixed(2),
        isSimulated: scan.isSimulated
      },
      stages: scan.stages,
      findingsCount: (scan.findings || []).length,
      findings: scan.findings || []
    },
    null,
    2
  );
}

export function generateCsvReport(scan) {
  const escapeCsv = (str) => `"${String(str || '').replace(/"/g, '""')}"`;

  const headers = [
    "Scan ID",
    "Scan Name",
    "Target",
    "Rule ID",
    "Finding Title",
    "Severity",
    "Status",
    "File",
    "Line",
    "Why Matched",
    "Generic Remediation",
    "Exploit Verified",
    "Patch Available"
  ].map(escapeCsv);

  const rows = (scan.findings || []).map((f) => [
    escapeCsv(scan.id),
    escapeCsv(scan.name),
    escapeCsv(scan.target),
    escapeCsv(f.ruleId),
    escapeCsv(f.title),
    escapeCsv(f.severity),
    escapeCsv(f.status || 'Needs manual verification'),
    escapeCsv(f.targetFile),
    escapeCsv(f.line || 1),
    escapeCsv(f.whyMatched),
    escapeCsv(f.genericRemediation),
    escapeCsv("FALSE (Not implemented in demo)"),
    escapeCsv("FALSE (No patch generated)")
  ]);

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
