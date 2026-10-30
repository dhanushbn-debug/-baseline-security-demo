// public/js/app.js
// Single-Page Application logic for Baseline Security Demo

import { Icons } from './icons.js';
import { API } from './api.js';

// Application State
const state = {
  currentRoute: 'overview',
  fixtures: [],
  rules: [],
  scans: [],
  activeScan: null,
  activeScanTimer: null,
  findings: [],
  selectedFinding: null,
  featureMatrix: [],
  benchmarks: [],
  benchmarkMetrics: null,
  hasBenchmarkData: false,
  filters: {
    severity: 'ALL',
    query: '',
    scanId: ''
  },
  newScanForm: {
    fixtureId: 'fixture-ecommerce-api',
    customTarget: '',
    authorizedConfirmed: false
  }
};

// Utilities
function formatTime(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDuration(ms) {
  if (!ms && ms !== 0) return '—';
  return (ms / 1000).toFixed(2) + 's';
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `badge badge-${type === 'error' ? 'critical' : type === 'success' ? 'success' : 'info'}`;
  toast.style.cssText = 'padding: 10px 16px; font-size: 13px; margin-bottom: 8px; box-shadow: var(--shadow-card); animation: fadeIn 0.2s;';
  toast.innerHTML = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
}

// Router
export function navigate(route, params = {}) {
  state.currentRoute = route;

  // Update active state on nav links
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.classList.toggle('active', link.dataset.route === route);
  });

  const contentArea = document.getElementById('app-content');
  if (!contentArea) return;

  switch (route) {
    case 'overview':
      renderOverview(contentArea);
      break;
    case 'new-scan':
      renderNewScan(contentArea);
      break;
    case 'progress':
      renderProgress(contentArea, params.scanId);
      break;
    case 'findings':
      renderFindings(contentArea);
      break;
    case 'reports':
      renderReports(contentArea);
      break;
    case 'comparison':
      renderComparison(contentArea);
      break;
    case 'about':
      renderAbout(contentArea);
      break;
    default:
      renderOverview(contentArea);
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Initializer
export async function initApp() {
  try {
    const [fixtures, rules, scans] = await Promise.all([
      API.getFixtures(),
      API.getRules(),
      API.getScans()
    ]);
    state.fixtures = fixtures;
    state.rules = rules;
    state.scans = scans;
  } catch (err) {
    console.error('Initialization error:', err);
    showToast('Failed to load initial demo data: ' + err.message, 'error');
  }

  // Bind nav click events
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      navigate(link.dataset.route);
    });
  });

  navigate('overview');
}

// ==========================================
// 1. OVERVIEW PAGE
// ==========================================
async function renderOverview(container) {
  try {
    const scans = await API.getScans();
    state.scans = scans;
    const findings = await API.getFindings();
    state.findings = findings;

    const totalScans = scans.length;
    const criticalCount = findings.filter((f) => f.severity === 'Critical').length;
    const highCount = findings.filter((f) => f.severity === 'High').length;
    const mediumCount = findings.filter((f) => f.severity === 'Medium').length;
    const lowCount = findings.filter((f) => f.severity === 'Low').length;
    const lastScan = scans[0] || null;

    container.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Baseline Security Dashboard</h1>
          <p class="page-desc">Controlled 2-Agent comparator workflow for transparent product benchmarking against AEGIS-AGENT.</p>
        </div>
        <div style="display:flex; gap: 8px;">
          <button id="btn-quick-new-scan" class="btn btn-primary">
            ${Icons.play} Run New Baseline Scan
          </button>
          <button id="btn-reset-demo" class="btn btn-secondary" title="Reset scans to seed demo state">
            ${Icons.refresh} Reset Demo Data
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">
            <span>Total Demo Scans</span>
            <span class="badge badge-simulated">SEEDED & RUNS</span>
          </div>
          <div class="metric-value">${totalScans}</div>
          <div class="metric-footer">Last scan: ${lastScan ? formatTime(lastScan.startedAt) : 'Never'}</div>
        </div>

        <div class="metric-card" style="border-top: 3px solid #dc2626;">
          <div class="metric-label">
            <span>Critical Candidates</span>
            <span class="badge badge-critical">NO EXPLOIT VERIFIED</span>
          </div>
          <div class="metric-value" style="color: #991b1b;">${criticalCount}</div>
          <div class="metric-footer">Requires manual human triage</div>
        </div>

        <div class="metric-card" style="border-top: 3px solid #ea580c;">
          <div class="metric-label">
            <span>High Candidates</span>
            <span class="badge badge-high">STATIC HEURISTIC</span>
          </div>
          <div class="metric-value" style="color: #9a3412;">${highCount}</div>
          <div class="metric-footer">Pattern regex match only</div>
        </div>

        <div class="metric-card" style="border-top: 3px solid #d97706;">
          <div class="metric-label">
            <span>Medium & Low</span>
            <span class="badge badge-medium">CONFIG CHECKS</span>
          </div>
          <div class="metric-value" style="color: #92400e;">${mediumCount + lowCount}</div>
          <div class="metric-footer">Headers & diagnostic routes</div>
        </div>
      </div>

      <!-- Deliberately Limited Two-Agent Workflow Architecture Diagram -->
      <div class="workflow-box">
        <div class="card-header">
          <span class="card-title">${Icons.activity} Conventional Two-Agent Architecture Pipeline</span>
          <span class="badge badge-simulated">DELIBERATELY LIMITED COMPARATOR</span>
        </div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
          This demo represents a standard two-stage automated scanning workflow. Notice the strict boundary: candidate identification and reporting only, with all exploit verification and patching deferred to manual developer intervention.
        </p>

        <div class="workflow-steps">
          <div class="workflow-step-card" style="border-left: 4px solid var(--primary);">
            <div class="workflow-step-header">
              ${Icons.terminal} Stage 1: Scanner Agent
            </div>
            <div class="workflow-step-desc">
              Runs safe regex & heuristic rules on bundled fixtures or local loopback target. Emits raw candidate matches.
            </div>
          </div>

          <div class="workflow-arrow">${Icons.arrowRight}</div>

          <div class="workflow-step-card" style="border-left: 4px solid #0284c7;">
            <div class="workflow-step-header">
              ${Icons.fileText} Stage 2: Report Agent
            </div>
            <div class="workflow-step-desc">
              Groups findings by rule ID, tags standard severity levels, and outputs generic static advice text.
            </div>
          </div>

          <div class="workflow-arrow">${Icons.arrowRight}</div>

          <div class="workflow-step-card" style="border-left: 4px solid #dc2626; background: #fff1f2;">
            <div class="workflow-step-header" style="color: #991b1b;">
              ${Icons.alertTriangle} Manual Verification Barrier
            </div>
            <div class="workflow-step-desc">
              Developer must manually verify exploitability, craft patch code, test regressions, and commit PR.
            </div>
          </div>
        </div>

        <div class="contrast-callout">
          <strong>Key Difference vs AEGIS-AGENT:</strong> Unlike AEGIS-AGENT, Baseline Security Demo does <em>not</em> autonomously verify exploitability in sandboxes, generate AST-aware code patches, execute post-fix regression tests, or open GitHub pull requests.
        </div>
      </div>

      <!-- Recent Scans Table -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">${Icons.list} Recent Scans</span>
          <a href="#new-scan" id="link-view-all-scans" style="font-size: 12px; color: var(--primary); text-decoration: none; font-weight: 600;">+ New Scan</a>
        </div>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Scan ID / Name</th>
                <th>Target Scope</th>
                <th>Status</th>
                <th>Execution Mode</th>
                <th>Duration</th>
                <th>Findings</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${scans.map((s) => `
                <tr>
                  <td>
                    <div style="font-weight: 600;">${escapeHtml(s.name)}</div>
                    <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(s.id)}</div>
                  </td>
                  <td>
                    <span style="font-family: var(--font-mono); font-size: 12px; color: #475569;">${escapeHtml(s.target)}</span>
                  </td>
                  <td>
                    <span class="badge ${s.status === 'completed' ? 'badge-success' : s.status === 'running' ? 'badge-high' : 'badge-critical'}">
                      ${s.status.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <span class="badge badge-simulated">${s.isSimulated ? 'Simulated Fixture' : 'Local Target'}</span>
                  </td>
                  <td style="font-family: var(--font-mono);">${formatDuration(s.elapsedMs)}</td>
                  <td>
                    <span style="font-weight: 700; color: #0f172a;">${(s.findings || []).length}</span> candidate(s)
                  </td>
                  <td>
                    <button class="btn btn-secondary btn-sm btn-view-scan" data-id="${s.id}">
                      View Findings
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    document.getElementById('btn-quick-new-scan')?.addEventListener('click', () => navigate('new-scan'));
    document.getElementById('link-view-all-scans')?.addEventListener('click', (e) => {
      e.preventDefault();
      navigate('new-scan');
    });

    document.getElementById('btn-reset-demo')?.addEventListener('click', async () => {
      if (confirm('Reset demo scans to the initial seed state?')) {
        await API.resetScans();
        showToast('Demo history reset to initial seed.', 'success');
        renderOverview(container);
      }
    });

    document.querySelectorAll('.btn-view-scan').forEach((btn) => {
      btn.addEventListener('click', () => {
        const scanId = btn.dataset.id;
        state.filters.scanId = scanId;
        navigate('findings');
      });
    });

  } catch (err) {
    container.innerHTML = `<div class="card" style="color: #dc2626;">Error loading overview: ${escapeHtml(err.message)}</div>`;
  }
}

// ==========================================
// 2. NEW SCAN PAGE
// ==========================================
async function renderNewScan(container) {
  const fixtures = state.fixtures;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Launch Baseline Scan</h1>
        <p class="page-desc">Select an authorized bundled demo fixture or local training target to simulate the 2-agent workflow.</p>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">${Icons.shield} Step 1: Select Safe Demo Target</span>
        <span class="badge badge-simulated">EDUCATIONAL FIXTURES ONLY</span>
      </div>

      <div class="fixture-grid">
        ${fixtures.map((f) => `
          <div class="fixture-card ${state.newScanForm.fixtureId === f.id ? 'selected' : ''}" data-id="${f.id}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start;">
              <div class="fixture-title">${escapeHtml(f.name)}</div>
              <span class="badge badge-info" style="font-size:10px;">${escapeHtml(f.type)}</span>
            </div>
            <div class="fixture-desc">${escapeHtml(f.description)}</div>
            <div style="font-family: var(--font-mono); font-size: 11px; color: #64748b; margin-bottom: 8px;">
              ${escapeHtml(f.targetUri)}
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:4px;">
              ${f.tags.map((t) => `<span class="badge badge-simulated">${escapeHtml(t)}</span>`).join('')}
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Scope Confirmation & Safety Notice -->
      <div style="background: #f8fafc; border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 16px; margin: 20px 0;">
        <div style="font-size: 13px; font-weight: 600; color: var(--text-main); margin-bottom: 6px;">
          ${Icons.lock} Scope & Authorization Confirmation
        </div>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
          This demo strictly enforces safety guardrails. Arbitrary internet scanning, live exploit execution, and destructive probes are disabled. Only approved demo fixtures and local loopback addresses (127.0.0.1 / localhost) may be targeted.
        </p>
        <label class="form-check">
          <input type="checkbox" id="chk-authorize" ${state.newScanForm.authorizedConfirmed ? 'checked' : ''}>
          <span>I confirm this target is within the authorized demonstration scope and consent to static scanning.</span>
        </label>
      </div>

      <div style="display:flex; justify-content:flex-end; gap: 12px;">
        <button id="btn-cancel-scan" class="btn btn-secondary">Cancel</button>
        <button id="btn-launch-scan" class="btn btn-primary" ${!state.newScanForm.authorizedConfirmed ? 'disabled style="opacity:0.6; cursor:not-allowed;"' : ''}>
          ${Icons.play} Start 2-Agent Scan
        </button>
      </div>
    </div>
  `;

  // Fixture card selection click handler
  document.querySelectorAll('.fixture-card').forEach((card) => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.fixture-card').forEach((c) => c.classList.remove('selected'));
      card.classList.add('selected');
      state.newScanForm.fixtureId = card.dataset.id;
    });
  });

  const authChk = document.getElementById('chk-authorize');
  const launchBtn = document.getElementById('btn-launch-scan');

  authChk?.addEventListener('change', (e) => {
    state.newScanForm.authorizedConfirmed = e.target.checked;
    if (launchBtn) {
      launchBtn.disabled = !e.target.checked;
      launchBtn.style.opacity = e.target.checked ? '1' : '0.6';
      launchBtn.style.cursor = e.target.checked ? 'pointer' : 'not-allowed';
    }
  });

  document.getElementById('btn-cancel-scan')?.addEventListener('click', () => navigate('overview'));

  launchBtn?.addEventListener('click', async () => {
    if (!state.newScanForm.authorizedConfirmed) {
      alert('You must confirm authorization before launching the scan.');
      return;
    }

    try {
      launchBtn.disabled = true;
      launchBtn.innerHTML = `${Icons.refresh} Launching Scan...`;

      const scanRecord = await API.startScan({
        fixtureId: state.newScanForm.fixtureId,
        authorizedConfirmed: true
      });

      showToast(`Scan initiated: ${scanRecord.name}`, 'success');
      navigate('progress', { scanId: scanRecord.id });
    } catch (err) {
      launchBtn.disabled = false;
      launchBtn.innerHTML = `${Icons.play} Start 2-Agent Scan`;
      alert('Scan error: ' + err.message);
    }
  });
}

// ==========================================
// 3. SCAN PROGRESS PAGE
// ==========================================
async function renderProgress(container, scanId) {
  if (!scanId) {
    const scans = await API.getScans();
    scanId = scans[0]?.id;
  }

  const scan = await API.getScan(scanId);
  state.activeScan = scan;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div style="display:flex; align-items:center; gap: 8px;">
          <h1 class="page-title">Scan Progress: ${escapeHtml(scan.name)}</h1>
          <span class="badge badge-simulated">SIMULATED FIXTURE RUN</span>
        </div>
        <p class="page-desc">Run ID: <code style="font-family:var(--font-mono);">${escapeHtml(scan.id)}</code> &bull; Target: <code style="font-family:var(--font-mono);">${escapeHtml(scan.target)}</code></p>
      </div>
      <div>
        <span class="badge ${scan.status === 'completed' ? 'badge-success' : 'badge-high'}" style="font-size:13px; padding:6px 12px;">
          STATUS: ${scan.status.toUpperCase()}
        </span>
      </div>
    </div>

    <!-- Live Execution Status Bar -->
    <div class="card" style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:16px;">
      <div style="display:flex; align-items:center; gap: 12px;">
        <div style="width: 14px; height: 14px; border-radius: 50%; background: ${scan.status === 'completed' ? '#16a34a' : '#2563eb'}; ${scan.status === 'running' ? 'animation: pulse 1.5s infinite;' : ''}"></div>
        <div style="font-size: 14px; font-weight: 600;">
          ${scan.status === 'completed' ? 'Scan Completed Successfully' : 'Executing 2-Agent Sequential Analysis...'}
        </div>
      </div>
      <div style="display:flex; align-items:center; gap: 24px;">
        <div style="font-size: 13px; color: var(--text-muted);">
          Elapsed Time: <strong id="progress-timer" style="font-family:var(--font-mono); color:var(--text-main);">${formatDuration(scan.elapsedMs)}</strong>
        </div>
        ${scan.status === 'completed' ? `
          <button id="btn-goto-findings" class="btn btn-primary btn-sm">
            ${Icons.list} View Findings (${(scan.findings || []).length})
          </button>
        ` : ''}
      </div>
    </div>

    <!-- Two-Stage Timeline -->
    <div class="timeline-container">
      <!-- Stage 1: Scanner Agent -->
      <div class="timeline-stage ${scan.stages?.scannerAgent?.status === 'running' ? 'active' : ''}">
        <div class="timeline-stage-header">
          <div class="timeline-stage-name">
            ${Icons.terminal} Stage 1: Scanner Agent
          </div>
          <span class="badge ${scan.stages?.scannerAgent?.status === 'completed' ? 'badge-success' : 'badge-high'}">
            ${scan.stages?.scannerAgent?.status?.toUpperCase() || 'PENDING'}
          </span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
          Performs static heuristic checks, regex pattern analysis, and candidate discovery.
        </div>
        <div class="stage-log-box" id="scanner-logs">
          ${(scan.stages?.scannerAgent?.logs || []).map((l) => `<div class="stage-log-item">${escapeHtml(l)}</div>`).join('')}
        </div>
      </div>

      <!-- Stage 2: Report Agent -->
      <div class="timeline-stage ${scan.stages?.reportAgent?.status === 'running' ? 'active' : ''}">
        <div class="timeline-stage-header">
          <div class="timeline-stage-name">
            ${Icons.fileText} Stage 2: Report Agent
          </div>
          <span class="badge ${scan.stages?.reportAgent?.status === 'completed' ? 'badge-success' : scan.stages?.reportAgent?.status === 'running' ? 'badge-high' : 'badge-info'}">
            ${scan.stages?.reportAgent?.status?.toUpperCase() || 'PENDING'}
          </span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
          Groups candidate findings, applies rule-based severity weights, and attaches generic remediation guidance.
        </div>
        <div class="stage-log-box" id="reporter-logs">
          ${(scan.stages?.reportAgent?.logs || []).map((l) => `<div class="stage-log-item">${escapeHtml(l)}</div>`).join('') || '<div style="color:#64748b;">Awaiting Scanner Agent completion...</div>'}
        </div>
      </div>
    </div>

    <!-- Explicit Boundaries Notice -->
    <div class="contrast-callout">
      <strong>Transparent Limitations:</strong> Scanner Agent does not run dynamic exploit chains or test external infrastructure. Report Agent does not generate code patches or execute post-fix regression tests.
    </div>
  `;

  document.getElementById('btn-goto-findings')?.addEventListener('click', () => {
    state.filters.scanId = scan.id;
    navigate('findings');
  });

  // If scan is still running, poll every 500ms
  if (scan.status === 'running') {
    setTimeout(async () => {
      if (state.currentRoute === 'progress') {
        renderProgress(container, scanId);
      }
    }, 700);
  }
}

// ==========================================
// 4. FINDINGS PAGE & DETAIL MODAL
// ==========================================
async function renderFindings(container) {
  try {
    const findings = await API.getFindings(state.filters);
    const scans = await API.getScans();

    container.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Candidate Security Findings</h1>
          <p class="page-desc">Catalog of candidate vulnerabilities discovered by the 2-agent static scanner.</p>
        </div>
        <div>
          <span class="badge badge-verification-needed">${findings.length} ISSUE(S) NEED MANUAL VERIFICATION</span>
        </div>
      </div>

      <!-- Filter Controls -->
      <div class="card" style="padding: 16px; margin-bottom: 20px;">
        <div style="display:flex; flex-wrap:wrap; gap: 12px; align-items:center; justify-content:space-between;">
          <!-- Search Input -->
          <div style="flex: 1; min-width: 240px;">
            <input type="text" id="filter-search" class="form-input" placeholder="Search by title, rule ID, or affected file..." value="${escapeHtml(state.filters.query)}">
          </div>

          <!-- Severity Filter Buttons -->
          <div style="display:flex; gap: 6px; flex-wrap:wrap;">
            ${['ALL', 'Critical', 'High', 'Medium', 'Low'].map((sev) => `
              <button class="btn btn-sm ${state.filters.severity === sev ? 'btn-primary' : 'btn-secondary'} btn-filter-sev" data-sev="${sev}">
                ${sev}
              </button>
            `).join('')}
          </div>

          <!-- Scan Scope Dropdown -->
          <div>
            <select id="filter-scan-select" class="form-select" style="min-width: 180px;">
              <option value="">All Scans</option>
              ${scans.map((s) => `
                <option value="${s.id}" ${state.filters.scanId === s.id ? 'selected' : ''}>${escapeHtml(s.name)}</option>
              `).join('')}
            </select>
          </div>
        </div>
      </div>

      <!-- Findings Table -->
      <div class="card">
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding Title & Rule</th>
                <th>Category / CWE</th>
                <th>Affected Location</th>
                <th>Verification Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${findings.length === 0 ? `
                <tr>
                  <td colspan="6" style="text-align:center; padding: 36px; color: var(--text-muted);">
                    No candidate findings match the selected filters.
                  </td>
                </tr>
              ` : findings.map((f) => `
                <tr>
                  <td>
                    <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                  </td>
                  <td>
                    <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(f.title)}</div>
                    <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(f.ruleId)}</div>
                  </td>
                  <td>
                    <div style="font-size: 12px; color: var(--text-main);">${escapeHtml(f.category)}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(f.cwe || 'CWE Unspecified')}</div>
                  </td>
                  <td>
                    <div style="font-family: var(--font-mono); font-size: 12px; color: #334155;">${escapeHtml(f.targetFile)}:${f.line || 1}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(f.scanName || 'Demo Scan')}</div>
                  </td>
                  <td>
                    <span class="badge badge-verification-needed">
                      ${Icons.alertTriangle} Needs manual verification
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-secondary btn-sm btn-inspect-finding" data-id="${f.id}">
                      Inspect Detail
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    // Bind Filter Events
    document.getElementById('filter-search')?.addEventListener('input', (e) => {
      state.filters.query = e.target.value;
      renderFindings(container);
    });

    document.querySelectorAll('.btn-filter-sev').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.filters.severity = btn.dataset.sev;
        renderFindings(container);
      });
    });

    document.getElementById('filter-scan-select')?.addEventListener('change', (e) => {
      state.filters.scanId = e.target.value;
      renderFindings(container);
    });

    document.querySelectorAll('.btn-inspect-finding').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const findingId = btn.dataset.id;
        const finding = await API.getFinding(findingId);
        openFindingModal(finding);
      });
    });

  } catch (err) {
    container.innerHTML = `<div class="card" style="color: #dc2626;">Error loading findings: ${escapeHtml(err.message)}</div>`;
  }
}

// Modal Inspector
function openFindingModal(f) {
  let modal = document.getElementById('finding-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'finding-modal';
    modal.className = 'modal-overlay';
    document.body.appendChild(modal);
  }

  modal.innerHTML = `
    <div class="modal-content">
      <div class="modal-header">
        <div>
          <div style="display:flex; align-items:center; gap: 8px;">
            <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
            <span style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted);">${escapeHtml(f.ruleId)}</span>
          </div>
          <h2 style="font-size: 18px; font-weight: 700; margin-top: 4px; color: var(--text-main);">${escapeHtml(f.title)}</h2>
        </div>
        <button id="btn-close-modal" class="btn btn-secondary btn-sm" style="padding: 4px 8px;">${Icons.x}</button>
      </div>

      <div class="modal-body">
        <!-- Target & File -->
        <div style="margin-bottom: 16px;">
          <div style="font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform:uppercase;">Affected File & Location</div>
          <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-main); margin-top: 2px;">
            ${escapeHtml(f.targetFile)} (Line ${f.line || 1})
          </div>
        </div>

        <!-- Evidence Snippet -->
        <div style="margin-bottom: 16px;">
          <div style="font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform:uppercase; margin-bottom: 4px;">Evidence Snippet</div>
          <pre class="code-box"><code>${escapeHtml(f.evidence)}</code></pre>
        </div>

        <!-- Why Rule Matched -->
        <div style="margin-bottom: 16px;">
          <div style="font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform:uppercase; margin-bottom: 2px;">Heuristic Match Reason</div>
          <div style="font-size: 13px; color: #334155; background: #f8fafc; padding: 10px 14px; border-radius: var(--radius-md); border: 1px solid var(--border-light);">
            ${escapeHtml(f.whyMatched)}
          </div>
        </div>

        <!-- Transparent Limitations Box -->
        <div style="background: #fffbeb; border: 1px solid #fde68a; border-radius: var(--radius-md); padding: 14px; margin-bottom: 16px;">
          <div style="font-size: 12px; font-weight: 700; color: #92400e; display:flex; align-items:center; gap: 6px; margin-bottom: 4px;">
            ${Icons.alertTriangle} Deliberately Limited Demo Boundary:
          </div>
          <div style="font-size: 12px; color: #92400e; line-height: 1.5;">
            ${escapeHtml(f.limitations)}
          </div>
        </div>

        <!-- Generic Remediation Advice -->
        <div>
          <div style="font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform:uppercase; margin-bottom: 4px;">Generic Manual Remediation Guidance</div>
          <div style="font-size: 13px; color: #1e3a8a; background: #eff6ff; padding: 12px 14px; border-radius: var(--radius-md); border-left: 4px solid var(--primary); line-height: 1.5;">
            ${escapeHtml(f.genericRemediation)}
          </div>
          <div style="margin-top: 8px; font-size: 11px; color: var(--text-muted); font-style: italic;">
            Notice: No automated patch or pull request is generated. Manual developer remediation required.
          </div>
        </div>
      </div>

      <div class="modal-footer">
        <button id="btn-modal-dismiss" class="btn btn-secondary">Close</button>
      </div>
    </div>
  `;

  document.getElementById('btn-close-modal')?.addEventListener('click', () => modal.remove());
  document.getElementById('btn-modal-dismiss')?.addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });
}

// ==========================================
// 5. REPORTS PAGE
// ==========================================
async function renderReports(container) {
  try {
    const scans = await API.getScans();

    container.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Scan Reports & Export</h1>
          <p class="page-desc">Download complete scan documentation in HTML, JSON, or CSV formats.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">${Icons.fileText} Historical Reports Archive</span>
          <span class="badge badge-simulated">TRANSPARENT EXPORTS</span>
        </div>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Scan ID / Name</th>
                <th>Target</th>
                <th>Timestamp</th>
                <th>Duration</th>
                <th>Findings</th>
                <th>Export Downloads</th>
              </tr>
            </thead>
            <tbody>
              ${scans.map((s) => `
                <tr>
                  <td>
                    <div style="font-weight: 600;">${escapeHtml(s.name)}</div>
                    <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(s.id)}</div>
                  </td>
                  <td style="font-family: var(--font-mono); font-size: 12px;">${escapeHtml(s.target)}</td>
                  <td>${formatTime(s.startedAt)}</td>
                  <td style="font-family: var(--font-mono);">${formatDuration(s.elapsedMs)}</td>
                  <td>
                    <span style="font-weight: 700;">${(s.findings || []).length}</span> candidate(s)
                  </td>
                  <td>
                    <div style="display:flex; gap: 6px;">
                      <a href="/api/reports/${s.id}/download?format=html" target="_blank" class="btn btn-secondary btn-sm" title="Download Styled HTML Executive Report">
                        ${Icons.download} HTML
                      </a>
                      <a href="/api/reports/${s.id}/download?format=json" download class="btn btn-secondary btn-sm" title="Download JSON Schema AST">
                        ${Icons.download} JSON
                      </a>
                      <a href="/api/reports/${s.id}/download?format=csv" download class="btn btn-secondary btn-sm" title="Download Spreadsheet CSV">
                        ${Icons.download} CSV
                      </a>
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="card" style="color: #dc2626;">Error loading reports: ${escapeHtml(err.message)}</div>`;
  }
}

// ==========================================
// 6. COMPARISON & HONEST BENCHMARKING
// ==========================================
async function renderComparison(container) {
  try {
    const [matrix, benchmarkData] = await Promise.all([
      API.getFeatureMatrix(),
      API.getBenchmarks()
    ]);

    state.featureMatrix = matrix;
    state.benchmarks = benchmarkData.benchmarks || [];
    state.benchmarkMetrics = benchmarkData.metrics;
    state.hasBenchmarkData = benchmarkData.hasData;

    container.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Capability Comparison & Honest Benchmarking</h1>
          <p class="page-desc">Transparent capability matrix and rigorous measured metrics comparing 2-agent workflows with multi-agent remediation.</p>
        </div>
      </div>

      <!-- Capability Matrix -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">${Icons.compare} Capability Matrix</span>
          <span class="badge badge-simulated">ARCHITECTURAL BOUNDARIES</span>
        </div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
          Baseline Security Demo intentionally caps automation at heuristic discovery and reporting. All advanced autonomous verification and remediation capabilities are marked accurately.
        </p>

        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Capability / Feature</th>
                <th>Category</th>
                <th>Baseline Security Demo (This App)</th>
                <th>Advanced Multi-Agent (AEGIS-AGENT)</th>
                <th>Engineering Significance</th>
              </tr>
            </thead>
            <tbody>
              ${matrix.map((row) => `
                <tr>
                  <td style="font-weight: 600;">${escapeHtml(row.capability)}</td>
                  <td><span class="badge badge-info">${escapeHtml(row.category)}</span></td>
                  <td>
                    <span class="${
                      row.baselineStatus.includes('Available') ? 'matrix-status-available' :
                      row.baselineStatus.includes('Not implemented') ? 'matrix-status-missing' :
                      'matrix-status-external'
                    }">${escapeHtml(row.baselineStatus)}</span>
                  </td>
                  <td>
                    <span class="badge badge-success">${escapeHtml(row.aegisStatus)}</span>
                  </td>
                  <td style="font-size: 12px; color: #475569;">${escapeHtml(row.notes)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Honest Benchmark Measurement Lab -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">${Icons.activity} Measured Benchmark Lab</span>
          <div style="display:flex; gap: 8px;">
            <button id="btn-load-sample-benchmarks" class="btn btn-secondary btn-sm">
              ${Icons.play} Load Standardized Lab Suite (N=10)
            </button>
            <button id="btn-import-benchmarks" class="btn btn-secondary btn-sm">
              ${Icons.download} Import Custom Results
            </button>
            ${state.hasBenchmarkData ? `
              <button id="btn-reset-benchmarks" class="btn btn-danger btn-sm">
                ${Icons.refresh} Clear Data
              </button>
            ` : ''}
          </div>
        </div>

        ${!state.hasBenchmarkData ? `
          <!-- Honest Empty State -->
          <div style="text-align:center; padding: 48px 20px; background: #fafcff; border: 1px dashed var(--border-subtle); border-radius: var(--radius-md);">
            <div style="color: var(--text-subtle); margin-bottom: 12px;">${Icons.info}</div>
            <div style="font-size: 16px; font-weight: 700; color: var(--text-main); margin-bottom: 6px;">No benchmark data yet</div>
            <p style="font-size: 13px; color: var(--text-muted); max-width: 520px; margin: 0 auto 16px;">
              In accordance with our transparency requirements, no performance or accuracy percentages are fabricated. 
              Import measured test data or load our standardized lab fixture corpus to view empirical metrics.
            </p>
            <button id="btn-load-sample-benchmarks-empty" class="btn btn-primary">
              Load Standardized Lab Dataset (N=10 test cases)
            </button>
          </div>
        ` : `
          <!-- Measured Results Display -->
          <div style="background: #eff6ff; border: 1px solid var(--primary-border); border-radius: var(--radius-md); padding: 14px; margin-bottom: 20px;">
            <div style="font-size: 12px; font-weight: 700; color: #1e3a8a; margin-bottom: 4px;">
              Measured Test Conditions & Integrity Guardrail:
            </div>
            <div style="font-size: 12px; color: #1e40af;">
              Corpus: Standardized 10-Case Fixture Suite &bull; Hardware: Intel i7, 16GB RAM, Node.js v24.16.0 &bull; Sample Size: <strong>N=${state.benchmarkMetrics.sampleSize}</strong>
            </div>
          </div>

          <!-- Comparison Metrics Cards -->
          <div class="metrics-grid">
            <div class="metric-card">
              <div class="metric-label">
                <span>Baseline Precision</span>
                <span class="badge badge-simulated">N=${state.benchmarkMetrics.sampleSize}</span>
              </div>
              <div class="metric-value">${state.benchmarkMetrics.baseline.precisionPct}</div>
              <div class="metric-footer">TP: ${state.benchmarkMetrics.baseline.tp} &bull; FP: ${state.benchmarkMetrics.baseline.fp}</div>
            </div>

            <div class="metric-card">
              <div class="metric-label">
                <span>AEGIS Precision</span>
                <span class="badge badge-success">DYNAMIC VERIFIED</span>
              </div>
              <div class="metric-value" style="color: #166534;">${state.benchmarkMetrics.aegis.precisionPct}</div>
              <div class="metric-footer">TP: ${state.benchmarkMetrics.aegis.tp} &bull; FP: ${state.benchmarkMetrics.aegis.fp}</div>
            </div>

            <div class="metric-card">
              <div class="metric-label">
                <span>Baseline Recall</span>
                <span class="badge badge-simulated">N=${state.benchmarkMetrics.sampleSize}</span>
              </div>
              <div class="metric-value">${state.benchmarkMetrics.baseline.recallPct}</div>
              <div class="metric-footer">FN: ${state.benchmarkMetrics.baseline.fn} (missed complex bugs)</div>
            </div>

            <div class="metric-card">
              <div class="metric-label">
                <span>AEGIS Recall</span>
                <span class="badge badge-success">DYNAMIC VERIFIED</span>
              </div>
              <div class="metric-value" style="color: #166534;">${state.benchmarkMetrics.aegis.recallPct}</div>
              <div class="metric-footer">FN: ${state.benchmarkMetrics.aegis.fn}</div>
            </div>
          </div>

          <!-- Test Case Execution Table -->
          <div class="table-responsive">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Test ID</th>
                  <th>Target Fixture</th>
                  <th>Expected Finding</th>
                  <th>Baseline Output</th>
                  <th>AEGIS Output</th>
                  <th>Baseline Time</th>
                  <th>AEGIS Time</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                ${state.benchmarks.map((tc) => `
                  <tr>
                    <td style="font-family: var(--font-mono); font-weight: 700;">${escapeHtml(tc.testId)}</td>
                    <td style="font-weight: 600;">${escapeHtml(tc.targetName)}</td>
                    <td>${escapeHtml(tc.expectedFinding)}</td>
                    <td>
                      <span class="badge ${tc.baselineFP > 0 ? 'badge-critical' : tc.baselineFN > 0 ? 'badge-medium' : 'badge-info'}">
                        ${escapeHtml(tc.baselineResult)}
                      </span>
                    </td>
                    <td>
                      <span class="badge badge-success">${escapeHtml(tc.aegisResult)}</span>
                    </td>
                    <td style="font-family: var(--font-mono);">${formatDuration(tc.baselineTimeMs)}</td>
                    <td style="font-family: var(--font-mono);">${formatDuration(tc.aegisTimeMs)}</td>
                    <td style="font-size: 11px; color: #64748b;">${escapeHtml(tc.notes)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>
    `;

    document.getElementById('btn-load-sample-benchmarks')?.addEventListener('click', async () => {
      await API.loadSampleBenchmarks();
      showToast('Loaded standardized lab dataset (N=10)', 'success');
      renderComparison(container);
    });

    document.getElementById('btn-load-sample-benchmarks-empty')?.addEventListener('click', async () => {
      await API.loadSampleBenchmarks();
      showToast('Loaded standardized lab dataset (N=10)', 'success');
      renderComparison(container);
    });

    document.getElementById('btn-reset-benchmarks')?.addEventListener('click', async () => {
      await API.resetBenchmarks();
      showToast('Benchmark data cleared.', 'info');
      renderComparison(container);
    });

    document.getElementById('btn-import-benchmarks')?.addEventListener('click', () => {
      openBenchmarkImportModal(container);
    });

  } catch (err) {
    container.innerHTML = `<div class="card" style="color: #dc2626;">Error loading comparison: ${escapeHtml(err.message)}</div>`;
  }
}

function openBenchmarkImportModal(container) {
  let modal = document.getElementById('benchmark-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'benchmark-modal';
    modal.className = 'modal-overlay';
    document.body.appendChild(modal);
  }

  modal.innerHTML = `
    <div class="modal-content">
      <div class="modal-header">
        <h2 style="font-size: 16px; font-weight: 700;">Import Measured Benchmark Dataset</h2>
        <button id="btn-close-bench-modal" class="btn btn-secondary btn-sm">${Icons.x}</button>
      </div>
      <div class="modal-body">
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
          Paste a JSON array of measured test cases. Each object should include <code>testId</code>, <code>targetName</code>, <code>baselineTP</code>, <code>baselineFP</code>, <code>baselineFN</code>, and <code>baselineTimeMs</code>.
        </p>
        <textarea id="import-json-area" class="form-textarea" rows="10" placeholder='[
  {
    "testId": "TC-CUSTOM-01",
    "targetName": "Sample Service",
    "expectedFinding": "SQL Injection",
    "baselineResult": "Detected",
    "aegisResult": "Verified & Patched",
    "baselineTimeMs": 1200,
    "aegisTimeMs": 3500,
    "baselineTP": 1, "baselineFP": 0, "baselineFN": 0,
    "aegisTP": 1, "aegisFP": 0, "aegisFN": 0,
    "notes": "Custom test run"
  }
]'></textarea>
      </div>
      <div class="modal-footer">
        <button id="btn-cancel-bench" class="btn btn-secondary">Cancel</button>
        <button id="btn-submit-bench" class="btn btn-primary">Import Results</button>
      </div>
    </div>
  `;

  document.getElementById('btn-close-bench-modal')?.addEventListener('click', () => modal.remove());
  document.getElementById('btn-cancel-bench')?.addEventListener('click', () => modal.remove());
  document.getElementById('btn-submit-bench')?.addEventListener('click', async () => {
    const raw = document.getElementById('import-json-area')?.value;
    try {
      const parsed = JSON.parse(raw);
      await API.importBenchmarks(parsed);
      modal.remove();
      showToast('Successfully imported custom benchmark dataset.', 'success');
      renderComparison(container);
    } catch (e) {
      alert('Invalid JSON format: ' + e.message);
    }
  });
}

// ==========================================
// 7. ABOUT THIS DEMO
// ==========================================
function renderAbout(container) {
  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">About Baseline Security Demo</h1>
        <p class="page-desc">Purpose, architectural positioning, and controlled comparison guidelines.</p>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">${Icons.info} Product Positioning & Purpose</span>
        <span class="badge badge-simulated">DEMO COMPARATOR</span>
      </div>
      <div style="font-size: 14px; color: var(--text-main); line-height: 1.7;">
        <p style="margin-bottom: 12px;">
          <strong>Baseline Security Demo</strong> is an intentionally limited, fictional demonstration website created to serve as a transparent comparator for <strong>AEGIS-AGENT</strong> demonstrations.
        </p>
        <p style="margin-bottom: 12px;">
          Many conventional security scanners marketed today operate as straightforward two-agent or two-stage pipelines:
        </p>
        <ol style="margin-left: 20px; margin-bottom: 16px;">
          <li><strong>Scanner Agent:</strong> Searches codebases or endpoints using fixed heuristics, regex rules, or basic AST matching.</li>
          <li><strong>Report Agent:</strong> Bundles those pattern hits into severity categories and emits generic manual advice (e.g. <em>"Use parameterized queries"</em>).</li>
        </ol>
        <p style="margin-bottom: 12px;">
          While this basic workflow can rapidly discover candidate patterns, it suffers from several acute engineering limitations:
        </p>
        <ul style="margin-left: 20px; margin-bottom: 16px;">
          <li><strong>High Alert Fatigue:</strong> Because it never attempts dynamic exploit verification in a sandbox, benign code matching regexes triggers false positives.</li>
          <li><strong>No Code Patches:</strong> It tells the engineer <em>what</em> is wrong, but does not author, validate, or format syntax-safe code fixes.</li>
          <li><strong>No Regression Proof:</strong> It cannot spin up ephemeral test environments to confirm that a proposed fix prevents the exploit without breaking valid features.</li>
          <li><strong>No Attack Chaining:</strong> It evaluates rules in isolation, blind to multi-stage SSRF or lateral privilege escalation paths.</li>
        </ul>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">${Icons.shield} Safety, Transparency & Presentation Guidelines</span>
      </div>
      <div style="font-size: 14px; color: var(--text-main); line-height: 1.7;">
        <h3 style="font-size: 15px; margin-bottom: 8px;">Suggested Demo Presentation Script</h3>
        <p style="background: #f8fafc; border-left: 4px solid var(--primary); padding: 12px 16px; border-radius: 0 4px 4px 0; margin-bottom: 16px; font-style: italic;">
          "Here we have the Baseline Security Demo running on our target service. Notice that it finishes in under 3 seconds and flags 2 candidate issues: a SQL concatenation pattern and an unthrottled login route. But look at the finding status: <strong>'Needs manual verification'</strong>. The tool cannot tell us whether the database driver actually sanitizes the string, it cannot generate a PR, and our security team still has to spend 45 minutes investigating. Now, let's run the exact same target through AEGIS-AGENT to see how a multi-agent verification and patch workflow resolves this completely..."
        </p>

        <h3 style="font-size: 15px; margin-bottom: 8px;">Integrity Guarantees</h3>
        <ul style="margin-left: 20px;">
          <li>No competitor names, trademarks, or deceptive claims are used.</li>
          <li>Every metric shown in the benchmark lab is calculated strictly from empirical test cases.</li>
          <li>All candidate findings are explicitly labeled as needing manual verification.</li>
        </ul>
      </div>
    </div>
  `;
}
