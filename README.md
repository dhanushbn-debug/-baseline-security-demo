# Baseline Security Demo

> **Fictional baseline workflow for controlled product comparison with AEGIS-AGENT.**

[![Automated Tests](https://img.shields.io/badge/tests-11%20passed-brightgreen.svg)](#test-suite)
[![Architecture](https://img.shields.io/badge/workflow-2--agent%20scanner-blue.svg)](#two-agent-architecture)
[![Database](https://img.shields.io/badge/database-SQLite%203-lightgrey.svg)](#persistence--data)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-success.svg)](#zero-dependency-runtime)

---

## 1. Purpose & Product Positioning

**Baseline Security Demo** is a complete, deployable demonstration website representing a conventional, intentionally limited security-scanning workflow. It is built specifically to be shown alongside **AEGIS-AGENT** to clearly explain the difference between a traditional two-agent workflow and an autonomous, evidence-backed multi-agent remediation architecture.

### Transparency Notice
* This site is a **fictional baseline comparator**, not a real commercial competitor or an independently tested third-party product.
* Detection outputs, execution stages, and metrics are simulated using bundled educational fixtures and controlled benchmark suites.
* All candidate findings are explicitly labeled as **"Needs manual verification"**.

---

## 2. Two-Agent Architecture & Deliberate Boundaries

The demo implements exactly **TWO** agents:

```
┌─────────────────────────────────┐       ┌───────────────────────────────┐       ┌───────────────────────────────┐
│     Stage 1: Scanner Agent      │       │     Stage 2: Report Agent     │       │   Manual Developer Action     │
│  - Static regex & heuristic     │ ───>  │  - Rule-based severity triage │ ───>  │  - Exploit verification       │
│  - Bundled fixture matching     │       │  - Generic remediation text   │       │  - Code patch authoring       │
│  - Candidate finding discovery  │       │  - Multi-format report export │       │  - Post-fix regression test   │
└─────────────────────────────────┘       └───────────────────────────────┘       └───────────────────────────────┘
```

### Intentional Capability Boundaries
| Capability | Baseline Security Demo (This App) | Advanced Multi-Agent (AEGIS-AGENT) |
| :--- | :--- | :--- |
| **Static Heuristic & Regex Matching** | **Available in this demo** | Supported (Multi-Engine) |
| **Candidate Finding Triage & Severity** | **Available in this demo** | Supported (Context-Aware) |
| **Generic Manual Remediation Text** | **Available in this demo** | Supported (Dynamic Context) |
| **Autonomous Dynamic Exploit Verification** | **Not implemented in this demo** | Core Multi-Agent Capability |
| **AST-Aware Code Patch Generation** | **Not implemented in this demo** | Core Multi-Agent Capability |
| **Post-Fix Ephemeral Sandbox Regression** | **Not implemented in this demo** | Core Multi-Agent Capability |
| **Multi-Step Attack Path Chaining** | **Not implemented in this demo** | Core Multi-Agent Capability |
| **Security Memory & Context Retention** | **Not implemented in this demo** | Core Multi-Agent Capability |
| **Automated GitHub PR Creation** | **Requires external integration** | Native Automated Flow |

---

## 3. User Journey & Screens

1. **Overview Dashboard**: High-level telemetry, scans counter, candidate findings by severity, two-agent pipeline diagram, recent scans log, and quick reset.
2. **New Scan**: Curated selection of 3 educational demo fixtures + local loopback training target. Enforces scope authorization and rejects arbitrary public internet URLs.
3. **Scan Progress**: Live two-stage execution timeline with honest stage status, live elapsed timer, log stream, and explicit *"Simulated fixture run"* labeling.
4. **Findings & Detail Modal**: Searchable and filterable candidate list with explicit *"Needs manual verification"* badges. Forensic drawer displays heuristic match reason, evidence snippet, limitations, and generic advice.
5. **Reports Archive**: Instant downloads of complete scan reports in **HTML** (self-contained executive report), **JSON** (schema-compliant AST), and **CSV** (spreadsheet export).
6. **Comparison & Honest Benchmark Lab**: Transparent capability matrix and measured benchmark lab. Displays *"No benchmark data yet"* when empty; dynamically computes Precision, Recall, F1, and Elapsed Time strictly from empirical test cases (e.g. Standardized N=10 Lab Suite).
7. **About this Demo**: Comprehensive architectural contrast, presentation script, and safety guarantees.

---

## 4. Educational Demo Fixtures

- **Sample 1: Web App API Gateway** (`bundled://fixtures/ecommerce-api/v1`): Inline SQL concatenation (`RULE-SEC-001`), missing rate limiting on auth route (`RULE-SEC-007`).
- **Sample 2: Public Cloud Portal** (`bundled://fixtures/cloud-portal/web`): Missing CSP (`RULE-SEC-002`), missing HSTS (`RULE-SEC-003`), clickjacking exposure (`RULE-SEC-004`).
- **Sample 3: Internal Admin Service** (`bundled://fixtures/internal-admin/service`): Exposed debug profiling route `/debug/vars` (`RULE-SEC-005`), environment route leak (`RULE-SEC-006`), verbose error stack trace (`RULE-SEC-008`).
- **Local Training Target** (`http://127.0.0.1:3000/fixture`): Authorized loopback development target for dynamic verification.

---

## 5. Quick Start (Zero Dependencies)

The server is built using native **Node.js (v24+) core modules** (`node:http`, `node:sqlite`, `node:fs`, `node:crypto`). No external npm packages or build steps are required.

### Local Run
```bash
# 1. Start the server
npm start
# or directly:
node server.js

# 2. Open the application in your browser:
# http://localhost:5000
```

On Windows, you can also simply double-click `start.bat`.

### Test Suite
Run the 11 automated verification tests:
```bash
npm test
```

Test coverage includes:
- Health check and metadata endpoint
- Fixture and rule catalogs
- Safety authorization enforcement
- Arbitrary public URL scan rejection
- 2-Stage scan lifecycle (Scanner Agent -> Report Agent)
- Findings persistence in SQLite
- Multi-format report export (HTML, JSON, CSV)
- Benchmark data management and dynamic metrics computation
- Static assets and SPA client-side deep routing

---

## 6. Public Hosting & Deployment

### Option A: 1-Click Render Deployment (`render.yaml` included)
1. Fork or push this repository to GitHub.
2. Sign in to [Render](https://render.com).
3. Click **New +** -> **Blueprint** and connect the repository.
4. Render will read `render.yaml`, provision a free Node.js Web Service, attach a persistent 1GB disk for SQLite (`data/baseline_demo.sqlite`), and configure the `/api/health` check.

### Option B: Vercel Deployment (`vercel.json` included)
1. Install the Vercel CLI or import the repo on the Vercel Dashboard.
2. Run `vercel --prod`.
3. Vercel routes `/api/*` requests to `server.js` via `@vercel/node` and serves `/public/*` as static assets.
*(Note: Vercel serverless instances are ephemeral; demo scans reset on new serverless instances unless connected to hosted PostgreSQL/Vercel Storage).*

### Option C: Docker Container (`Dockerfile` included)
```bash
docker build -t baseline-security-demo .
docker run -p 5000:5000 baseline-security-demo
```

---

## 7. API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Health check, uptime, version |
| `/api/fixtures` | `GET` | Bundled educational demo fixtures |
| `/api/rules` | `GET` | Safe static check rule catalog |
| `/api/scans` | `GET` | List all persisted scans from SQLite |
| `/api/scans` | `POST` | Trigger new 2-stage scan (requires authorization) |
| `/api/scans/:id` | `GET` | Scan details, stage status, timestamps |
| `/api/scans/reset` | `POST` | Reset scan history back to demo seed |
| `/api/findings` | `GET` | Filterable findings list (`?severity=`, `?query=`) |
| `/api/findings/:id` | `GET` | Detailed finding forensic view |
| `/api/reports/:id/download` | `GET` | Download report (`?format=html`, `json`, `csv`) |
| `/api/comparison/matrix` | `GET` | Transparent capability feature matrix |
| `/api/benchmarks` | `GET` | Current benchmark dataset & computed metrics |
| `/api/benchmarks` | `POST` | Import custom test cases |
| `/api/benchmarks/load-sample` | `POST` | Load standardized N=10 lab test corpus |
| `/api/benchmarks/reset` | `POST` | Clear benchmark data ("No benchmark data yet") |

---

## 8. Suggested Presentation Script

When demonstrating **Baseline Security Demo** alongside **AEGIS-AGENT**:

> *"Here we have the Baseline Security Demo representing standard two-stage automated scanners. Notice how quickly it runs — completing in under 3 seconds and surfacing 2 candidate issues on our payment API fixture: a potential SQL string concatenation and an unthrottled login endpoint.*
>
> *However, observe the status badge: **'Needs manual verification'**. The tool operates on regex heuristics alone — it cannot test whether the backend database driver actually sanitizes the string, cannot produce verified proof-of-exploit, and does not generate code patches.*
>
> *Our engineering team would still have to manually investigate, author the patch, test for regressions, and open a pull request. Now, let's run the exact same fixture through AEGIS-AGENT to see how an autonomous multi-agent verification and remediation system eliminates this manual friction."*

---

## 9. Deployment Acceptance Checklist

- [x] Public HTTPS URL opens without authentication errors.
- [x] Overview, New Scan, Findings, Reports, Comparison, and About pages work on desktop and mobile.
- [x] Fixture scan completes through both agents (Scanner Agent -> Report Agent) and creates persisted SQLite history.
- [x] Every fixture result is visibly marked as simulated/demo.
- [x] Report downloads instantly and contains scope, run ID, findings, evidence, and limitations in HTML, JSON, and CSV.
- [x] Feature matrix accurately marks unimplemented capabilities ("Not implemented in this demo").
- [x] No fabricated accuracy, speed, or false-positive claims appear ("No benchmark data yet" by default).
- [x] Hosting configuration (`render.yaml`, `vercel.json`, `Dockerfile`) and deployment instructions included in README.

