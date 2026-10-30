// server/fixtures.js
// Bundled safe educational sample fixtures for demonstration

export const SAMPLE_FIXTURES = [
  {
    id: "fixture-ecommerce-api",
    name: "Sample 1: Web App API Gateway",
    type: "API Backend",
    targetType: "bundled-fixture",
    description: "Node.js REST service with inline SQL queries and unthrottled authentication endpoints.",
    tags: ["Input Validation", "Rate Limiting", "SQL Pattern"],
    targetUri: "bundled://fixtures/ecommerce-api/v1",
    candidateRules: ["RULE-SEC-001", "RULE-SEC-007"],
    files: [
      {
        path: "src/controllers/userController.js",
        lines: 38,
        snippet: `// Line 24: Dynamic query construction
const query = "SELECT id, username, role FROM users WHERE email = '" + req.body.email + "' AND status = 'active'";
const result = await db.query(query);
if (result.rows.length === 0) {
  return res.status(401).json({ message: "Invalid credentials" });
}`
      },
      {
        path: "src/routes/authRoutes.js",
        lines: 19,
        snippet: `// Line 12: Route without rate limiter middleware
router.post('/api/v1/auth/login', authController.login);
router.post('/api/v1/auth/register', authController.register);`
      }
    ]
  },
  {
    id: "fixture-cloud-portal",
    name: "Sample 2: Public Cloud Portal",
    type: "Frontend Web Gateway",
    targetType: "bundled-fixture",
    description: "Customer-facing web portal lacking browser defense headers (CSP, HSTS, X-Frame-Options).",
    tags: ["Security Headers", "Clickjacking", "Transport Security"],
    targetUri: "bundled://fixtures/cloud-portal/web",
    candidateRules: ["RULE-SEC-002", "RULE-SEC-003", "RULE-SEC-004"],
    files: [
      {
        path: "nginx/conf.d/default.conf",
        lines: 45,
        snippet: `server {
    listen 80;
    server_name portal.example.internal;

    # Notice: No Content-Security-Policy or Strict-Transport-Security directives configured
    location / {
        proxy_pass http://portal_upstream;
        proxy_set_header Host $host;
    }
}`
      },
      {
        path: "public/index.html",
        lines: 28,
        snippet: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <!-- Missing meta http-equiv="Content-Security-Policy" -->
  <title>Cloud Management Console</title>
</head>
<body><div id="root"></div></body>
</html>`
      }
    ]
  },
  {
    id: "fixture-internal-admin",
    name: "Sample 3: Internal Admin Service",
    type: "Microservice",
    targetType: "bundled-fixture",
    description: "Internal microservice exposing runtime profiling endpoints and raw exception traces.",
    tags: ["Information Disclosure", "Debug Route", "Error Handling"],
    targetUri: "bundled://fixtures/internal-admin/service",
    candidateRules: ["RULE-SEC-005", "RULE-SEC-006", "RULE-SEC-008"],
    files: [
      {
        path: "cmd/server/main.go",
        lines: 62,
        snippet: `// Profiling handlers enabled on public mux
http.HandleFunc("/debug/vars", expvar.Handler)
http.HandleFunc("/api/internal/env", func(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(os.Environ())
})`
      },
      {
        path: "middleware/errorHandler.js",
        lines: 22,
        snippet: `// Global error handler exposing runtime stack
app.use((err, req, res, next) => {
  res.status(500).json({
    status: 'error',
    message: err.message,
    stack: err.stack // Sensitive stack trace exposed
  });
});`
      }
    ]
  },
  {
    id: "fixture-local-target",
    name: "Local Training Target (Authorized Loopback)",
    type: "Local Target",
    targetType: "authorized-local",
    description: "Authorized local development target on loopback IP (127.0.0.1:3000/fixture) for testing.",
    tags: ["Local Loopback", "Safe Training Target"],
    targetUri: "http://127.0.0.1:3000/fixture",
    candidateRules: ["RULE-SEC-001", "RULE-SEC-002", "RULE-SEC-005"],
    files: [
      {
        path: "server/fixtures/local_mock.js",
        lines: 30,
        snippet: `// Local mock handler for controlled testing
app.get('/fixture/status', (req, res) => {
  res.send({ status: 'ok', debug: true });
});`
      }
    ]
  }
];

export function getFixtureById(id) {
  return SAMPLE_FIXTURES.find((f) => f.id === id) || null;
}
