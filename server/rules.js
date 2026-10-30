// server/rules.js
// Safe, predefined static check rules for the Scanner Agent & Report Agent

export const PREDEFINED_RULES = [
  {
    id: "RULE-SEC-001",
    name: "SQL String Concatenation Pattern",
    category: "Input Validation",
    cwe: "CWE-89: SQL Injection",
    severity: "High",
    confidence: "Low (Static Heuristic)",
    description: "Detected direct string concatenation inside database query invocation.",
    whyMatched: "Found regex pattern `db.query('SELECT * FROM ...' + req.body...)` without parameterized bindings.",
    limitations: "Candidate finding only. Baseline demo does not verify exploitability dynamically, execute payloads, or test database dialect defenses. Manual verification required.",
    genericRemediation: "Replace inline string concatenation with parameterized SQL queries or an ORM prepared statement mechanism. Ensure all user inputs undergo strict type casting.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  },
  {
    id: "RULE-SEC-002",
    name: "Missing Content-Security-Policy (CSP)",
    category: "Security Headers",
    cwe: "CWE-1021: Improper Restriction of Rendered UI Layers",
    severity: "Medium",
    confidence: "Medium (Header Scan)",
    description: "The HTTP response does not include a Content-Security-Policy header, leaving client-side resources open to untrusted script execution.",
    whyMatched: "Inspection of HTTP response header map returned null for 'Content-Security-Policy'.",
    limitations: "Header presence check only. Scanner Agent cannot evaluate whether reverse proxies or downstream CDNs inject headers dynamically.",
    genericRemediation: "Configure the web server or reverse proxy (e.g. Nginx, Cloudflare, Helmet.js) to emit a restrictive Content-Security-Policy header directive.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  },
  {
    id: "RULE-SEC-003",
    name: "Missing HTTP Strict-Transport-Security (HSTS)",
    category: "Transport Security",
    cwe: "CWE-319: Cleartext Transmission of Sensitive Information",
    severity: "Medium",
    confidence: "Medium (Header Scan)",
    description: "HSTS header is absent, allowing potential downgrade attacks from HTTPS to HTTP on insecure networks.",
    whyMatched: "HTTP response headers omitted 'Strict-Transport-Security'.",
    limitations: "Static check only. Does not verify whether domain is included in browser HSTS preload lists.",
    genericRemediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses at the gateway level.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  },
  {
    id: "RULE-SEC-004",
    name: "Clickjacking Exposure (Missing X-Frame-Options)",
    category: "Security Headers",
    cwe: "CWE-1021: Clickjacking / Framing",
    severity: "Low",
    confidence: "Medium (Header Scan)",
    description: "Web application frames can be embedded by third-party origins because X-Frame-Options or frame-ancestors is not set.",
    whyMatched: "Header 'X-Frame-Options' was not returned by the mock server endpoint.",
    limitations: "Does not verify CSP frame-ancestors equivalence or client side frame-busting scripts.",
    genericRemediation: "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or implement CSP 'frame-ancestors \\'self\\''.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  },
  {
    id: "RULE-SEC-005",
    name: "Exposed Debug / Diagnostic Route",
    category: "Information Disclosure",
    cwe: "CWE-200: Exposure of Sensitive Information",
    severity: "High",
    confidence: "High (Route Discovery)",
    description: "Internal runtime profiling or diagnostic route is reachable without authentication.",
    whyMatched: "Route probe to `/debug/vars` returned HTTP 200 with runtime memory metrics.",
    limitations: "Candidate finding only. Baseline Scanner does not attempt privilege escalation or credential extraction. Must be manually verified by developer.",
    genericRemediation: "Disable debug routes in production configurations or bind them strictly to an internal loopback network protected by mutual TLS / VPN.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  },
  {
    id: "RULE-SEC-006",
    name: "Exposed Environment Configuration Endpoint",
    category: "Information Disclosure",
    cwe: "CWE-526: Exposure of Sensitive System Information",
    severity: "Critical",
    confidence: "High (Route Discovery)",
    description: "Route returns system environment variables which could expose internal infrastructure hostnames or secrets.",
    whyMatched: "Target route `/api/internal/env` returned JSON containing active server configuration keys.",
    limitations: "No credential harvesting or downstream database access was attempted. Manual developer review required to assess exposure.",
    genericRemediation: "Remove or restrict internal management endpoints. Never return environment variables or secrets via public or unauthenticated HTTP routes.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  },
  {
    id: "RULE-SEC-007",
    name: "Unthrottled Authentication Endpoint",
    category: "Rate Limiting & DoS",
    cwe: "CWE-307: Improper Restriction of Excessive Authentication Attempts",
    severity: "Medium",
    confidence: "Low (Static Inspection)",
    description: "Authentication login route lacks visible rate limiting or exponential backoff middleware in source inspection.",
    whyMatched: "Endpoint `POST /api/v1/auth/login` does not reference rate-limiter middleware (e.g., `express-rate-limit` or Redis token bucket).",
    limitations: "Static check only. Does not simulate brute-force load or test cloud WAF rate-limiting rules.",
    genericRemediation: "Apply IP and account-based rate limiting to authentication routes. Return HTTP 429 Too Many Requests when threshold is exceeded.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  },
  {
    id: "RULE-SEC-008",
    name: "Verbose Exception Stack Trace Exposure",
    category: "Error Handling",
    cwe: "CWE-209: Generation of Error Message Containing Sensitive Information",
    severity: "Low",
    confidence: "Medium (Static Heuristic)",
    description: "Global error handler returns raw exception stack trace `err.stack` directly in HTTP response payload.",
    whyMatched: "Matched `res.status(500).json({ error: err.message, stack: err.stack })` in error middleware.",
    limitations: "Does not verify whether NODE_ENV guards are enforced at runtime.",
    genericRemediation: "Sanitize error responses in production environments. Log full stack traces internally to secure APM while returning opaque error IDs to clients.",
    remediationType: "Generic Manual Guidance (No patch generated)"
  }
];

export function getRuleById(ruleId) {
  return PREDEFINED_RULES.find((r) => r.id === ruleId) || null;
}
