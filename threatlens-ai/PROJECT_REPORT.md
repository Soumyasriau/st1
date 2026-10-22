# ThreatLens AI: AI-Assisted Website Security Risk Assessment & Threat Modeling Tool
## Academic Mini-Project Report

**Project Title:** ThreatLens AI — Website Security Risk Assessment Tool  
**Domain:** Cybersecurity / Web Application Security / Threat Modeling  
**Implementation Stack:** Python, Flask, SQLite, HTML5, CSS3, JavaScript, ReportLab, Chart.js  

---

## Abstract

As modern web applications face increasingly sophisticated cyber threats, identifying vulnerabilities early in the software development lifecycle has become paramount. However, traditional vulnerability scanners are often resource-heavy, intrusive, and yield complex vulnerability dumps that confuse entry-level developers and decision-makers without providing contextual threat modeling.

**ThreatLens AI** is an educational, full-stack cybersecurity risk assessment tool designed to bridge passive configuration analysis with structured threat modeling. The system takes a target website URL, rigorously enforces anti-Server-Side Request Forgery (SSRF) validation, and performs passive, non-intrusive evaluations across seven key security dimensions: HTTPS transport availability, TLS certificate validity, HTTP security headers, cookie flag configurations, information disclosure indicators, redirect behavior, and mixed content references.

Observable configuration findings are correlated into Microsoft’s STRIDE threat modeling framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege). Risk is quantitatively estimated using an industry-standard formula: $\text{Risk Score} = \text{Likelihood (1–5)} \times \text{Impact (1–5)}$. The application features an interactive cybersecurity dashboard, dynamic risk adjustment controls, remediation workflow tracking, and automated multi-format reporting (HTML, JSON, and PDF). ThreatLens AI demonstrates how passive reconnaissance can be transformed into actionable defensive engineering without violating target boundaries or requiring paid third-party APIs.

---

## 1. Problem Statement & Motivation

### 1.1 The Challenge
Modern web applications frequently suffer from basic security misconfigurations:
1. **Missing Security Headers:** Browsers lack directives to restrict inline script execution (Content-Security-Policy), enforce HTTPS (Strict-Transport-Security), or prevent clickjacking (X-Frame-Options).
2. **Insecure Cookies:** Session cookies emitted without `Secure`, `HttpOnly`, or `SameSite` flags expose sessions to cross-site scripting (XSS) and cross-site request forgery (CSRF).
3. **Information Leakage:** Detailed web server and runtime banners (`Apache/2.4.41`, `PHP/7.4.3`) assist malicious adversaries during reconnaissance.
4. **Lack of Threat Modeling:** Typical audit tools list raw findings (e.g. "Missing X-Content-Type-Options") without explaining the attack vector, the STRIDE category, or the impact on business assets.

### 1.2 Motivation
For computer science students and junior security analysts, learning threat modeling traditionally relies on dry theoretical worksheets. There is a need for a practical, working software tool that:
- Runs locally with zero complicated infrastructure.
- Uses passive HTTP requests rather than aggressive exploits.
- Automatically generates threat scenarios from observed configurations.
- Allows students to adjust Likelihood and Impact interactively to see how risk ratings evolve.

---

## 2. Project Objectives

The primary objectives of the ThreatLens AI project are:
1. **Passive Security Auditing:** Safely evaluate publicly observable web server configurations using standard HTTP requests and TLS sockets without launching attacks.
2. **Robust Anti-SSRF Architecture:** Prevent Server-Side Request Forgery by strictly validating input URLs, rejecting non-HTTP schemes, resolving DNS before connections, and blocking private RFC 1918 subnets, loopbacks, and cloud metadata endpoints.
3. **STRIDE Threat Modeling:** Map observable configuration weaknesses to appropriate STRIDE threat categories with realistic attack scenarios.
4. **Transparent Risk Scoring:** Implement a quantitative formula ($\text{Likelihood} \times \text{Impact} = 1 \text{ to } 25$) classified into Low, Medium, High, and Critical severities with immediate user recalculation.
5. **Remediation & Verification:** Supply actionable defensive configurations (e.g. Nginx, Apache snippets) and step-by-step verification procedures.
6. **Executive Reporting:** Provide multi-format report exports: interactive web results, print-ready CSS reports, native PDF export via ReportLab, and JSON dumps.
7. **Offline Demo Capability:** Include pre-built realistic demo profiles (Insecure, Moderate, Hardened) for classroom and viva presentations without external network dependencies.

---

## 3. Threat Modeling Methodology

ThreatLens AI models cybersecurity risk through a 7-stage pipeline:

```
[Target URL Input]
       │
       ▼
[Stage 1: Anti-SSRF Validation & DNS Resolution]
       │
       ▼
[Stage 2: Passive HTTP & TLS Observation]
       │
       ▼
[Stage 3: Weakness Identification (Pass/Warning/Fail)]
       │
       ▼
[Stage 4: STRIDE Threat Mapping]
       │
       ▼
[Stage 5: Quantitative Risk Estimation (L × I)]
       │
       ▼
[Stage 6: Mitigation & Verification Checklist]
       │
       ▼
[Stage 7: Multi-Format Reporting & SQLite Persistence]
```

### 3.1 STRIDE Threat Categorization
- **Spoofing:** Impersonating another entity (e.g. expired TLS certificates allowing adversary-in-the-middle impersonation).
- **Tampering:** Malicious modification of data (e.g. missing HTTPS or missing CSP allowing cleartext manipulation or script injection).
- **Repudiation:** Inability to prove an action occurred.
- **Information Disclosure:** Exposing confidential data to unauthorized entities (e.g. server banners, missing cookie `HttpOnly` flags, referrer URL leakage).
- **Denial of Service:** Degrading availability (e.g. excessive redirect loops, expiring TLS certificates).
- **Elevation of Privilege:** Gaining unauthorized capabilities (e.g. missing frame protection enabling clickjacking, missing `nosniff` enabling MIME confusion).

### 3.2 Risk Scoring Model
$$\text{Risk Score} = \text{Likelihood (1–5)} \times \text{Impact (1–5)}$$

- **Likelihood Scale (1 to 5):** 1: Rare, 2: Unlikely, 3: Possible, 4: Likely, 5: Almost Certain.
- **Impact Scale (1 to 5):** 1: Negligible, 2: Minor, 3: Moderate, 4: Major, 5: Severe.
- **Severity Classification Bands:**
  - **1 – 4:** Low Severity (Green)
  - **5 – 9:** Medium Severity (Amber)
  - **10 – 16:** High Severity (Orange)
  - **17 – 25:** Critical Severity (Red)

---

## 4. System Architecture

ThreatLens AI is organized around a clean Model-View-Controller (MVC) architecture:

```
+-------------------------------------------------------------+
|                      Browser Client                         |
|  - Modern Dark Navy UI (HTML5 / Vanilla CSS / JavaScript)   |
|  - Chart.js Visualizations (Donut & Horizontal Bar)        |
|  - Interactive Risk Tuning Sliders & AJAX Recalculation     |
+------------------------------▲------------------------------+
                               │ HTTP / JSON
+------------------------------▼------------------------------+
|                   Flask Application Layer                   |
|  - app.py: Routing, Controller Logic, Session & Error Mgmt   |
+--------------▲------------------------------▲---------------+
               │                              │
+--------------▼---------------+  +-----------▼---------------+
|   Security Auditing Engine   |  |   Threat Modeling Engine  |
|  - security_checks.py        |  |  - threat_model.py        |
|  - Anti-SSRF Pre-validator   |  |  - STRIDE Knowledge Base  |
|  - Socket & TLS Inspector    |  |  - Risk Score Calculator  |
|  - Response Size/Hop Limiter |  |  - Executive Synthesizer  |
+--------------▲---------------+  +-----------▲---------------+
               │                              │
+--------------▼------------------------------▼---------------+
|                    Data & Reporting Layer                   |
|  - database.py: SQLite Database (Assessments, Threats)      |
|  - pdf_generator.py: ReportLab Vector PDF Builder           |
|  - sample_data.py: Pre-configured Demonstration Profiles    |
+-------------------------------------------------------------+
```

### 4.1 Database Design (SQLite)
The relational schema comprises four primary tables:
1. **`assessments`:** Stores primary metadata (target URL, hostname, scan timestamp, overall security hygiene score, JSON summaries, and executive summary).
2. **`findings`:** Stores granular check outcomes (finding code, title, category, status: `PASS`/`WARNING`/`FAIL`, severity, and raw evidence).
3. **`threat_scenarios`:** Stores STRIDE threat records linked to findings (threat category, attack scenario, likelihood, impact, calculated risk score, severity, mitigation, and verification steps).
4. **`mitigation_status`:** Tracks remediation workflow (`Open`, `In Progress`, `Mitigated`, `Accepted`) and timestamped engineer notes.

---

## 5. Security Checks Implementation

### Check A: HTTPS Availability & Port 80 Redirection
Tests if port 443 connects over TLS and validates if plaintext HTTP requests to port 80 return HTTP 301/308 redirects pointing to an HTTPS destination.

### Check B: TLS Certificate & Cryptography
Establishes a standard TLS socket using Python's `ssl.create_default_context()`. Inspects the certificate's Common Name (CN), Subject Alternative Names (SAN), issuing Certificate Authority, expiration timestamp, days remaining, protocol version (TLS 1.2, TLS 1.3), and negotiated cipher suite. Flags expired certificates as Critical and certificates expiring within 30 days as Warning.

### Check C: HTTP Security Headers
Inspects response headers against modern security standards:
- **Content-Security-Policy (CSP):** Validates script and object boundaries; flags `'unsafe-inline'` and wildcard origins.
- **Strict-Transport-Security (HSTS):** Enforces HTTPS; verifies `max-age` $\ge 15,552,000$ seconds (6 months), `includeSubDomains`, and `preload`.
- **X-Content-Type-Options:** Enforces `nosniff`.
- **Frame Protection:** Checks for modern CSP `frame-ancestors` or legacy `X-Frame-Options` (`DENY`/`SAMEORIGIN`).
- **Referrer-Policy:** Validates privacy-preserving policies (`strict-origin-when-cross-origin`, `no-referrer`).
- **Permissions-Policy:** Verifies hardware sensor restrictions (camera, microphone, geolocation).

### Check D: Cookie Security Attributes
Audits `Set-Cookie` response headers for `Secure`, `HttpOnly`, and `SameSite` attributes. **Privacy safeguard:** Sensitive cookie values are never stored or logged; only cookie names and security flag booleans are processed.

### Check E: Information Exposure
Examines `Server`, `X-Powered-By`, and framework headers. Detects granular software and operating system version numbers that assist attacker reconnaissance.

### Check F: Redirect Behavior
Traces redirection chains up to 5 hops. Detects security downgrade redirects (HTTPS redirecting to HTTP) and excessive redirection latency.

### Check G: Mixed Content References
Parses static HTML responses using `BeautifulSoup`. Flags active mixed content (`<script>`, `<link rel="stylesheet">`, `<iframe>`) and passive mixed content (`<img>`, `<video>`) declared with `http://` URLs on an HTTPS site.

---

## 6. Security of the Application (Anti-SSRF Architecture)

Because ThreatLens AI accepts user-supplied URLs to audit, it must protect internal infrastructure against Server-Side Request Forgery:
1. **Scheme Whitelisting:** Strictly permits `http://` and `https://`. Blocks `file://`, `ftp://`, `gopher://`, etc.
2. **Credential Sanitization:** Rejects URLs containing embedded user credentials (`http://user:pass@host`).
3. **Pre-connection DNS Resolution:** Resolves target hostnames using `socket.getaddrinfo()` before opening connections.
4. **IP Category Filtering:** Every resolved IPv4 and IPv6 address is evaluated with Python's `ipaddress` module:
   - Blocks Loopback (`127.0.0.0/8`, `::1`)
   - Blocks Private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
   - Blocks Link-Local subnets (`169.254.0.0/16`, `fe80::/10`)
   - Blocks Multicast and Reserved ranges (`0.0.0.0`, etc.)
   - Explicitly blocks Cloud Metadata endpoints (`169.254.169.254`, `metadata.google.internal`)
5. **Redirect Revalidation:** When following HTTP redirects, every intermediate hop target is re-validated against anti-SSRF filters before fetching.
6. **Safety Caps:** Caps redirects at 5 hops, enforces 6.0-second timeouts, and streams response content up to a 2 MB ceiling to prevent denial-of-service memory exhaustion.
7. **Strict TLS Verification:** Certificate validation (`verify=True`) is never disabled.

---

## 7. Testing & Quality Assurance

ThreatLens AI includes an automated test suite executed with `pytest`:

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-8.0.0
rootdir: C:\Users\USER\Desktop\st1\threatlens-ai
collected 46 items

tests/test_database_and_app.py::TestDatabaseLayer::test_save_and_retrieve_assessment PASSED
tests/test_database_and_app.py::TestDatabaseLayer::test_update_threat_risk PASSED
tests/test_database_and_app.py::TestDatabaseLayer::test_update_mitigation_workflow PASSED
tests/test_database_and_app.py::TestDatabaseLayer::test_delete_assessment_cascades PASSED
tests/test_database_and_app.py::TestDatabaseLayer::test_dashboard_metrics_aggregation PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_homepage_renders PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_sample_loading_route PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_dashboard_renders PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_history_renders PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_ssrf_blocking_via_form_post PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_json_export_endpoint PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_pdf_export_endpoint PASSED
tests/test_database_and_app.py::TestFlaskApplicationRoutes::test_api_threat_risk_recalculation PASSED
tests/test_mock_limits.py::TestSafeHTTPRequestBoundaries::test_redirect_limit_exceeded PASSED
tests/test_mock_limits.py::TestSafeHTTPRequestBoundaries::test_oversized_response_body_truncation PASSED
tests/test_mock_limits.py::TestSafeHTTPRequestBoundaries::test_connection_timeout_handling PASSED
tests/test_mock_limits.py::TestSafeHTTPRequestBoundaries::test_tls_error_handling PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_localhost PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_ipv4_loopback PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_private_rfc1918_class_a PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_private_rfc1918_class_b PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_private_rfc1918_class_c PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_cloud_metadata_ipv4 PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_cloud_metadata_hostname PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_non_http_schemes PASSED
tests/test_security_checks.py::TestSSRFProtections::test_block_embedded_credentials PASSED
tests/test_security_checks.py::TestSSRFProtections::test_allow_valid_public_domain PASSED
tests/test_security_checks.py::TestSecurityHeadersInspection::test_missing_all_security_headers PASSED
tests/test_security_checks.py::TestSecurityHeadersInspection::test_well_hardened_security_headers PASSED
tests/test_security_checks.py::TestSecurityHeadersInspection::test_permissive_csp_warning PASSED
tests/test_security_checks.py::TestSecurityHeadersInspection::test_short_hsts_duration_warning PASSED
tests/test_cookie_security.py::TestCookieSecurity::test_no_cookies_returns_pass PASSED
tests/test_cookie_security.py::TestCookieSecurity::test_vulnerable_cookies_flagged PASSED
tests/test_cookie_security.py::TestCookieSecurity::test_hardened_cookie_passes PASSED
tests/test_security_checks.py::TestInformationExposure::test_revealing_version_banners PASSED
tests/test_security_checks.py::TestInformationExposure::test_generic_masked_banner PASSED
tests/test_security_checks.py::TestInformationExposure::test_no_server_headers PASSED
tests/test_security_checks.py::TestMixedContent::test_insecure_scripts_detected PASSED
tests/test_security_checks.py::TestMixedContent::test_clean_https_markup PASSED
tests/test_security_checks.py::TestRedirectBehavior::test_clean_single_hop PASSED
tests/test_security_checks.py::TestRedirectBehavior::test_downgrade_redirect_detected PASSED
tests/test_security_checks.py::TestRedirectBehavior::test_excessive_redirect_hops PASSED
tests/test_threat_model.py::TestRiskFormulaAndSeverity::test_risk_score_calculation PASSED
tests/test_threat_model.py::TestRiskFormulaAndSeverity::test_clamping_out_of_bounds PASSED
tests/test_threat_model.py::TestSTRIDEThreatMapping::test_stride_mapping_for_findings PASSED
tests/test_threat_model.py::TestSTRIDEThreatMapping::test_executive_summary_postures PASSED

============================= 46 passed in 1.01s ==============================
```

---

## 8. Limitations & Future Scope

### 8.1 Current Limitations
1. **Passive Scope Only:** The tool only inspects what a web server sends in ordinary responses. It does not identify SQL injection, broken authentication, IDORs, or business logic vulnerabilities.
2. **Static DOM Limitations:** Mixed content analysis operates on initial HTML responses. Insecure resources injected dynamically via client-side JavaScript frameworks (React, Vue, Angular) are not observed.
3. **Internal Network Scanning:** In order to protect internal networks and prevent SSRF, internal intranet domains cannot be audited with this tool.

### 8.2 Future Scope
1. **Pluggable Large Language Model (LLM) Integration:** An optional API hook allowing users to connect a local or cloud LLM (e.g. Gemini, Ollama, OpenAI) to synthesize customized attack narratives and developer remediation pull requests.
2. **Headless Browser Execution:** Introducing a lightweight headless browser (Playwright or Chromium) to capture dynamic DOM modifications and JavaScript-injected mixed content.
3. **Scheduled Monitoring (Cron):** Automated recurring scans with email/webhook alerting upon certificate expiration or header regression.

---

## 9. Conclusion

ThreatLens AI successfully demonstrates how cybersecurity threat modeling can be made accessible, practical, and beginner-friendly. By combining safe, passive configuration audits with Microsoft’s STRIDE taxonomy and quantitative risk scoring, the project bridges the gap between raw vulnerability finding and strategic risk mitigation.

The project runs entirely on local, open-source technology without expensive cloud subscriptions, making it an ideal demonstration project for college coursework, engineering vivas, and foundational cybersecurity education.

---

## 10. References
- OWASP Top 10 Web Application Security Risks: [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
- Microsoft STRIDE Threat Modeling: [https://learn.microsoft.com/en-us/previous-versions/commerce-server/ee823872(v=cs.20)](https://learn.microsoft.com/en-us/previous-versions/commerce-server/ee823872(v=cs.20))
- OWASP Secure Headers Project: [https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)
- NIST Special Publication 800-30: *Guide for Conducting Risk Assessments*
- Mozilla Developer Network (MDN) Web Security Guidelines
