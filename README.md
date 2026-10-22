# ThreatLens AI — Website Security Risk Assessment & Threat Modeling Tool

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/database-SQLite-blue.svg)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/license-Academic%20Educational-green.svg)]()

> **ThreatLens AI** is a full-stack, beginner-friendly cybersecurity threat modeling and website security risk assessment tool. Built for college mini-project demonstrations and security engineering education, it bridges the gap between passive configuration auditing, Microsoft STRIDE threat modeling, and transparent quantitative risk scoring (Likelihood × Impact).

---

## 🛡️ Table of Contents

1. [Project Overview](#-project-overview)
2. [Key Capabilities & Features](#-key-capabilities--features)
3. [Technology Stack](#-technology-stack)
4. [Project Structure](#-project-structure)
5. [Installation & Setup](#-installation--setup)
6. [Running the Application](#-running-the-application)
7. [Running Automated Tests](#-running-automated-tests)
8. [Threat Modeling & Scoring Methodology](#-threat-modeling--scoring-methodology)
9. [Offline College Demo Mode](#-offline-college-demo-mode)
10. [Ethical & Security Guardrails](#-ethical--security-guardrails)

---

## 🎯 Project Overview

In real-world cybersecurity, finding a missing header or expired certificate is only the first step. Engineers must communicate **what the threat is**, **how an attacker might exploit it**, **what the business impact is**, and **how to verify the fix**.

ThreatLens AI automates this 7-stage threat modeling workflow:
1. **Target Identification:** Enforces strict anti-SSRF host normalization.
2. **Passive Observation:** Safe, non-intrusive HTTP/TLS inspection without exploits or payloads.
3. **Weakness Identification:** Analyzes transport encryption, certificate trust, headers, cookies, and asset links.
4. **STRIDE Threat Mapping:** Correlates weaknesses to Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege.
5. **Risk Estimation:** Computes quantitative risk scores: $\text{Risk Score} = \text{Likelihood (1–5)} \times \text{Impact (1–5)}$.
6. **Mitigation & Verification Guidance:** Delivers concrete remediation configurations and developer verification steps.
7. **Executive Reporting:** Generates print-ready HTML reports, ReportLab PDF downloads, and JSON dumps.

---

## ✨ Key Capabilities & Features

- **Anti-SSRF Protection Engine:** Pre-resolves DNS records and blocks RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`, `::1`), link-local IPs, and cloud metadata services (`169.254.169.254`, `metadata.google.internal`). Revalidates every redirect hop.
- **7 Automated Passive Security Checks:**
  1. *HTTPS Availability & Port 80 Enforcement* (detects missing 301/308 redirects)
  2. *TLS Certificate & Cryptography* (expiry, trusted CA, protocol versions, cipher suites)
  3. *HTTP Security Headers* (CSP, HSTS, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy)
  4. *Cookie Security Flags* (checks `Secure`, `HttpOnly`, and `SameSite` flags without storing sensitive values)
  5. *Information Exposure* (detects `Server` and `X-Powered-By` version fingerprinting)
  6. *Redirect Behavior* (identifies HTTP downgrades or excessive chains)
  7. *Static Mixed Content* (scans static HTML markup for insecure `http://` assets on HTTPS pages)
- **STRIDE Threat Modeling Matrix:** Maps configuration weaknesses to realistic, hypothetical attack scenarios.
- **Interactive Risk Tuner:** Users can dynamically adjust Likelihood (1–5) and Impact (1–5) via dropdowns in the web UI; the risk score and severity badge recalculate and save to SQLite in real time via AJAX.
- **Remediation Workflow Tracker:** Manage findings through lifecycle stages: `Open`, `In Progress`, `Mitigated`, or `Risk Accepted`.
- **Multi-Format Reporting:**
  - Full-featured web results page with live search filters
  - Executive Printable Report styled with `@media print`
  - Downloadable PDF report generated with `reportlab`
  - Structured machine-readable JSON export
- **Interactive Dashboard:** Aggregated metrics, Chart.js risk severity distribution donut chart, and STRIDE category bar chart.

---

## 🛠️ Technology Stack

| Layer | Component | Description |
|---|---|---|
| **Backend** | Python 3.10+ & Flask | Lightweight, clean MVC architecture |
| **Database** | SQLite3 | Embedded, zero-configuration relational database |
| **Security Audit** | Standard `ssl`, `socket`, `requests` | Passive HTTP/TLS auditing with strict anti-SSRF controls |
| **HTML Parsing** | `BeautifulSoup4` | Static HTML parser for mixed-content asset analysis |
| **PDF Engine** | `ReportLab` | Native Python PDF generation for executive reports |
| **Frontend** | HTML5, Modern CSS, Vanilla JS | Dark navy cybersecurity theme with cyan/blue accents |
| **Data Viz** | `Chart.js` | Interactive risk distribution and STRIDE category charts |
| **Testing** | `pytest` | 46 comprehensive unit and integration tests |

---

## 📁 Project Structure

```text
threatlens-ai/
│
├── app.py                      # Flask routes and controller endpoints
├── security_checks.py          # Passive scanning engine with anti-SSRF validator
├── threat_model.py             # STRIDE threat mapping & risk scoring logic
├── database.py                 # SQLite schema, queries, and cascade operations
├── sample_data.py              # Pre-configured demo profiles for offline evaluation
├── pdf_generator.py            # ReportLab PDF report generation module
├── requirements.txt            # Python dependencies
├── README.md                   # Project overview & execution guide
├── PROJECT_REPORT.md           # Comprehensive academic mini-project report
├── VIVA_GUIDE.md               # College viva preparation & interview Q&A
│
├── templates/                  # Jinja2 HTML Templates
│   ├── base.html               # Common layout with dark theme, navbar, and flash alerts
│   ├── index.html              # Homepage with URL input & live loading sequence
│   ├── dashboard.html          # Analytics dashboard with Chart.js visualizations
│   ├── results.html            # Detailed findings & interactive STRIDE tuner
│   ├── history.html            # Searchable historical assessments log & modal delete
│   └── report.html             # Print-ready executive assessment report
│
├── static/                     # Static Web Assets
│   ├── style.css               # Dark navy cybersecurity CSS with print media queries
│   └── script.js               # Client-side validation & UI handlers
│
└── tests/                      # Automated Test Suite (46 Tests)
    ├── test_security_checks.py # SSRF blocking, headers, cookies, redirects
    ├── test_threat_model.py    # STRIDE categorization & risk formula tests
    ├── test_database_and_app.py# SQLite persistence & Flask route tests
    └── test_mock_limits.py     # Request timeouts, response size, and redirect limits
```

---

## 💻 Installation & Setup

### Prerequisites
- Python 3.10 or higher installed on your system.
- Standard internet connection for first-time dependency installation.

### Step-by-Step Installation

1. **Navigate to the project directory:**
   ```bash
   cd threatlens-ai
   ```

2. **(Optional but recommended) Create a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Running the Application

1. **Start the Flask web server:**
   ```bash
   python app.py
   ```

2. **Open your web browser:**
   Navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000).

3. **Perform a Scan:**
   - Enter any authorized public website URL (e.g., `https://example.com`) and click **"Analyze Website"**.
   - Or click one of the **Sample Demo Profiles** on the homepage to instantly evaluate a pre-configured target without internet access!

---

## 🧪 Running Automated Tests

Run the full suite of 46 automated unit and integration tests:

```bash
python -m pytest -v
```

All tests run locally using mocks and isolated temporary databases without making external network calls.

---

## 📐 Threat Modeling & Scoring Methodology

### Quantitative Risk Formula

$$\text{Risk Score} = \text{Likelihood} \times \text{Impact}$$

Where **Likelihood** (1–5) and **Impact** (1–5) are integer ratings based on OWASP Risk Rating Methodology:

| Likelihood Rating | Description |
|---|---|
| **1 — Rare** | Complex multi-step prerequisite or isolated circumstance |
| **2 — Unlikely** | Specific prerequisite or non-standard configuration required |
| **3 — Possible** | Achievable on typical untrusted network segments (e.g. public Wi-Fi) |
| **4 — Likely** | Common automated attack vector or easily discoverable gap |
| **5 — Almost Certain** | Trivial, opportunistic exploitation |

| Impact Rating | Description |
|---|---|
| **1 — Negligible** | Minor telemetry disclosure without direct threat |
| **2 — Minor** | Technology stack identification; assists reconnaissance |
| **3 — Moderate** | Session vulnerability or UI redressing without full compromise |
| **4 — Major** | Credential theft, script injection, or session hijacking |
| **5 — Severe** | Total transport layer compromise, plaintext eavesdropping, or identity spoofing |

### Severity Classifications

| Risk Score | Severity Band | Operational Meaning | Suggested SLA |
|:---:|:---:|---|---|
| **17 – 25** | 🔴 **Critical** | Fundamental transport or cryptographic trust breakdown | 24 Hours |
| **10 – 16** | 🟠 **High** | Significant defense gap (e.g. missing CSP, framing unprotected) | 7 Days |
| **5 – 9** | 🟡 **Medium** | Missing defense-in-depth header or cookie attribute | 30 Days |
| **1 – 4** | 🟢 **Low** | Minor informational exposure or reconnaissance clue | Next Release |

---

## 🧪 Offline College Demo Mode

During a viva or classroom presentation, internet connectivity can be unreliable. ThreatLens AI features a built-in **Sample Evaluation Mode** with three realistic scenarios:

1. **Insecure Legacy Portal (`Score: 22/100`):**
   - Demonstrates: Expired TLS certificate, cleartext HTTP port 80, missing CSP, missing HSTS, missing X-Frame-Options, cookies without `HttpOnly`/`Secure`, exposed Apache version banners.
2. **Moderate Web Application (`Score: 64/100`):**
   - Demonstrates: Functional HTTPS with valid TLS, but missing CSP defense-in-depth, short HSTS duration, missing clickjacking protection, and missing `SameSite` cookie flags.
3. **Hardened Defense Portal (`Score: 95/100`):**
   - Demonstrates: Modern TLS 1.3, strict CSP without inline scripts, 1-year HSTS preload, strict cookie flags, and sanitized server banners.

---

## ⚖️ Ethical & Security Guardrails

- **Strictly Passive Checks:** ThreatLens AI sends standard HTTP `GET`/`HEAD` requests and TLS handshakes. It does not send exploit payloads, perform SQL injection, fuzz parameters, or attempt password cracking.
- **Anti-SSRF Protection:** Protects internal networks by resolving hostnames prior to connection and rejecting private, loopback, link-local, and cloud metadata IPs. Every redirect is revalidated.
- **Privacy First:** When auditing cookies, ThreatLens AI inspects flag presence (`Secure`, `HttpOnly`, `SameSite`) and cookie names only. Cookie values are discarded and never logged or stored.
- **Educational Disclaimer:** A clean score indicates good baseline hygiene under passive checks; it is not a guarantee of immunity against internal application logic flaws. Always obtain proper authorization before assessing external websites.
