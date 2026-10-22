# ThreatLens AI — Viva & Technical Oral Exam Guide
## College Mini-Project Defense Reference

This guide provides direct, structured answers to questions commonly asked by professors, external examiners, and evaluators during project vivas.

---

### Q1: What is ThreatLens AI and what does it do?
**Answer:**  
ThreatLens AI is a defensive web application security tool that evaluates the publicly observable security configuration of websites using safe, passive HTTP/TLS requests. It identifies weaknesses (like missing security headers or unencrypted cookies), maps them to Microsoft's **STRIDE threat modeling categories**, calculates quantitative risk scores using the formula $\text{Likelihood} \times \text{Impact}$, and provides concrete mitigations and verification steps.

---

### Q2: Why did you choose passive scanning rather than active vulnerability scanning?
**Answer:**  
1. **Ethical & Legal Safety:** Active scanning sends malicious payloads, SQL injection tests, or brute-force requests, which is illegal against targets without explicit, signed penetration-testing contracts.
2. **Defensive Focus:** Passive scanning inspects response headers, TLS handshake details, and static HTML tags without altering server state, stressing network bandwidth, or risking service denial.
3. **SSRF Immunity:** Passive inspection strictly observes public targets without accessing internal intranet endpoints.

---

### Q3: What is STRIDE and how is it implemented in your project?
**Answer:**  
STRIDE is a threat modeling methodology developed by Microsoft to categorize security threats into six distinct types:

| Letter | Category | Definition | Example in ThreatLens AI |
|:---:|:---|:---|:---|
| **S** | **Spoofing** | Pretending to be someone or something else. | An expired or self-signed TLS certificate allows an attacker on the network to impersonate the target server. |
| **T** | **Tampering** | Modifying data in transit or storage. | Absence of HTTPS or missing CSP allows network eavesdroppers to inject rogue scripts into cleartext traffic. |
| **R** | **Repudiation** | Denying an action took place without proof. | Lack of origin tracking or security audit headers. |
| **I** | **Information Disclosure** | Leaking sensitive data to unauthorized parties. | Exposing granular `Server: Apache/2.4.41` banners, missing `HttpOnly` on session cookies, or permissive Referrer-Policy. |
| **D** | **Denial of Service** | Degrading or exhausting system availability. | Expiring TLS certificates causing browser blocking; redirect loops. |
| **E** | **Elevation of Privilege** | Gaining unauthorized access or capabilities. | Missing `X-Frame-Options` allowing Clickjacking (UI redressing), or missing `nosniff` enabling MIME-type confusion attacks. |

---

### Q4: What risk scoring formula did you use?
**Answer:**  
We used the standard OWASP and NIST risk formula:

$$\text{Risk Score} = \text{Likelihood (1 to 5)} \times \text{Impact (1 to 5)}$$

- The result ranges from **1 to 25**.
- We classify risk into four severity bands:
  - **1 – 4:** Low Severity (Green)
  - **5 – 9:** Medium Severity (Amber)
  - **10 – 16:** High Severity (Orange)
  - **17 – 25:** Critical Severity (Red)
- **Interactive Feature:** Users can adjust Likelihood and Impact on the results screen, and the tool recalculates the risk score and severity badge in real time via AJAX.

---

### Q5: How does your application prevent Server-Side Request Forgery (SSRF)?
**Answer:**  
SSRF occurs when an attacker tricks a backend server into making requests to internal or prohibited addresses. We prevent SSRF using a multi-layer defense:
1. **Scheme Validation:** Only `http://` and `https://` are permitted. Schemes like `file://`, `gopher://`, or `dict://` are blocked.
2. **Pre-connection DNS Resolution:** Before establishing any connection, we resolve the domain using `socket.getaddrinfo()`.
3. **IP Range Filtering (`ipaddress` module):** Every resolved IP is evaluated. We strictly block:
   - Loopback addresses (`127.0.0.1`, `::1`)
   - Private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local addresses (`169.254.0.0/16`, `fe80::/10`)
   - Cloud metadata IP (`169.254.169.254`) and hostnames (`metadata.google.internal`)
4. **Redirect Revalidation:** Every intermediate redirect destination URL is parsed, resolved, and re-checked against the anti-SSRF filters before fetching.
5. **Safety Limits:** Timeouts (6 seconds), max redirects (5 hops), and max response body size (2 MB) prevent resource exhaustion.

---

### Q6: Explain the key HTTP security headers evaluated by your tool.
**Answer:**
1. **Content-Security-Policy (CSP):** Tells browsers which script, style, and image sources are authorized to execute. Prevents Cross-Site Scripting (XSS) and data exfiltration.
2. **Strict-Transport-Security (HSTS):** Instructs browsers to interact with the domain *strictly over HTTPS* for a specified duration (`max-age`), protecting against SSL-stripping attacks.
3. **X-Content-Type-Options:** When set to `nosniff`, it prevents browsers from MIME-sniffing a response away from the declared `Content-Type`, preventing malicious executable uploads disguised as text or images.
4. **X-Frame-Options / CSP frame-ancestors:** Restricts whether external websites can embed your site in an `<iframe>`, preventing Clickjacking attacks.
5. **Referrer-Policy:** Restricts how much URL path and query information is sent in the `Referer` header to external websites, preventing token leaks.
6. **Permissions-Policy:** Explicitly restricts browser hardware features like camera, microphone, and geolocation.

---

### Q7: What checks are performed on TLS certificates?
**Answer:**  
Using Python's standard `ssl` library with verification enabled (`ssl.create_default_context()`):
1. **Validity & Expiry:** Compares the certificate's `notAfter` timestamp against UTC time to determine if it is expired or expiring within 30 days.
2. **Issuer & Trust:** Retrieves the Certificate Authority (e.g. Let's Encrypt, DigiCert) and checks for self-signed or untrusted certificates.
3. **Protocol & Cipher:** Inspects the negotiated TLS version (TLS 1.2 or TLS 1.3) and cipher suite (e.g. `TLS_AES_256_GCM_SHA384`).
4. **SANs (Subject Alternative Names):** Confirms the audited hostname matches the DNS entries listed in the certificate.

---

### Q8: How does your tool audit cookies while respecting user privacy?
**Answer:**  
ThreatLens AI inspects the `Set-Cookie` header for three essential defensive flags:
- **`Secure`:** Ensures cookies are only transmitted over encrypted HTTPS connections.
- **`HttpOnly`:** Blocks JavaScript (`document.cookie`) from accessing session tokens, mitigating cookie theft via XSS.
- **`SameSite`:** Controls whether cookies are sent with cross-site requests (`Strict` or `Lax`), preventing Cross-Site Request Forgery (CSRF).
- **Privacy Guarantee:** The tool parses the cookie name and flags, but **immediately discards the sensitive cookie value**. No secret session identifiers are ever stored in the database or logs.

---

### Q9: What is Mixed Content and why is it dangerous?
**Answer:**  
Mixed content occurs when an initial HTML page is loaded securely over HTTPS, but references other resources (like `<script src="http://...">` or `<img src="http://...">`) over unencrypted HTTP.
- **Active Mixed Content (Scripts, Stylesheets, Iframes):** An attacker on the local network can intercept the unencrypted HTTP script and replace it with malicious JavaScript, completely compromising the HTTPS page.
- **Passive Mixed Content (Images, Audio, Video):** An attacker can alter images to deceive users or track viewing habits.

---

### Q10: Where is the AI in ThreatLens AI?
**Answer (Honest & Accurate Academic Answer):**  
"In this prototype, ThreatLens AI utilizes an **expert-rule threat synthesis engine** founded on STRIDE and OWASP heuristics to correlate observable configuration anomalies into structured attack scenarios, risk rationales, and mitigations. 

The architecture includes a dedicated **pluggable AI integration point** that can be connected to large language models (such as Google Gemini, OpenAI, or a local Ollama instance) to dynamically enrich threat narratives. For local offline evaluation and college demonstrations, the deterministic expert-rules engine guarantees reliable, consistent, and instant threat modeling without relying on paid APIs or external network latency."

---

### Q11: How does the offline demonstration mode work?
**Answer:**  
ThreatLens AI includes a module called `sample_data.py` with three realistic, pre-configured profiles:
1. **Insecure Legacy Portal (Score: 22/100):** Exhibits expired TLS, cleartext HTTP port 80, missing CSP, missing HSTS, missing X-Frame-Options, vulnerable cookies, and exposed server version banners.
2. **Moderate Web App (Score: 64/100):** Operates over HTTPS with valid TLS, but lacks CSP defense-in-depth, has short HSTS duration, and misses clickjacking protection.
3. **Hardened Defense Portal (Score: 95/100):** Features TLS 1.3, strict CSP without inline scripts, 1-year HSTS preload, secure cookies, and sanitized server headers.

This guarantees a seamless demonstration during exams even if the lab has no internet connectivity!

---

### Q12: How is the database organized?
**Answer:**  
We use SQLite (`threatlens.db`) with foreign keys enabled (`PRAGMA foreign_keys = ON`):
- `assessments`: Primary scan metadata, overall score, and JSON summaries.
- `findings`: Granular check results (`PASS`, `WARNING`, `FAIL`), severity, and observed evidence.
- `threat_scenarios`: STRIDE threat records linked to findings with Likelihood, Impact, Risk Score, and mitigation instructions.
- `mitigation_status`: Remediation workflow state (`Open`, `In Progress`, `Mitigated`, `Accepted`) and timestamped notes.
- **Cascade Deletion:** Deleting an assessment automatically deletes all linked findings and threat records.
