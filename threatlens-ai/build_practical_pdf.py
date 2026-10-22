"""
ThreatLens AI - Practical Output Report PDF Generator (Strict 10-Page Format)
Generates the exact 10-page academic mini-project report with student details:
Venkata Soumya Sri Allamsetti, embedding all 10 visual evidence figures and STRIDE models.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
)
from reportlab.pdfgen import canvas

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_assets")
OUTPUT_PDF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ThreatLens_AI_Mini_Project_Report.pdf")


class NumberedCanvas(canvas.Canvas):
    """Custom canvas that tracks total page count and prints 'Page X' centered at bottom."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#334155"))
        page_text = f"Page {self._pageNumber}"
        self.drawCentredString(letter[0] / 2.0, 26, page_text)
        self.restoreState()


def build_10page_pdf():
    # 36 pt (0.5 in) margins
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=32,
        bottomMargin=38
    )

    styles = getSampleStyleSheet()

    h1_center = ParagraphStyle(
        'H1Center', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=13, leading=16,
        textColor=colors.black, alignment=1, spaceAfter=6
    )

    h1_sub = ParagraphStyle(
        'H1Sub', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9.5, leading=13,
        textColor=colors.black, alignment=1, spaceAfter=6
    )

    sec_title = ParagraphStyle(
        'SecTitle', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=10.5, leading=14,
        textColor=colors.black, spaceBefore=4, spaceAfter=3, keepWithNext=True
    )

    sub_sec_title = ParagraphStyle(
        'SubSecTitle', parent=styles['Heading3'],
        fontName='Helvetica-Bold', fontSize=9.5, leading=12,
        textColor=colors.black, spaceBefore=3, spaceAfter=2, keepWithNext=True
    )

    body = ParagraphStyle(
        'BodyTxt', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8, leading=11,
        textColor=colors.HexColor('#0f172a'), spaceAfter=3
    )

    body_bold = ParagraphStyle(
        'BodyBold', parent=body,
        fontName='Helvetica-Bold'
    )

    bullet_style = ParagraphStyle(
        'BulletTxt', parent=body,
        leftIndent=12, firstLineIndent=-8, spaceAfter=2
    )

    fig_cap = ParagraphStyle(
        'FigCaption', parent=styles['Normal'],
        fontName='Helvetica-Oblique', fontSize=7.5, leading=10,
        textColor=colors.HexColor('#334155'), alignment=1, spaceBefore=2, spaceAfter=4
    )

    cell_style = ParagraphStyle(
        'TableCell', parent=styles['Normal'],
        fontName='Helvetica', fontSize=7.5, leading=9.5,
        textColor=colors.HexColor('#0f172a')
    )

    cell_bold = ParagraphStyle(
        'TableCellBold', parent=cell_style,
        fontName='Helvetica-Bold'
    )

    story = []

    # =========================================================================
    # PAGE 1: Header, Metadata Table, 1. Aim, 2. Objectives, 3. Introduction
    # =========================================================================
    story.append(Paragraph("Cybersecurity Practical: Mini Projects / Practical Output", h1_sub))
    story.append(Paragraph("Mini Project 3: AI-Assisted Cybersecurity Threat Model", h1_center))

    meta_data = [
        [Paragraph("Student name", cell_bold), Paragraph("Allamsetti Venkata Soumya Sri", cell_bold)],
        [Paragraph("Roll number / Student Code", cell_bold), Paragraph("STU-93A9D6", cell_style)],
        [Paragraph("Course / Group", cell_bold), Paragraph("Cyber Security / G17", cell_style)],
        [Paragraph("Platform", cell_bold), Paragraph("SURE ProEd", cell_style)],
        [Paragraph("Host OS", cell_bold), Paragraph("Windows 11", cell_style)],
        [Paragraph("Date", cell_bold), Paragraph("22/10/2026", cell_style)]
    ]
    t_meta = Table(meta_data, colWidths=[160, 380])
    t_meta.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 6))

    story.append(Paragraph("1. Aim", sec_title))
    story.append(Paragraph(
        "To analyse cybersecurity threats in the ThreatLens AI website security risk assessment and threat modeling system "
        "using the STRIDE methodology and AI-assisted recommendations. The report uses the supplied runtime screenshots, "
        "source code implementations, and automated test outputs as evidence and does not treat AI recommendations as proof "
        "of implemented controls.",
        body
    ))

    story.append(Paragraph("2. Objectives", sec_title))
    objs = [
        "Review the multi-tier ThreatLens AI architecture encompassing the browser UI, Flask web service, passive auditing engine, anti-SSRF validator, and SQLite database.",
        "Analyse four critical threats affecting transport layer security, HTTP security header execution context, frame clickjacking boundaries, and audit log data integrity.",
        "Classify each threat systematically using the STRIDE threat-modeling methodology.",
        "Use AI to explain attack scenarios, impacts, mitigations, limitations and verification evidence.",
        "Compare original baseline mitigations with AI-assisted recommendations.",
        "Apply human judgment and report only values supported by code and runtime test evidence."
    ]
    for obj in objs:
        story.append(Paragraph(f"• {obj}", bullet_style))

    story.append(Paragraph("3. Introduction", sec_title))
    story.append(Paragraph(
        "Threat modeling identifies how a system could be attacked and what protections may reduce the risk. In this practical, "
        "the ThreatLens AI defensive ecosystem was modeled to evaluate website configurations, detect missing defenses, and map "
        "observable findings to structured STRIDE threat scenarios. The architecture bridges safe client-side observation and "
        "analytical backend services. AI was used to improve the written analysis and brainstorm mitigations, while human review "
        "was used to check technical accuracy, verify offline constraints, and avoid unsupported claims.",
        body
    ))

    story.append(Paragraph("3.1 Background: Website Security Risk Assessment & Threat Modeling System", sub_sec_title))
    story.append(Paragraph(
        "The model contains an Internet-facing context (untrusted target websites, cleartext port 80 endpoints, and redirection paths), "
        "an internal auditing engine context (anti-SSRF pre-validator, DNS resolver, TLS socket inspector, and heuristic security header analyzer), "
        "a Flask application service, and a persistent SQLite database. In addition, an anti-SSRF protection engine inspects pre-resolved IP addresses "
        "to block loopbacks, RFC 1918 subnets, link-local addresses, and cloud metadata endpoints for secure, zero-latency local execution without "
        "reliance on paid external cloud APIs.",
        body
    ))

    # =========================================================================
    # PAGE 2: Figure 1, 4. STRIDE Table, 5. Tools and Technologies
    # =========================================================================
    story.append(PageBreak())

    fig1_path = os.path.join(ASSETS_DIR, "fig1_architecture.png")
    if os.path.exists(fig1_path):
        story.append(Image(fig1_path, width=520, height=195))
        story.append(Paragraph("Figure 1: ThreatLens AI Multi-Tier System Architecture and STRIDE Boundary Diagram.", fig_cap))

    story.append(Paragraph("4. STRIDE Threat Modeling", sec_title))
    story.append(Paragraph(
        "STRIDE is a threat-modeling acronym used to organise common security threats: Spoofing, Tampering, Repudiation, "
        "Information Disclosure, Denial of Service and Elevation of Privilege. This project focuses on Spoofing, Tampering, "
        "Repudiation and Elevation of Privilege because those are the primary categories shown in the selected ThreatLens AI entries.",
        body
    ))

    stride_data = [
        [Paragraph("STRIDE category", cell_bold), Paragraph("Full form", cell_bold), Paragraph("Meaning in this practical", cell_bold)],
        [Paragraph("S", cell_bold), Paragraph("Spoofing", cell_style), Paragraph("An attacker impersonates a legitimate web application via expired or self-signed TLS certificates.", cell_style)],
        [Paragraph("T", cell_bold), Paragraph("Tampering", cell_style), Paragraph("An attacker intercepts unencrypted HTTP traffic, performs SSL-stripping, or injects inline malicious scripts into the DOM.", cell_style)],
        [Paragraph("R", cell_bold), Paragraph("Repudiation", cell_style), Paragraph("A user or attacker denies submitting malicious inputs or probes because reliable audit logging evidence is missing.", cell_style)],
        [Paragraph("I", cell_bold), Paragraph("Information Disclosure", cell_style), Paragraph("Sensitive server versions (Apache, PHP), session tokens without HttpOnly, or URL query parameters are leaked.", cell_style)],
        [Paragraph("D", cell_bold), Paragraph("Denial of Service", cell_style), Paragraph("A web service or audit tool becomes unresponsive due to infinite redirect loops or oversized response streams.", cell_style)],
        [Paragraph("E", cell_bold), Paragraph("Elevation of Privilege", cell_style), Paragraph("An adversary frames the application in an invisible iframe (clickjacking) or exploits MIME confusion to execute unauthorized actions.", cell_style)]
    ]
    t_stride = Table(stride_data, colWidths=[55, 125, 360])
    t_stride.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
    ]))
    story.append(t_stride)
    story.append(Spacer(1, 4))

    story.append(Paragraph("5. Tools and Technologies Used", sec_title))
    tools = [
        "Python 3.x & Flask: Backend application server providing security check controllers, risk scoring APIs, and threat classification matrix.",
        "SQLite 3: Lightweight relational database storing persistent assessment summaries, granular findings, and threat models.",
        "Standard Socket & SSL: Low-level Python cryptographic libraries for passive TLS handshake, cipher inspection, and certificate validation.",
        "Anti-SSRF Protection Engine: Architectural validator enforcing pre-connection DNS resolution and blocking private IP subnets.",
        "BeautifulSoup4: Static HTML parser for detecting unencrypted HTTP asset references on secure HTTPS contexts.",
        "ReportLab & Chart.js: Executive PDF report generation and client-side threat intelligence chart rendering.",
        "AI assistant: Analytical recommendation, attack scenario expansion, and mitigation explanation support.",
        "STRIDE: Threat classification and security boundary evaluation method."
    ]
    for t in tools:
        story.append(Paragraph(f"• {t}", bullet_style))

    # =========================================================================
    # PAGE 3: 6. Config Table, 7. Methodology, Figure 2, 8. AI Prompt
    # =========================================================================
    story.append(PageBreak())

    story.append(Paragraph("6. System Configuration and Model Evidence", sec_title))
    config_data = [
        [Paragraph("Component", cell_bold), Paragraph("Details", cell_bold)],
        [Paragraph("Threat-modeling framework", cell_style), Paragraph("Microsoft STRIDE & Quantitative Risk Scoring (Likelihood x Impact = 1 to 25)", cell_style)],
        [Paragraph("Model", cell_style), Paragraph("ThreatLens AI Multi-Tier Website Security Risk Assessment Architecture", cell_style)],
        [Paragraph("Client UI Component", cell_style), Paragraph("Web Frontend (HTML5, Vanilla CSS Cyber Theme, JavaScript, Chart.js)", cell_style)],
        [Paragraph("Application component", cell_style), Paragraph("Python Flask Web Application (REST API / Assessment Controller)", cell_style)],
        [Paragraph("Security Engine", cell_style), Paragraph("Passive Auditing Engine (security_checks.py) & Anti-SSRF Pre-Validator", cell_style)],
        [Paragraph("Database component", cell_style), Paragraph("SQLite (threatlens.db with parameterized SQL queries)", cell_style)],
        [Paragraph("Threat Feed Source", cell_style), Paragraph("STRIDE Heuristic Threat Knowledge Base & OWASP Top 10 Guidelines", cell_style)],
        [Paragraph("Evidence source", cell_style), Paragraph("Source code files, Web dashboard, results screen, and automated pytest execution logs", cell_style)]
    ]
    t_config = Table(config_data, colWidths=[160, 380])
    t_config.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
    ]))
    story.append(t_config)
    story.append(Spacer(1, 4))

    story.append(Paragraph("7. Methodology and Practical Procedure", sec_title))
    steps = [
        "1. Opened and structured the ThreatLens AI project files under modern Flask MVC architecture.",
        "2. Engineered the anti-SSRF validator with socket.getaddrinfo to block loopback, RFC 1918, and cloud metadata targets.",
        "3. Implemented safe passive security checks for HTTPS redirection, TLS certificate validity, and response headers.",
        "4. Built the HTTP security header inspector evaluating CSP, HSTS, X-Content-Type-Options, and Frame Protection.",
        "5. Developed the Flask web controller and SQLite database schema with parameterized queries to prevent SQL injection.",
        "6. Prepared an AI prompt requesting beginner-friendly analysis, practical controls, limitations, and verification evidence.",
        "7. Reviewed the AI output, evaluated trade-offs, and refined the practical mitigations across client and server tiers.",
        "8. Separated observed implementation facts, automated unit test results, and conceptual recommendations."
    ]
    for s in steps:
        story.append(Paragraph(s, bullet_style))
    story.append(Spacer(1, 3))

    fig2_path = os.path.join(ASSETS_DIR, "fig2_dashboard.png")
    if os.path.exists(fig2_path):
        story.append(Image(fig2_path, width=520, height=170))
        story.append(Paragraph("Figure 2: ThreatLens AI Web Dashboard showing real-time risk scoring, assessment summaries, and monitoring controls.", fig_cap))

    story.append(Paragraph("8. AI Prompt and AI-Assisted Analysis", sec_title))
    story.append(Paragraph(
        "The supplied AI prompt asked the assistant to act as a cybersecurity threat-modeling analyst reviewing the ThreatLens AI "
        "system. It named four threats: transport security downgrade via cleartext interception, script injection via missing CSP, "
        "transparent DOM clickjacking, and server-side request forgery / audit log tampering. For each threat it requested an attack scenario, "
        "impact, practical controls, verification evidence, limitations and a human-review decision.",
        body
    ))

    # =========================================================================
    # PAGE 4: Figure 3, Threat 1 Table, 9.1 Threat 1 Updated Mitigation
    # =========================================================================
    story.append(PageBreak())

    fig3_path = os.path.join(ASSETS_DIR, "fig3_ai_prompt.png")
    if os.path.exists(fig3_path):
        story.append(Image(fig3_path, width=520, height=155))
        story.append(Paragraph("Figure 3: AI-assisted threat-analysis prompt supplied in the evidence archive.", fig_cap))

    story.append(Paragraph(
        "The AI output was reviewed and used to expand the practical mitigation recommendations. Relying solely on client heuristics "
        "or basic HTTP checks does not automatically remove the risk; multi-layered controls and human review remain essential.",
        body
    ))

    story.append(Paragraph("9. Threat 1: Credential Harvesting & Transport Security Downgrade", sec_title))
    threat1_data = [
        [Paragraph("Affected component", cell_bold), Paragraph("Transport Layer / Socket & TLS Inspector (security_checks.py)", cell_style)],
        [Paragraph("STRIDE category", cell_bold), Paragraph("Tampering / Spoofing", cell_style)],
        [Paragraph("Attack scenario", cell_bold), Paragraph("An attacker on an untrusted local network (e.g. public Wi-Fi) intercepts unencrypted HTTP port 80 traffic or forces an SSL-stripping downgrade to capture credentials and session tokens.", cell_style)],
        [Paragraph("Potential impact", cell_bold), Paragraph("Loss of confidentiality, cleartext credential theft, unauthorized session hijacking, and reputational damage.", cell_style)],
        [Paragraph("Existing mitigation / status", cell_bold), Paragraph("Automatic HTTP-to-HTTPS 301 redirection verification, HSTS header presence audit, and TLS expiration check. Status: Mitigated; Score: 12 (High Risk).", cell_style)],
        [Paragraph("AI recommendations", cell_bold), Paragraph("Enforce HSTS with max-age=31536000 and includeSubDomains; submit domain to browser HSTS preload list; deploy automated ACME renewal agents.", cell_style)],
        [Paragraph("Verification evidence", cell_bold), Paragraph("Automated unit test [PASS] test_downgrade_redirect_detected and socket TLS handshake verification.", cell_style)],
        [Paragraph("Human conclusion", cell_bold), Paragraph("Reasonable recommendations. Automatic 301 redirection combined with HSTS preload permanently closes the cleartext window.", cell_style)]
    ]
    t_threat1 = Table(threat1_data, colWidths=[150, 390])
    t_threat1.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
    ]))
    story.append(t_threat1)

    story.append(Paragraph("9.1 Threat 1: Updated Mitigation", sec_title))
    story.append(Paragraph(
        "The updated mitigation recommendations expand basic keyword matching by combining syntactic transport inspection with compound scoring rules. "
        "Under the enhanced defense in security_checks.py, if a target website fails to redirect plaintext HTTP traffic to HTTPS, "
        "the engine assigns an immediate penalty and generates a High Severity Tampering threat record (Likelihood: 3, Impact: 4, "
        "Risk Score: 12). If paired with an expired certificate, the score elevates to 20+ (Critical Severity). "
        "The web interface displays exact redirect status and certificate expiration window, enabling engineers to adjust sliders dynamically.",
        body
    ))

    # =========================================================================
    # PAGE 5: Figure 4, Figure 5, 10. Threat 2 Table
    # =========================================================================
    story.append(PageBreak())

    fig4_path = os.path.join(ASSETS_DIR, "fig4_results_threat1.png")
    if os.path.exists(fig4_path):
        story.append(Image(fig4_path, width=520, height=170))
        story.append(Paragraph("Figure 4: Threat 1 assessment screen showing transport security warning, evidence breakdown, and safe recommendations.", fig_cap))

    fig5_path = os.path.join(ASSETS_DIR, "fig5_code_threat1.png")
    if os.path.exists(fig5_path):
        story.append(Image(fig5_path, width=520, height=140))
        story.append(Paragraph("Figure 5: Threat 1 updated mitigation recommendations and TLS inspection logic in security_checks.py.", fig_cap))

    story.append(Paragraph("10. Threat 2: Deceptive Script Execution & Missing Content-Security-Policy", sec_title))
    threat2_data = [
        [Paragraph("Affected component", cell_bold), Paragraph("Security Headers Inspector (security_checks.py)", cell_style)],
        [Paragraph("STRIDE category", cell_bold), Paragraph("Tampering / Elevation of Privilege", cell_style)],
        [Paragraph("Attack scenario", cell_bold), Paragraph("In the event of an input sanitization flaw in the application, the absence of a Content-Security-Policy allows injected JavaScript to execute unrestricted, exfiltrating tokens and modifying DOM elements.", cell_style)],
        [Paragraph("Potential impact", cell_bold), Paragraph("Cross-site scripting (XSS) amplification, session token theft, unauthorized client-side actions, and telemetry tracking.", cell_style)],
        [Paragraph("Existing mitigation / status", cell_bold), Paragraph("Content-Security-Policy audit inspecting for header presence, unsafe-inline, unsafe-eval, and wildcard origins. Status: Mitigated; Score: 12 (High Risk).", cell_style)],
        [Paragraph("AI recommendations", cell_bold), Paragraph("Deploy strict CSP header with default-src 'self', script nonces (nonce-...), object-src 'none', and automated CSP violation reporting endpoints.", cell_style)],
        [Paragraph("Verification evidence", cell_bold), Paragraph("Automated unit tests [PASS] test_missing_all_security_headers and [PASS] test_permissive_csp_warning.", cell_style)],
        [Paragraph("Human conclusion", cell_bold), Paragraph("Strict CSP provides vital defense-in-depth against injection flaws; nonces prevent script execution bypasses.", cell_style)]
    ]
    t_threat2 = Table(threat2_data, colWidths=[150, 390])
    t_threat2.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
    ]))
    story.append(t_threat2)

    # =========================================================================
    # PAGE 6: Figure 6, 11. Threat 3 Table, Figure 7
    # =========================================================================
    story.append(PageBreak())

    fig6_path = os.path.join(ASSETS_DIR, "fig6_code_threat2.png")
    if os.path.exists(fig6_path):
        story.append(Image(fig6_path, width=520, height=140))
        story.append(Paragraph("Figure 6: Threat 2 HTTP security header audit logic and CSP defense in security_checks.py.", fig_cap))

    story.append(Paragraph("11. Threat 3: Clickjacking & Transparent Viewport Traps", sec_title))
    threat3_data = [
        [Paragraph("Affected component", cell_bold), Paragraph("Frame Protection Inspector (security_checks.py)", cell_style)],
        [Paragraph("STRIDE category", cell_bold), Paragraph("Elevation of Privilege / Tampering", cell_style)],
        [Paragraph("Attack scenario", cell_bold), Paragraph("An attacker overlays an invisible, full-screen transparent iframe (e.g., opacity: 0, z-index: 999999) on a malicious decoy page to hijack user clicks into triggering unauthorized administrative or financial actions.", cell_style)],
        [Paragraph("Potential impact", cell_bold), Paragraph("Involuntary execution of privileged actions, fraudulent transactions, altered user permissions, and UI deception.", cell_style)],
        [Paragraph("Existing mitigation / status", cell_bold), Paragraph("Frame protection evaluation inspecting for CSP frame-ancestors directive or X-Frame-Options (DENY / SAMEORIGIN). Status: Mitigated; Score: 12 (High Risk).", cell_style)],
        [Paragraph("AI recommendations", cell_bold), Paragraph("Configure Content-Security-Policy: frame-ancestors 'self' across all endpoints; enforce X-Frame-Options: SAMEORIGIN; set SameSite=Lax on all session cookies.", cell_style)],
        [Paragraph("Verification evidence", cell_bold), Paragraph("Response header inspection verifies framing restrictions; simulated iframe embedding confirms browser blocks rendering.", cell_style)],
        [Paragraph("Human conclusion", cell_bold), Paragraph("Frame-ancestors is the modern standard for clickjacking prevention; SameSite cookies provide secondary CSRF and clickjack protection.", cell_style)]
    ]
    t_threat3 = Table(threat3_data, colWidths=[150, 390])
    t_threat3.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
    ]))
    story.append(t_threat3)
    story.append(Spacer(1, 4))

    fig7_path = os.path.join(ASSETS_DIR, "fig7_threat3_diagram.png")
    if os.path.exists(fig7_path):
        story.append(Image(fig7_path, width=520, height=155))
        story.append(Paragraph("Figure 7: Threat 3 neutralization of invisible full-screen clickjack traps via Frame-Protection.", fig_cap))

    # =========================================================================
    # PAGE 7: 12. Threat 4 Table, 12.1 Figure 8
    # =========================================================================
    story.append(PageBreak())

    story.append(Paragraph("12. Threat 4: Threat Intelligence & Analysis History Tampering (Anti-SSRF)", sec_title))
    threat4_data = [
        [Paragraph("Affected component", cell_bold), Paragraph("Anti-SSRF URL Pre-Validator & SQLite Database (security_checks.py & database.py)", cell_style)],
        [Paragraph("STRIDE category", cell_bold), Paragraph("Tampering / Repudiation", cell_style)],
        [Paragraph("Attack scenario", cell_bold), Paragraph("An attacker submits internal IP targets (127.0.0.1, 169.254.169.254) to execute Server-Side Request Forgery, or injects SQL payloads into the analysis form to truncate audit records.", cell_style)],
        [Paragraph("Potential impact", cell_bold), Paragraph("Falsification of security audit records, internal cloud metadata exposure, database corruption, and non-repudiation failure.", cell_style)],
        [Paragraph("Existing mitigation / status", cell_bold), Paragraph("Architectural anti-SSRF validator with socket.getaddrinfo pre-resolution blocking private/loopback/cloud metadata; 100% parameterized SQLite execution. Status: Mitigated; Score: 16 (High Risk).", cell_style)],
        [Paragraph("AI recommendations", cell_bold), Paragraph("HMAC-SHA256 cryptographic chaining of history rows, append-only file system permissions, and remote SIEM syslog replication.", cell_style)],
        [Paragraph("Verification evidence", cell_bold), Paragraph("Automated unit tests [PASS] test_block_localhost, [PASS] test_block_cloud_metadata_ipv4, and parameterized SQL tests.", cell_style)],
        [Paragraph("Human conclusion", cell_bold), Paragraph("Pre-connection DNS validation and parameterized queries fully eliminate SSRF and SQL injection; HMAC hashing is a valuable future enhancement.", cell_style)]
    ]
    t_threat4 = Table(threat4_data, colWidths=[150, 390])
    t_threat4.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
    ]))
    story.append(t_threat4)
    story.append(Spacer(1, 4))

    story.append(Paragraph("12.1 Threat 4 Evidence", sub_sec_title))
    fig8_path = os.path.join(ASSETS_DIR, "fig8_history_ledger.png")
    if os.path.exists(fig8_path):
        story.append(Image(fig8_path, width=520, height=215))
        story.append(Paragraph("Figure 8: Flask web analyzer interface showing threat metrics, assessment records, and SQLite analysis ledger.", fig_cap))

    # =========================================================================
    # PAGE 8: 13. Comparison Table, 14. Human Evaluation, Figure 9
    # =========================================================================
    story.append(PageBreak())

    story.append(Paragraph("13. Existing Mitigations versus AI Recommendations", sec_title))
    comp_data = [
        [Paragraph("Threat", cell_bold), Paragraph("Existing evidence", cell_bold), Paragraph("AI-assisted recommendation", cell_bold), Paragraph("Evidence status", cell_bold)],
        [Paragraph("Transport Downgrade", cell_style), Paragraph("Port 80 redirect check (+15), TLS validity check; Score: 12", cell_style), Paragraph("HSTS preload, TLS 1.3 protocol enforcement, DNS CAA records", cell_style), Paragraph("Verified via unit tests & live socket checks", cell_style)],
        [Paragraph("Script Injection (CSP)", cell_style), Paragraph("CSP audit, unsafe-inline & wildcard inspection; Score: 12", cell_style), Paragraph("Cryptographic nonces, object-src 'none', CSP reporting URI", cell_style), Paragraph("Verified via response header unit tests", cell_style)],
        [Paragraph("Clickjacking", cell_style), Paragraph("Frame-ancestors & X-Frame-Options inspection; Score: 12", cell_style), Paragraph("CSP frame-ancestors 'self', SameSite=Lax cookie attribute", cell_style), Paragraph("Verified via DOM element inspection & unit tests", cell_style)],
        [Paragraph("Audit Tampering / SSRF", cell_style), Paragraph("Anti-SSRF pre-validator, parameterized SQLite queries; Score: 16", cell_style), Paragraph("HMAC log chaining, append-only permissions, SIEM replication", cell_style), Paragraph("Verified via SSRF tests & SQL injection tests", cell_style)]
    ]
    t_comp = Table(comp_data, colWidths=[100, 140, 160, 140])
    t_comp.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 4))

    story.append(Paragraph(
        "The comparison shows that AI broadened short mitigation statements into comprehensive, enterprise-grade defense-in-depth "
        "themes. It does not establish that every proposed technology is currently implemented in code.",
        body
    ))

    story.append(Paragraph("14. Human Evaluation of AI Recommendations", sec_title))
    story.append(Paragraph(
        "Human judgment was required to decide whether each recommendation matched the threat, whether it was technically "
        "reasonable, and whether it went beyond the evidence. The most critical review decision was to ensure that ThreatLens AI "
        "remained 100% passive, safe, and privacy-preserving, rejecting AI suggestions that mandated intrusive payload injection "
        "or external telemetry servers. A second decision was to maintain transparent risk score formulas (Likelihood x Impact = 1 to 25), "
        "preventing opaque AI black-box calculations.",
        body
    ))
    story.append(Spacer(1, 3))

    fig9_path = os.path.join(ASSETS_DIR, "fig9_ai_response.png")
    if os.path.exists(fig9_path):
        story.append(Image(fig9_path, width=520, height=170))
        story.append(Paragraph("Figure 9: AI-assisted threat analysis response including limitations and a human-review decision.", fig_cap))

    # =========================================================================
    # PAGE 9: Figure 10, 15. Results and Discussion, 16. Limitations
    # =========================================================================
    story.append(PageBreak())

    fig10_path = os.path.join(ASSETS_DIR, "fig10_pytest_execution.png")
    if os.path.exists(fig10_path):
        story.append(Image(fig10_path, width=520, height=195))
        story.append(Paragraph("Figure 10: Automated unit test suite execution confirming 46 passing tests with zero failures.", fig_cap))

    story.append(Paragraph("15. Results and Discussion", sec_title))
    res_items = [
        "The multi-tier ThreatLens AI architecture was successfully modeled across client, security engine, and server tiers.",
        "Four critical threats were analyzed covering Spoofing, Tampering, Repudiation, and Elevation of Privilege.",
        "Threat 1 demonstrated robust transport downgrade detection, achieving an evidenced risk score of 12 (High).",
        "Threat 2 verified Content-Security-Policy script restriction auditing with an evidenced risk score of 12 (High).",
        "Threats 3 and 4 successfully validated in-page clickjack defense and anti-SSRF parameterized database security.",
        "AI improved explanation quality and defense-in-depth perspectives, but human review remained necessary."
    ]
    for r in res_items:
        story.append(Paragraph(f"• {r}", bullet_style))

    story.append(Paragraph(
        "Result: STRIDE threat modeling and AI-assisted analysis were applied to four core threats in ThreatLens AI, and every AI "
        "recommendation was evaluated against verifiable code and automated test evidence before being reported.",
        body_bold
    ))

    story.append(Paragraph("16. Limitations and Recommendations", sec_title))
    story.append(Paragraph("16.1 Limitations", sub_sec_title))
    lims = [
        "Passive HTTP/TLS checks cannot inspect internal server-side application logic, database queries, or stored credentials.",
        "Web applications with client-side JavaScript rendering (SPAs) may dynamically load unobservable DOM resources.",
        "Multi-hop redirect expansion without network HEAD requests is limited to observable browser navigation events.",
        "AI recommendations can introduce unnecessary architectural complexity if accepted without scrutiny."
    ]
    for l in lims:
        story.append(Paragraph(f"• {l}", bullet_style))

    # =========================================================================
    # PAGE 10: 16.2 Recommendations, 17. Conclusion, 18. References
    # =========================================================================
    story.append(PageBreak())

    story.append(Paragraph("16.2 Recommendations", sub_sec_title))
    recs = [
        "Deploy lightweight on-device machine learning (e.g., TensorFlow.js or ONNX) to recognize non-linear phishing indicators.",
        "Incorporate perceptual favicon and visual logo hashing to detect brand spoofing on zero-day clean domains.",
        "Implement HMAC-SHA256 cryptographic chaining in SQLite to ensure immutable audit log integrity.",
        "Establish an automated daily sync workflow for emerging CVE vulnerability feeds.",
        "Expand automated test fixtures to cover emerging unicode homograph attacks (punycode spoofing).",
        "Keep browser extension permissions strictly scoped to minimize endpoint attack surface."
    ]
    for r in recs:
        story.append(Paragraph(f"• {r}", bullet_style))

    story.append(Paragraph("17. Conclusion", sec_title))
    story.append(Paragraph(
        "This project applied the STRIDE threat modeling methodology and AI-assisted analysis to four primary threats in the "
        "ThreatLens AI cybersecurity ecosystem. AI expanded baseline mitigation ideas into structured, multi-tier controls covering "
        "transport security, script injection boundaries, clickjacking traps, and database audit security. The final evaluation confirms that "
        "an AI recommendation is not the same as an implemented and effective security control. Empirical evidence, automated "
        "testing, and human judgment remain essential to robust cybersecurity engineering.",
        body
    ))

    story.append(Paragraph("18. References", sec_title))
    refs = [
        "1. OWASP Threat Modeling Community: https://owasp.org/www-community/Threat_Modeling",
        "2. Microsoft STRIDE Threat Modeling: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats",
        "3. OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/",
        "4. OWASP Top 10 Web Application Security Risks: https://owasp.org/www-project-top-ten/",
        "5. OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/",
        "6. NIST Special Publication 800-63B (Digital Identity Guidelines): https://pages.nist.gov/800-63-3/sp800-63b.html",
        "7. IANA RFC 2606 (Reserved Top Level DNS Names for Testing): https://datatracker.ietf.org/doc/html/rfc2606"
    ]
    for ref in refs:
        story.append(Paragraph(ref, bullet_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[OK] Master 10-page report PDF built successfully: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_10page_pdf()
