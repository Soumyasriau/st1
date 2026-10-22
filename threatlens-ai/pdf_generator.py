"""
ThreatLens AI - PDF Report Generation
Generates a downloadable, well-formatted cybersecurity assessment PDF report using ReportLab.
"""

import io
from typing import Dict, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak


def generate_pdf_report(assessment: Dict[str, Any]) -> io.BytesIO:
    """
    Generate an executive PDF security assessment report from assessment data.
    Returns an in-memory BytesIO buffer containing the PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=0,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=14
    )

    h2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0284c7'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1e293b')
    )

    bullet_style = ParagraphStyle(
        'BulletText',
        parent=body_style,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    story = []

    # Header / Title Block
    story.append(Paragraph("ThreatLens AI — Website Security Risk Assessment Report", title_style))
    meta_text = (
        f"<b>Target Host:</b> {assessment.get('hostname')} | "
        f"<b>Assessment Date:</b> {assessment.get('scan_timestamp')} | "
        f"<b>Overall Score:</b> {assessment.get('overall_score')}/100"
    )
    story.append(Paragraph(meta_text, subtitle_style))
    story.append(Spacer(1, 10))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    exec_summary = assessment.get("executive_summary", "").replace("\n", "<br/>")
    story.append(Paragraph(exec_summary, body_style))
    story.append(Spacer(1, 12))

    # Metrics Summary Table
    story.append(Paragraph("2. Assessment Overview & Scorecard", h2_style))
    risk_sum = assessment.get("risk_summary", {})
    checks_sum = assessment.get("checks_summary", {})

    scorecard_data = [
        ["Security Hygiene Score", f"{assessment.get('overall_score')}/100", "Total Checks", str(checks_sum.get('total', 0))],
        ["Checks Passed", str(checks_sum.get('passed', 0)), "Checks Requiring Attention", str(checks_sum.get('warning', 0) + checks_sum.get('failed', 0))],
        ["Critical Threats", str(risk_sum.get('critical', 0)), "High Severity Threats", str(risk_sum.get('high', 0))],
        ["Medium Threats", str(risk_sum.get('medium', 0)), "Low Severity Threats", str(risk_sum.get('low', 0))]
    ]

    t_scorecard = Table(scorecard_data, colWidths=[140, 120, 140, 140])
    t_scorecard.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_scorecard)
    story.append(Spacer(1, 14))

    # Security Findings Table
    story.append(Paragraph("3. Observed Security Findings", h2_style))
    findings_data = [["Code", "Finding Title", "Category", "Status", "Severity"]]
    for f in assessment.get("findings", []):
        findings_data.append([
            f.get("finding_code", ""),
            f.get("title", "")[:35],
            f.get("category", "")[:20],
            f.get("status", ""),
            f.get("severity", "")
        ])

    t_findings = Table(findings_data, colWidths=[65, 185, 130, 80, 80])
    t_findings.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0284c7')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_findings)
    story.append(Spacer(1, 14))

    # STRIDE Threat Modeling Section
    story.append(Paragraph("4. STRIDE Threat Model Scenarios & Risk Scoring", h2_style))
    story.append(Paragraph(
        "Risk Score = Likelihood (1-5) x Impact (1-5). Severity: Low (1-4), Medium (5-9), High (10-16), Critical (17-25).",
        body_style
    ))
    story.append(Spacer(1, 6))

    threats = assessment.get("threat_scenarios", [])
    if not threats:
        story.append(Paragraph("No active threat scenarios mapped for this assessment.", body_style))
    else:
        for t in threats:
            threat_block = []
            header_str = (
                f"<b>[{t.get('threat_id')}] {t.get('title')}</b> — "
                f"STRIDE: <b>{t.get('threat_category')}</b> | "
                f"Risk Score: <b>{t.get('risk_score')}/25 ({t.get('severity')})</b>"
            )
            threat_block.append(Paragraph(header_str, ParagraphStyle(
                'ThreatHeader',
                parent=body_style,
                fontName='Helvetica-Bold',
                fontSize=9,
                textColor=colors.HexColor('#b91c1c') if t.get('severity') in ('High', 'Critical') else colors.HexColor('#d97706')
            )))

            scenario_p = f"<b>Attack Scenario:</b> {t.get('attack_scenario')}"
            threat_block.append(Paragraph(scenario_p, bullet_style))

            mitigation_p = f"<b>Recommended Mitigation:</b> {t.get('mitigation')}"
            threat_block.append(Paragraph(mitigation_p, bullet_style))

            steps_p = f"<b>Verification:</b> {t.get('verification_steps')}".replace("\n", "<br/>")
            threat_block.append(Paragraph(steps_p, bullet_style))
            threat_block.append(Spacer(1, 6))

            story.append(KeepTogether(threat_block))

    # Scope & Methodology Disclaimer
    story.append(Spacer(1, 10))
    story.append(Paragraph("5. Scope, Limitations & Educational Disclaimer", h2_style))
    disclaimer_text = (
        "ThreatLens AI performs solely passive, non-intrusive HTTP checks against authorized hosts. "
        "It does not perform penetration testing, credential attacks, or vulnerability exploitation. "
        "A passing assessment indicates good baseline configuration hygiene under tested parameters and does not "
        "guarantee absolute security against application-layer vulnerabilities or zero-day exploits."
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle(
        'Disclaimer',
        parent=body_style,
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748b')
    )))

    doc.build(story)
    buffer.seek(0)
    return buffer
