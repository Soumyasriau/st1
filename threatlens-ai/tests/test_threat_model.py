"""
Unit tests for ThreatLens AI Threat Modeling & STRIDE Risk Scoring Engine.
"""

import pytest
from threat_model import (
    calculate_risk,
    generate_threat_model,
    generate_executive_summary
)


class TestRiskFormulaAndSeverity:
    """Test suite validating Risk Score = Likelihood x Impact and severity classifications."""

    def test_risk_score_calculation(self):
        # 1-4: Low
        score, sev = calculate_risk(1, 1)
        assert score == 1
        assert sev == "Low"

        score, sev = calculate_risk(2, 2)
        assert score == 4
        assert sev == "Low"

        # 5-9: Medium
        score, sev = calculate_risk(2, 3)
        assert score == 6
        assert sev == "Medium"

        score, sev = calculate_risk(3, 3)
        assert score == 9
        assert sev == "Medium"

        # 10-16: High
        score, sev = calculate_risk(2, 5)
        assert score == 10
        assert sev == "High"

        score, sev = calculate_risk(4, 4)
        assert score == 16
        assert sev == "High"

        # 17-25: Critical
        score, sev = calculate_risk(4, 5)
        assert score == 20
        assert sev == "Critical"

        score, sev = calculate_risk(5, 5)
        assert score == 25
        assert sev == "Critical"

    def test_clamping_out_of_bounds(self):
        # Inputs below 1 should clamp to 1
        score, sev = calculate_risk(0, -2)
        assert score == 1
        assert sev == "Low"

        # Inputs above 5 should clamp to 5
        score, sev = calculate_risk(10, 8)
        assert score == 25
        assert sev == "Critical"


class TestSTRIDEThreatMapping:
    """Test suite verifying mapping of findings to STRIDE categories."""

    def test_stride_mapping_for_findings(self):
        findings = [
            {
                "finding_code": "TL-FIND-01",
                "title": "HTTPS Transport & Redirection",
                "status": "FAIL",
                "category": "Transport Security",
                "evidence": "HTTPS connection refused."
            },
            {
                "finding_code": "TL-FIND-02",
                "title": "TLS Certificate Validity & Cryptography",
                "status": "FAIL",
                "category": "Cryptographic Controls",
                "evidence": "Certificate expired 10 days ago."
            },
            {
                "finding_code": "TL-FIND-03",
                "title": "Content-Security-Policy (CSP)",
                "status": "FAIL",
                "category": "Security Headers",
                "evidence": "CSP header missing."
            },
            {
                "finding_code": "TL-FIND-06",
                "title": "Clickjacking & Frame Protection",
                "status": "FAIL",
                "category": "Security Headers",
                "evidence": "X-Frame-Options missing."
            },
            {
                "finding_code": "TL-FIND-10",
                "title": "Server Information Disclosure",
                "status": "WARNING",
                "category": "Information Disclosure",
                "evidence": "Apache/2.4.41 exposed."
            },
            {
                "finding_code": "TL-FIND-05",
                "title": "MIME-Type Sniffing Protection",
                "status": "PASS",
                "category": "Security Headers",
                "evidence": "nosniff present."
            }
        ]

        threats = generate_threat_model(findings, "test-target.com")

        # PASS findings should be excluded from active threats
        assert len(threats) == 5

        categories = {t["finding_title"]: t["threat_category"] for t in threats}
        assert categories["HTTPS Transport & Redirection"] == "Tampering"
        assert categories["TLS Certificate Validity & Cryptography"] == "Spoofing"
        assert categories["Content-Security-Policy (CSP)"] == "Tampering"
        assert categories["Clickjacking & Frame Protection"] == "Elevation of Privilege"
        assert categories["Server Information Disclosure"] == "Information Disclosure"

        # Check threat record structure
        for t in threats:
            assert t["threat_id"].startswith("TL-THR-")
            assert "attack_scenario" in t
            assert "mitigation" in t
            assert "verification_steps" in t
            assert 1 <= t["likelihood"] <= 5
            assert 1 <= t["impact"] <= 5
            assert t["risk_score"] == t["likelihood"] * t["impact"]

    def test_executive_summary_postures(self):
        # 1. Robust posture
        summary_robust = generate_executive_summary("hardened.com", 95, [], {"total": 12, "passed": 12, "warning": 0, "failed": 0})
        assert "Robust" in summary_robust
        assert "hardened.com" in summary_robust

        # 2. Moderate posture
        threats_mod = [{"severity": "Medium"}, {"severity": "High"}]
        summary_mod = generate_executive_summary("moderate.com", 65, threats_mod, {"total": 12, "passed": 8, "warning": 2, "failed": 2})
        assert "Moderate" in summary_mod

        # 3. Critical / Elevated exposure
        threats_crit = [{"severity": "Critical"}, {"severity": "High"}]
        summary_crit = generate_executive_summary("insecure.com", 30, threats_crit, {"total": 12, "passed": 2, "warning": 4, "failed": 6})
        assert "Elevated Risk" in summary_crit
