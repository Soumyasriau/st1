"""
ThreatLens AI - Pre-configured Sample Assessments for Demos and Offline Evaluation
Enables instant demonstration during college project presentations and vivas without external internet dependency.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from threat_model import generate_threat_model, generate_executive_summary, calculate_risk


def get_sample_assessment(profile: str = "vulnerable") -> Dict[str, Any]:
    """
    Generate complete realistic assessment data for testing and presentations.
    Supported profiles:
      - 'vulnerable': Legacy unhardened site (Score: 24/100, Critical & High findings)
      - 'hardened': Modern enterprise site (Score: 95/100, minimal findings)
      - 'moderate': Typical small-business portal (Score: 62/100, moderate findings)
    """
    now_iso = datetime.now(timezone.utc).isoformat() + "Z"

    if profile == "hardened":
        hostname = "secure-portal.defense-lab.edu"
        target_url = f"https://{hostname}"
        overall_score = 95

        findings = [
            {
                "finding_code": "TL-FIND-01",
                "title": "HTTPS Transport & Redirection",
                "category": "Transport Security",
                "status": "PASS",
                "severity": "Low",
                "evidence": "HTTPS is active on port 443. Port 80 automatically issues HTTP 301 redirecting to https://secure-portal.defense-lab.edu.",
                "description": "Verifies encrypted transport availability and port 80 enforcement.",
                "recommendation": "Maintain automatic 301 redirection."
            },
            {
                "finding_code": "TL-FIND-02",
                "title": "TLS Certificate Validity & Cryptography",
                "category": "Cryptographic Controls",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Valid TLS certificate issued by 'Let's Encrypt Authority X3'. Expires in 184 days. Protocol: TLSv1.3 using TLS_AES_256_GCM_SHA384 (256 bits).",
                "description": "Examines TLS validity and modern cryptography.",
                "recommendation": "Automated renewal active via ACME."
            },
            {
                "finding_code": "TL-FIND-03",
                "title": "Content-Security-Policy (CSP)",
                "category": "Security Headers",
                "status": "PASS",
                "severity": "Low",
                "evidence": "CSP configured with strict directives: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'.",
                "description": "Defines permitted sources of content to mitigate XSS.",
                "recommendation": "Regularly audit policy when adding external dependencies."
            },
            {
                "finding_code": "TL-FIND-04",
                "title": "HTTP Strict Transport Security (HSTS)",
                "category": "Security Headers",
                "status": "PASS",
                "severity": "Low",
                "evidence": "HSTS configured with max-age=31536000 (1 year); includeSubDomains; preload.",
                "description": "Enforces HTTPS-only browsing in modern browsers.",
                "recommendation": "Submit domain to the HSTS preload list."
            },
            {
                "finding_code": "TL-FIND-05",
                "title": "MIME-Type Sniffing Protection",
                "category": "Security Headers",
                "status": "PASS",
                "severity": "Low",
                "evidence": "X-Content-Type-Options is set to 'nosniff'.",
                "description": "Prevents MIME sniffing attacks.",
                "recommendation": "Maintain header."
            },
            {
                "finding_code": "TL-FIND-06",
                "title": "Clickjacking & Frame Protection",
                "category": "Security Headers",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Modern frame protection established via CSP frame-ancestors 'none'.",
                "description": "Prevents unauthorized iframe embedding.",
                "recommendation": "Maintain frame-ancestors directive."
            },
            {
                "finding_code": "TL-FIND-07",
                "title": "Referrer Policy Configuration",
                "category": "Security Headers",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Configured to safe policy: 'strict-origin-when-cross-origin'.",
                "description": "Protects sensitive URL query parameters.",
                "recommendation": "Maintain header."
            },
            {
                "finding_code": "TL-FIND-08",
                "title": "Permissions & Feature Policy",
                "category": "Security Headers",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Permissions-Policy explicitly disables camera, microphone, and geolocation.",
                "description": "Controls browser hardware access.",
                "recommendation": "Maintain policy."
            },
            {
                "finding_code": "TL-FIND-09",
                "title": "Cookie Flag Security (Secure, HttpOnly, SameSite)",
                "category": "Session Management",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Observed 2 cookies: 'sess_id' and 'csrf_token'. Both configure Secure, HttpOnly, and SameSite=Strict.",
                "description": "Protects session cookies against theft.",
                "recommendation": "Continue setting Secure, HttpOnly, and SameSite attributes."
            },
            {
                "finding_code": "TL-FIND-10",
                "title": "Server Information Disclosure",
                "category": "Information Disclosure",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Server header is masked to generic 'cloud-edge'; no framework banners disclosed.",
                "description": "Prevents tech stack fingerprinting.",
                "recommendation": "Keep banner suppression enabled."
            },
            {
                "finding_code": "TL-FIND-11",
                "title": "HTTP Redirect Behavior",
                "category": "Transport Security",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Clean direct HTTPS connection with zero superfluous redirect hops.",
                "description": "Analyzes redirect chains.",
                "recommendation": "No action needed."
            },
            {
                "finding_code": "TL-FIND-12",
                "title": "Static Mixed Content References",
                "category": "Content Integrity",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Zero unencrypted HTTP asset references found in HTML markup.",
                "description": "Ensures assets load over HTTPS.",
                "recommendation": "Maintain relative and HTTPS asset paths."
            }
        ]

        raw_checks = {
            "https": {"status": "PASS", "evidence": "HTTPS enforced and verified."},
            "tls": {"status": "PASS", "evidence": "Valid certificate expires in 184 days."},
            "headers": {
                "Content-Security-Policy": {"status": "PASS"},
                "Strict-Transport-Security": {"status": "PASS"},
                "X-Content-Type-Options": {"status": "PASS"},
                "Frame-Protection": {"status": "PASS"},
                "Referrer-Policy": {"status": "PASS"},
                "Permissions-Policy": {"status": "PASS"}
            },
            "cookies": {"status": "PASS", "evidence": "All cookies have Secure, HttpOnly, and SameSite flags."},
            "info_exposure": {"status": "PASS", "evidence": "Generic banners only."},
            "redirects": {"status": "PASS", "evidence": "Zero unnecessary hops."},
            "mixed_content": {"status": "PASS", "evidence": "Zero mixed content."}
        }

    elif profile == "moderate":
        hostname = "shop.campus-store.org"
        target_url = f"https://{hostname}"
        overall_score = 64

        findings = [
            {
                "finding_code": "TL-FIND-01",
                "title": "HTTPS Transport & Redirection",
                "category": "Transport Security",
                "status": "PASS",
                "severity": "Low",
                "evidence": "HTTPS is operational and port 80 redirects to https://.",
                "description": "Verifies encrypted transport availability.",
                "recommendation": "Maintain automatic 301 redirection."
            },
            {
                "finding_code": "TL-FIND-02",
                "title": "TLS Certificate Validity & Cryptography",
                "category": "Cryptographic Controls",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Valid TLS certificate issued by 'DigiCert Inc'. Expires in 72 days. Protocol: TLSv1.2 using ECDHE-RSA-AES128-GCM-SHA256.",
                "description": "Examines TLS validity.",
                "recommendation": "Schedule renewal before 30 days remain."
            },
            {
                "finding_code": "TL-FIND-03",
                "title": "Content-Security-Policy (CSP)",
                "category": "Security Headers",
                "status": "FAIL",
                "severity": "High",
                "evidence": "Header is missing. Browser does not restrict sources of executable scripts, objects, or styles.",
                "description": "Defines permitted sources of content to mitigate XSS.",
                "recommendation": "Deploy a Content-Security-Policy header restricting script execution to trusted domains."
            },
            {
                "finding_code": "TL-FIND-04",
                "title": "HTTP Strict Transport Security (HSTS)",
                "category": "Security Headers",
                "status": "WARNING",
                "severity": "Medium",
                "evidence": "HSTS is enabled but max-age (2592000s / 30 days) is shorter than recommended 6 months (15552000s).",
                "description": "Enforces HTTPS-only browsing.",
                "recommendation": "Increase HSTS max-age to 31536000 seconds (1 year) and includeSubDomains."
            },
            {
                "finding_code": "TL-FIND-05",
                "title": "MIME-Type Sniffing Protection",
                "category": "Security Headers",
                "status": "PASS",
                "severity": "Low",
                "evidence": "X-Content-Type-Options is set to 'nosniff'.",
                "description": "Prevents MIME sniffing attacks.",
                "recommendation": "Maintain header."
            },
            {
                "finding_code": "TL-FIND-06",
                "title": "Clickjacking & Frame Protection",
                "category": "Security Headers",
                "status": "FAIL",
                "severity": "High",
                "evidence": "Neither CSP frame-ancestors nor X-Frame-Options is configured. Web pages may be framed by external sites (Clickjacking risk).",
                "description": "Restricts iframe embedding.",
                "recommendation": "Add 'X-Frame-Options: SAMEORIGIN' or CSP 'frame-ancestors' header."
            },
            {
                "finding_code": "TL-FIND-07",
                "title": "Referrer Policy Configuration",
                "category": "Security Headers",
                "status": "WARNING",
                "severity": "Medium",
                "evidence": "Header missing. Browsers default to referrer policy which may leak URLs.",
                "description": "Controls referrer information sharing.",
                "recommendation": "Implement 'Referrer-Policy: strict-origin-when-cross-origin'."
            },
            {
                "finding_code": "TL-FIND-08",
                "title": "Permissions & Feature Policy",
                "category": "Security Headers",
                "status": "WARNING",
                "severity": "Low",
                "evidence": "Header missing. Hardware capabilities are not explicitly restricted.",
                "description": "Controls browser device APIs.",
                "recommendation": "Configure Permissions-Policy header."
            },
            {
                "finding_code": "TL-FIND-09",
                "title": "Cookie Flag Security (Secure, HttpOnly, SameSite)",
                "category": "Session Management",
                "status": "WARNING",
                "severity": "Medium",
                "evidence": "Observed cookie 'session_token' is missing the 'SameSite' attribute.",
                "description": "Checks cookie protection flags.",
                "recommendation": "Set SameSite=Lax on all session cookies."
            },
            {
                "finding_code": "TL-FIND-10",
                "title": "Server Information Disclosure",
                "category": "Information Disclosure",
                "status": "WARNING",
                "severity": "Low",
                "evidence": "Response headers expose detailed software and version identifiers (server: 'nginx/1.18.0').",
                "description": "Exposes stack versions.",
                "recommendation": "Set server_tokens off in Nginx configuration."
            },
            {
                "finding_code": "TL-FIND-11",
                "title": "HTTP Redirect Behavior",
                "category": "Transport Security",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Clean redirect from HTTP to HTTPS in 1 hop.",
                "description": "Analyzes redirect sequences.",
                "recommendation": "No action required."
            },
            {
                "finding_code": "TL-FIND-12",
                "title": "Static Mixed Content References",
                "category": "Content Integrity",
                "status": "PASS",
                "severity": "Low",
                "evidence": "Zero unencrypted HTTP asset references found in HTML markup.",
                "description": "Ensures assets load over HTTPS.",
                "recommendation": "Maintain relative and HTTPS asset paths."
            }
        ]

        raw_checks = {
            "https": {"status": "PASS", "evidence": "HTTPS operational."},
            "tls": {"status": "PASS", "evidence": "Valid cert (72 days left)."},
            "headers": {
                "Content-Security-Policy": {"status": "FAIL"},
                "Strict-Transport-Security": {"status": "WARNING"},
                "X-Content-Type-Options": {"status": "PASS"},
                "Frame-Protection": {"status": "FAIL"},
                "Referrer-Policy": {"status": "WARNING"},
                "Permissions-Policy": {"status": "WARNING"}
            },
            "cookies": {"status": "WARNING", "evidence": "Missing SameSite on session cookie."},
            "info_exposure": {"status": "WARNING", "evidence": "Nginx/1.18.0 exposed."},
            "redirects": {"status": "PASS", "evidence": "1 hop."},
            "mixed_content": {"status": "PASS", "evidence": "Zero mixed content."}
        }

    else:
        # Default: "vulnerable"
        hostname = "legacy-portal.vulnerable-test.internal"
        target_url = f"http://{hostname}"
        overall_score = 22

        findings = [
            {
                "finding_code": "TL-FIND-01",
                "title": "HTTPS Transport & Redirection",
                "category": "Transport Security",
                "status": "FAIL",
                "severity": "High",
                "evidence": "HTTPS service is not enforced; web server serves plaintext HTTP on port 80 without automatic redirection.",
                "description": "Verifies whether encrypted HTTPS communication is supported.",
                "recommendation": "Enforce HTTPS across all application endpoints and configure HTTP 301 permanent redirects from port 80 to port 443."
            },
            {
                "finding_code": "TL-FIND-02",
                "title": "TLS Certificate Validity & Cryptography",
                "category": "Cryptographic Controls",
                "status": "FAIL",
                "severity": "Critical",
                "evidence": "TLS certificate expired 42 days ago on 2026-09-10 12:00:00 UTC (Issuer: 'Old Internal CA').",
                "description": "Examines TLS certificate expiration and trust.",
                "recommendation": "Renew TLS certificates immediately and deploy automated renewal agents."
            },
            {
                "finding_code": "TL-FIND-03",
                "title": "Content-Security-Policy (CSP)",
                "category": "Security Headers",
                "status": "FAIL",
                "severity": "High",
                "evidence": "Header is missing. Browser does not restrict sources of executable scripts, objects, or styles.",
                "description": "Defines permitted sources of content to mitigate XSS.",
                "recommendation": "Implement a strict Content-Security-Policy header disallowing unsafe-inline scripts."
            },
            {
                "finding_code": "TL-FIND-04",
                "title": "HTTP Strict Transport Security (HSTS)",
                "category": "Security Headers",
                "status": "FAIL",
                "severity": "High",
                "evidence": "HSTS header is absent. Browsers are not instructed to enforce HTTPS-only connections.",
                "description": "Enforces HTTPS-only browsing in modern browsers.",
                "recommendation": "Deploy Strict-Transport-Security: max-age=31536000; includeSubDomains header."
            },
            {
                "finding_code": "TL-FIND-05",
                "title": "MIME-Type Sniffing Protection",
                "category": "Security Headers",
                "status": "FAIL",
                "severity": "Medium",
                "evidence": "Header missing. Browsers may attempt MIME-type sniffing on executable or untyped content.",
                "description": "Prevents browsers from sniffing content types.",
                "recommendation": "Add 'X-Content-Type-Options: nosniff' header."
            },
            {
                "finding_code": "TL-FIND-06",
                "title": "Clickjacking & Frame Protection",
                "category": "Security Headers",
                "status": "FAIL",
                "severity": "High",
                "evidence": "Neither CSP frame-ancestors nor X-Frame-Options is configured. Web pages may be framed by external sites.",
                "description": "Restricts iframe embedding against UI redressing.",
                "recommendation": "Set X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'."
            },
            {
                "finding_code": "TL-FIND-07",
                "title": "Referrer Policy Configuration",
                "category": "Security Headers",
                "status": "WARNING",
                "severity": "Medium",
                "evidence": "Header missing. Browsers use default referrer policy, potentially exposing URL parameters to third parties.",
                "description": "Controls referrer information sharing.",
                "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin."
            },
            {
                "finding_code": "TL-FIND-08",
                "title": "Permissions & Feature Policy",
                "category": "Security Headers",
                "status": "WARNING",
                "severity": "Low",
                "evidence": "Header missing. Browser hardware access is not explicitly restricted.",
                "description": "Restricts access to hardware sensors.",
                "recommendation": "Configure Permissions-Policy header."
            },
            {
                "finding_code": "TL-FIND-09",
                "title": "Cookie Flag Security (Secure, HttpOnly, SameSite)",
                "category": "Session Management",
                "status": "WARNING",
                "severity": "Medium",
                "evidence": "Observed cookie security flag omissions: 'PHPSESSID' (missing Secure, HttpOnly, SameSite); 'auth_user' (missing Secure, SameSite).",
                "description": "Checks whether response cookies configure Secure, HttpOnly, and SameSite attributes.",
                "recommendation": "Append '; Secure; HttpOnly; SameSite=Lax' to all session cookie definitions."
            },
            {
                "finding_code": "TL-FIND-10",
                "title": "Server Information Disclosure",
                "category": "Information Disclosure",
                "status": "WARNING",
                "severity": "Low",
                "evidence": "Response headers expose detailed software and version identifiers (server: 'Apache/2.4.29 (Ubuntu)', x-powered-by: 'PHP/7.2.24').",
                "description": "Discloses operating system and software versions.",
                "recommendation": "Disable ServerTokens and expose_php in web server configurations."
            },
            {
                "finding_code": "TL-FIND-11",
                "title": "HTTP Redirect Behavior",
                "category": "Transport Security",
                "status": "FAIL",
                "severity": "High",
                "evidence": "Security downgrade detected in redirect chain: an HTTPS endpoint redirected to insecure HTTP.",
                "description": "Analyzes HTTP redirects.",
                "recommendation": "Prohibit redirects to unencrypted HTTP."
            },
            {
                "finding_code": "TL-FIND-12",
                "title": "Static Mixed Content References",
                "category": "Content Integrity",
                "status": "WARNING",
                "severity": "Medium",
                "evidence": "Observed 3 statically declared HTTP resource reference(s) (http://cdn.insecure.org/script.js, http://cdn.insecure.org/style.css).",
                "description": "Identifies unencrypted resources on HTTPS pages.",
                "recommendation": "Update all asset links to HTTPS."
            }
        ]

        raw_checks = {
            "https": {"status": "FAIL", "evidence": "HTTPS not enforced."},
            "tls": {"status": "FAIL", "evidence": "Certificate expired 42 days ago."},
            "headers": {
                "Content-Security-Policy": {"status": "FAIL"},
                "Strict-Transport-Security": {"status": "FAIL"},
                "X-Content-Type-Options": {"status": "FAIL"},
                "Frame-Protection": {"status": "FAIL"},
                "Referrer-Policy": {"status": "WARNING"},
                "Permissions-Policy": {"status": "WARNING"}
            },
            "cookies": {"status": "WARNING", "evidence": "PHPSESSID missing Secure and HttpOnly."},
            "info_exposure": {"status": "WARNING", "evidence": "Apache/2.4.29 and PHP/7.2.24 exposed."},
            "redirects": {"status": "FAIL", "evidence": "HTTPS downgraded to HTTP."},
            "mixed_content": {"status": "WARNING", "evidence": "3 unencrypted assets."}
        }

    # Generate STRIDE threats from findings
    threat_scenarios = generate_threat_model(findings, hostname)

    # Summaries
    critical_count = sum(1 for t in threat_scenarios if t["severity"] == "Critical")
    high_count = sum(1 for t in threat_scenarios if t["severity"] == "High")
    medium_count = sum(1 for t in threat_scenarios if t["severity"] == "Medium")
    low_count = sum(1 for t in threat_scenarios if t["severity"] == "Low")

    risk_summary = {
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "total_threats": len(threat_scenarios)
    }

    checks_summary = {
        "passed": sum(1 for f in findings if f["status"] == "PASS"),
        "warning": sum(1 for f in findings if f["status"] == "WARNING"),
        "failed": sum(1 for f in findings if f["status"] == "FAIL"),
        "total": len(findings)
    }

    exec_summary = generate_executive_summary(hostname, overall_score, threat_scenarios, checks_summary)

    return {
        "target_url": target_url,
        "hostname": hostname,
        "scan_timestamp": now_iso,
        "overall_score": overall_score,
        "https_status": "PASS" if overall_score > 60 else "FAIL",
        "tls_status": "PASS" if overall_score > 60 else "FAIL",
        "headers_status": "PASS" if overall_score >= 90 else "WARNING",
        "risk_summary": risk_summary,
        "checks_summary": checks_summary,
        "executive_summary": exec_summary,
        "raw_results": raw_checks,
        "findings": findings,
        "threat_scenarios": threat_scenarios
    }
