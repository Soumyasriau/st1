"""
ThreatLens AI - Threat Modeling & STRIDE Risk Assessment Engine
Maps observable security findings to structured threat scenarios, calculates
Likelihood x Impact risk scores, and provides concrete mitigations.
"""

from typing import Any, Dict, List, Tuple


def calculate_risk(likelihood: int, impact: int) -> Tuple[int, str]:
    """
    Calculate risk score and severity level:
    Risk Score = Likelihood x Impact (1 to 25)
    Severity:
      1-4:   Low
      5-9:   Medium
      10-16: High
      17-25: Critical
    """
    likelihood = max(1, min(5, int(likelihood)))
    impact = max(1, min(5, int(impact)))
    score = likelihood * impact

    if score >= 17:
        severity = "Critical"
    elif score >= 10:
        severity = "High"
    elif score >= 5:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity


# Knowledge Base mapping finding identifiers and conditions to STRIDE threat scenarios
THREAT_KNOWLEDGE_BASE = {
    "HTTPS Transport & Redirection": {
        "FAIL": {
            "threat_category": "Tampering",
            "title": "Cleartext Interception & Man-in-the-Middle (MitM) Manipulation",
            "attack_scenario": (
                "An attacker positioned on an untrusted local network (e.g., public Wi-Fi) or "
                "compromised routing node can intercept unencrypted HTTP communications. "
                "Because traffic is transmitted in plaintext, the adversary can eavesdrop on credentials, "
                "steal session tokens, and inject arbitrary malicious scripts or ads into web responses."
            ),
            "likelihood": 4,
            "impact": 5,
            "rationale": "High likelihood on untrusted network segments; critical impact because confidentiality and integrity are completely unencrypted.",
            "mitigation": "Enforce HTTPS encryption across all web services, bind valid TLS certificates, and configure web servers to automatically redirect port 80 traffic to port 443 with HTTP 301.",
            "verification_steps": (
                "1. Run `curl -I http://yourdomain.com` and verify the response is HTTP 301/308 pointing to https://.\n"
                "2. Ensure browser automatically locks the connection with a valid TLS padlock.\n"
                "3. Verify non-HTTPS ports are firewalled."
            )
        },
        "WARNING": {
            "threat_category": "Tampering",
            "title": "Opportunistic Unencrypted HTTP Navigation",
            "attack_scenario": (
                "Although HTTPS is accessible, the web server does not automatically redirect plain HTTP requests. "
                "Users typing the domain without 'https://' will browse in plaintext until they explicitly click an HTTPS link, "
                "leaving an initial window of exposure for eavesdropping or token leakage."
            ),
            "likelihood": 3,
            "impact": 3,
            "rationale": "Users frequently type domain names without protocol prefixes; unforced HTTPS permits casual unencrypted sessions.",
            "mitigation": "Configure web server (Nginx/Apache/Caddy) to enforce 301 Moved Permanently redirects for all port 80 requests to their HTTPS equivalent.",
            "verification_steps": (
                "1. Access `http://yourdomain.com` in a browser and verify automatic redirection to https://.\n"
                "2. Inspect network headers to confirm HTTP 301/308 redirect status."
            )
        }
    },

    "TLS Certificate Validity & Cryptography": {
        "FAIL": {
            "threat_category": "Spoofing",
            "title": "Adversary-in-the-Middle TLS Impersonation & Trust Failure",
            "attack_scenario": (
                "If the TLS certificate is expired, self-signed, or presents a hostname mismatch, browsers present "
                "intrusive security warning interstitials. In environments where users bypass warnings or API clients disable verification, "
                "an attacker executing DNS spoofing or ARP poisoning can present their own certificate and decrypt all application traffic."
            ),
            "likelihood": 4,
            "impact": 5,
            "rationale": "Expired or untrusted certificates compromise the fundamental chain of trust and train users to ignore browser safety warnings.",
            "mitigation": "Deploy automated certificate renewal via ACME / Let's Encrypt or cloud certificate managers. Ensure all SANs match active hostnames.",
            "verification_steps": (
                "1. Run `openssl s_client -connect yourdomain.com:443 -servername yourdomain.com`.\n"
                "2. Verify certificate verification returns `Verify return code: 0 (ok)`.\n"
                "3. Confirm expiration date is more than 30 days in the future."
            )
        },
        "WARNING": {
            "threat_category": "Denial of Service",
            "title": "Imminent Outage from Expiring TLS Certificate",
            "attack_scenario": (
                "The server's TLS certificate is nearing its expiration date (within 30 days). "
                "Failure to renew in time will cause immediate application downtime and trigger browser security warnings for all visitors."
            ),
            "likelihood": 3,
            "impact": 4,
            "rationale": "Unscheduled certificate expiration causes immediate availability loss and reputational damage.",
            "mitigation": "Initiate TLS certificate renewal immediately and configure automated alerting at 30, 14, and 7 days prior to expiry.",
            "verification_steps": (
                "1. Inspect expiry timestamp via certificate management dashboard or `curl -vI https://yourdomain.com`.\n"
                "2. Verify automated renewal daemon (e.g. certbot) is active and tested."
            )
        }
    },

    "Content-Security-Policy (CSP)": {
        "FAIL": {
            "threat_category": "Tampering",
            "title": "Cross-Site Scripting (XSS) Amplification & Data Exfiltration",
            "attack_scenario": (
                "Hypothetical threat: In the event that an input sanitization flaw exists within the application, "
                "the absence of a Content-Security-Policy allows injected JavaScript to execute unrestricted. "
                "The script can steal session tokens, log keystrokes, and exfiltrate user data to an attacker-controlled external domain."
            ),
            "likelihood": 3,
            "impact": 4,
            "rationale": "CSP acts as a defense-in-depth barrier. Without CSP, any single injection bug becomes fully exploitable in the client context.",
            "mitigation": "Implement a strict Content-Security-Policy header. Example: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';`.",
            "verification_steps": (
                "1. Check response headers in browser Developer Tools -> Network tab for `Content-Security-Policy`.\n"
                "2. Verify browser console exhibits no unexpected CSP blocking errors during regular site navigation."
            )
        },
        "WARNING": {
            "threat_category": "Tampering",
            "title": "Weakened Defense-in-Depth via Permissive CSP Directives",
            "attack_scenario": (
                "A Content-Security-Policy is present, but allows `'unsafe-inline'`, `'unsafe-eval'`, or wildcard `*` origins. "
                "An attacker exploiting an injection vulnerability can bypass the CSP restrictions using inline script blocks or eval constructs."
            ),
            "likelihood": 2,
            "impact": 3,
            "rationale": "Permissive directives dilute the protection benefits intended by modern CSP standards.",
            "mitigation": "Refactor inline scripts into external files or utilize cryptographic nonces (`nonce-...`) / SHA hashes rather than `'unsafe-inline'`.",
            "verification_steps": (
                "1. Audit the CSP header string to eliminate `'unsafe-inline'` and `'unsafe-eval'`.\n"
                "2. Use Google's CSP Evaluator tool to confirm header resilience."
            )
        }
    },

    "HTTP Strict Transport Security (HSTS)": {
        "FAIL": {
            "threat_category": "Tampering",
            "title": "SSL-Stripping & Transport Downgrade Attacks",
            "attack_scenario": (
                "Without HSTS, a user's initial connection to the website is made over unencrypted HTTP before being redirected. "
                "An active adversary on the local network using tools like `sslstrip` can intercept the initial HTTP request, "
                "prevent the redirect to HTTPS, and maintain a cleartext link with the victim while talking HTTPS to the server."
            ),
            "likelihood": 3,
            "impact": 3,
            "rationale": "Adversaries on public networks exploit the gap between user input and HTTP-to-HTTPS redirection.",
            "mitigation": "Deploy the `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` header on all HTTPS responses.",
            "verification_steps": (
                "1. Run `curl -sI https://yourdomain.com | grep -i strict-transport-security`.\n"
                "2. Verify `max-age` is at least 31536000 (1 year) and includes subdomains."
            )
        },
        "WARNING": {
            "threat_category": "Tampering",
            "title": "Short HSTS Cache Window & Subdomain Exposure",
            "attack_scenario": (
                "HSTS is active, but configured with a short `max-age` (less than 180 days) or omits `includeSubDomains`. "
                "After the short duration expires, browsers return to trusting plaintext requests, reopening the SSL-stripping window."
            ),
            "likelihood": 2,
            "impact": 2,
            "rationale": "Short durations limit protection persistence; omitted subdomains leave subdomains vulnerable.",
            "mitigation": "Increase `max-age` to at least 31536000 seconds (1 year) and include the `includeSubDomains` directive.",
            "verification_steps": (
                "1. Verify HSTS header value specifies `max-age=31536000; includeSubDomains`."
            )
        }
    },

    "MIME-Type Sniffing Protection": {
        "FAIL": {
            "threat_category": "Elevation of Privilege",
            "title": "MIME Confusion & Untyped Executable Execution",
            "attack_scenario": (
                "When `X-Content-Type-Options: nosniff` is absent, older web browsers or specific rendering components "
                "may ignore the server's declared `Content-Type` and 'sniff' the file payload. If user-uploaded content (e.g., an image or text file) "
                "contains embedded HTML or JavaScript, the browser may treat and execute it as HTML, executing script in the site's origin."
            ),
            "likelihood": 2,
            "impact": 3,
            "rationale": "MIME confusion can lead to cross-site scripting if the application hosts user-generated attachments.",
            "mitigation": "Add the response header `X-Content-Type-Options: nosniff` to all web server responses.",
            "verification_steps": (
                "1. Inspect HTTP response headers for `X-Content-Type-Options: nosniff`.\n"
                "2. Confirm browsers refuse to execute stylesheets or scripts unless properly typed."
            )
        }
    },

    "Clickjacking & Frame Protection": {
        "FAIL": {
            "threat_category": "Elevation of Privilege",
            "title": "UI Redressing & Clickjacking Attack Vectors",
            "attack_scenario": (
                "Without frame-ancestors or X-Frame-Options, an external malicious website can embed your application inside a transparent `<iframe>`. "
                "By enticing an authenticated user to click seemingly harmless elements on the decoy page, the attacker tricks the user into "
                "triggering hidden buttons on your website (e.g. transfer funds, change passwords, or alter permissions)."
            ),
            "likelihood": 3,
            "impact": 4,
            "rationale": "High impact for authenticated applications; clickjacking bypasses standard CSRF token protections.",
            "mitigation": "Send `Content-Security-Policy: frame-ancestors 'self'` or `X-Frame-Options: SAMEORIGIN` (or `DENY` if framing is never required).",
            "verification_steps": (
                "1. Create a local test HTML file containing `<iframe src='https://yourdomain.com'></iframe>`.\n"
                "2. Load the page in a browser and verify that the browser blocks the iframe with a framing error."
            )
        }
    },

    "Referrer Policy Configuration": {
        "WARNING": {
            "threat_category": "Information Disclosure",
            "title": "URL Query Parameter & Sensitive Path Leakage",
            "attack_scenario": (
                "Without a strict Referrer-Policy, when users click outbound links or third-party resources are fetched, "
                "the browser sends the full page URL in the `Referer` request header. If URL query parameters contain sensitive tokens, "
                "email addresses, or reset IDs, they are disclosed in third-party server access logs."
            ),
            "likelihood": 3,
            "impact": 2,
            "rationale": "Modern best practices treat URLs as semi-confidential; query parameters frequently contain sensitive context.",
            "mitigation": "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer` in HTTP response headers.",
            "verification_steps": (
                "1. Check response headers for `Referrer-Policy: strict-origin-when-cross-origin`.\n"
                "2. Click an external link from your site and verify that the outgoing `Referer` header only contains the domain name, not query paths."
            )
        }
    },

    "Permissions & Feature Policy": {
        "WARNING": {
            "threat_category": "Information Disclosure",
            "title": "Unrestricted Browser Sensor & Hardware Feature Access",
            "attack_scenario": (
                "When Permissions-Policy is omitted, third-party embedded scripts or iframes have default permission to request "
                "access to sensitive hardware APIs (such as geolocation, camera, microphone, and payment request). "
                "A compromised third-party script could attempt covert sensor access."
            ),
            "likelihood": 2,
            "impact": 2,
            "rationale": "Limits peripheral exposure and adheres to the principle of least privilege in the browser environment.",
            "mitigation": "Specify `Permissions-Policy: camera=(), microphone=(), geolocation=()` to disable unused hardware capabilities.",
            "verification_steps": (
                "1. Inspect response headers for `Permissions-Policy`.\n"
                "2. Ensure unused features return disabled status in browser capability queries."
            )
        }
    },

    "Cookie Flag Security (Secure, HttpOnly, SameSite)": {
        "WARNING": {
            "threat_category": "Information Disclosure",
            "title": "Session Token Hijacking & CSRF Vulnerability Exposure",
            "attack_scenario": (
                "Cookies issued without `HttpOnly` can be accessed by JavaScript via `document.cookie` if an XSS vulnerability occurs. "
                "Cookies issued without `Secure` can be leaked in cleartext if sent over unencrypted connections. "
                "Cookies lacking `SameSite=Lax` or `Strict` are automatically attached to cross-site requests, facilitating Cross-Site Request Forgery (CSRF)."
            ),
            "likelihood": 3,
            "impact": 4,
            "rationale": "Session cookies are primary targets for account takeover; missing flags significantly lower the barrier for exploitation.",
            "mitigation": "Update application session management configuration so all `Set-Cookie` headers append `; Secure; HttpOnly; SameSite=Lax`.",
            "verification_steps": (
                "1. Open Browser DevTools -> Application tab -> Cookies.\n"
                "2. Verify that the 'Secure' and 'HttpOnly' columns show checked marks and 'SameSite' is set to 'Lax' or 'Strict'."
            )
        }
    },

    "Server Information Disclosure": {
        "WARNING": {
            "threat_category": "Information Disclosure",
            "title": "Infrastructure Fingerprinting & Targeted CVE Profiling",
            "attack_scenario": (
                "Exposing detailed server banners (e.g., `Server: Apache/2.4.41 (Ubuntu) PHP/7.4.3`) allows adversaries "
                "during reconnaissance to quickly query vulnerability databases for known CVEs matching that exact software and patch version. "
                "Note: This reflects an information-disclosure indicator, not a verified exploitable flaw."
            ),
            "likelihood": 4,
            "impact": 2,
            "rationale": "High likelihood because automated scanners collect banners easily; impact is low to medium as it assists reconnaissance rather than granting access directly.",
            "mitigation": "Disable or mask software identification headers. For Apache: `ServerTokens Prod` & `ServerSignature Off`. For Nginx: `server_tokens off;`. In PHP: `expose_php = Off`.",
            "verification_steps": (
                "1. Execute `curl -I https://yourdomain.com`.\n"
                "2. Verify the `Server` header returns either a generic token or is stripped entirely, and `X-Powered-By` is absent."
            )
        }
    },

    "HTTP Redirect Behavior": {
        "FAIL": {
            "threat_category": "Tampering",
            "title": "Insecure Redirect Downgrade to Plaintext HTTP",
            "attack_scenario": (
                "An HTTPS endpoint redirected the client to an unencrypted HTTP destination. "
                "This breaks the confidentiality of the session and exposes subsequently transmitted credentials, cookies, or payloads to network interception."
            ),
            "likelihood": 3,
            "impact": 5,
            "rationale": "Redirecting from HTTPS to HTTP defeats the security provided by TLS.",
            "mitigation": "Audit web application routing and reverse-proxy rewrite rules to guarantee that no redirect location begins with `http://`.",
            "verification_steps": (
                "1. Run `curl -IL https://yourdomain.com` and trace the location header for each step.\n"
                "2. Ensure every step maintains `https://`."
            )
        },
        "WARNING": {
            "threat_category": "Denial of Service",
            "title": "Excessive Redirect Chaining & Latency Degradation",
            "attack_scenario": (
                "The target website initiates a chain of multiple redirects (more than 3 hops) before landing on the final page. "
                "Excessive redirect chains increase connection latency, waste bandwidth, and can trigger browser redirect-loop aborts."
            ),
            "likelihood": 3,
            "impact": 2,
            "rationale": "Excessive hops degrade performance and complicate security audit trails.",
            "mitigation": "Consolidate multiple redirect rules into a single canonical redirect directly to the final HTTPS destination.",
            "verification_steps": (
                "1. Inspect redirect chain hops using `curl -IL https://yourdomain.com`.\n"
                "2. Verify the site reaches its destination in 1 hop."
            )
        }
    },

    "Static Mixed Content References": {
        "WARNING": {
            "threat_category": "Tampering",
            "title": "Mixed-Content Active Asset Tampering on HTTPS Context",
            "attack_scenario": (
                "The web page is delivered over HTTPS, but includes static references to external resources (such as scripts, images, or iframes) "
                "over insecure HTTP. An attacker on the local network can tamper with the HTTP assets, injecting malicious script into the secure page "
                "or replacing images with deceptive content."
            ),
            "likelihood": 3,
            "impact": 4,
            "rationale": "Modern browsers block active mixed content (scripts/styles) and warn on passive mixed content (images), breaking page rendering.",
            "mitigation": "Update all asset references in HTML templates and CSS to use `https://` URLs or relative paths (`/assets/...`).",
            "verification_steps": (
                "1. Open Browser DevTools -> Console on the target page.\n"
                "2. Verify there are zero 'Mixed Content: The page at ... was loaded over HTTPS, but requested an insecure resource' warnings."
            )
        }
    }
}


def generate_threat_model(findings: List[Dict[str, Any]], hostname: str) -> List[Dict[str, Any]]:
    """
    Evaluate findings against STRIDE threat knowledge base and generate structured threat records.
    Only maps categories that are relevant to observed findings.
    """
    threat_scenarios = []
    threat_index = 1

    for finding in findings:
        title = finding.get("title", "")
        status = finding.get("status", "NOT_ASSESSED")
        finding_code = finding.get("finding_code", "TL-FIND")

        # Skip PASS or NOT_ASSESSED findings as they do not constitute active threats
        if status in ("PASS", "NOT_ASSESSED"):
            continue

        # Lookup in knowledge base
        finding_kb = THREAT_KNOWLEDGE_BASE.get(title, {})
        threat_template = finding_kb.get(status) or finding_kb.get("WARNING") or finding_kb.get("FAIL")

        if not threat_template:
            # Fallback generic threat mapping
            threat_template = {
                "threat_category": "Information Disclosure",
                "title": f"Potential Risk: {title}",
                "attack_scenario": (
                    f"Observed configuration issue: {finding.get('evidence', '')}. "
                    f"This misconfiguration may expose {hostname} to unauthorized access or information disclosure."
                ),
                "likelihood": 2,
                "impact": 2,
                "rationale": "Observable configuration issue requiring remediation according to security standards.",
                "mitigation": finding.get("recommendation", "Review server configuration and apply vendor hardening guides."),
                "verification_steps": "Inspect configuration and verify appropriate response headers."
            }

        likelihood = threat_template["likelihood"]
        impact = threat_template["impact"]
        risk_score, severity = calculate_risk(likelihood, impact)

        threat_scenarios.append({
            "threat_id": f"TL-THR-{threat_index:02d}",
            "finding_code": finding_code,
            "finding_title": title,
            "affected_control": finding.get("category", "General Control"),
            "threat_category": threat_template["threat_category"],
            "title": threat_template["title"],
            "attack_scenario": threat_template["attack_scenario"],
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": risk_score,
            "severity": severity,
            "rationale": threat_template["rationale"],
            "evidence": finding.get("evidence", ""),
            "mitigation": threat_template["mitigation"],
            "verification_steps": threat_template["verification_steps"]
        })
        threat_index += 1

    return threat_scenarios


def generate_executive_summary(
    hostname: str,
    overall_score: int,
    threats: List[Dict[str, Any]],
    checks_summary: Dict[str, Any]
) -> str:
    """
    Generate a professional cybersecurity executive summary detailing observed posture,
    highest severity findings, and prioritized remediation actions.
    """
    critical_count = sum(1 for t in threats if t["severity"] == "Critical")
    high_count = sum(1 for t in threats if t["severity"] == "High")
    medium_count = sum(1 for t in threats if t["severity"] == "Medium")
    low_count = sum(1 for t in threats if t["severity"] == "Low")

    if overall_score >= 80 and critical_count == 0 and high_count == 0:
        posture = "Robust / Well-Hardened"
        verdict = (
            f"The target host '{hostname}' demonstrates a strong baseline security posture with an overall hygiene score of "
            f"{overall_score}/100. Publicly observable transport encryption and core HTTP security headers conform to modern "
            f"industry practices. Few minor configuration adjustments are recommended to achieve optimal resilience."
        )
    elif overall_score >= 50 and critical_count == 0:
        posture = "Moderate / Attention Needed"
        verdict = (
            f"The target host '{hostname}' demonstrates a moderate security baseline ({overall_score}/100) with "
            f"{high_count} high-priority and {medium_count} medium-priority threat scenarios identified. While basic HTTPS connectivity "
            f"is operational, missing defense-in-depth controls (such as Content-Security-Policy or cookie security flags) "
            f"present potential attack surfaces in the presence of application-level bugs."
        )
    else:
        posture = "Elevated Risk / Action Required"
        verdict = (
            f"The target host '{hostname}' exhibits significant security weaknesses ({overall_score}/100) with "
            f"{critical_count} critical and {high_count} high severity threat scenarios identified. Immediate remediation "
            f"is advised to harden transport layer encryption, deploy foundational HTTP security headers, and prevent session tampering."
        )

    disclaimer = (
        "\n\nNotice & Educational Disclaimer: ThreatLens AI operates exclusively via passive HTTP checks and does not perform "
        "intrusive penetration testing, credential stuffing, or exploit execution. The findings and STRIDE threat models reflect "
        "observable configuration hygiene and hypothetical threat scenarios; they do not guarantee that the website is completely secure or insecure."
    )

    return f"Security Assessment Summary for {hostname} — Posture: {posture}\n\n{verdict}{disclaimer}"
