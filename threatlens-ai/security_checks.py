"""
ThreatLens AI - Passive Security Assessment Engine
Performs safe, non-intrusive, publicly observable checks on web servers.
Enforces strict anti-SSRF protections, timeouts, and redirect controls.
"""

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests

# Safety limits
REQUEST_TIMEOUT = 6.0  # seconds
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB response limit
SAFE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatLensAI-SecurityAssessment/1.0"


class SSRFValidationError(ValueError):
    """Raised when a URL resolves to a prohibited internal or private network target."""
    pass


def validate_and_resolve_url(raw_url: str) -> Tuple[str, str, str, int]:
    """
    Validate URL syntax and enforce anti-SSRF policies.
    Blocks:
    - Non-HTTP/HTTPS schemes
    - Localhost, private RFC 1918 IPs, IPv6 loopback / link-local / ULA
    - Cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.)
    - Malformed or userinfo credentials in URLs

    Returns:
        (normalized_url, scheme, hostname, port)
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("Target URL cannot be empty.")

    raw_url = raw_url.strip()

    # If scheme delimiter is present, check scheme immediately
    if "://" in raw_url:
        scheme_part = raw_url.split("://", 1)[0].lower()
        if scheme_part not in ("http", "https"):
            raise ValueError(f"Prohibited scheme '{scheme_part}'. Only HTTP and HTTPS are permitted.")
    elif not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        # Default to https:// for domain inputs like "example.com"
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Prohibited scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    if not parsed.hostname:
        raise ValueError("Invalid target: Hostname could not be parsed.")

    # Disallow user credentials embedded in URL (e.g., http://user:pass@host)
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded authentication credentials are not permitted.")

    hostname = parsed.hostname.lower().strip(".")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    # Prohibited hostnames list
    prohibited_hosts = {
        "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
        "metadata.google.internal", "metadata", "instance-data",
        "169.254.169.254", "fd00:ec2::254"
    }
    if hostname in prohibited_hosts or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise SSRFValidationError(f"Target host '{hostname}' is an internal or reserved destination and cannot be scanned.")

    # DNS Resolution and IP validation
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for '{hostname}': {str(e)}")

    if not addr_info:
        raise ValueError(f"No IP addresses resolved for '{hostname}'.")

    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFValidationError(f"Invalid resolved IP format: {ip_str}")

        # Check all RFC prohibited categories
        if (ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_unspecified):
            raise SSRFValidationError(
                f"Prohibited target: '{hostname}' resolves to restricted IP {ip_str} "
                f"(Private/Loopback/Link-Local/Reserved). SSRF protection engaged."
            )

        # Cloud metadata IPv4 & IPv6 explicitly
        if str(ip_obj) in ("169.254.169.254", "fd00:ec2::254"):
            raise SSRFValidationError(f"Prohibited access to cloud metadata IP: {ip_str}")

    # Reconstruct normalized URL
    normalized = f"{parsed.scheme.lower()}://{hostname}"
    if parsed.port and (
        (parsed.scheme.lower() == "http" and parsed.port != 80) or
        (parsed.scheme.lower() == "https" and parsed.port != 443)
    ):
        normalized += f":{parsed.port}"
    normalized += parsed.path or "/"
    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized, parsed.scheme.lower(), hostname, port


def safe_http_request(url: str, max_redirects: int = MAX_REDIRECTS) -> Tuple[requests.Response, List[Dict[str, Any]]]:
    """
    Execute a secure HTTP GET request with SSRF revalidation on every redirect hop,
    response size limits, and standard TLS verification.
    """
    current_url = url
    redirect_history: List[Dict[str, Any]] = []

    session = requests.Session()
    session.headers.update({
        "User-Agent": SAFE_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close"
    })

    hops = 0
    final_response = None

    while hops <= max_redirects:
        # Validate current hop against SSRF
        validate_and_resolve_url(current_url)

        try:
            resp = session.get(
                current_url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                verify=True,
                stream=True
            )
        except requests.exceptions.SSLError as e:
            raise requests.exceptions.SSLError(f"TLS/SSL certificate error: {str(e)}")
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Connection timed out after {REQUEST_TIMEOUT} seconds while contacting {current_url}")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"HTTP request failed: {str(e)}")

        redirect_history.append({
            "url": current_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers)
        })

        # Check if redirect
        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            hops += 1
            if hops > max_redirects:
                raise ValueError(f"Exceeded maximum allowed redirects ({MAX_REDIRECTS}). Potential redirect loop.")
            next_url = urljoin(current_url, resp.headers["Location"])
            current_url = next_url
            continue
        else:
            final_response = resp
            break

    # Read body up to MAX_RESPONSE_BYTES to prevent memory bloat
    content_chunks = []
    total_bytes = 0
    for chunk in final_response.iter_content(chunk_size=8192):
        total_bytes += len(chunk)
        if total_bytes > MAX_RESPONSE_BYTES:
            break
        content_chunks.append(chunk)

    final_response._content = b"".join(content_chunks)
    return final_response, redirect_history


def check_https_availability(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Check if HTTPS port connects and verify whether HTTP port 80 redirects to HTTPS."""
    result = {
        "check_name": "HTTPS Availability",
        "category": "Transport Security",
        "status": "NOT_ASSESSED",
        "https_supported": False,
        "http_redirects_to_https": False,
        "evidence": "",
        "details": {}
    }

    # 1. Test HTTPS connection
    try:
        https_url = f"https://{hostname}"
        resp, history = safe_http_request(https_url)
        result["https_supported"] = True
    except requests.exceptions.SSLError as e:
        result["status"] = "FAIL"
        result["evidence"] = f"HTTPS handshake failed: TLS verification issue ({str(e)})."
        return result
    except Exception as e:
        result["status"] = "FAIL"
        result["evidence"] = f"HTTPS service is unreachable: {str(e)}"
        return result

    # 2. Test HTTP (port 80) redirection behavior
    try:
        http_url = f"http://{hostname}"
        validate_and_resolve_url(http_url)
        session = requests.Session()
        session.headers.update({"User-Agent": SAFE_USER_AGENT})
        http_resp = session.get(http_url, allow_redirects=False, timeout=REQUEST_TIMEOUT, verify=True)

        if http_resp.status_code in (301, 302, 307, 308):
            target_loc = http_resp.headers.get("Location", "")
            if target_loc.startswith("https://") or "https://" in urljoin(http_url, target_loc):
                result["http_redirects_to_https"] = True
                result["status"] = "PASS"
                result["evidence"] = (
                    f"HTTPS is accessible. Port 80 correctly redirects HTTP requests to HTTPS "
                    f"via HTTP {http_resp.status_code} -> {target_loc}."
                )
            else:
                result["status"] = "WARNING"
                result["evidence"] = (
                    f"HTTPS is accessible, but HTTP port 80 redirects to a non-HTTPS destination: {target_loc}."
                )
        else:
            result["status"] = "WARNING"
            result["evidence"] = (
                f"HTTPS is accessible, but port 80 responds with HTTP {http_resp.status_code} "
                f"without enforcing an automatic redirect to HTTPS."
            )
    except Exception as e:
        # HTTP port might be closed / blocked by firewall while HTTPS is up
        result["status"] = "PASS" if result["https_supported"] else "FAIL"
        result["evidence"] = (
            f"HTTPS is operational. Plain HTTP test encountered: {str(e)}. "
            f"(Port 80 may be intentionally closed or firewalled)."
        )

    return result


def check_tls_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Inspect the TLS certificate using standard Python SSL socket verification."""
    result = {
        "check_name": "TLS Certificate",
        "category": "Cryptographic Controls",
        "status": "NOT_ASSESSED",
        "subject": "",
        "issuer": "",
        "valid_from": "",
        "valid_until": "",
        "days_until_expiry": None,
        "tls_version": "",
        "cipher": "",
        "san_list": [],
        "evidence": "",
        "details": {}
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                result["tls_version"] = tls_version
                result["cipher"] = f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)" if cipher else "Unknown"

                # Parse dates
                not_after_str = cert.get("notAfter")
                not_before_str = cert.get("notBefore")
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["valid_until"] = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
                    now = datetime.now(timezone.utc)
                    days_left = (not_after - now).days
                    result["days_until_expiry"] = days_left

                if not_before_str:
                    not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["valid_from"] = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")

                # Parse subject & issuer
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                result["subject"] = subject_dict.get("commonName", hostname)
                result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Unknown Issuer")

                # Parse SANs
                sans = [item[1] for item in cert.get("subjectAltName", ()) if item[0] == "DNS"]
                result["san_list"] = sans[:10]

                # Evaluation
                if result["days_until_expiry"] is not None and result["days_until_expiry"] < 0:
                    result["status"] = "FAIL"
                    result["evidence"] = f"TLS certificate expired {abs(result['days_until_expiry'])} days ago on {result['valid_until']}."
                elif result["days_until_expiry"] is not None and result["days_until_expiry"] <= 30:
                    result["status"] = "WARNING"
                    result["evidence"] = f"TLS certificate expires soon in {result['days_until_expiry']} days (Issuer: {result['issuer']})."
                else:
                    result["status"] = "PASS"
                    result["evidence"] = (
                        f"Valid TLS certificate issued by '{result['issuer']}'. "
                        f"Expires in {result['days_until_expiry']} days ({result['valid_until']}). "
                        f"Negotiated {tls_version} using {result['cipher']}."
                    )
    except ssl.SSLCertVerificationError as e:
        result["status"] = "FAIL"
        result["evidence"] = f"TLS certificate verification failed: {e.verify_message} (Error code: {e.verify_code})."
    except Exception as e:
        result["status"] = "FAIL"
        result["evidence"] = f"Could not inspect TLS certificate: {str(e)}"

    return result


def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Inspect HTTP response headers against cybersecurity best practice standards.
    Headers assessed:
    - Content-Security-Policy (CSP)
    - Strict-Transport-Security (HSTS)
    - X-Content-Type-Options
    - Frame Protection (CSP frame-ancestors or X-Frame-Options)
    - Referrer-Policy
    - Permissions-Policy
    """
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    header_results: Dict[str, Dict[str, Any]] = {}

    # 1. Content-Security-Policy
    csp = normalized_headers.get("content-security-policy")
    if not csp:
        header_results["Content-Security-Policy"] = {
            "status": "FAIL",
            "present": False,
            "value": "",
            "evidence": "Header is missing. Browser does not restrict sources of executable scripts, objects, or styles."
        }
    else:
        warnings = []
        if "'unsafe-inline'" in csp:
            warnings.append("contains 'unsafe-inline' which weakens XSS mitigation")
        if "'unsafe-eval'" in csp:
            warnings.append("contains 'unsafe-eval' which allows string-to-code execution")
        if "default-src *" in csp or "script-src *" in csp:
            warnings.append("contains overly permissive wildcard '*' origins")

        if warnings:
            header_results["Content-Security-Policy"] = {
                "status": "WARNING",
                "present": True,
                "value": csp[:150] + ("..." if len(csp) > 150 else ""),
                "evidence": f"CSP present but permissive: {', '.join(warnings)}."
            }
        else:
            header_results["Content-Security-Policy"] = {
                "status": "PASS",
                "present": True,
                "value": csp[:150] + ("..." if len(csp) > 150 else ""),
                "evidence": "CSP is configured with restrictive source directives."
            }

    # 2. Strict-Transport-Security (HSTS)
    hsts = normalized_headers.get("strict-transport-security")
    if not hsts:
        header_results["Strict-Transport-Security"] = {
            "status": "FAIL",
            "present": False,
            "value": "",
            "evidence": "HSTS header is absent. Browsers are not instructed to enforce HTTPS-only connections."
        }
    else:
        # Check max-age
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        min_recommended = 15552000  # 6 months (180 days)

        if max_age < min_recommended:
            header_results["Strict-Transport-Security"] = {
                "status": "WARNING",
                "present": True,
                "value": hsts,
                "evidence": f"HSTS is enabled but max-age ({max_age}s) is shorter than recommended 6 months (15552000s)."
            }
        else:
            includes_subdomains = "includesubdomains" in hsts.lower()
            header_results["Strict-Transport-Security"] = {
                "status": "PASS",
                "present": True,
                "value": hsts,
                "evidence": f"HSTS configured with max-age={max_age}s{' (includes subdomains)' if includes_subdomains else ''}."
            }

    # 3. X-Content-Type-Options
    xcto = normalized_headers.get("x-content-type-options")
    if not xcto:
        header_results["X-Content-Type-Options"] = {
            "status": "FAIL",
            "present": False,
            "value": "",
            "evidence": "Header missing. Browsers may attempt MIME-type sniffing on executable or untyped content."
        }
    elif xcto.strip().lower() == "nosniff":
        header_results["X-Content-Type-Options"] = {
            "status": "PASS",
            "present": True,
            "value": xcto,
            "evidence": "Configured correctly to 'nosniff'."
        }
    else:
        header_results["X-Content-Type-Options"] = {
            "status": "WARNING",
            "present": True,
            "value": xcto,
            "evidence": f"Configured with non-standard value: '{xcto}' (expected 'nosniff')."
        }

    # 4. Frame Protection (X-Frame-Options or CSP frame-ancestors)
    xfo = normalized_headers.get("x-frame-options")
    has_csp_frame_ancestors = csp and "frame-ancestors" in csp.lower()

    if has_csp_frame_ancestors:
        header_results["Frame-Protection"] = {
            "status": "PASS",
            "present": True,
            "value": "CSP frame-ancestors directive",
            "evidence": "Modern frame protection established via CSP frame-ancestors."
        }
    elif xfo:
        xfo_val = xfo.strip().upper()
        if xfo_val in ("DENY", "SAMEORIGIN"):
            header_results["Frame-Protection"] = {
                "status": "PASS",
                "present": True,
                "value": f"X-Frame-Options: {xfo_val}",
                "evidence": f"Framing restricted to '{xfo_val}' via X-Frame-Options."
            }
        else:
            header_results["Frame-Protection"] = {
                "status": "WARNING",
                "present": True,
                "value": f"X-Frame-Options: {xfo}",
                "evidence": f"X-Frame-Options set to deprecated or non-standard value: '{xfo}'."
            }
    else:
        header_results["Frame-Protection"] = {
            "status": "FAIL",
            "present": False,
            "value": "",
            "evidence": "Neither CSP frame-ancestors nor X-Frame-Options is configured. Web pages may be framed by external sites (Clickjacking risk)."
        }

    # 5. Referrer-Policy
    referrer = normalized_headers.get("referrer-policy")
    if not referrer:
        header_results["Referrer-Policy"] = {
            "status": "WARNING",
            "present": False,
            "value": "",
            "evidence": "Header missing. Browsers use default referrer policy, potentially exposing sensitive path parameters to external domains."
        }
    else:
        safe_policies = [
            "no-referrer", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "no-referrer-when-downgrade"
        ]
        if any(sp in referrer.lower() for sp in safe_policies):
            header_results["Referrer-Policy"] = {
                "status": "PASS",
                "present": True,
                "value": referrer,
                "evidence": f"Configured to safe policy: '{referrer}'."
            }
        else:
            header_results["Referrer-Policy"] = {
                "status": "WARNING",
                "present": True,
                "value": referrer,
                "evidence": f"Referrer-Policy is permissive: '{referrer}'."
            }

    # 6. Permissions-Policy
    perms = normalized_headers.get("permissions-policy") or normalized_headers.get("feature-policy")
    if not perms:
        header_results["Permissions-Policy"] = {
            "status": "WARNING",
            "present": False,
            "value": "",
            "evidence": "Header missing. Browser hardware access (camera, microphone, geolocation) is not explicitly restricted."
        }
    else:
        header_results["Permissions-Policy"] = {
            "status": "PASS",
            "present": True,
            "value": perms[:120] + ("..." if len(perms) > 120 else ""),
            "evidence": "Browser hardware permissions and experimental features are explicitly controlled."
        }

    return header_results


def check_cookie_security(response: requests.Response, is_https: bool) -> Dict[str, Any]:
    """
    Inspect Set-Cookie headers for Secure, HttpOnly, and SameSite attributes.
    SAFETY NOTE: Cookie values are never stored or logged, only cookie names and security flags.
    """
    cookies_analyzed = []
    # Extract raw set-cookie headers
    raw_cookies = []
    if "set-cookie" in response.headers:
        # In requests, multiple Set-Cookie headers might be combined or accessible via raw
        for header_key, header_val in response.raw.headers.items():
            if header_key.lower() == "set-cookie":
                raw_cookies.append(header_val)

    if not raw_cookies and "set-cookie" in response.headers:
        raw_cookies.append(response.headers["set-cookie"])

    if not raw_cookies:
        return {
            "check_name": "Cookie Security",
            "category": "Session Management",
            "status": "PASS",
            "cookies_found": 0,
            "evidence": "No Set-Cookie response headers observed during initial passive inspection.",
            "cookies": []
        }

    has_issue = False
    for cookie_header in raw_cookies:
        parts = [p.strip() for p in cookie_header.split(";")]
        if not parts:
            continue
        # Extract cookie name only, NEVER the sensitive value
        cookie_name = parts[0].split("=")[0].strip()
        lower_parts = [p.lower() for p in parts[1:]]

        has_secure = any(p == "secure" for p in lower_parts)
        has_httponly = any(p == "httponly" for p in lower_parts)

        samesite = "None"
        for p in lower_parts:
            if p.startswith("samesite="):
                samesite = p.split("=")[1].capitalize()

        missing_flags = []
        if is_https and not has_secure:
            missing_flags.append("Secure")
        if not has_httponly:
            missing_flags.append("HttpOnly")
        if samesite == "None" or not any("samesite" in p for p in lower_parts):
            missing_flags.append("SameSite")

        if missing_flags:
            has_issue = True

        cookies_analyzed.append({
            "name": cookie_name,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite,
            "missing_flags": missing_flags
        })

    if has_issue:
        status = "WARNING"
        issue_cookies = [f"'{c['name']}' (missing {', '.join(c['missing_flags'])})" for c in cookies_analyzed if c['missing_flags']]
        evidence = f"Observed cookie security flag omissions: {'; '.join(issue_cookies)}."
    else:
        status = "PASS"
        evidence = f"All {len(cookies_analyzed)} inspected cookies configure appropriate Secure, HttpOnly, and SameSite attributes."

    return {
        "check_name": "Cookie Security",
        "category": "Session Management",
        "status": status,
        "cookies_found": len(cookies_analyzed),
        "evidence": evidence,
        "cookies": cookies_analyzed
    }


def check_information_exposure(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Check for software banners and framework indicators that disclose internal stack details.
    Examples: Server, X-Powered-By, X-AspNet-Version, X-Runtime.
    """
    disclosed = []
    revealing_headers = [
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-drupal-cache", "x-varnish", "x-runtime"
    ]
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    for h in revealing_headers:
        if h in normalized_headers:
            val = normalized_headers[h]
            # Flag if detailed version numbers are present
            has_version = bool(re.search(r"\d+\.\d+", val))
            disclosed.append({
                "header": h,
                "value": val,
                "has_version": has_version
            })

    if not disclosed:
        return {
            "check_name": "Information Exposure",
            "category": "Information Disclosure",
            "status": "PASS",
            "evidence": "No server or application framework identification banners were disclosed in response headers.",
            "disclosed_headers": []
        }

    version_exposed = any(d["has_version"] for d in disclosed)
    summary_items = [f"{d['header']}: '{d['value']}'" for d in disclosed]

    if version_exposed:
        return {
            "check_name": "Information Exposure",
            "category": "Information Disclosure",
            "status": "WARNING",
            "evidence": (
                f"Response headers expose detailed software and version identifiers ({'; '.join(summary_items)}). "
                f"Note: This is an information-disclosure indicator for reconnaissance, not a direct vulnerability."
            ),
            "disclosed_headers": disclosed
        }
    else:
        return {
            "check_name": "Information Exposure",
            "category": "Information Disclosure",
            "status": "PASS",
            "evidence": f"Headers provide generic software identifiers without disclosing granular versions ({'; '.join(summary_items)}).",
            "disclosed_headers": disclosed
        }


def check_redirect_behavior(redirect_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Inspect redirect chain for downgrade redirects, excessive hops, or unexpected destinations."""
    if len(redirect_history) <= 1:
        return {
            "check_name": "Redirect Behavior",
            "category": "Transport Security",
            "status": "PASS",
            "hop_count": 0,
            "evidence": "Direct response received without redirects.",
            "chain": []
        }

    hop_count = len(redirect_history) - 1
    downgrade_detected = False
    chain_summary = []

    for i in range(len(redirect_history) - 1):
        from_url = redirect_history[i]["url"]
        to_url = redirect_history[i + 1]["url"]
        code = redirect_history[i]["status_code"]
        chain_summary.append(f"{code}: {from_url} -> {to_url}")

        if from_url.startswith("https://") and to_url.startswith("http://"):
            downgrade_detected = True

    if downgrade_detected:
        return {
            "check_name": "Redirect Behavior",
            "category": "Transport Security",
            "status": "FAIL",
            "hop_count": hop_count,
            "evidence": f"Security downgrade detected in redirect chain: an HTTPS endpoint redirected to insecure HTTP. Chain: {' | '.join(chain_summary)}",
            "chain": chain_summary
        }
    elif hop_count > 3:
        return {
            "check_name": "Redirect Behavior",
            "category": "Transport Security",
            "status": "WARNING",
            "hop_count": hop_count,
            "evidence": f"High number of redirects observed ({hop_count} hops). May indicate misconfiguration or redirect chaining. Chain: {' | '.join(chain_summary)}",
            "chain": chain_summary
        }
    else:
        return {
            "check_name": "Redirect Behavior",
            "category": "Transport Security",
            "status": "PASS",
            "hop_count": hop_count,
            "evidence": f"Clean redirect chain observed ({hop_count} hop{'s' if hop_count > 1 else ''}). Chain: {' | '.join(chain_summary)}",
            "chain": chain_summary
        }


def check_mixed_content(html_content: str, is_https: bool) -> Dict[str, Any]:
    """
    Check static HTML response for insecure HTTP resource references on an HTTPS page.
    Explains that dynamic JS-injected resources cannot be observed passively.
    """
    if not is_https:
        return {
            "check_name": "Mixed Content",
            "category": "Content Integrity",
            "status": "NOT_ASSESSED",
            "evidence": "Target page is served over plain HTTP; mixed-content rules only apply to HTTPS contexts.",
            "insecure_resources": []
        }

    if not html_content:
        return {
            "check_name": "Mixed Content",
            "category": "Content Integrity",
            "status": "PASS",
            "evidence": "No HTML body content observed to inspect.",
            "insecure_resources": []
        }

    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception as e:
        return {
            "check_name": "Mixed Content",
            "category": "Content Integrity",
            "status": "NOT_ASSESSED",
            "evidence": f"HTML parsing was not completed: {str(e)}",
            "insecure_resources": []
        }

    insecure_items = []

    # Check tags: script, link, img, iframe, audio, video
    for tag in soup.find_all(["script", "iframe", "audio", "video"]):
        src = tag.get("src", "")
        if src.startswith("http://"):
            insecure_items.append({"tag": tag.name, "url": src[:100], "type": "Active mixed content (High risk)"})

    for link in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
        href = link.get("href", "")
        if href.startswith("http://"):
            insecure_items.append({"tag": "link[rel=stylesheet]", "url": href[:100], "type": "Active mixed content (High risk)"})

    for img in soup.find_all("img"):
        src = img.get("src", "")
        if src.startswith("http://"):
            insecure_items.append({"tag": "img", "url": src[:100], "type": "Passive mixed content (Display risk)"})

    if insecure_items:
        return {
            "check_name": "Mixed Content",
            "category": "Content Integrity",
            "status": "WARNING",
            "evidence": (
                f"Observed {len(insecure_items)} statically declared HTTP resource reference(s) on this HTTPS page. "
                f"Note: Passive scanning checks static HTML tags; client-side JavaScript or DOM-loaded assets cannot be observed."
            ),
            "insecure_resources": insecure_items[:15]
        }
    else:
        return {
            "check_name": "Mixed Content",
            "category": "Content Integrity",
            "status": "PASS",
            "evidence": (
                "No insecure HTTP asset references were found in the static HTML markup. "
                "Note: Passive inspection verifies static markup; client-side dynamic resources require browser testing."
            ),
            "insecure_resources": []
        }


def calculate_overall_security_score(checks: Dict[str, Any]) -> int:
    """
    Calculate educational security score (0 - 100) based on weighted passive security checks:
    - HTTPS & TLS: 25 points
    - Core Security Headers (CSP, HSTS, X-Content-Type, Frame Protection): 40 points
    - Secondary Headers (Referrer, Permissions): 15 points
    - Cookie Security: 10 points
    - Information Exposure & Mixed Content: 10 points
    """
    score = 0

    # HTTPS (15)
    https_check = checks.get("https", {})
    if https_check.get("status") == "PASS":
        score += 15
    elif https_check.get("status") == "WARNING":
        score += 8

    # TLS (10)
    tls_check = checks.get("tls", {})
    if tls_check.get("status") == "PASS":
        score += 10
    elif tls_check.get("status") == "WARNING":
        score += 5

    # Headers (55 total)
    headers = checks.get("headers", {})

    # CSP (15)
    csp = headers.get("Content-Security-Policy", {})
    if csp.get("status") == "PASS":
        score += 15
    elif csp.get("status") == "WARNING":
        score += 7

    # HSTS (10)
    hsts = headers.get("Strict-Transport-Security", {})
    if hsts.get("status") == "PASS":
        score += 10
    elif hsts.get("status") == "WARNING":
        score += 5

    # X-Content-Type (8)
    xcto = headers.get("X-Content-Type-Options", {})
    if xcto.get("status") == "PASS":
        score += 8

    # Frame protection (7)
    fp = headers.get("Frame-Protection", {})
    if fp.get("status") == "PASS":
        score += 7
    elif fp.get("status") == "WARNING":
        score += 3

    # Referrer-Policy (8)
    rp = headers.get("Referrer-Policy", {})
    if rp.get("status") == "PASS":
        score += 8
    elif rp.get("status") == "WARNING":
        score += 4

    # Permissions-Policy (7)
    pp = headers.get("Permissions-Policy", {})
    if pp.get("status") == "PASS":
        score += 7

    # Cookies (10)
    cookie_check = checks.get("cookies", {})
    if cookie_check.get("status") == "PASS":
        score += 10
    elif cookie_check.get("status") == "WARNING":
        score += 4

    # Info exposure (5)
    info_check = checks.get("info_exposure", {})
    if info_check.get("status") == "PASS":
        score += 5

    # Mixed Content (5)
    mixed_check = checks.get("mixed_content", {})
    if mixed_check.get("status") == "PASS":
        score += 5
    elif mixed_check.get("status") == "NOT_ASSESSED":
        score += 3

    return min(100, max(0, score))


def perform_website_assessment(raw_url: str) -> Dict[str, Any]:
    """
    Run the full suite of passive website security checks on an authorized target URL.
    Returns complete findings, raw metadata, and calculated scores.
    """
    # 1. URL Validation and SSRF check
    normalized_url, scheme, hostname, port = validate_and_resolve_url(raw_url)

    # 2. HTTP Request with redirect tracing
    response, redirect_history = safe_http_request(normalized_url)
    is_https = normalized_url.startswith("https://") or response.url.startswith("https://")

    # 3. Individual checks
    https_result = check_https_availability(hostname)
    tls_result = check_tls_certificate(hostname) if is_https else {
        "check_name": "TLS Certificate",
        "category": "Cryptographic Controls",
        "status": "NOT_ASSESSED",
        "evidence": "Target requested via plain HTTP; TLS certificate inspection not applicable.",
        "days_until_expiry": None
    }
    headers_result = check_security_headers(response.headers)
    cookies_result = check_cookie_security(response, is_https)
    info_exposure_result = check_information_exposure(response.headers)
    redirect_result = check_redirect_behavior(redirect_history)

    # Mixed content inspects static HTML body
    html_text = ""
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        try:
            html_text = response.text
        except Exception:
            html_text = ""
    mixed_content_result = check_mixed_content(html_text, is_https)

    raw_checks = {
        "https": https_result,
        "tls": tls_result,
        "headers": headers_result,
        "cookies": cookies_result,
        "info_exposure": info_exposure_result,
        "redirects": redirect_result,
        "mixed_content": mixed_content_result
    }

    overall_score = calculate_overall_security_score(raw_checks)

    # Compile unified findings list
    findings = []
    finding_counter = 1

    # HTTPS finding
    findings.append({
        "finding_code": f"TL-FIND-{finding_counter:02d}",
        "title": "HTTPS Transport & Redirection",
        "category": "Transport Security",
        "status": https_result["status"],
        "severity": "High" if https_result["status"] == "FAIL" else ("Medium" if https_result["status"] == "WARNING" else "Low"),
        "evidence": https_result["evidence"],
        "description": "Verifies whether encrypted HTTPS communication is supported and whether plaintext HTTP connections are automatically redirected.",
        "recommendation": "Enforce HTTPS across all application endpoints and configure HTTP 301 permanent redirects from port 80 to port 443."
    })
    finding_counter += 1

    # TLS finding
    if tls_result["status"] != "NOT_ASSESSED":
        findings.append({
            "finding_code": f"TL-FIND-{finding_counter:02d}",
            "title": "TLS Certificate Validity & Cryptography",
            "category": "Cryptographic Controls",
            "status": tls_result["status"],
            "severity": "Critical" if tls_result["status"] == "FAIL" else ("Medium" if tls_result["status"] == "WARNING" else "Low"),
            "evidence": tls_result["evidence"],
            "description": "Examines TLS certificate expiration, trusted certificate authorities, and modern cryptographic cipher negotiation.",
            "recommendation": "Renew TLS certificates prior to expiration, utilize trusted CA chains, and restrict cipher suites to modern standards (TLS 1.2+)."
        })
        finding_counter += 1

    # Headers findings
    header_titles = {
        "Content-Security-Policy": ("Content-Security-Policy (CSP)", "Defines permitted sources of content to mitigate Cross-Site Scripting (XSS) and data injection."),
        "Strict-Transport-Security": ("HTTP Strict Transport Security (HSTS)", "Instructs browsers to strictly interact only over HTTPS to prevent SSL-stripping."),
        "X-Content-Type-Options": ("MIME-Type Sniffing Protection", "Prevents browsers from MIME-sniffing a response away from the declared content-type."),
        "Frame-Protection": ("Clickjacking & Frame Protection", "Restricts embedding of the web application in iframes on external domains to stop UI redressing."),
        "Referrer-Policy": ("Referrer Policy Configuration", "Controls how much referrer information is included with requests initiated from the website."),
        "Permissions-Policy": ("Permissions & Feature Policy", "Restricts access to browser APIs such as geolocation, camera, and microphone.")
    }

    for h_key, h_data in headers_result.items():
        title_meta = header_titles.get(h_key, (h_key, "HTTP Security Header"))
        sev = "High" if h_data["status"] == "FAIL" and h_key in ("Content-Security-Policy", "Strict-Transport-Security", "Frame-Protection") else (
            "Medium" if h_data["status"] in ("FAIL", "WARNING") else "Low"
        )
        findings.append({
            "finding_code": f"TL-FIND-{finding_counter:02d}",
            "title": title_meta[0],
            "category": "Security Headers",
            "status": h_data["status"],
            "severity": sev,
            "evidence": h_data["evidence"],
            "description": title_meta[1],
            "recommendation": f"Add or optimize the '{h_key}' response header with recommended restrictive policies in the web server or reverse proxy configuration."
        })
        finding_counter += 1

    # Cookies finding
    findings.append({
        "finding_code": f"TL-FIND-{finding_counter:02d}",
        "title": "Cookie Flag Security (Secure, HttpOnly, SameSite)",
        "category": "Session Management",
        "status": cookies_result["status"],
        "severity": "Medium" if cookies_result["status"] == "WARNING" else "Low",
        "evidence": cookies_result["evidence"],
        "description": "Checks whether response cookies configure the Secure attribute (transmission only via HTTPS), HttpOnly (inaccessible via JavaScript document.cookie), and SameSite (CSRF mitigation).",
        "recommendation": "Ensure all cookies emitted by the server specify 'Secure; HttpOnly; SameSite=Lax' (or SameSite=Strict where appropriate)."
    })
    finding_counter += 1

    # Information Exposure finding
    findings.append({
        "finding_code": f"TL-FIND-{finding_counter:02d}",
        "title": "Server Information Disclosure",
        "category": "Information Disclosure",
        "status": info_exposure_result["status"],
        "severity": "Low",
        "evidence": info_exposure_result["evidence"],
        "description": "Checks if response headers advertise specific operating system, web server, or programming language versions.",
        "recommendation": "Configure reverse proxies and application servers to suppress or obfuscate 'Server' and 'X-Powered-By' headers."
    })
    finding_counter += 1

    # Redirect finding
    findings.append({
        "finding_code": f"TL-FIND-{finding_counter:02d}",
        "title": "HTTP Redirect Behavior",
        "category": "Transport Security",
        "status": redirect_result["status"],
        "severity": "High" if redirect_result["status"] == "FAIL" else ("Medium" if redirect_result["status"] == "WARNING" else "Low"),
        "evidence": redirect_result["evidence"],
        "description": "Analyzes the sequence and destinations of HTTP redirects.",
        "recommendation": "Minimize redirect chains and strictly prohibit HTTPS endpoints from redirecting back to insecure HTTP."
    })
    finding_counter += 1

    # Mixed content finding
    findings.append({
        "finding_code": f"TL-FIND-{finding_counter:02d}",
        "title": "Static Mixed Content References",
        "category": "Content Integrity",
        "status": mixed_content_result["status"],
        "severity": "Medium" if mixed_content_result["status"] == "WARNING" else "Low",
        "evidence": mixed_content_result["evidence"],
        "description": "Identifies HTTP resource URLs referenced inside HTTPS HTML markup.",
        "recommendation": "Update all static resource links (images, scripts, styles, iframes) to relative paths or explicit HTTPS URLs."
    })

    # Summary counts
    passed_count = sum(1 for f in findings if f["status"] == "PASS")
    warning_count = sum(1 for f in findings if f["status"] == "WARNING")
    failed_count = sum(1 for f in findings if f["status"] == "FAIL")

    return {
        "target_url": normalized_url,
        "hostname": hostname,
        "scan_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "overall_score": overall_score,
        "https_status": https_result["status"],
        "tls_status": tls_result["status"],
        "headers_status": "PASS" if all(h["status"] == "PASS" for h in headers_result.values()) else "WARNING",
        "checks_summary": {
            "passed": passed_count,
            "warning": warning_count,
            "failed": failed_count,
            "total": len(findings)
        },
        "raw_results": raw_checks,
        "findings": findings
    }
