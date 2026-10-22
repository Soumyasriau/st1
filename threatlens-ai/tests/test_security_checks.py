"""
Unit tests for ThreatLens AI Security Checks and Anti-SSRF Protections.
Uses local mocks and isolated unit validation without external internet dependency.
"""

import pytest
import socket
from unittest.mock import patch, MagicMock
from security_checks import (
    validate_and_resolve_url,
    SSRFValidationError,
    check_security_headers,
    check_cookie_security,
    check_information_exposure,
    check_mixed_content,
    check_redirect_behavior,
    calculate_overall_security_score
)


class TestSSRFProtections:
    """Test suite ensuring complete protection against Server-Side Request Forgery."""

    def test_block_localhost(self):
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url("http://localhost")

    def test_block_ipv4_loopback(self):
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url("http://127.0.0.1")

    def test_block_private_rfc1918_class_a(self):
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url("http://10.0.0.1")

    def test_block_private_rfc1918_class_b(self):
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url("http://172.16.0.1")

    def test_block_private_rfc1918_class_c(self):
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url("http://192.168.1.1")

    def test_block_cloud_metadata_ipv4(self):
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url("http://169.254.169.254/latest/meta-data/")

    def test_block_cloud_metadata_hostname(self):
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url("http://metadata.google.internal")

    def test_block_non_http_schemes(self):
        with pytest.raises(ValueError, match="Only HTTP and HTTPS are permitted"):
            validate_and_resolve_url("file:///etc/passwd")

        with pytest.raises(ValueError, match="Only HTTP and HTTPS are permitted"):
            validate_and_resolve_url("gopher://127.0.0.1:70")

    def test_block_embedded_credentials(self):
        with pytest.raises(ValueError, match="embedded authentication credentials"):
            validate_and_resolve_url("http://admin:secret@example.com")

    @patch("socket.getaddrinfo")
    def test_allow_valid_public_domain(self, mock_getaddrinfo):
        # Mock DNS resolution to public IP 93.184.216.34 (example.com)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('93.184.216.34', 443))
        ]
        norm_url, scheme, hostname, port = validate_and_resolve_url("example.com")
        assert norm_url == "https://example.com/"
        assert scheme == "https"
        assert hostname == "example.com"
        assert port == 443


class TestSecurityHeadersInspection:
    """Test suite evaluating HTTP security header auditing logic."""

    def test_missing_all_security_headers(self):
        empty_headers = {"Content-Type": "text/html"}
        results = check_security_headers(empty_headers)

        assert results["Content-Security-Policy"]["status"] == "FAIL"
        assert results["Strict-Transport-Security"]["status"] == "FAIL"
        assert results["X-Content-Type-Options"]["status"] == "FAIL"
        assert results["Frame-Protection"]["status"] == "FAIL"
        assert results["Referrer-Policy"]["status"] == "WARNING"

    def test_well_hardened_security_headers(self):
        good_headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
        }
        results = check_security_headers(good_headers)

        assert results["Content-Security-Policy"]["status"] == "PASS"
        assert results["Strict-Transport-Security"]["status"] == "PASS"
        assert results["X-Content-Type-Options"]["status"] == "PASS"
        assert results["Frame-Protection"]["status"] == "PASS"
        assert results["Referrer-Policy"]["status"] == "PASS"
        assert results["Permissions-Policy"]["status"] == "PASS"

    def test_permissive_csp_warning(self):
        permissive_headers = {
            "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"
        }
        results = check_security_headers(permissive_headers)
        assert results["Content-Security-Policy"]["status"] == "WARNING"
        assert "unsafe-inline" in results["Content-Security-Policy"]["evidence"]

    def test_short_hsts_duration_warning(self):
        short_hsts = {
            "Strict-Transport-Security": "max-age=86400"  # 1 day
        }
        results = check_security_headers(short_hsts)
        assert results["Strict-Transport-Security"]["status"] == "WARNING"
        assert "shorter than recommended" in results["Strict-Transport-Security"]["evidence"]


class TestCookieSecurity:
    """Test suite inspecting Set-Cookie attributes without exposing cookie values."""

    def test_no_cookies_returns_pass(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.raw.headers.items.return_value = []

        res = check_cookie_security(mock_resp, is_https=True)
        assert res["status"] == "PASS"
        assert res["cookies_found"] == 0

    def test_vulnerable_cookies_flagged(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"set-cookie": "session_id=SECRET123; Path=/"}
        mock_resp.raw.headers.items.return_value = [("set-cookie", "session_id=SECRET123; Path=/")]

        res = check_cookie_security(mock_resp, is_https=True)
        assert res["status"] == "WARNING"
        assert res["cookies_found"] == 1
        cookie = res["cookies"][0]
        assert cookie["name"] == "session_id"
        assert "Secure" in cookie["missing_flags"]
        assert "HttpOnly" in cookie["missing_flags"]
        assert "SameSite" in cookie["missing_flags"]

    def test_hardened_cookie_passes(self):
        mock_resp = MagicMock()
        mock_cookie_header = "auth_tok=XYZ; Secure; HttpOnly; SameSite=Strict; Path=/"
        mock_resp.headers = {"set-cookie": mock_cookie_header}
        mock_resp.raw.headers.items.return_value = [("set-cookie", mock_cookie_header)]

        res = check_cookie_security(mock_resp, is_https=True)
        assert res["status"] == "PASS"
        assert res["cookies_found"] == 1
        assert len(res["cookies"][0]["missing_flags"]) == 0


class TestInformationExposure:
    """Test suite evaluating server banner leaks."""

    def test_revealing_version_banners(self):
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3"
        }
        res = check_information_exposure(headers)
        assert res["status"] == "WARNING"
        assert len(res["disclosed_headers"]) == 2

    def test_generic_masked_banner(self):
        headers = {
            "Server": "cloudflare"
        }
        res = check_information_exposure(headers)
        assert res["status"] == "PASS"

    def test_no_server_headers(self):
        headers = {"Content-Type": "text/html"}
        res = check_information_exposure(headers)
        assert res["status"] == "PASS"


class TestMixedContent:
    """Test suite identifying unencrypted assets in static HTML."""

    def test_insecure_scripts_detected(self):
        html = """
        <html>
            <head><script src="http://cdn.example.com/analytics.js"></script></head>
            <body><img src="http://cdn.example.com/logo.png"></body>
        </html>
        """
        res = check_mixed_content(html, is_https=True)
        assert res["status"] == "WARNING"
        assert len(res["insecure_resources"]) == 2

    def test_clean_https_markup(self):
        html = """
        <html>
            <head><script src="https://cdn.example.com/app.js"></script></head>
            <body><img src="/static/logo.png"></body>
        </html>
        """
        res = check_mixed_content(html, is_https=True)
        assert res["status"] == "PASS"
        assert len(res["insecure_resources"]) == 0


class TestRedirectBehavior:
    """Test suite tracing redirect hops."""

    def test_clean_single_hop(self):
        history = [
            {"url": "http://example.com", "status_code": 301, "headers": {}},
            {"url": "https://example.com", "status_code": 200, "headers": {}}
        ]
        res = check_redirect_behavior(history)
        assert res["status"] == "PASS"
        assert res["hop_count"] == 1

    def test_downgrade_redirect_detected(self):
        history = [
            {"url": "https://example.com/checkout", "status_code": 302, "headers": {}},
            {"url": "http://example.com/confirmation", "status_code": 200, "headers": {}}
        ]
        res = check_redirect_behavior(history)
        assert res["status"] == "FAIL"
        assert "Security downgrade" in res["evidence"]

    def test_excessive_redirect_hops(self):
        history = [
            {"url": "https://example.com/1", "status_code": 302, "headers": {}},
            {"url": "https://example.com/2", "status_code": 302, "headers": {}},
            {"url": "https://example.com/3", "status_code": 302, "headers": {}},
            {"url": "https://example.com/4", "status_code": 302, "headers": {}},
            {"url": "https://example.com/5", "status_code": 200, "headers": {}}
        ]
        res = check_redirect_behavior(history)
        assert res["status"] == "WARNING"
        assert res["hop_count"] == 4
