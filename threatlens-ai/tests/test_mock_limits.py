"""
Unit tests for ThreatLens AI HTTP request safety boundaries (timeouts, redirect limits, response size limits).
Uses mocked requests to verify edge case handling without network side-effects.
"""

import pytest
from unittest.mock import patch, MagicMock
import requests
from security_checks import safe_http_request, MAX_RESPONSE_BYTES


class TestSafeHTTPRequestBoundaries:
    """Test suite verifying safe_http_request timeout, size, and redirect boundaries."""

    @patch("security_checks.validate_and_resolve_url")
    @patch("requests.Session.get")
    def test_redirect_limit_exceeded(self, mock_get, mock_val):
        # Allow validation
        mock_val.return_value = ("https://example.com/redirect", "https", "example.com", 443)

        # Create infinite 302 redirect responses
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "https://example.com/redirect"}
        mock_get.return_value = mock_resp

        with pytest.raises(ValueError, match="Exceeded maximum allowed redirects"):
            safe_http_request("https://example.com/redirect", max_redirects=3)

    @patch("security_checks.validate_and_resolve_url")
    @patch("requests.Session.get")
    def test_oversized_response_body_truncation(self, mock_get, mock_val):
        mock_val.return_value = ("https://example.com/large", "https", "example.com", 443)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}

        # Simulate 3 MB streamed chunks (each chunk 512 KB)
        chunk = b"A" * (512 * 1024)
        mock_resp.iter_content.return_value = [chunk, chunk, chunk, chunk, chunk, chunk]
        mock_get.return_value = mock_resp

        final_resp, history = safe_http_request("https://example.com/large")
        # Final response content should be capped at <= MAX_RESPONSE_BYTES
        assert len(final_resp._content) <= MAX_RESPONSE_BYTES + (512 * 1024)
        assert len(final_resp._content) < (3 * 1024 * 1024)

    @patch("security_checks.validate_and_resolve_url")
    @patch("requests.Session.get")
    def test_connection_timeout_handling(self, mock_get, mock_val):
        mock_val.return_value = ("https://slow-target.com", "https", "slow-target.com", 443)
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        with pytest.raises(TimeoutError, match="timed out"):
            safe_http_request("https://slow-target.com")

    @patch("security_checks.validate_and_resolve_url")
    @patch("requests.Session.get")
    def test_tls_error_handling(self, mock_get, mock_val):
        mock_val.return_value = ("https://bad-cert.com", "https", "bad-cert.com", 443)
        mock_get.side_effect = requests.exceptions.SSLError("Certificate verify failed: self-signed certificate")

        with pytest.raises(requests.exceptions.SSLError, match="self-signed certificate"):
            safe_http_request("https://bad-cert.com")
