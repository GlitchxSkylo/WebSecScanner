# tests/test_checks.py
#
# Unit tests for every public check function in scanner/checks.py.
#
# All HTTP calls are mocked with unittest.mock so no real network
# traffic is made and the suite runs completely offline.
#
# Run with:
#   python -m pytest tests/
#   python -m unittest discover tests

import unittest
from unittest.mock import MagicMock, patch

import datetime
import ssl

from scanner.checks import (
    check_https,
    check_security_headers,
    check_cookies,
    check_server_info,
    check_redirect_to_https,
    check_ssl_certificate,
    run_all_checks,
    validate_url,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_response(headers=None, cookies=None, url="https://example.com"):
    """Build a minimal mock requests.Response."""
    resp = MagicMock()
    resp.headers = headers or {}
    resp.cookies = cookies if cookies is not None else []
    resp.url = url
    return resp


# ── check_https ───────────────────────────────────────────────────────────────

class TestCheckHttps(unittest.TestCase):

    def test_https_url_passes(self):
        result = check_https("https://example.com")
        self.assertTrue(result["passed"])
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["name"], "HTTPS in use")

    def test_http_url_fails(self):
        result = check_https("http://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "fail")

    def test_https_uppercase_passes(self):
        # URL scheme comparison should be case-insensitive
        result = check_https("HTTPS://example.com")
        self.assertTrue(result["passed"])


# ── check_security_headers ────────────────────────────────────────────────────

class TestCheckSecurityHeaders(unittest.TestCase):

    ALL_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }

    @patch("scanner.checks._fetch")
    def test_all_headers_present_all_pass(self, mock_fetch):
        mock_fetch.return_value = _make_response(headers=self.ALL_HEADERS)
        results = check_security_headers("https://example.com")
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertTrue(r["passed"], msg=f"{r['name']} should pass")
            self.assertEqual(r["status"], "pass")

    @patch("scanner.checks._fetch")
    def test_missing_headers_warn(self, mock_fetch):
        mock_fetch.return_value = _make_response(headers={})
        results = check_security_headers("https://example.com")
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertFalse(r["passed"], msg=f"{r['name']} should warn")
            self.assertEqual(r["status"], "warn")

    @patch("scanner.checks._fetch")
    def test_request_failure_returns_single_fail(self, mock_fetch):
        import requests
        mock_fetch.side_effect = requests.RequestException("timeout")
        results = check_security_headers("https://example.com")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["passed"])
        self.assertEqual(results[0]["status"], "fail")


# ── check_cookies ─────────────────────────────────────────────────────────────

class TestCheckCookies(unittest.TestCase):

    def _make_cookie(self, name, secure=True, httponly=True):
        """Build a minimal mock cookie object."""
        cookie = MagicMock()
        cookie.name = name
        cookie.secure = secure
        # Simulate the two paths checks.py uses to detect HttpOnly
        cookie.has_nonstandard_attr.return_value = httponly
        cookie._rest = {"HttpOnly": None} if httponly else {}
        return cookie

    @patch("scanner.checks._fetch")
    def test_no_cookies_passes(self, mock_fetch):
        mock_fetch.return_value = _make_response(cookies=[])
        results = check_cookies("https://example.com")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["passed"])
        self.assertEqual(results[0]["status"], "pass")

    @patch("scanner.checks._fetch")
    def test_secure_httponly_cookie_passes(self, mock_fetch):
        cookie = self._make_cookie("session", secure=True, httponly=True)
        mock_fetch.return_value = _make_response(cookies=[cookie])
        results = check_cookies("https://example.com")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["passed"])
        self.assertEqual(results[0]["status"], "pass")

    @patch("scanner.checks._fetch")
    def test_missing_secure_flag_warns(self, mock_fetch):
        cookie = self._make_cookie("session", secure=False, httponly=True)
        mock_fetch.return_value = _make_response(cookies=[cookie])
        results = check_cookies("https://example.com")
        self.assertFalse(results[0]["passed"])
        self.assertEqual(results[0]["status"], "warn")
        self.assertIn("Secure", results[0]["detail"])

    @patch("scanner.checks._fetch")
    def test_missing_httponly_flag_warns(self, mock_fetch):
        cookie = self._make_cookie("session", secure=True, httponly=False)
        mock_fetch.return_value = _make_response(cookies=[cookie])
        results = check_cookies("https://example.com")
        self.assertFalse(results[0]["passed"])
        self.assertEqual(results[0]["status"], "warn")
        self.assertIn("HttpOnly", results[0]["detail"])

    @patch("scanner.checks._fetch")
    def test_request_failure_returns_fail(self, mock_fetch):
        import requests
        mock_fetch.side_effect = requests.RequestException("refused")
        results = check_cookies("https://example.com")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["passed"])
        self.assertEqual(results[0]["status"], "fail")


# ── check_server_info ─────────────────────────────────────────────────────────

class TestCheckServerInfo(unittest.TestCase):

    @patch("scanner.checks._fetch")
    def test_no_server_header_passes(self, mock_fetch):
        mock_fetch.return_value = _make_response(headers={})
        result = check_server_info("https://example.com")
        self.assertTrue(result["passed"])
        self.assertEqual(result["status"], "pass")

    @patch("scanner.checks._fetch")
    def test_server_header_present_warns(self, mock_fetch):
        mock_fetch.return_value = _make_response(headers={"Server": "Apache/2.4.1"})
        result = check_server_info("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "warn")
        self.assertIn("Apache/2.4.1", result["detail"])

    @patch("scanner.checks._fetch")
    def test_x_powered_by_header_warns(self, mock_fetch):
        mock_fetch.return_value = _make_response(headers={"X-Powered-By": "PHP/8.1"})
        result = check_server_info("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "warn")
        self.assertIn("PHP/8.1", result["detail"])

    @patch("scanner.checks._fetch")
    def test_request_failure_returns_fail(self, mock_fetch):
        import requests
        mock_fetch.side_effect = requests.RequestException("timeout")
        result = check_server_info("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "fail")


# ── check_redirect_to_https ───────────────────────────────────────────────────

class TestCheckRedirectToHttps(unittest.TestCase):

    def test_http_url_skipped_with_warn(self):
        # When the supplied URL is already HTTP the check cannot run
        result = check_redirect_to_https("http://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "warn")

    @patch("scanner.checks.requests.get")
    def test_redirect_to_https_passes(self, mock_get):
        mock_get.return_value = _make_response(url="https://example.com/")
        result = check_redirect_to_https("https://example.com")
        self.assertTrue(result["passed"])
        self.assertEqual(result["status"], "pass")

    @patch("scanner.checks.requests.get")
    def test_no_redirect_fails(self, mock_get):
        mock_get.return_value = _make_response(url="http://example.com/")
        result = check_redirect_to_https("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "fail")

    @patch("scanner.checks.requests.get")
    def test_request_failure_returns_fail(self, mock_get):
        import requests
        mock_get.side_effect = requests.RequestException("connection error")
        result = check_redirect_to_https("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "fail")


# ── check_ssl_certificate ─────────────────────────────────────────────────────

class TestCheckSslCertificate(unittest.TestCase):

    def test_http_url_returns_warn(self):
        """http:// URLs cannot have a certificate checked — expect a warning."""
        result = check_ssl_certificate("http://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["name"], "SSL certificate validity")
        self.assertIn("plain HTTP", result["detail"])

    @patch("scanner.checks.socket.create_connection")
    @patch("scanner.checks.ssl.create_default_context")
    def test_valid_cert_far_in_future_passes(self, mock_ctx_cls, mock_conn):
        """Certificate expiring 180 days from now → pass."""
        future = datetime.datetime.utcnow() + datetime.timedelta(days=180)
        not_after = future.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {"notAfter": not_after}
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = lambda s: s
        mock_raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_cls.return_value = mock_ctx

        result = check_ssl_certificate("https://example.com")
        self.assertTrue(result["passed"])
        self.assertEqual(result["status"], "pass")
        self.assertIn("valid for", result["detail"])

    @patch("scanner.checks.socket.create_connection")
    @patch("scanner.checks.ssl.create_default_context")
    def test_cert_expiring_within_30_days_warns(self, mock_ctx_cls, mock_conn):
        """Certificate expiring in 15 days → warning."""
        soon = datetime.datetime.utcnow() + datetime.timedelta(days=15)
        not_after = soon.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {"notAfter": not_after}
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = lambda s: s
        mock_raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_cls.return_value = mock_ctx

        result = check_ssl_certificate("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "warn")
        self.assertIn("expires in", result["detail"])

    @patch("scanner.checks.socket.create_connection")
    @patch("scanner.checks.ssl.create_default_context")
    def test_expired_cert_fails(self, mock_ctx_cls, mock_conn):
        """Certificate that expired 5 days ago → fail."""
        past = datetime.datetime.utcnow() - datetime.timedelta(days=5)
        not_after = past.strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {"notAfter": not_after}
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = lambda s: s
        mock_raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_cls.return_value = mock_ctx

        result = check_ssl_certificate("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "fail")
        self.assertIn("EXPIRED", result["detail"])

    @patch("scanner.checks.socket.create_connection")
    @patch("scanner.checks.ssl.create_default_context")
    def test_invalid_cert_fails(self, mock_ctx_cls, mock_conn):
        """SSLCertVerificationError during handshake → fail."""
        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = lambda s: s
        mock_raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert verify failed")
        mock_ctx_cls.return_value = mock_ctx

        result = check_ssl_certificate("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "fail")
        self.assertIn("invalid or untrusted", result["detail"])

    @patch("scanner.checks.socket.create_connection")
    @patch("scanner.checks.ssl.create_default_context")
    def test_connection_failure_fails(self, mock_ctx_cls, mock_conn):
        """Cannot reach port 443 → fail."""
        mock_conn.side_effect = OSError("Connection refused")

        result = check_ssl_certificate("https://example.com")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "fail")
        self.assertIn("port 443", result["detail"])

    def test_https_url_with_path_and_query_extracts_hostname(self):
        """Hostname extraction must strip path, query string, and fragment."""
        # We only verify the function does not raise and returns a dict with
        # the right name; the connection will be mocked at the socket level.
        with patch("scanner.checks.socket.create_connection") as mock_conn:
            mock_conn.side_effect = OSError("no network in test")
            result = check_ssl_certificate("https://example.com/path?q=1#frag")
        self.assertEqual(result["name"], "SSL certificate validity")
        self.assertEqual(result["status"], "fail")


# ── run_all_checks ────────────────────────────────────────────────────────────

class TestRunAllChecks(unittest.TestCase):

    @patch("scanner.checks.socket.create_connection")
    @patch("scanner.checks.ssl.create_default_context")
    @patch("scanner.checks.requests.get")
    @patch("scanner.checks._fetch")
    def test_returns_list_of_dicts(self, mock_fetch, mock_get, mock_ctx_cls, mock_conn):
        mock_fetch.return_value = _make_response(headers={}, cookies=[])
        mock_get.return_value = _make_response(url="https://example.com/")
        mock_conn.side_effect = OSError("no network in test")
        results = run_all_checks("https://example.com")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertIn("name",   r)
            self.assertIn("passed", r)
            self.assertIn("status", r)
            self.assertIn("detail", r)

    @patch("scanner.checks.socket.create_connection")
    @patch("scanner.checks.ssl.create_default_context")
    @patch("scanner.checks.requests.get")
    @patch("scanner.checks._fetch")
    def test_result_count_matches_checks(self, mock_fetch, mock_get, mock_ctx_cls, mock_conn):
        # No headers, no cookies →
        # 1 (https) + 6 (headers) + 1 (cookies) + 1 (server) + 1 (redirect) + 1 (ssl) = 11
        mock_fetch.return_value = _make_response(headers={}, cookies=[])
        mock_get.return_value = _make_response(url="https://example.com/")
        mock_conn.side_effect = OSError("no network in test")
        results = run_all_checks("https://example.com")
        self.assertEqual(len(results), 11)


# ── validate_url ──────────────────────────────────────────────────────────────

class TestValidateUrl(unittest.TestCase):

    # ── scheme checks ────────────────────────────────────────────────────────

    @patch("scanner.checks.socket.getaddrinfo")
    def test_https_url_is_allowed(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        ok, reason = validate_url("https://example.com")
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    @patch("scanner.checks.socket.getaddrinfo")
    def test_http_url_is_allowed(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        ok, reason = validate_url("http://example.com")
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_ftp_scheme_is_blocked(self):
        ok, reason = validate_url("ftp://example.com/file.txt")
        self.assertFalse(ok)
        self.assertIn("⛔", reason)
        self.assertIn("http", reason.lower())

    def test_javascript_scheme_is_blocked(self):
        ok, reason = validate_url("javascript:alert(1)")
        self.assertFalse(ok)
        self.assertIn("⛔", reason)

    def test_empty_string_is_blocked(self):
        ok, reason = validate_url("")
        self.assertFalse(ok)

    # ── localhost checks ─────────────────────────────────────────────────────

    def test_localhost_hostname_is_blocked(self):
        ok, reason = validate_url("http://localhost/admin")
        self.assertFalse(ok)
        self.assertIn("⛔", reason)
        self.assertIn("localhost", reason.lower())

    def test_localhost_with_port_is_blocked(self):
        ok, reason = validate_url("http://localhost:8080/")
        self.assertFalse(ok)
        self.assertIn("localhost", reason.lower())

    def test_localhost_uppercase_is_blocked(self):
        ok, reason = validate_url("http://LOCALHOST/")
        self.assertFalse(ok)

    # ── private IP checks (no real DNS resolution needed) ────────────────────

    @patch("scanner.checks.socket.getaddrinfo")
    def test_loopback_127_is_blocked(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("127.0.0.1", 0))]
        ok, reason = validate_url("http://127.0.0.1/")
        self.assertFalse(ok)
        self.assertIn("⛔", reason)
        self.assertIn("127.0.0.1", reason)

    @patch("scanner.checks.socket.getaddrinfo")
    def test_rfc1918_10_is_blocked(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("10.0.0.1", 0))]
        ok, reason = validate_url("http://internal.corp/")
        self.assertFalse(ok)
        self.assertIn("10.0.0.1", reason)

    @patch("scanner.checks.socket.getaddrinfo")
    def test_rfc1918_172_16_is_blocked(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("172.16.0.5", 0))]
        ok, reason = validate_url("http://host.local/")
        self.assertFalse(ok)
        self.assertIn("172.16.0.5", reason)

    @patch("scanner.checks.socket.getaddrinfo")
    def test_rfc1918_172_31_is_blocked(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("172.31.255.254", 0))]
        ok, reason = validate_url("http://host.local/")
        self.assertFalse(ok)

    @patch("scanner.checks.socket.getaddrinfo")
    def test_rfc1918_192_168_is_blocked(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("192.168.1.100", 0))]
        ok, reason = validate_url("http://router.local/")
        self.assertFalse(ok)
        self.assertIn("192.168.1.100", reason)

    @patch("scanner.checks.socket.getaddrinfo")
    def test_ipv6_loopback_is_blocked(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("::1", 0, 0, 0))]
        ok, reason = validate_url("http://[::1]/")
        self.assertFalse(ok)
        self.assertIn("::1", reason)

    @patch("scanner.checks.socket.getaddrinfo")
    def test_public_ip_is_allowed(self, mock_gai):
        mock_gai.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        ok, reason = validate_url("https://example.com")
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    # ── unresolvable hostname ─────────────────────────────────────────────────

    @patch("scanner.checks.socket.getaddrinfo")
    def test_unresolvable_host_is_allowed_through(self, mock_gai):
        import socket as _socket
        mock_gai.side_effect = _socket.gaierror("Name or service not known")
        ok, reason = validate_url("https://nonexistent.invalid/")
        # Should not block — the HTTP request will fail instead
        self.assertTrue(ok)
        self.assertEqual(reason, "")


if __name__ == "__main__":
    unittest.main()
