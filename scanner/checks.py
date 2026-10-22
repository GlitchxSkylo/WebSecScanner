# scanner/checks.py
#
# Each function in this file performs one specific security check against a URL.
# Every check returns a dict with three keys:
#   - "name"   : short label shown in the report
#   - "passed" : True if the site looks safe, False if there's a potential issue
#   - "detail" : a human-readable explanation of what was found

import datetime
import ipaddress
import socket
import ssl

import requests


# ── safety limits ─────────────────────────────────────────────────────────────

# Only these URL schemes are permitted.
_ALLOWED_SCHEMES = ("http://", "https://")

# Private / loopback networks that must never be scanned.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("10.0.0.0/8"),     # RFC-1918 class A
    ipaddress.ip_network("172.16.0.0/12"),  # RFC-1918 class B (172.16–172.31)
    ipaddress.ip_network("192.168.0.0/16"), # RFC-1918 class C
    ipaddress.ip_network("169.254.0.0/16"), # link-local
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
]


def validate_url(url: str) -> tuple[bool, str]:
    """Validate a URL against the scanner's safety limits.

    Checks (in order):
    1. Scheme must be http:// or https://.
    2. Hostname must not resolve to localhost or a private/internal IP address.

    Returns:
        (True, "")           – URL is safe to scan.
        (False, reason_str)  – URL is blocked; reason_str explains why.
    """
    # ── 1. Scheme check ───────────────────────────────────────────────────────
    if not url.lower().startswith(_ALLOWED_SCHEMES):
        return False, (
            "⛔ Blocked: only http:// and https:// URLs are allowed. "
            f"Got: {url!r}"
        )

    # ── 2. Extract hostname ───────────────────────────────────────────────────
    # Strip scheme, then take everything before the first / ? or #
    after_scheme = url.split("://", 1)[1]
    hostname = after_scheme.split("/")[0].split("?")[0].split("#")[0]
    # Strip port if present (handles both host:port and [IPv6]:port)
    if hostname.startswith("["):
        hostname = hostname.split("]")[0].lstrip("[")
    else:
        hostname = hostname.rsplit(":", 1)[0]

    # Plain "localhost" check (covers http://localhost and http://localhost:8080)
    if hostname.lower() == "localhost":
        return False, (
            "⛔ Blocked: scanning localhost is not permitted."
        )

    # ── 3. Resolve hostname to IP and check against blocked networks ──────────
    try:
        # getaddrinfo returns all addresses (IPv4 + IPv6) for the hostname.
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Cannot resolve — let the scan proceed; the HTTP request will fail
        # naturally and the individual checks will surface a "request failed"
        # result rather than a cryptic blocked message.
        return True, ""

    for family, _type, _proto, _canon, sockaddr in addr_infos:
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                return False, (
                    f"⛔ Blocked: {hostname!r} resolves to {raw_ip}, "
                    "which is a private or internal IP address. "
                    "Scanning internal hosts is not permitted."
                )

    return True, ""


# ── helpers ──────────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 5) -> requests.Response:
    """Send a GET request and return the Response object.

    Raises requests.RequestException on network errors so the caller can
    decide how to handle them.
    """
    headers = {"User-Agent": "WebSecScanner/1.0 (educational tool)"}
    return requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)


# ── individual checks ─────────────────────────────────────────────────────────

def check_https(url: str) -> dict:
    """Check 1 – Does the URL use HTTPS?

    HTTPS encrypts traffic between the browser and the server.
    Plain HTTP should be avoided for any site that handles user data.
    """
    passed = url.lower().startswith("https://")
    return {
        "name":   "HTTPS in use",
        "passed": passed,
        "status": "pass" if passed else "fail",
        "detail": "✅ URL uses HTTPS." if passed
                  else "❌ URL uses plain HTTP — traffic is not encrypted.",
    }


def check_security_headers(url: str) -> list[dict]:
    """Check 2 – Are important HTTP security headers present?

    Security headers tell the browser how to behave and can prevent many
    common attacks (XSS, clickjacking, MIME sniffing, etc.).
    Returns one result dict per header so they can be reported individually.
    """
    # Headers we look for and a plain-English reason why each matters
    important_headers = {
        "Strict-Transport-Security": "Enforces HTTPS and prevents protocol downgrade attacks.",
        "X-Frame-Options":           "Prevents the page from being embedded in iframes (clickjacking).",
        "X-Content-Type-Options":    "Stops browsers from guessing (sniffing) the content type.",
        "Content-Security-Policy":   "Controls which resources the browser is allowed to load.",
        "Referrer-Policy":           "Controls how much referrer information is sent with requests.",
        "Permissions-Policy":        "Restricts access to browser features like camera or microphone.",
    }

    results = []
    try:
        response = _fetch(url)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header, reason in important_headers.items():
            present = header.lower() in response_headers
            results.append({
                "name":   f"Header: {header}",
                "passed": present,
                "status": "pass" if present else "warn",
                "detail": "✅ Present." if present
                          else f"⚠️ Missing. {reason}",
            })
    except requests.RequestException as exc:
        # If the request itself failed, report a single error entry
        results.append({
            "name":   "Security Headers (request failed)",
            "passed": False,
            "status": "fail",
            "detail": f"❌ Could not fetch headers: {exc}",
        })

    return results


def check_cookies(url: str) -> list[dict]:
    """Check 3 – Do cookies have Secure and HttpOnly flags?

    - Secure  : cookie is only sent over HTTPS connections.
    - HttpOnly: JavaScript cannot read the cookie (helps against XSS theft).
    """
    results = []
    try:
        response = _fetch(url)

        if not response.cookies:
            results.append({
                "name":   "Cookies",
                "passed": True,
                "status": "pass",
                "detail": "✅ No cookies were set by this page.",
            })
            return results

        for cookie in response.cookies:
            secure   = cookie.secure
            httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly") is not None

            issues = []
            if not secure:
                issues.append("missing Secure flag")
            if not httponly:
                issues.append("missing HttpOnly flag")

            passed = len(issues) == 0
            results.append({
                "name":   f"Cookie: {cookie.name}",
                "passed": passed,
                "status": "pass" if passed else "warn",
                "detail": "✅ Has both Secure and HttpOnly flags." if passed
                          else f"⚠️ {cookie.name} is {', '.join(issues)}.",
            })
    except requests.RequestException as exc:
        results.append({
            "name":   "Cookies (request failed)",
            "passed": False,
            "status": "fail",
            "detail": f"❌ Could not check cookies: {exc}",
        })

    return results


def check_server_info(url: str) -> dict:
    """Check 4 – Does the Server header reveal software version info?

    Exposing the exact web server type and version helps attackers look up
    known vulnerabilities for that specific software release.
    """
    try:
        response = _fetch(url)
        server = response.headers.get("Server", "")
        x_powered = response.headers.get("X-Powered-By", "")

        leaks = [h for h in [server, x_powered] if h]
        passed = not leaks
        status = "pass" if passed else "warn"
        detail = (
            "✅ Server does not expose software version information."
            if passed
            else f"⚠️ Server reveals: {', '.join(leaks)} — consider hiding version details."
        )
    except requests.RequestException as exc:
        passed = False
        status = "fail"
        detail = f"❌ Could not check server info: {exc}"

    return {"name": "Server info disclosure", "passed": passed, "status": status, "detail": detail}


def check_redirect_to_https(url: str) -> dict:
    """Check 5 – Does the HTTP version redirect to HTTPS?

    Even if users type the HTTPS URL directly, a missing redirect means anyone
    who accidentally visits the HTTP version gets an unencrypted response.
    Only meaningful when the supplied URL is already HTTPS.
    """
    if not url.lower().startswith("https://"):
        return {
            "name":   "HTTP → HTTPS redirect",
            "passed": False,
            "status": "warn",
            "detail": "⚠️ Not checked — URL does not start with HTTPS.",
        }

    # Build the HTTP equivalent and see where it ends up
    http_url = "http://" + url[len("https://"):]
    try:
        response = requests.get(
            http_url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "WebSecScanner/1.0"},
        )
        final_url = response.url
        passed = final_url.lower().startswith("https://")
        status = "pass" if passed else "fail"
        detail = (
            f"✅ HTTP redirects to HTTPS (landed on {final_url})."
            if passed
            else f"❌ HTTP version did NOT redirect to HTTPS (landed on {final_url})."
        )
    except requests.RequestException as exc:
        passed = False
        status = "fail"
        detail = f"❌ Could not test HTTP redirect: {exc}"

    return {"name": "HTTP → HTTPS redirect", "passed": passed, "status": status, "detail": detail}


def check_ssl_certificate(url: str) -> dict:
    """Check 11 – Is the SSL/TLS certificate valid and not expiring soon?

    For https:// URLs, opens a raw TLS connection on port 443 (timeout 5 s),
    reads the certificate's notAfter date, and classifies the result:
      - Pass    : valid for more than 30 days.
      - Warning : expires within 30 days.
      - Fail    : already expired, or the connection/certificate was invalid.

    For http:// URLs the check cannot apply, so a Warning is returned to
    indicate that no certificate protection exists at all.
    """
    name = "SSL certificate validity"

    if not url.lower().startswith("https://"):
        return {
            "name":   name,
            "passed": False,
            "status": "warn",
            "detail": "⚠️ No certificate to check — URL uses plain HTTP, not HTTPS.",
        }

    # Extract hostname (reuse the same parsing logic as validate_url)
    after_scheme = url.split("://", 1)[1]
    hostname = after_scheme.split("/")[0].split("?")[0].split("#")[0]
    if hostname.startswith("["):
        hostname = hostname.split("]")[0].lstrip("[")
    else:
        hostname = hostname.rsplit(":", 1)[0]

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # notAfter is a string like "May 10 12:00:00 2026 GMT"
        not_after_str = cert.get("notAfter", "")
        expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days

        if days_left < 0:
            return {
                "name":   name,
                "passed": False,
                "status": "fail",
                "detail": (
                    f"❌ Certificate EXPIRED {abs(days_left)} day(s) ago "
                    f"(expired {expiry.strftime('%Y-%m-%d')})."
                ),
            }
        elif days_left <= 30:
            return {
                "name":   name,
                "passed": False,
                "status": "warn",
                "detail": (
                    f"⚠️ Certificate expires in {days_left} day(s) "
                    f"({expiry.strftime('%Y-%m-%d')}) — renew it soon."
                ),
            }
        else:
            return {
                "name":   name,
                "passed": True,
                "status": "pass",
                "detail": (
                    f"✅ Certificate is valid for {days_left} more day(s) "
                    f"(expires {expiry.strftime('%Y-%m-%d')})."
                ),
            }

    except ssl.SSLCertVerificationError as exc:
        return {
            "name":   name,
            "passed": False,
            "status": "fail",
            "detail": f"❌ Certificate is invalid or untrusted: {exc}",
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {
            "name":   name,
            "passed": False,
            "status": "fail",
            "detail": f"❌ Could not connect to port 443 to check the certificate: {exc}",
        }
    except Exception as exc:  # noqa: BLE001 — surface any unexpected SSL error
        return {
            "name":   name,
            "passed": False,
            "status": "fail",
            "detail": f"❌ Certificate check failed: {exc}",
        }


# ── main entry point ──────────────────────────────────────────────────────────

def run_all_checks(url: str) -> list[dict]:
    """Run every check and return a flat list of result dicts.

    This is the single function that app.py calls — it collects results from
    every individual check into one list so the report module can display them.
    """
    results = []

    results.append(check_https(url))
    results.extend(check_security_headers(url))
    results.extend(check_cookies(url))
    results.append(check_server_info(url))
    results.append(check_redirect_to_https(url))
    results.append(check_ssl_certificate(url))

    return results
