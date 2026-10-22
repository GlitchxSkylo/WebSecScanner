# 🛡️ WebSecScanner

> **Scan smarter. Fix faster. Stay secure.**

A lightweight, browser-based web security scanner built with [Streamlit](https://streamlit.io) and developed with assistance from [IBM Bob](https://www.ibm.com/). Point it at any public URL and get an instant, beginner-friendly security report covering HTTPS, HTTP security headers, cookies, SSL/TLS certificates, and server information disclosure — no installation of external security tools required.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Security Checks Performed](#security-checks-performed)
4. [Technologies Used](#technologies-used)
5. [Project Structure](#project-structure)
6. [Prerequisites](#prerequisites)
7. [Installation](#installation)
8. [Running Locally](#running-locally)
9. [How to Use the Scanner](#how-to-use-the-scanner)
10. [Running the Tests](#running-the-tests)
11. [Deploying to Streamlit Community Cloud](#deploying-to-streamlit-community-cloud)
12. [Limitations](#limitations)
13. [Ethical Use & Responsible Scanning](#ethical-use--responsible-scanning)
14. [Author](#author)

---

## Overview

WebSecScanner is a Python + Streamlit application that performs surface-level HTTP security assessments against publicly accessible websites. It is designed for developers, students, and site owners who want a quick, readable summary of common security misconfigurations without needing to run professional penetration-testing suites.

All scanning logic lives in [`scanner/checks.py`](scanner/checks.py) and all Streamlit rendering lives in [`scanner/report.py`](scanner/report.py), keeping the main entry point ([`Saikat Dey_Websecscanner.py`](Saikat%20Dey_Websecscanner.py)) clean and minimal.

---

## Key Features

- **Consent gate** — the user must confirm ownership or authorisation before any network request is made.
- **Private/internal IP blocking** — `localhost`, RFC-1918 addresses (10.x, 172.16–31.x, 192.168.x), and IPv6 equivalents are blocked before scanning starts.
- **Live scanning animation** — a step-by-step `st.status` panel shows progress as each check runs.
- **Scored report** — results are aggregated into a 0–100 security score with a letter grade (A / B / C) and an SVG circular gauge.
- **Beginner-friendly summary** — plain-English explanations of every failing or warning check, prioritised into "Fix these first" and "Also worth fixing" sections.
- **Detailed per-check cards** — colour-coded PASS / WARNING / FAIL badges with technical detail for each individual check.
- **Downloadable report** — a plaintext `.txt` report with the full results and timestamp, downloadable directly from the browser.
- **Session-state persistence** — results survive Streamlit reruns triggered by expander clicks or the download button.
- **Dark neon-green terminal theme** — custom CSS and a `.streamlit/config.toml` theme.

---

## Security Checks Performed

| # | Check | What is tested |
|---|-------|----------------|
| 1 | **HTTPS in use** | Whether the supplied URL uses `https://` instead of `http://`. |
| 2 | **HTTP → HTTPS redirect** | Whether the plain-HTTP version of the URL redirects to HTTPS. |
| 3 | **Strict-Transport-Security** | Whether the HSTS header is present. |
| 4 | **X-Frame-Options** | Whether clickjacking protection is enabled. |
| 5 | **X-Content-Type-Options** | Whether MIME-sniffing protection is enabled. |
| 6 | **Content-Security-Policy** | Whether a CSP header is present. |
| 7 | **Referrer-Policy** | Whether referrer leakage is controlled. |
| 8 | **Permissions-Policy** | Whether browser feature access is restricted. |
| 9 | **Cookie: Secure flag** | Whether each cookie has the `Secure` attribute. |
| 10 | **Cookie: HttpOnly flag** | Whether each cookie has the `HttpOnly` attribute. |
| 11 | **Server info disclosure** | Whether the `Server` or `X-Powered-By` headers expose software versions. |
| 12 | **SSL certificate validity** | Whether the TLS certificate is valid and not expiring within 30 days. |

> **Note:** A site with no cookies produces a single passing "No cookies were set" result for checks 9–10. The exact number of result rows therefore varies by site.

---

## Technologies Used

| Library | Version | Purpose |
|---------|---------|---------|
| [Streamlit](https://streamlit.io) | `>= 1.32.0` | Web UI framework |
| [Requests](https://requests.readthedocs.io) | `>= 2.31.0` | HTTP requests for all checks |
| `ssl` | stdlib | TLS certificate inspection |
| `socket` | stdlib | DNS resolution and raw TCP for SSL check |
| `ipaddress` | stdlib | Private/internal IP blocking |
| `datetime` | stdlib | Certificate expiry calculation |
| `unittest` / `unittest.mock` | stdlib | Unit test framework |

---

## Project Structure

```
WebSecScanner/
├── Saikat Dey_Websecscanner.py   # Main Streamlit entry point (UI shell)
├── requirements.txt               # Python dependencies
├── .streamlit/
│   └── config.toml                # Dark neon-green Streamlit theme
├── scanner/
│   ├── __init__.py                # Makes scanner a Python package
│   ├── checks.py                  # All security check functions + URL validation
│   └── report.py                  # Streamlit report rendering (score, cards, download)
└── tests/
    └── test_checks.py             # Unit tests for every check function (fully mocked)
```

---

## Prerequisites

- **Python 3.10 or later** (the code uses `tuple[...]` and `list[...]` type hints that require 3.10+)
- **pip** (comes bundled with Python)
- An internet connection to reach the target websites

Verify your Python version:

```powershell
python --version
```

---

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/<your-username>/WebSecScanner.git
cd WebSecScanner
```

### 2. Create and activate a virtual environment *(recommended)*

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> If you see an execution-policy error, run this first (once, as Administrator):
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
> ```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

---

## Running Locally

Because the main filename contains a space, wrap it in quotes when calling Streamlit:

```powershell
streamlit run "Saikat Dey_Websecscanner.py"
```

Streamlit will print a local URL (typically `http://localhost:8501`). Open it in your browser.

To stop the server, press **Ctrl + C** in the terminal.

---

## How to Use the Scanner

1. **Open the app** in your browser at `http://localhost:8501`.
2. **Enter a URL** in the input field — include the full scheme, e.g. `https://example.com`.
3. **Tick the consent checkbox** — you must confirm that you own the site or have explicit permission to test it.
4. **Click "🔍 Scan"** — a live progress panel shows each check as it runs.
5. **Review the report:**
   - The **score banner** shows a 0–100 score and letter grade (A / B / C).
   - The **quick stats bar** shows counts of passed, warning, and failed checks.
   - The **Beginner-Friendly Summary** groups issues by priority with plain-English explanations and fix instructions.
   - The **Check Details** section shows every individual result with a colour-coded PASS / WARNING / FAIL badge.
6. **Download the report** — click **"⬇️ Download report"** to save a `.txt` copy.

### Score grading

| Score | Grade | Verdict |
|-------|-------|---------|
| 80 – 100 | **A** | Good security posture |
| 50 – 79 | **B** | Some issues found |
| 0 – 49 | **C** | Multiple issues — needs attention |

Scoring: each check contributes **1 point** for PASS, **0.5 points** for WARNING, and **0 points** for FAIL. The total is normalised to 100.

---

## Running the Tests

The test suite in [`tests/test_checks.py`](tests/test_checks.py) covers every public function in `scanner/checks.py`. All HTTP and socket calls are mocked — no real network traffic is made.

### Using pytest *(recommended)*

```powershell
pip install pytest
python -m pytest tests/ -v
```

### Using the built-in unittest runner

```powershell
python -m unittest discover tests
```

### Expected results

With no site under test and no internet connection required, the full suite should report **0 failures**. A typical run covers:

- `TestCheckHttps` (3 tests)
- `TestCheckSecurityHeaders` (3 tests)
- `TestCheckCookies` (5 tests)
- `TestCheckServerInfo` (4 tests)
- `TestCheckRedirectToHttps` (4 tests)
- `TestCheckSslCertificate` (7 tests)
- `TestRunAllChecks` (2 tests)
- `TestValidateUrl` (14 tests)

**Total: 44 tests**

---

## Deploying to Streamlit Community Cloud

[Streamlit Community Cloud](https://streamlit.io/cloud) can serve the app for free directly from a public GitHub repository.

### Steps

1. **Push your repository to GitHub** (must be public, or use a connected private repo).

2. **Log in** at [share.streamlit.io](https://share.streamlit.io) with your GitHub account.

3. **Click "New app"** and fill in:
   - **Repository:** `<your-username>/WebSecScanner`
   - **Branch:** `main`
   - **Main file path:** `Saikat Dey_Websecscanner.py`

   > ⚠️ The filename contains a space. Streamlit Community Cloud supports filenames with spaces in the path field — type it exactly as shown.

4. **Click "Deploy"** — Streamlit Cloud will install `requirements.txt` and launch the app automatically.

5. Once deployed, you will receive a public URL in the format:
   ```
   https://<app-slug>.streamlit.app
   ```

### Notes

- `requirements.txt` is the only dependency file needed — no `Pipfile` or `pyproject.toml` is required.
- The `.streamlit/config.toml` theme is automatically picked up by Streamlit Cloud.
- No environment variables or secrets are needed; the scanner makes only outbound HTTP/HTTPS/TLS requests.

---

## Limitations

- **Surface-level checks only.** The scanner reads HTTP response headers and checks TLS metadata. It does **not** perform: vulnerability scanning, SQL injection testing, XSS payload injection, port scanning, directory brute-forcing, or authentication testing.
- **Single HTTP request per check.** Server behaviour can vary between requests. Some headers may be conditionally set and not visible on the home page.
- **No authentication support.** Pages behind login walls cannot be tested.
- **No JavaScript execution.** Headers or cookies set by client-side scripts are invisible to this scanner.
- **SSL check uses port 443 only.** Sites using non-standard TLS ports are not covered.
- **Rate-limited by the target.** Aggressive rate-limiting or WAF rules on the target may cause check failures that do not reflect the actual security configuration.
- **`datetime.utcnow()` deprecation.** Python 3.12+ emits a `DeprecationWarning` for `datetime.datetime.utcnow()` used in the SSL expiry calculation. The code still works correctly; it should be migrated to `datetime.datetime.now(datetime.timezone.utc)` in a future update.

---

## Ethical Use & Responsible Scanning

> **Only scan websites you own or have explicit written permission to test.**

This tool sends real HTTP requests to the target URL. Scanning a site you do not own or have permission to test may:

- Violate the target's terms of service.
- Constitute unauthorised computer access under laws such as the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent legislation in your jurisdiction.

The application enforces a **consent checkbox** that must be ticked before any network activity begins. The `validate_url()` function also **blocks localhost and all RFC-1918 / link-local IP ranges** to prevent accidental scanning of internal infrastructure.

This project is intended for **educational purposes and authorised security testing only**.

---

## Author

**Saikat Dey**

- Project: WebSecScanner
- Built with Python 3 and Streamlit

---

*⚠️ Disclaimer: This tool performs lightweight, surface-level checks only. It is not a substitute for a full professional security audit.*
