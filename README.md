# 🔐 WebSecScanner

**Scan smarter. Fix faster. Stay secure.**

A simple, beginner-friendly website security scanner built with **Python**, **Streamlit**, and **Requests**.

Enter any public URL and the tool will run a set of lightweight security checks and display a colour-coded report right in your browser — all wrapped in a **dark cyber-themed UI** with neon-green accents.

---

## 🗂 Project Structure

```
WebSecScanner/
├── app.py                 # Streamlit UI entry point
├── scanner/
│   ├── __init__.py        # Makes 'scanner' a Python package
│   ├── checks.py          # All security check functions
│   └── report.py          # Streamlit rendering / report display
├── tests/
│   └── test_checks.py     # Unit tests for every check function
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

---

## 🔍 What It Checks

| # | Check | Why it matters |
|---|-------|---------------|
| 1 | **HTTPS in use** | Encrypts traffic between browser and server |
| 2–7 | **HTTP security headers** (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy) | Prevent XSS, clickjacking, MIME sniffing, and more |
| 8 | **Cookie flags** (Secure & HttpOnly) | Protect session cookies from theft |
| 9 | **Server info disclosure** | Hides software versions from attackers |
| 10 | **HTTP → HTTPS redirect** | Ensures plain-HTTP visitors are upgraded |
| 11 | **SSL certificate expiry** | Warns when the TLS certificate is missing, expired, or expiring within 30 days |

### URL Safety Limits

Before any scan is attempted, the submitted URL is validated against the following rules:

- **Protocol** — only `http://` and `https://` URLs are accepted; anything else is rejected outright.
- **Localhost blocked** — `localhost`, `127.0.0.1`, and `::1` are not permitted.
- **Private / internal IPs blocked** — addresses in RFC-1918 ranges (`10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`) and other reserved ranges are blocked to prevent server-side request forgery (SSRF) against internal infrastructure.

These checks run before any HTTP request is made.

---

Each check returns a result dict with three keys:

| Key | Type | Description |
|-----|------|-------------|
| `name` | `str` | Short label shown in the report |
| `passed` | `bool` | `True` if no issue was found |
| `status` | `str` | `"pass"`, `"warn"`, or `"fail"` |
| `detail` | `str` | Human-readable explanation of the finding |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/WebSecScanner.git
cd WebSecScanner
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
streamlit run app.py
```

Streamlit will open your browser automatically at `http://localhost:8501`.

---

## 📊 Example Output

Scanning `https://example.com` produces a report similar to the following.

**Live scan animation**

While the scan runs, a step-by-step `st.status` panel animates through each active check in real time, so you can see exactly what the scanner is doing before the final report appears.

**Circular score gauge**

Once the scan completes, the score is displayed as an SVG circular gauge rendered inside a dark background disc. The arc colour shifts from red → amber → green as the score improves, and the numeric score and letter grade sit at the centre.

```
Score: 72 / 100   Grade B
Some issues found — review the details below.
Total: 11 checks  |  5 passed  |  2 warnings  |  4 failed
```

**Severity badges & per-check details**

Every check result is labelled with a colour-coded severity badge before its detail text:

| Badge | Colour | Meaning |
|-------|--------|---------|
| `PASS` | green | No issue detected |
| `WARN` | amber | Potential issue worth reviewing |
| `FAIL` | red | Security problem found |

```
[PASS]  HTTPS in use
        ✅ URL uses HTTPS.

[PASS]  Header: Strict-Transport-Security
        ✅ Present.

[WARN]  Header: Content-Security-Policy
        ⚠️ Missing. Controls which resources the browser is allowed to load.

[WARN]  Header: Permissions-Policy
        ⚠️ Missing. Restricts access to browser features like camera or microphone.

[PASS]  Cookies
        ✅ No cookies were set by this page.

[WARN]  Server info disclosure
        ⚠️ Server reveals: ECS (nyb/1D2B) — consider hiding version details.

[PASS]  HTTP → HTTPS redirect
        ✅ HTTP redirects to HTTPS (landed on https://example.com/).
```

The full report can be downloaded as a `.txt` file using the **Download report** button at the bottom of the page.

---

## 🧩 How It Works

1. **`app.py`** — Sets up the Streamlit page, captures the URL input, and calls the scanner.
2. **`scanner/checks.py`** — Contains one function per security check. Each function returns a dict (or list of dicts) with `name`, `passed`, `status`, and `detail` keys. `run_all_checks()` is the single entry point called by the UI.
3. **`scanner/report.py`** — Receives the list of check results and renders them as a structured Streamlit report. Highlights include a self-contained SVG **circular score gauge**, colour-coded **severity badges** (`PASS` / `WARN` / `FAIL`) on every check card, and a downloadable plain-text report.

---

## 🧪 Running the Tests

Tests live in `tests/test_checks.py` and use only the Python standard library (`unittest` + `unittest.mock`) — no extra dependencies needed.

```bash
python -m pytest tests/          # with pytest
# or, using the standard library only:
python -m unittest discover tests
```

The project ships **44 automated tests**. Each check function has at least two tests: one where it **passes** and one where it **fails/warns**, using mocked HTTP responses so no real network calls are made.

---

## 🛠 Extending the Scanner

Adding a new check is straightforward:

1. Write a new function in `scanner/checks.py` that returns a `dict` (or `list[dict]`) with the four standard keys (`name`, `passed`, `status`, `detail`).
2. Call it inside `run_all_checks()` and `append` / `extend` its output to `results`.
3. Add a corresponding test in `tests/test_checks.py`.

That's it — the report view picks up every result automatically.

---

## ⚠️ Disclaimer

This tool performs **surface-level, read-only checks only**. It does not perform penetration testing, exploit vulnerabilities, or access anything beyond a standard HTTP GET request. It is intended for educational purposes and should not replace a professional security audit.

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `streamlit` | Web UI framework |
| `requests` | HTTP client for fetching URLs |

---

## 📄 License

MIT — free to use, modify, and distribute.
