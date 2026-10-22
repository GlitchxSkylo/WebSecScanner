# Saikat Dey_Websecscanner.py
#
# Entry point for the WebSecScanner Streamlit application.
# Run with:  streamlit run "Saikat Dey_Websecscanner.py"
#
# This file is intentionally kept short — it only handles the UI shell.
# All security logic lives in scanner/checks.py and all rendering logic
# lives in scanner/report.py.

import time

import streamlit as st

from scanner.checks import (
    check_https,
    check_redirect_to_https,
    check_security_headers,
    check_cookies,
    check_server_info,
    check_ssl_certificate,
    run_all_checks,
    validate_url,
)
from scanner.report import render_report


# ── Page configuration ────────────────────────────────────────────────────────
# Must be the very first Streamlit call in the script.
st.set_page_config(
    page_title="WebSecScanner",
    page_icon="🔐",
    layout="centered",
)


# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── Global typography & surface ────────────────────────────────────── */
    html, body, [class*="css"] {
        font-family: 'Courier New', Courier, monospace !important;
    }

    /* ── Hero header ─────────────────────────────────────────────────────── */
    .wss-hero {
        text-align: center;
        padding: 2.4rem 1rem 1.8rem;
        border-bottom: 1px solid #1e2a1e;
        margin-bottom: 1.8rem;
    }
    .wss-hero .shield {
        font-size: 4rem;
        line-height: 1;
        display: block;
        margin-bottom: 0.5rem;
        filter: drop-shadow(0 0 12px #39ff14aa);
    }
    .wss-hero h1 {
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: 0.06em;
        color: #39ff14;
        text-shadow: 0 0 18px #39ff1488, 0 0 36px #39ff1430;
        margin: 0 0 0.35rem;
        font-family: 'Courier New', Courier, monospace;
    }
    .wss-hero .tagline {
        font-size: 0.95rem;
        color: #7aba78;
        letter-spacing: 0.03em;
        font-family: 'Courier New', Courier, monospace;
    }

    /* ── Rounded cards (st.expander, metric, and info blocks) ───────────── */
    div[data-testid="stExpander"] {
        border: 1px solid #1e2e1e !important;
        border-radius: 10px !important;
        background: #111518 !important;
        margin-bottom: 6px;
    }
    div[data-testid="stMetric"] {
        background: #111518;
        border: 1px solid #1e2e1e;
        border-radius: 10px;
        padding: 12px 16px;
    }

    /* ── Neon-green glow on the primary (Scan) button ────────────────────── */
    div[data-testid="stButton"] > button[kind="primary"],
    div[data-testid="stBaseButton-primary"] {
        background: #0a0e0f !important;
        color: #39ff14 !important;
        border: 2px solid #39ff14 !important;
        border-radius: 8px !important;
        font-family: 'Courier New', Courier, monospace !important;
        font-weight: 700 !important;
        letter-spacing: 0.08em !important;
        box-shadow: 0 0 10px #39ff1455, 0 0 24px #39ff1422 !important;
        transition: box-shadow 0.2s ease, background 0.2s ease !important;
    }
    div[data-testid="stButton"] > button[kind="primary"]:hover,
    div[data-testid="stBaseButton-primary"]:hover {
        background: #39ff1412 !important;
        box-shadow: 0 0 18px #39ff1488, 0 0 40px #39ff1444 !important;
    }

    /* ── Input fields — dark with green border-focus ─────────────────────── */
    div[data-testid="stTextInput"] input {
        background: #111518 !important;
        border: 1px solid #2a3a2a !important;
        border-radius: 8px !important;
        color: #e2e8f0 !important;
        font-family: 'Courier New', Courier, monospace !important;
    }
    div[data-testid="stTextInput"] input:focus {
        border-color: #39ff14 !important;
        box-shadow: 0 0 0 2px #39ff1430 !important;
    }

    /* ── Horizontal rule ─────────────────────────────────────────────────── */
    hr {
        border-color: #1e2a1e !important;
    }

    /* ── Monospace for code/pre elements ─────────────────────────────────── */
    code, pre, .stCode {
        font-family: 'Courier New', Courier, monospace !important;
        background: #0d1210 !important;
        border: 1px solid #1e2e1e !important;
        border-radius: 6px !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── Hero header ───────────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="wss-hero">
        <span class="shield">🛡️</span>
        <h1>WebSecScanner</h1>
        <p class="tagline">Scan smarter. Fix faster. Stay secure.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ── Session-state initialisation ─────────────────────────────────────────────
# Results are stored in session_state so they survive every rerun that
# Streamlit triggers (checkbox ticks, expander opens, download-button clicks,
# etc.).  Without this the report — including the Download button — would
# disappear the moment the user interacted with anything after scanning.
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None   # (url, results) tuple or None


# ── Input form ────────────────────────────────────────────────────────────────
url_input = st.text_input(
    label="🌐 Website URL",
    placeholder="https://example.com",
    help="Include the full URL with https:// or http://",
)

consent = st.checkbox(
    "I own this website or have permission to test it.",
    help="You must confirm you are authorised to scan this target.",
)

scan_clicked = st.button("🔍 Scan", type="primary", use_container_width=True)


# ── Scan logic ────────────────────────────────────────────────────────────────
if scan_clicked:
    # Consent gate — must be ticked before any network activity starts
    if not consent:
        st.error(
            "❌ You must confirm that you own this website or have permission "
            "to test it before scanning."
        )
    # Basic validation — make sure the user entered something
    elif not url_input.strip():
        st.warning("⚠️ Please enter a URL before scanning.")
    elif not url_input.startswith(("http://", "https://")):
        st.warning("⚠️ URL must start with http:// or https://")
    else:
        # Safety-limit check — blocks localhost and private/internal IPs
        _safe, _reason = validate_url(url_input)
        if not _safe:
            st.error(_reason)
            st.stop()
        # Live scanning animation — st.status panel with step-by-step updates
        results = []
        try:
            with st.status(f"Scanning **{url_input}**…", expanded=True) as status:
                # Step 1 — HTTPS check
                step1 = st.empty()
                step1.write("⏳ Checking HTTPS...")
                results.append(check_https(url_input))
                time.sleep(0.3)
                step1.write("✅ Checking HTTPS")

                # Step 2 — HTTP → HTTPS redirect
                step2 = st.empty()
                step2.write("⏳ Testing HTTP to HTTPS redirect...")
                results.append(check_redirect_to_https(url_input))
                time.sleep(0.3)
                step2.write("✅ Testing HTTP to HTTPS redirect")

                # Step 3 — Security headers
                step3 = st.empty()
                step3.write("⏳ Analyzing security headers...")
                results.extend(check_security_headers(url_input))
                time.sleep(0.3)
                step3.write("✅ Analyzing security headers")

                # Step 4 — Cookies
                step4 = st.empty()
                step4.write("⏳ Inspecting cookies...")
                results.extend(check_cookies(url_input))
                time.sleep(0.3)
                step4.write("✅ Inspecting cookies")

                # Step 5 — Server info
                step5 = st.empty()
                step5.write("⏳ Checking server information...")
                results.append(check_server_info(url_input))
                time.sleep(0.3)
                step5.write("✅ Checking server information")

                # Step 6 — SSL certificate
                step6 = st.empty()
                step6.write("⏳ Verifying SSL certificate...")
                results.append(check_ssl_certificate(url_input))
                time.sleep(0.3)
                step6.write("✅ Verifying SSL certificate")

                status.update(label="Scan complete — building report", state="complete")
        except Exception as exc:
            # Catch unexpected errors so the app never crashes on screen
            st.error(f"❌ An unexpected error occurred: {exc}")
            results = []

        # Persist results so reruns (expander clicks, download click, etc.)
        # can still render the full report including the Download button.
        if results:
            st.session_state.scan_results = (url_input, results)


# ── Report rendering ──────────────────────────────────────────────────────────
# Rendered on every rerun as long as session_state holds results, so the
# Download button (and everything else) stays visible after any interaction.
if st.session_state.scan_results:
    saved_url, saved_results = st.session_state.scan_results
    render_report(saved_url, saved_results)
