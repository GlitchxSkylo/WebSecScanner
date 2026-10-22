# scanner/report.py
#
# This module turns a list of check results (produced by checks.py) into a
# nicely formatted Streamlit display.  All Streamlit rendering lives here so
# that app.py stays clean and checks.py stays free of UI concerns.

import datetime
import math

import streamlit as st


def _security_score(results: list[dict]) -> tuple[int, str, str, str, int, int, int]:
    """Compute a 0-100 security score from result statuses.

    Scoring:
        pass  → full point  (1.0)
        warn  → half point  (0.5)
        fail  → zero points (0.0)

    Returns:
        (score, grade_label, grade_color, verdict, n_pass, n_warn, n_fail)
    """
    total = len(results)
    if total == 0:
        return 0, "N/A", "gray", "No checks ran.", 0, 0, 0

    n_pass = sum(1 for r in results if r.get("status") == "pass")
    n_warn = sum(1 for r in results if r.get("status") == "warn")
    n_fail = sum(1 for r in results if r.get("status") == "fail")

    raw   = n_pass * 1.0 + n_warn * 0.5        # max possible = total * 1.0
    score = round(raw / total * 100)

    if score >= 80:
        grade_label = "A"
        grade_color = "#16a34a"   # green
        verdict     = "Good security posture 🎉"
    elif score >= 50:
        grade_label = "B"
        grade_color = "#d97706"   # amber
        verdict     = "Some issues found — review the details below."
    else:
        grade_label = "C"
        grade_color = "#dc2626"   # red
        verdict     = "Multiple issues found — this site needs attention."

    return score, grade_label, grade_color, verdict, n_pass, n_warn, n_fail


def _build_report_text(url: str, results: list[dict]) -> str:
    """Produce a plain-text version of the scan report for download.

    Args:
        url:     The URL that was scanned.
        results: A list of result dicts from checks.py.

    Returns:
        A multi-line string suitable for saving as a .txt file.
    """
    score, grade_label, _, verdict, n_pass, n_warn, n_fail = _security_score(results)
    total = len(results)
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "=" * 60,
        "  WebSecScanner — Security Report",
        "=" * 60,
        f"URL       : {url}",
        f"Scanned   : {timestamp}",
        f"Score     : {score}/100  (Grade {grade_label})",
        f"Verdict   : {verdict}",
        f"Checks    : {total} total  |  {n_pass} passed  |  {n_warn} warnings  |  {n_fail} failed",
        "=" * 60,
        "",
    ]

    icon_map = {"pass": "[PASS]", "warn": "[WARN]", "fail": "[FAIL]"}
    for result in results:
        status = result.get("status", "pass" if result["passed"] else "fail")
        icon = icon_map.get(status, "[?]")
        lines.append(f"{icon}  {result['name']}")
        lines.append(f"       {result['detail']}")
        lines.append("")

    lines += [
        "-" * 60,
        "Disclaimer: This tool performs lightweight, surface-level",
        "checks only. It is not a substitute for a full professional",
        "security audit.",
        "-" * 60,
    ]

    return "\n".join(lines)


# Plain-English explanations for every check name that can fail or warn.
# Keys are substrings of result["name"] so they match dynamically-named
# results (e.g. "Cookie: session_id", "Header: X-Frame-Options").
_PLAIN_EXPLANATIONS: list[tuple[str, str, str]] = [
    # (name_substring, plain_language_risk, what_to_do)
    (
        "HTTPS in use",
        "The site runs over plain HTTP, so any data sent (passwords, form "
        "inputs) can be read by anyone on the same network.",
        "Get an SSL/TLS certificate (free options: Let's Encrypt) and "
        "configure your web server to serve traffic over HTTPS.",
    ),
    (
        "HTTP → HTTPS redirect",
        "Visitors who type the plain HTTP address never get automatically "
        "switched to the secure HTTPS version.",
        "Add a server redirect rule that sends all HTTP traffic to HTTPS.",
    ),
    (
        "Header: Strict-Transport-Security",
        "Browsers are not told to always use HTTPS, so they might fall back "
        "to HTTP in some situations.",
        "Add the Strict-Transport-Security (HSTS) response header to your "
        "web server configuration.",
    ),
    (
        "Header: X-Frame-Options",
        "The page can be embedded inside another website's iframe, which "
        "enables 'clickjacking' — tricking users into clicking hidden buttons.",
        "Add the X-Frame-Options: DENY (or SAMEORIGIN) header.",
    ),
    (
        "Header: X-Content-Type-Options",
        "Browsers may try to guess the file type of downloads, which can "
        "lead to unexpected script execution.",
        "Add the X-Content-Type-Options: nosniff header.",
    ),
    (
        "Header: Content-Security-Policy",
        "There are no rules restricting which scripts or resources can load, "
        "making cross-site scripting (XSS) attacks easier.",
        "Define a Content-Security-Policy header that whitelists only the "
        "sources your site needs.",
    ),
    (
        "Header: Referrer-Policy",
        "The full URL of every page a user visits on your site may be sent "
        "to third-party services.",
        "Add a Referrer-Policy header (e.g. strict-origin-when-cross-origin).",
    ),
    (
        "Header: Permissions-Policy",
        "Browser features such as the camera or microphone are not explicitly "
        "restricted, so any injected script could request them.",
        "Add a Permissions-Policy header listing only the features your site "
        "actually uses.",
    ),
    (
        "Cookie:",
        "A cookie is missing security flags, meaning it could be stolen via "
        "an insecure connection or read by malicious JavaScript.",
        "Set the Secure and HttpOnly flags on all cookies, especially session "
        "cookies.",
    ),
    (
        "Server info disclosure",
        "The server reveals its software name and version, giving attackers "
        "a shortcut to look up known vulnerabilities.",
        "Configure your web server to hide or genericise the Server and "
        "X-Powered-By headers.",
    ),
    (
        "SSL certificate validity",
        "The site's SSL/TLS certificate is missing, expired, or expiring very "
        "soon. Browsers will show a security warning to visitors, and encrypted "
        "connections may not be trustworthy.",
        "Renew or install a valid SSL/TLS certificate. Free certificates are "
        "available from Let's Encrypt and most hosting providers.",
    ),
]


def _match_explanation(name: str) -> tuple[str, str] | None:
    """Return (risk, fix) for the first pattern that matches *name*, or None."""
    for substring, risk, fix in _PLAIN_EXPLANATIONS:
        if substring.lower() in name.lower():
            return risk, fix
    return None


def _render_beginner_summary(results: list[dict]) -> None:
    """Render a plain-language summary section below the score banner.

    Groups failing and warning checks by priority (fails first, then warns),
    shows a one-sentence risk explanation for each, and tells the user what
    to fix first.
    """
    fails = [r for r in results if r.get("status") == "fail"]
    warns = [r for r in results if r.get("status") == "warn"]

    # Nothing bad found — show a positive note and return
    if not fails and not warns:
        st.success(
            "🎉 No issues found! Your site passed all checks. "
            "Keep your software up to date to stay secure."
        )
        return

    st.markdown("### 🧭 Beginner-Friendly Summary")
    st.markdown(
        "Here's what the scan found, explained in plain language. "
        "Issues marked **❌ Fix first** have the biggest impact on security."
    )

    # Build a de-duplicated list of (priority, label, risk, fix) items.
    # Cookie checks often fire multiple times (one per cookie); we collapse
    # them into a single entry so the summary stays readable.
    seen_keys: set[str] = set()
    items: list[tuple[int, str, str, str]] = []

    for result in fails + warns:
        expl = _match_explanation(result["name"])
        if expl is None:
            continue

        risk, fix = expl
        # Use the explanation key as the de-dup key (e.g. "Cookie:" covers all cookies)
        dedup_key = next(
            (sub for sub, *_ in _PLAIN_EXPLANATIONS if sub.lower() in result["name"].lower()),
            result["name"],
        )
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        priority = 0 if result.get("status") == "fail" else 1
        label    = result["name"] if not result["name"].startswith("Cookie:") else "Cookie security flags"
        items.append((priority, label, risk, fix))

    if not items:
        return

    # Separate fix-first (fails) from secondary (warns)
    fix_first   = [(lbl, risk, fix) for pri, lbl, risk, fix in items if pri == 0]
    fix_after   = [(lbl, risk, fix) for pri, lbl, risk, fix in items if pri == 1]

    if fix_first:
        st.markdown("#### ❌ Fix these first")
        for lbl, risk, fix in fix_first:
            with st.expander(f"**{lbl}**"):
                st.markdown(f"**What's the risk?** {risk}")
                st.markdown(f"**How to fix it:** {fix}")

    if fix_after:
        st.markdown("#### ⚠️ Also worth fixing")
        for lbl, risk, fix in fix_after:
            with st.expander(f"**{lbl}**"):
                st.markdown(f"**What's the risk?** {risk}")
                st.markdown(f"**How to fix it:** {fix}")

    st.markdown("---")


def _gauge_banner_html(
    score: int,
    grade_label: str,
    grade_color: str,
    verdict: str,
) -> str:
    """Return a complete, self-contained HTML snippet for the gauge banner.

    Delivered via ``components.html()`` so the SVG is never stripped by
    Streamlit's markdown sanitiser.  No nested f-strings are used — all SVG
    coordinates and attributes are built with plain string concatenation so
    Python never misinterprets SVG curly-braces.

    Args:
        score:       Integer 0–100.
        grade_label: Grade letter ('A', 'B', or 'C').
        grade_color: Hex colour string matching the grade.
        verdict:     One-line verdict string.

    Returns:
        A full HTML document string.
    """
    cx, cy, r = 80, 80, 60
    stroke_w  = 14
    start_deg = 135.0
    sweep_deg = 270.0

    def polar(deg: float) -> tuple[float, float]:
        rad = math.radians(deg)
        return cx + r * math.cos(rad), cy + r * math.sin(rad)

    # Track arc — fixed 270 ° ring (subtract tiny epsilon so large-arc-flag = 1)
    tx0, ty0           = polar(start_deg)
    track_ex, track_ey = polar(start_deg + sweep_deg - 0.001)

    # Score arc
    fill_angle         = sweep_deg * (score / 100)
    fx0, fy0           = polar(start_deg)
    fill_ex, fill_ey   = polar(start_deg + fill_angle)
    large_arc          = "1" if fill_angle > 180 else "0"
    circle_r           = str(r + stroke_w // 2 + 2)

    # ── SVG built with string concatenation (no nested f-strings) ────────────
    svg_parts = [
        '<svg width="160" height="160" viewBox="0 0 160 160"',
        ' xmlns="http://www.w3.org/2000/svg"',
        ' style="display:block;flex-shrink:0;">',
        '<defs>',
        '<filter id="gg" x="-40%" y="-40%" width="180%" height="180%">',
        '<feGaussianBlur stdDeviation="4" result="blur"/>',
        '<feMerge>',
        '<feMergeNode in="blur"/>',
        '<feMergeNode in="SourceGraphic"/>',
        '</feMerge>',
        '</filter>',
        '</defs>',
        # dark background disc
        '<circle cx="' + str(cx) + '" cy="' + str(cy) + '" r="' + circle_r + '"'
        ' fill="#0d1210" stroke="#1e2a1e" stroke-width="1"/>',
        # track (full 270°)
        '<path d="M ' + f'{tx0:.3f}' + ' ' + f'{ty0:.3f}'
        + ' A ' + str(r) + ' ' + str(r) + ' 0 1 1 '
        + f'{track_ex:.3f}' + ' ' + f'{track_ey:.3f} "'
        + ' fill="none" stroke="#1e2e1e" stroke-width="' + str(stroke_w) + '"'
        + ' stroke-linecap="round"/>',
    ]

    # score arc (only when score > 0)
    if score > 0:
        svg_parts.append(
            '<path d="M ' + f'{fx0:.3f}' + ' ' + f'{fy0:.3f}'
            + ' A ' + str(r) + ' ' + str(r) + ' 0 ' + large_arc + ' 1 '
            + f'{fill_ex:.3f}' + ' ' + f'{fill_ey:.3f} "'
            + ' fill="none" stroke="' + grade_color + '" stroke-width="' + str(stroke_w) + '"'
            + ' stroke-linecap="round" filter="url(#gg)"/>'
        )

    # grade letter
    svg_parts.append(
        '<text x="' + str(cx) + '" y="' + str(cy - 8) + '"'
        ' text-anchor="middle" dominant-baseline="middle"'
        ' font-family="\'Courier New\',Courier,monospace"'
        ' font-size="28" font-weight="800"'
        ' fill="' + grade_color + '">'
        + grade_label +
        '</text>'
    )
    # score/100 label
    svg_parts.append(
        '<text x="' + str(cx) + '" y="' + str(cy + 18) + '"'
        ' text-anchor="middle" dominant-baseline="middle"'
        ' font-family="\'Courier New\',Courier,monospace"'
        ' font-size="12" font-weight="600" fill="#7aba78">'
        + str(score) + '/100'
        '</text>'
    )
    svg_parts.append('</svg>')
    svg = "".join(svg_parts)

    # ── Wrapper HTML ──────────────────────────────────────────────────────────
    border_col = grade_color + "55"
    bg_col     = grade_color + "14"
    html = (
        '<!DOCTYPE html>'
        '<html><head>'
        '<meta charset="utf-8">'
        '<style>'
        # transparent background so the iframe blends into Streamlit's dark surface
        'html,body{'
        'margin:0;padding:0;'
        'background:transparent;'
        'height:100%;'
        'overflow:hidden;'
        '}'
        # vertically center the banner inside the full iframe height
        'body{'
        'display:flex;align-items:center;justify-content:center;'
        'padding:4px 0;'
        'box-sizing:border-box;'
        '}'
        '.banner{'
        'width:100%;'
        'background:' + bg_col + ';'
        'border:2px solid ' + border_col + ';'
        'border-radius:14px;'
        'padding:20px 24px;'
        'display:flex;align-items:center;gap:28px;'
        'font-family:\'Courier New\',Courier,monospace;'
        'box-sizing:border-box;'
        '}'
        '.label{font-size:11px;color:#7aba78;letter-spacing:0.1em;'
        'text-transform:uppercase;margin-bottom:6px;}'
        '.verdict{font-size:18px;font-weight:700;color:#e2e8f0;margin-bottom:6px;}'
        '.hint{font-size:12px;color:#556b55;}'
        '</style>'
        '</head><body>'
        '<div class="banner">'
        + svg +
        '<div style="flex:1;">'
        '<div class="label">Security Score</div>'
        '<div class="verdict">' + verdict + '</div>'
        '<div class="hint">'
        'Pass&nbsp;=&nbsp;full&nbsp;point&nbsp;&middot;&nbsp;'
        'Warning&nbsp;=&nbsp;&frac12;&nbsp;point&nbsp;&middot;&nbsp;'
        'Fail&nbsp;=&nbsp;no&nbsp;points'
        '</div>'
        '</div>'
        '</div>'
        '</body></html>'
    )
    return html


def render_report(url: str, results: list[dict]) -> None:
    """Render the full security report inside the Streamlit app.

    Args:
        url:     The URL that was scanned.
        results: A list of result dicts, each with 'name', 'passed',
                 'status' (pass/warn/fail), and 'detail'.
    """
    score, grade_label, grade_color, verdict, n_pass, n_warn, n_fail = _security_score(results)
    total = len(results)

    # ── Summary header ────────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader(f"📋 Scan Results for `{url}`")

    # ── Circular gauge banner ─────────────────────────────────────────────────
    # Rendered via st.iframe so the SVG is never stripped by Streamlit's
    # markdown sanitiser.  Height is set just tall enough to show the banner
    # without a scroll bar inside the iframe.
    banner_html = _gauge_banner_html(score, grade_label, grade_color, verdict)
    st.iframe(banner_html, height=200)

    # ── Progress bar (visual at-a-glance indicator) ───────────────────────────
    st.progress(score / 100)

    # ── Quick stats ───────────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total checks", total)
    col2.metric("✅ Passed",    n_pass)
    col3.metric("⚠️ Warnings",  n_warn)
    col4.metric("❌ Failed",    n_fail)

    st.markdown("---")

    # ── Beginner-friendly summary ─────────────────────────────────────────────
    _render_beginner_summary(results)

    # ── Individual results ────────────────────────────────────────────────────
    st.subheader("🔍 Check Details")

    # Palette for each status level
    _STATUS_STYLE = {
        "pass": {
            "border": "#16a34a",
            "bg":     "#16a34a0f",
            "badge_bg":   "#16a34a",
            "badge_text": "#0a0e0f",
            "label":      "PASS",
        },
        "warn": {
            "border": "#d97706",
            "bg":     "#d977060f",
            "badge_bg":   "#d97706",
            "badge_text": "#0a0e0f",
            "label":      "WARNING",
        },
        "fail": {
            "border": "#dc2626",
            "bg":     "#dc26260f",
            "badge_bg":   "#dc2626",
            "badge_text": "#ffffff",
            "label":      "FAIL",
        },
    }

    for result in results:
        status = result.get("status", "pass" if result["passed"] else "fail")
        sty    = _STATUS_STYLE.get(status, _STATUS_STYLE["pass"])

        # Escape any double-quotes in the detail text before embedding in HTML
        detail_html = str(result["detail"]).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        st.markdown(
            f"""
            <div style="
                border-left: 4px solid {sty['border']};
                background: {sty['bg']};
                border-radius: 0 8px 8px 0;
                padding: 12px 16px;
                margin-bottom: 8px;
                font-family: 'Courier New', Courier, monospace;
            ">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">
                    <span style="
                        background:{sty['badge_bg']};
                        color:{sty['badge_text']};
                        font-size:10px;
                        font-weight:800;
                        letter-spacing:0.08em;
                        padding:2px 7px;
                        border-radius:3px;
                        text-transform:uppercase;
                        flex-shrink:0;
                    ">{sty['label']}</span>
                    <span style="font-size:14px;font-weight:600;color:#e2e8f0;">
                        {result['name']}
                    </span>
                </div>
                <div style="font-size:13px;color:#9ab89a;padding-left:2px;">
                    {detail_html}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Download report ───────────────────────────────────────────────────────
    st.markdown("---")
    report_text = _build_report_text(url, results)
    st.download_button(
        label="⬇️ Download report",
        data=report_text,
        file_name="websecscanner_report.txt",
        mime="text/plain",
        use_container_width=True,
    )

    # ── Disclaimer ────────────────────────────────────────────────────────────
    st.markdown("---")
    st.caption(
        "⚠️ **Disclaimer:** This tool performs lightweight, surface-level checks only. "
        "It is not a substitute for a full professional security audit."
    )
