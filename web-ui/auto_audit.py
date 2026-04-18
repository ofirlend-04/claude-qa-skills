#!/usr/bin/env python3
"""
Web UI auto-audit.

Usage:
    python auto_audit.py https://mysite.com
    python auto_audit.py ./my-project/

Produces report.md in the current directory with P0/P1/P2 findings.

Deps: requests, beautifulsoup4
    pip install requests beautifulsoup4
"""

from __future__ import annotations

import os
import re
import sys
import json
import html
from pathlib import Path
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field, asdict
from typing import Iterable

try:
    import requests
except ImportError:
    print("ERROR: pip install requests beautifulsoup4", file=sys.stderr)
    sys.exit(2)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: pip install beautifulsoup4", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str            # "P0" | "P1" | "P2"
    rule: str                # e.g. "A1" from SKILL.md
    title: str
    location: str            # "file:line" or URL
    detail: str = ""
    fix: str = ""


@dataclass
class Report:
    target: str
    mode: str                # "url" | "folder"
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]


# ---------------------------------------------------------------------------
# Shared regex helpers
# ---------------------------------------------------------------------------

HEBREW_RE = re.compile(r"[\u0590-\u05FF]")
SECRET_RES: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI key",         re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("Stripe live key",    re.compile(r"pk_live_[A-Za-z0-9]{20,}")),
    ("Stripe secret key",  re.compile(r"sk_live_[A-Za-z0-9]{20,}")),
    ("Google API key",     re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("AWS access key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Slack bot token",    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("GitHub PAT",         re.compile(r"ghp_[A-Za-z0-9]{30,}")),
    ("RevenueCat app key", re.compile(r"\bapp[cl]_[A-Za-z0-9]{20,}")),
]

SOURCE_EXTS = {".html", ".htm", ".tsx", ".jsx", ".ts", ".js", ".vue", ".svelte", ".css", ".scss", ".sass"}
SKIP_DIRS   = {"node_modules", ".next", ".nuxt", "dist", "build", ".git", ".turbo", "coverage", ".vercel", ".svelte-kit"}


def iter_source_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in SOURCE_EXTS:
                yield p


def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


# ─── Inline suppressions: `// qa-ignore: B1,G5` on the line before ──────────
# Line N suppression also applies to N+1, N+2 (JSX often has multi-line opening
# tags, so the rule may fire 1-2 lines below the comment).
INLINE_SUPPRESS_RE = re.compile(r"(?:#|//)\s*qa-ignore\s*:\s*([A-Z0-9,\s]+)")


def build_line_suppressions(text: str) -> dict[int, set[str]]:
    """Map 1-based line number → set of rule IDs suppressed on that line."""
    sup: dict[int, set[str]] = {}
    for i, line in enumerate(text.split("\n"), start=1):
        m = INLINE_SUPPRESS_RE.search(line)
        if not m:
            continue
        rules = {r.strip() for r in m.group(1).split(",") if r.strip()}
        sup.setdefault(i, set()).update(rules)
        # JSX: a qa-ignore comment can precede the opening tag by 1-2 lines
        sup.setdefault(i + 1, set()).update(rules)
        sup.setdefault(i + 2, set()).update(rules)
    return sup


def is_suppressed(rule: str, line: int, sup: dict[int, set[str]]) -> bool:
    s = sup.get(line)
    if not s:
        return False
    return rule in s or "ALL" in s


# ---------------------------------------------------------------------------
# Folder mode — static source scan
# ---------------------------------------------------------------------------

def scan_folder(root: Path, report: Report) -> None:
    files = list(iter_source_files(root))
    if not files:
        report.add(Finding("P2", "meta", "No HTML/JSX/TSX/CSS files found", str(root),
                           detail="Folder scan found nothing to audit."))
        return

    for f in files:
        text = read_text(f)
        if not text:
            continue
        loc = rel(root, f)
        is_style = f.suffix.lower() in {".css", ".scss", ".sass"}
        is_markup = f.suffix.lower() in {".html", ".htm", ".tsx", ".jsx", ".vue", ".svelte"}
        is_script = f.suffix.lower() in {".ts", ".js"} or is_markup

        # Track how many findings exist before this file — anything added
        # by the scans below is "this file's" findings and is eligible for
        # line-level qa-ignore suppression.
        pre_count = len(report.findings)
        sup = build_line_suppressions(text)

        if is_markup:
            scan_markup_source(text, loc, report)
        if is_style:
            scan_stylesheet(text, loc, report)
        if is_script:
            scan_secrets(text, loc, report)
            scan_client_storage(text, loc, report)

        if HEBREW_RE.search(text) and is_markup:
            scan_rtl_specifics(text, loc, report)

        # Apply inline qa-ignore suppressions to findings from this file only.
        if sup:
            filtered: list[Finding] = []
            for existing in report.findings[:pre_count]:
                filtered.append(existing)
            for finding in report.findings[pre_count:]:
                line_match = re.search(r":(\d+)$", finding.location)
                if line_match:
                    fline = int(line_match.group(1))
                    if is_suppressed(finding.rule, fline, sup):
                        continue  # drop
                filtered.append(finding)
            report.findings = filtered

    # HTML file level checks (full parse)
    for f in files:
        if f.suffix.lower() not in {".html", ".htm"}:
            continue
        soup = BeautifulSoup(read_text(f), "html.parser")
        scan_html_document(soup, rel(root, f), report)


def scan_markup_source(text: str, loc: str, report: Report) -> None:
    # A1 — <img without alt
    for m in re.finditer(r"<img\b[^>]*>", text, flags=re.IGNORECASE):
        tag = m.group(0)
        if not re.search(r"\balt\s*=", tag, flags=re.IGNORECASE):
            report.add(Finding(
                "P0", "A1", "Image missing alt attribute",
                f"{loc}:{line_of(text, m.start())}",
                detail=tag[:120],
                fix='Add alt="..." (informative) or alt="" aria-hidden="true" (decorative).'))
        if not re.search(r"\bwidth\s*=", tag, flags=re.IGNORECASE) or \
           not re.search(r"\bheight\s*=", tag, flags=re.IGNORECASE):
            report.add(Finding(
                "P1", "D2", "Image without explicit width/height (CLS)",
                f"{loc}:{line_of(text, m.start())}",
                detail=tag[:120],
                fix="Add width and height attributes matching the intrinsic image ratio."))
        if not re.search(r"\bloading\s*=", tag, flags=re.IGNORECASE):
            report.add(Finding(
                "P1", "D1", "Image not lazy-loaded",
                f"{loc}:{line_of(text, m.start())}",
                detail=tag[:120],
                fix='Add loading="lazy" decoding="async" (or loading="eager" fetchpriority="high" for first-fold).'))

    # A3 — icon-only <button> without aria-label
    for m in re.finditer(r"<button\b(?P<attrs>[^>]*)>(?P<body>.*?)</button>",
                         text, flags=re.IGNORECASE | re.DOTALL):
        attrs = m.group("attrs")
        body = m.group("body")
        body_text = re.sub(r"<[^>]+>", "", body).strip()
        has_aria = re.search(r"\baria-label\s*=", attrs, flags=re.IGNORECASE)
        has_title = re.search(r"\btitle\s*=", attrs, flags=re.IGNORECASE)
        if not body_text and not has_aria and not has_title:
            report.add(Finding(
                "P0", "A3", "Icon button without aria-label",
                f"{loc}:{line_of(text, m.start())}",
                detail=m.group(0)[:120],
                fix='Add aria-label="..." describing the action.'))

    # G5 — onClick on <div>/<span> in JSX without role + tabindex
    for m in re.finditer(r"<(div|span)\b[^>]*\bonClick\s*=", text):
        tag_slice = text[m.start():m.start() + 240]
        if "role=" not in tag_slice.lower() or "tabIndex" not in tag_slice:
            report.add(Finding(
                "P0", "G5", "onClick on non-interactive element",
                f"{loc}:{line_of(text, m.start())}",
                detail=tag_slice.split(">")[0][:120] + ">",
                fix='Prefer <button>. If not possible, add role="button", tabIndex={0}, and onKeyDown for Space/Enter.'))

    # A6 — positive tabindex
    for m in re.finditer(r"tabindex\s*=\s*['\"]?([1-9][0-9]*)", text, flags=re.IGNORECASE):
        report.add(Finding(
            "P1", "A6", "Positive tabindex breaks natural tab order",
            f"{loc}:{line_of(text, m.start())}",
            detail=m.group(0),
            fix="Use tabindex='0' to include in order, or tabindex='-1' to remove. Never positive."))

    # D7 — <script src=> without async/defer/module
    for m in re.finditer(r"<script\b[^>]*\bsrc\s*=[^>]*>", text, flags=re.IGNORECASE):
        tag = m.group(0)
        if not re.search(r"\b(async|defer)\b", tag, flags=re.IGNORECASE) and \
           not re.search(r'type\s*=\s*["\']module', tag, flags=re.IGNORECASE):
            report.add(Finding(
                "P1", "D7", "Render-blocking <script> without async/defer",
                f"{loc}:{line_of(text, m.start())}",
                detail=tag[:120],
                fix="Add defer (preserves order) or async (independent)."))

    # G4 — empty <a> / <button>
    for m in re.finditer(r"<(a|button)\b(?P<attrs>[^>]*)>\s*</\1>", text, flags=re.IGNORECASE):
        attrs = m.group("attrs")
        if not re.search(r"\baria-label\s*=", attrs, flags=re.IGNORECASE):
            report.add(Finding(
                "P0", "G4", "Empty focusable element",
                f"{loc}:{line_of(text, m.start())}",
                detail=m.group(0)[:120],
                fix="Provide visible text or aria-label."))

    # B4 — text-align:left/right
    for m in re.finditer(r"text-align\s*:\s*(left|right)\b", text, flags=re.IGNORECASE):
        report.add(Finding(
            "P1", "B4", "Physical text-align (left/right) instead of logical (start/end)",
            f"{loc}:{line_of(text, m.start())}",
            detail=m.group(0),
            fix="Use text-align: start (or end) so RTL locales render correctly."))

    # E7 + E8 checked at document level for HTML files (see scan_html_document)


def scan_stylesheet(text: str, loc: str, report: Report) -> None:
    # B2 — physical margin/padding
    for m in re.finditer(
        r"\b(margin-left|margin-right|padding-left|padding-right)\s*:\s*[^;{}]+",
        text, flags=re.IGNORECASE):
        report.add(Finding(
            "P1", "B2", "Physical margin/padding instead of logical",
            f"{loc}:{line_of(text, m.start())}",
            detail=m.group(0)[:120],
            fix="Use margin-inline-start / margin-inline-end etc. for RTL-safe layout."))

    # C2 — fixed large widths
    for m in re.finditer(r"\bwidth\s*:\s*(\d{3,})\s*px\b", text, flags=re.IGNORECASE):
        px = int(m.group(1))
        if px >= 400:
            report.add(Finding(
                "P1", "C2", f"Fixed width {px}px (not responsive)",
                f"{loc}:{line_of(text, m.start())}",
                detail=m.group(0),
                fix=f"Use max-width: {px}px; width: 100%;"))

    # C3 — small font on inputs
    for rule in re.finditer(
        r"(?:input|textarea|select)\b[^{}]*\{[^{}]*\bfont-size\s*:\s*(\d+)\s*px[^{}]*\}",
        text, flags=re.IGNORECASE):
        size = int(rule.group(1))
        if size < 16:
            report.add(Finding(
                "P1", "C3", f"Input font-size {size}px triggers iOS zoom-in",
                f"{loc}:{line_of(text, rule.start())}",
                detail=rule.group(0)[:120],
                fix="Use font-size: 16px or larger on form inputs."))

    # D3 — @font-face without font-display
    for m in re.finditer(r"@font-face\s*\{[^}]*\}", text, flags=re.IGNORECASE | re.DOTALL):
        if "font-display" not in m.group(0).lower():
            report.add(Finding(
                "P1", "D3", "@font-face without font-display",
                f"{loc}:{line_of(text, m.start())}",
                detail=m.group(0)[:120],
                fix="Add font-display: swap; inside the @font-face block."))

    # B8 — font stack missing Hebrew-capable fallback (heuristic)
    for m in re.finditer(r"font-family\s*:\s*([^;]+);", text, flags=re.IGNORECASE):
        stack = m.group(1).lower()
        has_hebrew_font = any(name in stack for name in (
            "heebo", "rubik", "assistant", "arial hebrew", "frank ruhl",
            "secular one", "system-ui", "sans-serif", "serif"))
        if not has_hebrew_font:
            report.add(Finding(
                "P2", "B8", "font-family stack has no Hebrew-capable fallback",
                f"{loc}:{line_of(text, m.start())}",
                detail=m.group(0)[:120],
                fix="Append a Hebrew-capable fallback: 'Heebo', 'Assistant', system-ui, sans-serif."))


def scan_secrets(text: str, loc: str, report: Report) -> None:
    # Skip obvious server-only files: .env, api routes, server actions
    if any(seg in loc.lower() for seg in ("/api/", "\\api\\", "server.", ".server.", "/.env")):
        return
    for label, pat in SECRET_RES:
        for m in pat.finditer(text):
            report.add(Finding(
                "P0", "F2", f"{label} appears in client-bundled source",
                f"{loc}:{line_of(text, m.start())}",
                detail=m.group(0)[:40] + "…",
                fix="Move to server-side env var. Never prefix a secret with NEXT_PUBLIC_."))


def scan_client_storage(text: str, loc: str, report: Report) -> None:
    for m in re.finditer(r"localStorage\.setItem\(\s*['\"]([^'\"]+)['\"]", text):
        key = m.group(1).lower()
        if any(tok in key for tok in ("token", "jwt", "auth", "secret", "password", "apikey")):
            report.add(Finding(
                "P1", "F3", f"Sensitive key stored in localStorage: {key}",
                f"{loc}:{line_of(text, m.start())}",
                fix="Move to httpOnly secure cookies. localStorage is XSS-readable."))


def scan_rtl_specifics(text: str, loc: str, report: Report) -> None:
    # B1 — Hebrew content but no dir="rtl" anywhere in the file
    if not re.search(r'\bdir\s*=\s*["\']rtl["\']', text, flags=re.IGNORECASE):
        m = HEBREW_RE.search(text)
        if m:
            report.add(Finding(
                "P0", "B1", 'Hebrew text without dir="rtl"',
                f"{loc}:{line_of(text, m.start())}",
                fix='Add dir="rtl" on <html>, or wrap the Hebrew block in a container with dir="rtl".'))

    # B7 — toLocaleDateString() without he-IL in Hebrew file
    for m in re.finditer(r"toLocaleDateString\(\s*(?:'en[^']*'|\"en[^\"]*\"|)\s*\)", text):
        report.add(Finding(
            "P1", "B7", "Date formatted without he-IL locale in Hebrew file",
            f"{loc}:{line_of(text, m.start())}",
            detail=m.group(0),
            fix="Pass 'he-IL' locale: date.toLocaleDateString('he-IL')."))


def scan_html_document(soup: BeautifulSoup, loc: str, report: Report) -> None:
    html_tag = soup.find("html")
    if html_tag:
        if not html_tag.get("lang"):
            report.add(Finding("P1", "E8", "<html> missing lang", f"{loc}:1",
                               fix='Add lang="en" or lang="he".'))
        lang = (html_tag.get("lang") or "").lower()
        if lang.startswith("he") or lang.startswith("ar"):
            if not (html_tag.get("dir") or "").lower() == "rtl":
                report.add(Finding(
                    "P0", "B1", f'<html lang="{lang}"> without dir="rtl"',
                    f"{loc}:1",
                    fix='Add dir="rtl" to <html>.'))

    if not soup.find("meta", attrs={"name": "viewport"}):
        report.add(Finding("P0", "C1", "Viewport meta missing", f"{loc}:1",
                           fix='Add <meta name="viewport" content="width=device-width, initial-scale=1">.'))

    title = soup.find("title")
    if not title or not (title.string or "").strip():
        report.add(Finding("P1", "E1", "Missing <title>", f"{loc}:1",
                           fix="Add a unique, descriptive <title> ≤ 60 chars."))
    elif len(title.string.strip()) > 60:
        report.add(Finding("P1", "E1", f"<title> longer than 60 chars ({len(title.string.strip())})",
                           f"{loc}:1", fix="Shorten for SERP display."))

    if not soup.find("meta", attrs={"name": "description"}):
        report.add(Finding("P1", "E2", "Missing <meta name=description>",
                           f"{loc}:1", fix="Add a 140–160 char description."))

    for og in ("og:title", "og:description", "og:image"):
        if not soup.find("meta", attrs={"property": og}):
            report.add(Finding("P1", "E3", f"Missing {og}",
                               f"{loc}:1", fix=f'Add <meta property="{og}" content="...">.'))

    h1s = soup.find_all("h1")
    if len(h1s) == 0:
        report.add(Finding("P1", "E7", "No <h1> on page", f"{loc}:1",
                           fix="Add exactly one <h1> describing the page."))
    elif len(h1s) > 1:
        report.add(Finding("P1", "E7", f"{len(h1s)} <h1> elements on page", f"{loc}:1",
                           fix="Keep exactly one <h1>. Use <h2>+ for sections."))

    if not soup.find("link", attrs={"rel": "canonical"}):
        report.add(Finding("P1", "E5", "Missing canonical link", f"{loc}:1",
                           fix='Add <link rel="canonical" href="https://...">.'))

    if not soup.find("link", attrs={"rel": re.compile("icon", re.I)}):
        report.add(Finding("P2", "E4", "Missing favicon", f"{loc}:1",
                           fix='Add <link rel="icon" href="/favicon.ico">.'))

    # A4 — inputs without labels
    for inp in soup.find_all(["input", "textarea", "select"]):
        if inp.get("type") in ("hidden", "submit", "button", "image"):
            continue
        input_id = inp.get("id")
        has_aria = inp.get("aria-label") or inp.get("aria-labelledby")
        has_label = False
        if input_id:
            has_label = bool(soup.find("label", attrs={"for": input_id}))
        if not has_label and not has_aria:
            report.add(Finding("P0", "A4", f"<{inp.name}> without label",
                               f"{loc}:?", detail=str(inp)[:120],
                               fix='Add a <label for="..."> or aria-label="...".'))


# ---------------------------------------------------------------------------
# URL mode — live site checks
# ---------------------------------------------------------------------------

def scan_url(url: str, report: Report) -> None:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    # F5 — HTTPS redirect
    if parsed.scheme == "https":
        try:
            r = requests.get("http://" + parsed.netloc, allow_redirects=False, timeout=8)
            if r.status_code not in (301, 302, 307, 308) or not r.headers.get("location", "").startswith("https"):
                report.add(Finding("P0", "F5", "No HTTP→HTTPS redirect",
                                   f"http://{parsed.netloc}",
                                   fix="Configure 301 redirect to https at CDN or server."))
        except requests.RequestException:
            pass  # host may simply refuse http — that's fine

    try:
        resp = requests.get(url, timeout=15, headers={"Accept-Encoding": "br, gzip, deflate"})
    except requests.RequestException as e:
        report.add(Finding("P0", "meta", f"Could not load {url}: {e}", url))
        return

    # F1 — security headers
    missing = []
    h = {k.lower(): v for k, v in resp.headers.items()}
    if "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security")
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options")
    if "x-frame-options" not in h and "content-security-policy" not in h:
        missing.append("X-Frame-Options or CSP frame-ancestors")
    if "referrer-policy" not in h:
        missing.append("Referrer-Policy")
    for hdr in missing:
        report.add(Finding("P1", "F1", f"Missing security header: {hdr}", url,
                           fix="Set via CDN (Vercel vercel.json / Next.js headers())."))

    # D5 — compression
    enc = h.get("content-encoding", "").lower()
    if enc not in ("br", "gzip", "deflate"):
        report.add(Finding("P1", "D5", "Response not compressed",
                           url, detail=f"Content-Encoding: {enc or '(none)'}",
                           fix="Enable brotli/gzip at CDN or server."))

    # robots / sitemap
    for path, rule in (("/robots.txt", "E6"), ("/sitemap.xml", "E6")):
        try:
            r = requests.head(urljoin(url, path), timeout=6, allow_redirects=True)
            if r.status_code >= 400:
                report.add(Finding("P2", rule, f"{path} returns {r.status_code}",
                                   urljoin(url, path), fix=f"Serve {path}."))
        except requests.RequestException:
            pass

    # Parse page
    soup = BeautifulSoup(resp.text, "html.parser")
    scan_html_document(soup, url, report)

    # Link/image health
    seen: set[str] = set()
    def check(absolute: str, kind: str, rule: str, severity_internal: str):
        if absolute in seen:
            return
        seen.add(absolute)
        try:
            r = requests.head(absolute, timeout=8, allow_redirects=True)
            if r.status_code == 405:  # HEAD not supported
                r = requests.get(absolute, timeout=10, stream=True, allow_redirects=True)
        except requests.RequestException as e:
            report.add(Finding("P1", rule, f"Network error fetching {kind}: {absolute}",
                               url, detail=str(e)))
            return
        if r.status_code >= 400:
            internal = urlparse(absolute).netloc == parsed.netloc
            sev = severity_internal if internal else "P1"
            report.add(Finding(sev, rule, f"{kind} returns {r.status_code}",
                               url, detail=absolute,
                               fix="Update or remove the link/src."))

    base = url
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        check(urljoin(base, href), "link", "G1", "P0")

    for img in soup.find_all("img", src=True):
        check(urljoin(base, img["src"]), "<img>", "G3", "P0")


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def write_report(report: Report, outfile: Path) -> None:
    lines: list[str] = []
    lines.append(f"# Web UI Audit — {report.target}")
    lines.append("")
    counts = {s: len(report.by_severity(s)) for s in ("P0", "P1", "P2")}
    lines.append("## Summary")
    lines.append(f"- {counts['P0']} P0 (blocking)")
    lines.append(f"- {counts['P1']} P1 (should fix)")
    lines.append(f"- {counts['P2']} P2 (polish)")
    lines.append("")
    for sev, label in (("P0", "Blocking"), ("P1", "Should fix"), ("P2", "Polish")):
        items = report.by_severity(sev)
        if not items:
            continue
        lines.append(f"## {sev} — {label}")
        lines.append("")
        for i, f in enumerate(items, 1):
            lines.append(f"### {sev}.{i} [{f.rule}] {f.title}")
            lines.append(f"- **Location:** `{f.location}`")
            if f.detail:
                lines.append(f"- **Detail:** `{f.detail}`")
            if f.fix:
                lines.append(f"- **Fix:** {f.fix}")
            lines.append("")
    outfile.write_text("\n".join(lines), encoding="utf-8")

    # Also write JSON for programmatic use
    jsonfile = outfile.with_suffix(".json")
    jsonfile.write_text(json.dumps({
        "target": report.target,
        "mode": report.mode,
        "findings": [asdict(f) for f in report.findings],
    }, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip())
        return 1

    target = argv[1]
    is_url = bool(re.match(r"^https?://", target))
    report = Report(target=target, mode="url" if is_url else "folder")

    if is_url:
        scan_url(target, report)
    else:
        p = Path(target).expanduser().resolve()
        if not p.exists():
            print(f"Path not found: {p}", file=sys.stderr)
            return 1
        scan_folder(p, report)

    out = Path("report.md").resolve()
    write_report(report, out)
    print(f"Wrote {out}  ({len(report.findings)} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
