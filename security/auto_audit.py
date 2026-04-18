#!/usr/bin/env python3
"""
Security vulnerability scanner.

Usage:
    python3 auto_audit.py /path/to/project
    python3 auto_audit.py /path/to/project --json-out report.json --md-out report.md

Finds:
    A  Secrets in source          (OpenAI / Anthropic / Google / GitHub / Stripe / AWS / JWT / Slack)
    B  Client-side secrets        (NEXT_PUBLIC_* with keys, fetch() to LLM APIs, dangerouslyAllowBrowser)
    C  Missing auth on APIs       (Flask / FastAPI / Express / Cloud Run)
    D  Insecure CORS
    E  SQL injection
    F  Auth tokens in localStorage
    G  LLM vulnerabilities        (prompt injection, MCP no-auth, SSRF via agent, bill-stealing proxy)
    H  Insecure defaults          (debug=True, default creds, verify=False, http:// prod URLs, Math.random)
    I  Missing security headers   (CSP, HSTS, X-Frame-Options)  — web projects only
    J  .env committed / example leaks
    K  Missing rate limiting on sensitive endpoints

Exit codes:
    0  clean
    1  at least one P1 finding
    2  at least one P0 finding        ← use this to gate CI

False-positive control:
    - Put a .qaignore at the project root: one glob per line (skips matching files)
    - Inline suppression: add a comment `# qa-ignore: A1` or `// qa-ignore: B2,C1`
        to suppress the listed rule IDs on that line and the next.
    - The QA-skills repo auto-detects itself (folder name) and runs in doc-example mode
        so that bad examples in patterns/*.md don't flag the scanner.

Deps: stdlib only (optional: requests, not required by auto_audit).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str            # "P0" | "P1" | "P2"
    rule: str                # e.g. "A1"
    title: str
    location: str            # "file:line"
    evidence: str = ""       # redacted snippet
    fix: str = ""


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_sev(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]


# ---------------------------------------------------------------------------
# Skip rules
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", ".turbo", ".svelte-kit",
    "dist", "build", "out", "coverage", ".vercel", ".venv", "venv",
    "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
    "target", "Pods", "DerivedData", ".gradle", ".idea", ".vscode",
}

TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".html", ".htm",
    ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".env", ".json", ".sh", ".bash", ".zsh",
    ".tf", ".hcl",
    ".md", ".txt",
    ".dockerfile",
}
# Files with no extension we still want to scan
ALWAYS_SCAN_NAMES = {
    "Dockerfile", "Makefile", ".env", ".env.local", ".env.production",
    ".env.development", ".env.test", ".env.staging", ".gitignore",
}

MAX_FILE_BYTES = 1_200_000     # skip >1.2 MB files (minified / bundles)
REDACT_AFTER = 8


# ---------------------------------------------------------------------------
# .qaignore + inline suppressions
# ---------------------------------------------------------------------------

def load_qaignore(root: Path) -> list[str]:
    p = root / ".qaignore"
    if not p.exists():
        return []
    patterns: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def path_is_ignored(rel_path: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat):
            return True
        # also match "**/foo" style
        if pat.startswith("**/") and fnmatch.fnmatch(rel_path, pat[3:]):
            return True
    return False


# Inline: `# qa-ignore: A1,B2` or `// qa-ignore: C1`
INLINE_SUPPRESS_RE = re.compile(r"(?:#|//)\s*qa-ignore\s*:\s*([A-Z0-9,\s]+)")


def build_line_suppressions(text: str) -> dict[int, set[str]]:
    """Map line number (1-based) to set of suppressed rule IDs.
    A suppression on line N also applies to line N+1 (next line)."""
    sup: dict[int, set[str]] = {}
    for i, line in enumerate(text.split("\n"), start=1):
        m = INLINE_SUPPRESS_RE.search(line)
        if not m:
            continue
        rules = {r.strip() for r in m.group(1).split(",") if r.strip()}
        sup.setdefault(i, set()).update(rules)
        sup.setdefault(i + 1, set()).update(rules)
    return sup


def is_suppressed(rule: str, line: int, sup: dict[int, set[str]]) -> bool:
    s = sup.get(line)
    if not s:
        return False
    return rule in s or "ALL" in s


# ---------------------------------------------------------------------------
# Doc-mode detection (so the QA-skills repo doesn't flag its own examples)
# ---------------------------------------------------------------------------

def is_doc_example_repo(root: Path) -> bool:
    """Heuristic: are we scanning a repo that documents vulnerabilities as examples?"""
    name = root.name.lower()
    if "qa-skill" in name or "qa_skill" in name:
        return True
    readme = root / "README.md"
    if readme.exists():
        try:
            head = readme.read_text(encoding="utf-8", errors="ignore")[:4000].lower()
            if "claude qa skill" in head or "qa auditor" in head:
                return True
        except OSError:
            pass
    return False


# ---------------------------------------------------------------------------
# Secret patterns (A rules)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    # rule, label, severity, regex
    # Check Anthropic BEFORE generic OpenAI (both start with "sk-")
    ("A2", "Anthropic API key", "P0",
        re.compile(r"sk-ant-[A-Za-z0-9_-]{95,}")),
    ("A1", "OpenAI API key", "P0",
        # Negative look-ahead on "ant-" so we don't double-match Anthropic keys
        re.compile(r"sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("A3", "Google API key (incl. Gemini / Firebase)", "P0",
        re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("A4", "GitHub PAT", "P0",
        re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("A4", "GitHub fine-grained PAT", "P0",
        re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("A5", "Stripe secret (live)", "P0",
        re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    ("A5", "Stripe secret (test)", "P1",
        re.compile(r"sk_test_[A-Za-z0-9]{24,}")),
    ("A5", "Stripe restricted key", "P0",
        re.compile(r"rk_live_[A-Za-z0-9]{24,}")),
    ("A6", "AWS access key", "P0",
        re.compile(r"AKIA[A-Z0-9]{16}")),
    ("A7", "JWT", "P1",
        re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("A8", "Slack token", "P0",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
]

# Anthropic pattern may match OpenAI (sk-...) greedily — tighten ordering
PLACEHOLDER_WORDS = (
    "your_", "your-", "placeholder", "replace_me", "replaceme",
    "changeme", "change-me", "example", "dummy", "fake",
    "xxxxxxxx", "abcdefgh", "0123456789", "sk-xxxxx",
    "lorem", "todo",
)


def looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    return any(p in v for p in PLACEHOLDER_WORDS)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact(secret: str) -> str:
    if len(secret) <= REDACT_AFTER:
        return "***"
    return f"{secret[:REDACT_AFTER]}***"


# ---------------------------------------------------------------------------
# File iteration
# ---------------------------------------------------------------------------

def iter_files(root: Path, ignore_patterns: list[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # prune
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".venv")]
        for name in filenames:
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            if path_is_ignored(rel, ignore_patterns):
                continue
            if name in ALWAYS_SCAN_NAMES or name.startswith(".env"):
                yield p
                continue
            if p.suffix.lower() in TEXT_EXTS:
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                yield p


def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def rel_path(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# A — Secrets
# ---------------------------------------------------------------------------

FIREBASE_CONFIG_CONTEXT_RE = re.compile(
    r"firebaseConfig\s*[:=]\s*\{[^}]*AIza[0-9A-Za-z_-]{35}",
    re.DOTALL,
)


def scan_secrets(text: str, loc: str, report: Report,
                 sup: dict[int, set[str]], is_client_code: bool) -> None:
    # Detect if file is a Firebase config-style block — AIza in that context is
    # typically a public web key scoped by App Check / rules. Still flag P1.
    firebase_safe_ranges: list[tuple[int, int]] = []
    for m in FIREBASE_CONFIG_CONTEXT_RE.finditer(text):
        firebase_safe_ranges.append((m.start(), m.end()))

    def in_firebase_context(i: int) -> bool:
        return any(a <= i <= b for a, b in firebase_safe_ranges)

    for rule, label, sev, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            value = m.group(0)
            if looks_like_placeholder(value):
                continue
            line = line_of(text, m.start())
            if is_suppressed(rule, line, sup):
                continue
            effective_sev = sev
            # Google/Firebase web keys inside a firebaseConfig object — de-escalate
            if rule == "A3" and in_firebase_context(m.start()):
                effective_sev = "P1"
                title = f"{label} in Firebase config (usually public, but confirm App Check is on)"
            else:
                title = f"{label} in source"
            report.add(Finding(
                severity=effective_sev, rule=rule,
                title=title,
                location=f"{loc}:{line}",
                evidence=redact(value),
                fix=("Rotate key immediately. Move to server-side env var. "
                     "Scrub git history if this ever hit a public branch.")))

    # A10 — generic hardcoded secret assignments
    for m in re.finditer(
        r"""(?ix)
        \b(password|passwd|pwd|api[_-]?key|apikey|secret|token|authorization|auth[_-]?key)
        \s*[:=]\s*
        (['"])([^'"]{16,})\2
        """, text):
        value = m.group(3)
        if looks_like_placeholder(value):
            continue
        # skip obvious env-var reads
        if value.startswith(("process.env", "os.environ", "$")):
            continue
        # skip variables holding other variables
        if value.count(" ") > 3:
            continue
        if shannon_entropy(value) < 3.5:
            continue
        line = line_of(text, m.start())
        if is_suppressed("A10", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="A10",
            title=f"Hardcoded {m.group(1)} value (entropy {shannon_entropy(value):.1f})",
            location=f"{loc}:{line}",
            evidence=redact(value),
            fix="Move to an env var or a secret manager. Never hardcode credentials."))


# ---------------------------------------------------------------------------
# B — Client-side secrets
# ---------------------------------------------------------------------------

PUBLIC_PREFIX_RE = re.compile(
    r"""(?ix)
    \b(NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|PUBLIC_[A-Z0-9_]+)
    \s*=\s*
    (['"]?)([^\s'"]+)\2
    """
)

LLM_URL_RE = re.compile(
    r"""(?ix)
    fetch\s*\(\s*[^)]*?['"]
    https?://
    (?:api\.openai\.com
      |api\.anthropic\.com
      |generativelanguage\.googleapis\.com
      |api\.cohere\.ai
      |api\.mistral\.ai
      |api\.groq\.com
      |api\.together\.xyz
      |api\.replicate\.com
    )
    """
)

DANGEROUS_BROWSER_RE = re.compile(r"dangerouslyAllowBrowser\s*:\s*true", re.IGNORECASE)


def is_client_file(loc: str) -> bool:
    low = loc.lower().replace("\\", "/")
    if any(seg in low for seg in ("/api/", "/server/", "/route.ts", "/route.tsx",
                                  "/actions/", ".server.", "middleware.ts")):
        return False
    if any(low.endswith(ext) for ext in (".tsx", ".jsx", ".vue", ".svelte")):
        return True
    if any(low.endswith(ext) for ext in (".ts", ".js", ".mjs", ".cjs")):
        # heuristic: if path is under src/, app/, pages/, components/, lib/ and no server marker
        return any(seg in low for seg in ("/src/", "/app/", "/pages/", "/components/", "/lib/"))
    return False


def scan_client_secrets(text: str, loc: str, report: Report,
                        sup: dict[int, set[str]]) -> None:
    is_env = Path(loc).name.startswith(".env") or Path(loc).name.endswith(".env")

    # B1 — NEXT_PUBLIC_* with a secret-looking value (in env files OR source)
    for m in PUBLIC_PREFIX_RE.finditer(text):
        var_name = m.group(1)
        value = m.group(3)
        if looks_like_placeholder(value):
            continue
        matched_secret = None
        for _rule, label, _sev, pat in SECRET_PATTERNS:
            if pat.search(value):
                matched_secret = label
                break
        if not matched_secret:
            continue
        line = line_of(text, m.start())
        if is_suppressed("B1", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="B1",
            title=f"{var_name} contains {matched_secret} — shipped to client bundle",
            location=f"{loc}:{line}",
            evidence=f"{var_name}={redact(value)}",
            fix=("Rotate key. Remove the public prefix. Move the secret to server-side only "
                 "and proxy the API call through a server route.")))

    # B2 — fetch() to an LLM provider from client code
    if is_client_file(loc):
        for m in LLM_URL_RE.finditer(text):
            line = line_of(text, m.start())
            if is_suppressed("B2", line, sup):
                continue
            report.add(Finding(
                severity="P0", rule="B2",
                title="Client-side fetch() to an LLM provider (API key will leak)",
                location=f"{loc}:{line}",
                evidence=m.group(0)[:120],
                fix="Proxy the call through your own server route and authenticate + rate-limit it."))

        # B3 — dangerouslyAllowBrowser
        for m in DANGEROUS_BROWSER_RE.finditer(text):
            line = line_of(text, m.start())
            if is_suppressed("B3", line, sup):
                continue
            report.add(Finding(
                severity="P0", rule="B3",
                title="dangerouslyAllowBrowser: true — forces SDK to run in browser with key exposed",
                location=f"{loc}:{line}",
                evidence=m.group(0),
                fix="Remove this flag. Move the SDK call to a server route."))


# ---------------------------------------------------------------------------
# C — Missing auth on endpoints
# ---------------------------------------------------------------------------

AUTH_MARKERS = (
    "require_auth", "login_required", "requires_auth", "verify_token",
    "verify_jwt", "check_api_key", "authenticate(", "get_current_user",
    "get_current_active_user", "auth_required", "@jwt_required",
    "requireAuth", "authMiddleware", "ensureAuth", "withAuth",
    "verifyToken", "checkAuth", "isAuthenticated",
)

# Actual calls / SDK usage — not mere string references (which would false-positive
# on health-check endpoints that list API names, or imports at the top of the file).
SENSITIVE_CALL_MARKERS = (
    "openai.", "OpenAI(", "AsyncOpenAI(",
    "anthropic.", "Anthropic(", "AsyncAnthropic(",
    "genai.", "GenerativeModel(",
    "cohere.", "CohereClient(",
    "mistral.", "MistralClient(",
    "groq.", "Groq(",
    "replicate.run", "together.",
    "stripe.Charge", "stripe.PaymentIntent", "stripe.Subscription", "stripe.Customer",
    "db.query", "session.query", "cursor.execute", "conn.execute",
    "supabase.", "firestore.", "firestore()",
    ".chat.completions.create", ".messages.create", ".generate_content",
)

FLASK_ROUTE_RE = re.compile(
    r"@(?:app|bp|blueprint|[a-z_]+_bp)\.route\s*\(\s*(['\"])(?P<path>[^'\"]+)\1"
    r"(?:[^)]*methods\s*=\s*\[[^\]]*\bPOST\b[^\]]*\])?",
    re.IGNORECASE,
)

FASTAPI_ROUTE_RE = re.compile(
    r"@(?:app|router|[a-z_]+_router)\.(post|put|delete|patch|get)\s*\(\s*(['\"])(?P<path>[^'\"]+)\2",
    re.IGNORECASE,
)

EXPRESS_ROUTE_RE = re.compile(
    r"\b(?:app|router|[a-z_]+Router)\.(?:post|put|delete|patch)\s*\(\s*(['\"`])(?P<path>[^'\"`]+)\1",
)


_NEXT_ROUTE_RE = re.compile(
    r"""(?m)^\s*(@(?:app|bp|router|blueprint|[a-z_]+_bp|[a-z_]+_router)\.(?:route|get|post|put|delete|patch)\b)"""
)


def _function_body_after(text: str, start: int, max_lines: int = 40) -> str:
    """Return text starting at ``start`` bounded by either ``max_lines`` newlines
    or the next route decorator — whichever comes first. This prevents a route
    from 'spilling' into the next handler and inheriting its sensitive calls."""
    # Hard line budget
    end = start
    newlines = 0
    while end < len(text) and newlines < max_lines:
        if text[end] == "\n":
            newlines += 1
        end += 1
    # Also cut at next route decorator
    nxt = _NEXT_ROUTE_RE.search(text, start + 1)
    if nxt and nxt.start() < end:
        end = nxt.start()
    return text[start:end]


def scan_missing_auth_python(text: str, loc: str, report: Report,
                             sup: dict[int, set[str]]) -> None:
    # C1 Flask
    for m in FLASK_ROUTE_RE.finditer(text):
        block = _function_body_after(text, m.end(), 40)
        has_auth = any(marker in block for marker in AUTH_MARKERS)
        touches_sensitive = any(marker in block for marker in SENSITIVE_CALL_MARKERS)
        if not has_auth and touches_sensitive:
            line = line_of(text, m.start())
            if is_suppressed("C1", line, sup):
                continue
            report.add(Finding(
                severity="P0", rule="C1",
                title=f"Flask route {m.group('path')} has no auth and calls sensitive service",
                location=f"{loc}:{line}",
                evidence=m.group(0)[:120],
                fix="Add @require_auth / @login_required + rate-limit. "
                    "If truly public, add API key check + per-IP throttle."))

    # C2 FastAPI
    # Find the end of the handler signature (first `):` or `) ->`). A `Depends(...)`
    # that doesn't resolve to an auth-flavoured function is NOT evidence of auth
    # (it's very often `Depends(get_db)` — a DB session).
    for m in FASTAPI_ROUTE_RE.finditer(text):
        block = _function_body_after(text, m.end(), 40)
        # Extract the signature — from `)` of the decorator to the first `):` of the def
        sig_start = m.end()
        # search for async def / def
        def_m = re.search(r"(async\s+def|def)\s+\w+\s*\(", text[sig_start:sig_start + 400])
        sig = ""
        if def_m:
            sig_abs_start = sig_start + def_m.end()
            # find matching close paren
            depth = 1
            i = sig_abs_start
            while i < len(text) and depth > 0:
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                i += 1
            sig = text[sig_abs_start:i]
        # Count as auth only if Depends target name looks auth-related
        auth_dep_re = re.compile(
            r"(?:Depends|Security)\s*\(\s*([A-Za-z_][A-Za-z_0-9]*)\s*[,)]")
        has_auth_depends = any(
            ("user" in name.lower() or "auth" in name.lower()
             or "token" in name.lower() or "jwt" in name.lower()
             or "api_key" in name.lower() or "apikey" in name.lower())
            for name in auth_dep_re.findall(sig))
        has_auth_import = any(marker in block for marker in AUTH_MARKERS)
        # File-level auth hint — any of:
        #  1. `app = FastAPI(..., dependencies=[Depends(verify_token)])`
        #  2. auth middleware: `add_middleware(...Auth...)` / `APIKeyMiddleware` / etc.
        #  3. a global before-request hook (rare but possible)
        file_wide_auth = bool(re.search(
            r"(?:FastAPI|APIRouter)\s*\([^)]*dependencies\s*=\s*\[[^\]]*Depends\(",
            text)) or bool(re.search(
            r"""(?ix)
                add_middleware\s*\(\s*[A-Za-z_][A-Za-z_0-9]*(?:Auth|Token|ApiKey|APIKey|JWT|Bearer)
              | (?:Auth|Token|ApiKey|APIKey|JWT|Bearer)Middleware
              | @app\.middleware\s*\(\s*['"]http['"]\s*\)
            """,
            text))
        touches_sensitive = any(marker in block for marker in SENSITIVE_CALL_MARKERS)
        if not has_auth_depends and not has_auth_import and not file_wide_auth and touches_sensitive:
            line = line_of(text, m.start())
            if is_suppressed("C2", line, sup):
                continue
            report.add(Finding(
                severity="P0", rule="C2",
                title=f"FastAPI {m.group(1).upper()} {m.group('path')} has no Depends() auth and calls sensitive service",
                location=f"{loc}:{line}",
                evidence=m.group(0)[:120],
                fix="Add `user = Depends(get_current_user)` and an auth scheme."))


def scan_missing_auth_js(text: str, loc: str, report: Report,
                         sup: dict[int, set[str]]) -> None:
    # C3 Express — flag POST/PUT/DELETE routes that hit sensitive APIs
    # and the surrounding file has no auth middleware registration.
    file_uses_auth_middleware = any(
        marker in text for marker in ("requireAuth", "authMiddleware",
                                      "ensureAuth", "withAuth", "passport.authenticate",
                                      "jwtMiddleware", "verifyJWT"))
    for m in EXPRESS_ROUTE_RE.finditer(text):
        block = _function_body_after(text, m.end(), 40)
        touches_sensitive = any(marker in block for marker in SENSITIVE_CALL_MARKERS)
        # also check this specific route has middleware between path and handler
        route_slice = text[m.end(): m.end() + 300]
        route_has_mw = any(marker in route_slice for marker in ("requireAuth",
                                                                "authMiddleware",
                                                                "ensureAuth",
                                                                "verifyJWT"))
        if not file_uses_auth_middleware and not route_has_mw and touches_sensitive:
            line = line_of(text, m.start())
            if is_suppressed("C3", line, sup):
                continue
            report.add(Finding(
                severity="P0", rule="C3",
                title=f"Express route {m.group('path')} has no auth middleware and calls sensitive service",
                location=f"{loc}:{line}",
                evidence=m.group(0)[:120],
                fix="Add requireAuth middleware: app.post('/x', requireAuth, handler) "
                    "or router.use(requireAuth) at the top of the file."))


# ---------------------------------------------------------------------------
# C4 — Open Cloud Run
# ---------------------------------------------------------------------------

def scan_cloud_run(text: str, loc: str, report: Report,
                   sup: dict[int, set[str]]) -> None:
    patterns = [
        (r"--allow-unauthenticated\b",
         "Cloud Run deploy with --allow-unauthenticated"),
        (r"members?\s*[:=]\s*[\[\"\']allUsers",
         "IAM policy grants run.invoker to allUsers"),
        (r"roles/run\.invoker.*allUsers",
         "allUsers granted run.invoker"),
    ]
    for pat, title in patterns:
        for m in re.finditer(pat, text):
            line = line_of(text, m.start())
            if is_suppressed("C4", line, sup):
                continue
            report.add(Finding(
                severity="P0", rule="C4",
                title=title,
                location=f"{loc}:{line}",
                evidence=m.group(0)[:120],
                fix=("Remove --allow-unauthenticated. If the service truly must be public, "
                     "add application-level auth (API key / Firebase Auth / OIDC) and rate-limit.")))


# ---------------------------------------------------------------------------
# D — CORS
# ---------------------------------------------------------------------------

def scan_cors(text: str, loc: str, report: Report,
              sup: dict[int, set[str]]) -> None:
    # D1 Flask / generic
    for m in re.finditer(
        r"""(?ix)
        CORS\s*\([^)]*origins\s*[=:]\s*['"]?\*['"]?
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("D1", line, sup):
            continue
        severity = "P0" if "supports_credentials" in text else "P1"
        report.add(Finding(
            severity=severity, rule="D1",
            title="CORS allows any origin" +
                  (" (with credentials — browsers block but server trusts cookies)"
                   if severity == "P0" else ""),
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="List exact allowed origins. Never combine '*' with credentials."))

    # D2 FastAPI
    for m in re.finditer(
        r"CORSMiddleware\s*[,)][^)]*allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
        text):
        line = line_of(text, m.start())
        if is_suppressed("D2", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="D2",
            title="FastAPI CORSMiddleware(allow_origins=['*'])",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="List exact allowed origins."))

    # D3 Socket.IO / WS
    for m in re.finditer(
        r"""cors_allowed_origins\s*=\s*['"]\*['"]""",
        text):
        line = line_of(text, m.start())
        if is_suppressed("D3", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="D3",
            title="Socket.IO cors_allowed_origins='*'",
            location=f"{loc}:{line}",
            evidence=m.group(0),
            fix="List exact origins or drop to same-origin."))

    # Raw header
    for m in re.finditer(
        r"""Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*""",
        text):
        line = line_of(text, m.start())
        if is_suppressed("D1", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="D1",
            title="Access-Control-Allow-Origin: *",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="Return the specific origin, echo only allow-listed origins."))


# ---------------------------------------------------------------------------
# E — SQL injection
# ---------------------------------------------------------------------------

def scan_sql_injection(text: str, loc: str, report: Report,
                       sup: dict[int, set[str]]) -> None:
    # E1 — Python execute(f"...")
    for m in re.finditer(
        r"""(?ix)
        \.execute\s*\(
        \s*f(['"])                # f-string
        [^'"]*                    # SQL-ish
        (?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|VALUES)
        [^'"]*
        \{[^}]+\}                 # interpolated
        [^'"]*\1
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("E1", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="E1",
            title="SQL query built with f-string (SQL injection)",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:160],
            fix="Use parameters: cursor.execute('... WHERE x = %s', (value,))."))

    # E1b — Python execute(... .format(...))
    for m in re.finditer(
        r"""(?ix)
        \.execute\s*\(
        \s*['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*
        \.\s*format\s*\(
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("E1", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="E1",
            title="SQL query built with .format() (SQL injection)",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:160],
            fix="Use parameters, not .format()."))

    # E2 — SQLAlchemy text() + concat
    for m in re.finditer(
        r"""(?ix)
        \btext\s*\(\s*
        (?:['"][^'"]*['"]\s*\+|f['"][^'"]*\{[^}]+\})
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("E2", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="E2",
            title="SQLAlchemy text() concatenated with user input",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:160],
            fix="Use bound params: text('... WHERE id = :id'), {'id': id}."))

    # E3 — Node template literal in query
    for m in re.finditer(
        r"""(?ix)
        \.(query|raw|execute)\s*\(\s*`
        [^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}[^`]*`
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("E3", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="E3",
            title="SQL query built with template literal ${...} (SQL injection)",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:160],
            fix="Use parameterised query: db.query('... WHERE id = $1', [id])."))


# ---------------------------------------------------------------------------
# F — Auth tokens in localStorage
# ---------------------------------------------------------------------------

LOCAL_AUTH_KEY_RE = re.compile(
    r"""(?ix)
    (localStorage|sessionStorage)
    \.setItem\s*\(\s*
    (['"])([^'"]*(token|jwt|auth|session|apikey|bearer|credential)[^'"]*)\2
    """
)


def scan_client_storage(text: str, loc: str, report: Report,
                        sup: dict[int, set[str]]) -> None:
    for m in LOCAL_AUTH_KEY_RE.finditer(text):
        line = line_of(text, m.start())
        if is_suppressed("F1", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="F1",
            title=f"{m.group(1)} stores auth-like key: {m.group(3)}",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix=("Move to httpOnly; secure; sameSite=lax cookies set by the server. "
                 "localStorage is readable by any XSS payload.")))


# ---------------------------------------------------------------------------
# G — LLM-specific
# ---------------------------------------------------------------------------

PROMPT_INJECTION_RE = re.compile(
    r"""(?ix)
    (?:
        # Python f-string assigned to system prompt
        (system|system_prompt|instructions|prompt)\s*=\s*f['"][^'"]*\{[^}]+\}[^'"]*['"]
      |
        # JS template literal
        (system|systemPrompt|instructions|prompt)\s*[:=]\s*`[^`]*\$\{[^}]+\}[^`]*`
      |
        # Python .format on prompt
        (system|system_prompt|instructions|prompt)\s*=\s*['"][^'"]*\{[^}]*\}[^'"]*['"]\s*\.format
    )
    """
)

MCP_SERVER_RE = re.compile(
    r"""(?ix)
    (FastMCP\s*\(|McpServer\s*\(|new\s+Server\s*\(|StdioServerTransport|create_mcp_server)
    """
)


def scan_llm_specific(text: str, loc: str, report: Report,
                      sup: dict[int, set[str]]) -> None:
    # G1 — user input into system prompt
    for m in PROMPT_INJECTION_RE.finditer(text):
        line = line_of(text, m.start())
        if is_suppressed("G1", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="G1",
            title="User input interpolated into system prompt (prompt injection)",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:160],
            fix=("Keep the system prompt static. Put user data in a user-role message and "
                 "explicitly tell the model to treat it as data, not instructions.")))

    # G3 — MCP server — does the file mention any auth mechanism?
    if MCP_SERVER_RE.search(text):
        has_auth = any(marker in text for marker in (
            "auth_token", "auth_header", "Authorization", "Bearer ",
            "API_KEY", "api_key", "shared_secret", "allowlist",
            "allow_origin", "require_auth", "verify_token",
        ))
        if not has_auth:
            m = MCP_SERVER_RE.search(text)
            line = line_of(text, m.start()) if m else 1
            if not is_suppressed("G3", line, sup):
                report.add(Finding(
                    severity="P0", rule="G3",
                    title="MCP server exposes tools without visible authentication",
                    location=f"{loc}:{line}",
                    evidence=m.group(0)[:120],
                    fix=("Require a shared secret / Bearer token on every request. "
                         "For stdio, at minimum validate the parent process / environment.")))

    # G4 — agent tool that fetches arbitrary user URL (SSRF)
    for m in re.finditer(
        r"""(?ix)
        (fetch|requests\.get|requests\.post|axios|httpx\.(?:get|post))
        \s*\(\s*
        [^)]*(user_url|user_input|args\.url|input\.url|params\.url|req\.url)
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("G4", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="G4",
            title="Server-side fetch of user-supplied URL (SSRF risk)",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:160],
            fix=("Allowlist domains. Block 169.254.169.254, localhost, 10/8, 192.168/16, ::1. "
                 "Use a dedicated fetcher like safe-curl / ssrf-req-filter.")))


# ---------------------------------------------------------------------------
# H — Insecure defaults
# ---------------------------------------------------------------------------

def scan_insecure_defaults(text: str, loc: str, report: Report,
                           sup: dict[int, set[str]]) -> None:
    # H1 debug=True / DEBUG = True
    for m in re.finditer(
        r"""(?ix)
        (?:^|\s)
        (debug|DEBUG)\s*=\s*True\b
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("H1", line, sup):
            continue
        # skip tests
        if "/test" in loc.lower() or loc.lower().startswith("test"):
            continue
        report.add(Finding(
            severity="P1", rule="H1",
            title=f"{m.group(1)}=True (can leak stack traces + werkzeug RCE in Flask)",
            location=f"{loc}:{line}",
            evidence=m.group(0).strip(),
            fix="Read from env: DEBUG = os.environ.get('DEBUG') == '1'. Default False."))

    # H2 default credentials
    for m in re.finditer(
        r"""(?ix)
        (?:user(?:name)?|admin|login|POSTGRES_USER|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)
        \s*[:=]\s*['"]?(admin|root|postgres|password|123456|changeme|test)['"]?
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("H2", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="H2",
            title=f"Default credential: {m.group(0).strip()}",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="Set strong unique password via secret manager."))

    # H3 TLS verification disabled
    for m in re.finditer(
        r"""(?ix)
        (verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl\s*:\s*\{[^}]*rejectUnauthorized\s*:\s*false)
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("H3", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="H3",
            title="TLS certificate verification disabled",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="Remove this flag. If you need a private CA, pin it explicitly."))

    # H4 http:// to a prod-ish host
    for m in re.finditer(
        r"""['"]http://[^'"\s]*(?:api|auth|login|pay|admin|account)[^'"\s]*['"]""",
        text):
        line = line_of(text, m.start())
        if is_suppressed("H4", line, sup):
            continue
        # skip comments / test files
        if loc.lower().endswith(".md") or "/test" in loc.lower():
            continue
        report.add(Finding(
            severity="P1", rule="H4",
            title="Plain http:// URL for a sensitive service",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="Use https://. Even internal traffic should be TLS where possible."))

    # H5 Math.random / random.random for tokens
    for m in re.finditer(
        r"""(?ix)
        (?:token|secret|code|otp|reset|apikey)\s*[:=].*?
        (Math\.random|random\.random|Random\(\))
        """, text):
        line = line_of(text, m.start())
        if is_suppressed("H5", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="H5",
            title="Non-cryptographic RNG used for a secret/token",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="Use crypto.randomBytes / secrets.token_urlsafe / crypto.randomUUID()."))


# ---------------------------------------------------------------------------
# I — Missing security headers (web projects)
# ---------------------------------------------------------------------------

def scan_security_headers(root: Path, report: Report) -> None:
    # Looks for Next.js `headers()` export, vercel.json, or helmet() usage.
    # If none found but the project looks web-y, flag once.
    has_next = (root / "next.config.js").exists() or (root / "next.config.mjs").exists() \
        or (root / "next.config.ts").exists()
    has_vercel = (root / "vercel.json").exists()
    has_pkg = (root / "package.json").exists()
    if not (has_next or has_vercel or has_pkg):
        return

    found_csp = False
    found_xfo = False
    found_hsts = False
    found_helmet = False

    for p in iter_files(root, []):
        if p.suffix.lower() not in (".js", ".ts", ".mjs", ".cjs", ".tsx", ".json", ".yaml", ".yml", ".conf"):
            continue
        t = read_text(p)
        low = t.lower()
        if "content-security-policy" in low:
            found_csp = True
        if "x-frame-options" in low or "frame-ancestors" in low:
            found_xfo = True
        if "strict-transport-security" in low:
            found_hsts = True
        if "helmet(" in low or "require('helmet')" in low or 'from "helmet"' in low:
            found_helmet = True

    if has_pkg and not found_helmet:
        # only recommend, don't flag unless Next/Vercel
        pass

    if (has_next or has_vercel) and not found_csp:
        report.add(Finding(
            severity="P1", rule="I1",
            title="No Content-Security-Policy header configured",
            location=str(root),
            fix="Configure CSP via next.config.js headers() or vercel.json > headers."))
    if (has_next or has_vercel) and not found_xfo:
        report.add(Finding(
            severity="P1", rule="I2",
            title="No X-Frame-Options / frame-ancestors (clickjacking risk)",
            location=str(root),
            fix='Add "X-Frame-Options: DENY" or CSP "frame-ancestors \'none\'".'))
    if (has_next or has_vercel) and not found_hsts:
        report.add(Finding(
            severity="P1", rule="I3",
            title="No Strict-Transport-Security header",
            location=str(root),
            fix='Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".'))


# ---------------------------------------------------------------------------
# J — .env committed / example leaks
# ---------------------------------------------------------------------------

def scan_env_committed(root: Path, report: Report) -> None:
    gitignore = root / ".gitignore"
    ignored = set()
    if gitignore.exists():
        for line in gitignore.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ignored.add(line)

    for name in (".env", ".env.local", ".env.production", ".env.staging",
                 ".env.development"):
        p = root / name
        if not p.exists():
            continue
        # Is it gitignored?
        is_ignored = False
        for pat in ignored:
            # simple check
            if pat == name or pat == ".env" or pat == ".env*":
                is_ignored = True
                break
        if is_ignored:
            # still flag if we can see real secret patterns inside
            text = read_text(p)
            for _rule, label, _sev, pat in SECRET_PATTERNS:
                m = pat.search(text)
                if m and not looks_like_placeholder(m.group(0)):
                    report.add(Finding(
                        severity="P1", rule="J1",
                        title=f"{name} (gitignored) contains real {label}",
                        location=f"{name}:{line_of(text, m.start())}",
                        evidence=redact(m.group(0)),
                        fix="Confirm the file was never committed (git log -- " + name + "). "
                        "Rotate the secret if there's any doubt."))
                    break
        else:
            report.add(Finding(
                severity="P0", rule="J1",
                title=f"{name} is present and NOT covered by .gitignore",
                location=name,
                fix=f"Add `{name}` to .gitignore. Rotate any secrets that were ever committed. "
                "Run git log -- " + name + " to check blast radius."))


# ---------------------------------------------------------------------------
# K — Missing rate limiting
# ---------------------------------------------------------------------------

def scan_missing_rate_limit(text: str, loc: str, report: Report,
                            sup: dict[int, set[str]],
                            project_rate_limited: bool = False) -> None:
    """Heuristic: file ACTIVELY uses an LLM / payment SDK + defines an endpoint
    + has no visible rate limiter. Requires both: an LLM call marker AND a
    route definition (not just a string mention in a health check).

    If `project_rate_limited=True` (global middleware detected somewhere in the
    project), we skip the finding — the app has baseline rate limits.
    """
    if project_rate_limited:
        return
    sensitive_call = any(m in text for m in SENSITIVE_CALL_MARKERS)
    # Must also define at least one route
    has_route = bool(
        FLASK_ROUTE_RE.search(text)
        or FASTAPI_ROUTE_RE.search(text)
        or EXPRESS_ROUTE_RE.search(text)
    )
    if not (sensitive_call and has_route):
        return
    has_limiter = any(m in text for m in (
        "@limiter.limit", "express-rate-limit", "rateLimit(", "slowapi",
        "Limiter(", "RateLimiter(", "@ratelimit", "Ratelimit.", "ratelimit.limit",
        "flask_limiter", "fastapi-limiter",
    ))
    if has_limiter:
        return
    # emit once per file on the first sensitive-call match
    m = None
    for marker in SENSITIVE_CALL_MARKERS:
        idx = text.find(marker)
        if idx != -1:
            # synthesize a match-like location
            line = text.count("\n", 0, idx) + 1
            if is_suppressed("K1", line, sup):
                return
            report.add(Finding(
                severity="P1", rule="K1",
                title="Sensitive endpoint without visible rate limiter",
                location=f"{loc}:{line}",
                evidence=marker,
                fix=("Add a rate limiter: slowapi / flask-limiter / express-rate-limit / upstash ratelimit. "
                     "Per-IP + per-user caps. Stop bill-stealing and brute force.")))
            return


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def detect_project_wide_rate_limiter(root: Path, is_doc_repo: bool = False) -> bool:
    """Walk the project looking for evidence of a global rate-limiting middleware.

    Detects:
      - FastAPI:  SlowAPIMiddleware, init_rate_limiter(app), Limiter(...)
      - Flask:    flask_limiter.Limiter, @limiter.limit at module level
      - Express:  app.use(rateLimit(...)), app.use(rateLimiter)
      - Node/Hono: upstash ratelimit, Ratelimit.fixedWindow
    If ANY source file in the project has these markers, we assume all routes
    are rate-limited by the global middleware.
    """
    markers = (
        "SlowAPIMiddleware", "init_rate_limiter", "slowapi",
        "flask_limiter", "fastapi-limiter", "express-rate-limit",
        "rateLimit(", "Ratelimit.", "ratelimit.limit",
    )
    for p in iter_files(root, []):
        suffix = p.suffix.lower()
        if suffix not in (".py", ".js", ".ts", ".tsx", ".mjs", ".cjs"):
            continue
        if is_doc_repo and p.name in ("auto_audit.py", "playwright_checks.js"):
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(m in t for m in markers):
            return True
    return False


def detect_project_wide_auth(root: Path, is_doc_repo: bool = False) -> bool:
    """Walk the project looking for evidence of an app-wide auth middleware
    or global dependency. If any file has it, we assume all routes in the
    project are auth'd (and only flag specifically suppressed or separately
    mounted endpoints)."""
    for p in iter_files(root, []):
        if p.suffix.lower() != ".py":
            continue
        if is_doc_repo and p.name in ("auto_audit.py", "playwright_checks.js"):
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(
            r"(?:FastAPI|APIRouter)\s*\([^)]*dependencies\s*=\s*\[[^\]]*Depends\(",
            t):
            return True
        if re.search(
            r"""(?ix)
                add_middleware\s*\(\s*[A-Za-z_][A-Za-z_0-9]*(?:Auth|Token|ApiKey|APIKey|JWT|Bearer)
              | (?:Auth|Token|ApiKey|APIKey|JWT|Bearer)Middleware
            """, t):
            return True
    return False


def scan_file(p: Path, root: Path, report: Report,
              is_doc_repo: bool,
              project_auth: bool = False,
              project_rate_limited: bool = False) -> None:
    text = read_text(p)
    if not text:
        return
    loc = rel_path(root, p)
    sup = build_line_suppressions(text)

    suffix = p.suffix.lower()
    name = p.name

    # In doc-example mode, the QA-skills repo's own pattern docs and scanner
    # source files are allowed to show "bad" examples (they literally document
    # the vulnerability patterns). Skip them; scan everything else normally.
    if is_doc_repo:
        # skip all .md (pattern docs, SKILL.md, checklist.md, README.md)
        if suffix == ".md":
            return
        # skip scanner scripts themselves — their regex strings match their own rules
        if name == "auto_audit.py" or name == "playwright_checks.js":
            return

    # Always run secrets scan on everything text-ish
    scan_secrets(text, loc, report, sup, is_client_file(loc))
    scan_client_secrets(text, loc, report, sup)

    # Python
    if suffix == ".py":
        if not project_auth:
            scan_missing_auth_python(text, loc, report, sup)
        scan_cors(text, loc, report, sup)
        scan_sql_injection(text, loc, report, sup)
        scan_llm_specific(text, loc, report, sup)
        scan_insecure_defaults(text, loc, report, sup)
        scan_missing_rate_limit(text, loc, report, sup, project_rate_limited=project_rate_limited)

    # JS/TS/TSX/JSX
    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        if not project_auth:
            scan_missing_auth_js(text, loc, report, sup)
        scan_cors(text, loc, report, sup)
        scan_sql_injection(text, loc, report, sup)
        scan_client_storage(text, loc, report, sup)
        scan_llm_specific(text, loc, report, sup)
        scan_insecure_defaults(text, loc, report, sup)
        scan_missing_rate_limit(text, loc, report, sup, project_rate_limited=project_rate_limited)

    # YAML / Terraform / deploy
    if suffix in (".yaml", ".yml", ".tf", ".hcl", ".json") or name.lower() == "dockerfile":
        scan_cloud_run(text, loc, report, sup)
        scan_insecure_defaults(text, loc, report, sup)

    # Dockerfile and compose
    if suffix in (".yml", ".yaml") and "compose" in name.lower():
        scan_insecure_defaults(text, loc, report, sup)

    # Shell scripts can carry deploy commands
    if suffix in (".sh", ".bash", ".zsh"):
        scan_cloud_run(text, loc, report, sup)


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def write_markdown(report: Report, out: Path) -> None:
    lines: list[str] = []
    lines.append(f"# Security Audit — {report.target}")
    lines.append("")
    counts = {s: len(report.by_sev(s)) for s in ("P0", "P1", "P2")}
    lines.append("## Summary")
    lines.append(f"- Files scanned: {report.files_scanned}")
    lines.append(f"- **{counts['P0']} P0** (production risk)")
    lines.append(f"- **{counts['P1']} P1** (data risk)")
    lines.append(f"- **{counts['P2']} P2** (hardening)")
    lines.append("")
    if not report.findings:
        lines.append("No findings. Scanner clean — rerun manually with `checklist.md` for anything static analysis can't catch.")
        out.write_text("\n".join(lines), encoding="utf-8")
        return
    for sev, label in (("P0", "Production risk"),
                       ("P1", "Data risk"),
                       ("P2", "Hardening")):
        items = report.by_sev(sev)
        if not items:
            continue
        lines.append(f"## {sev} — {label}")
        lines.append("")
        for i, f in enumerate(items, 1):
            lines.append(f"### {sev}.{i} [{f.rule}] {f.title}")
            lines.append(f"- **Location:** `{f.location}`")
            if f.evidence:
                lines.append(f"- **Evidence:** `{f.evidence}`")
            if f.fix:
                lines.append(f"- **Fix:** {f.fix}")
            lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")


def write_json(report: Report, out: Path) -> None:
    out.write_text(json.dumps({
        "target": report.target,
        "files_scanned": report.files_scanned,
        "summary": {
            "p0": len(report.by_sev("P0")),
            "p1": len(report.by_sev("P1")),
            "p2": len(report.by_sev("P2")),
        },
        "findings": [asdict(f) for f in report.findings],
    }, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Security vulnerability scanner.")
    ap.add_argument("path", help="Project folder to scan.")
    ap.add_argument("--md-out", default="report.md", help="Markdown report path.")
    ap.add_argument("--json-out", default="report.json", help="JSON report path.")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    args = ap.parse_args(argv[1:])

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 1
    if not root.is_dir():
        print(f"Path is not a directory: {root}", file=sys.stderr)
        return 1

    report = Report(target=str(root))
    ignore_patterns = load_qaignore(root)
    is_doc_repo = is_doc_example_repo(root)

    if not args.quiet and is_doc_repo:
        print("[info] Doc-example repo detected — suppressing .md pattern examples.",
              file=sys.stderr)

    project_auth = detect_project_wide_auth(root, is_doc_repo=is_doc_repo)
    if not args.quiet and project_auth:
        print("[info] Project-wide auth middleware detected — C1/C2/C3 will "
              "not flag individual routes. Suppress inline with `# qa-ignore: ALL`.",
              file=sys.stderr)

    project_rate_limited = detect_project_wide_rate_limiter(root, is_doc_repo=is_doc_repo)
    if not args.quiet and project_rate_limited:
        print("[info] Global rate-limiting middleware detected — K1 will "
              "not flag individual endpoints. Per-route decorators still "
              "recommended for sensitive ops (LLM/payment/auth).",
              file=sys.stderr)

    for p in iter_files(root, ignore_patterns):
        report.files_scanned += 1
        try:
            scan_file(p, root, report, is_doc_repo,
                      project_auth=project_auth,
                      project_rate_limited=project_rate_limited)
        except Exception as e:  # pragma: no cover
            if not args.quiet:
                print(f"[warn] skipped {p}: {e}", file=sys.stderr)

    # Project-wide checks
    scan_security_headers(root, report)
    scan_env_committed(root, report)

    md_path = Path(args.md_out).resolve()
    json_path = Path(args.json_out).resolve()
    write_markdown(report, md_path)
    write_json(report, json_path)

    if not args.quiet:
        print(f"Scanned {report.files_scanned} files. "
              f"Wrote {md_path} and {json_path}. "
              f"P0={len(report.by_sev('P0'))} "
              f"P1={len(report.by_sev('P1'))} "
              f"P2={len(report.by_sev('P2'))}.")

    if report.by_sev("P0"):
        return 2
    if report.by_sev("P1"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
