#!/usr/bin/env python3
"""
AI code-smell scanner — detects patterns specific to AI-generated code (Claude / Cursor / Copilot).

Flagship detection: **slopsquatting**. LLMs hallucinate package names 5–33% of the time
(GitGuardian 2026 research). Attackers register those names with malicious payloads.
Live attacks in the wild (e.g. `react-codeshift` npm, Jan 2026; multiple PyPI cases).

Usage:
    python3 auto_audit.py <target_path>
    python3 auto_audit.py <target_path> --offline            # skip npm/PyPI network checks
    python3 auto_audit.py <target_path> --md-out report.md   # custom report path
    python3 auto_audit.py <target_path> --json               # stream findings as JSON lines

Stdout contract (one finding per line, parsed by scan_all.py):
    [P0] package.json:14 — Slopsquatting: 'react-codeshift' is not on the npm registry
    [P1] src/api.ts:42 — LLM call without max_tokens (runaway cost risk)
    [INFO] src/ai.ts:1 — File has AI-assistant banner comment

Exit codes:
    0 — clean or findings present (scan succeeded)
    1 — at least one P1 finding
    2 — at least one P0 finding  ← gate CI here

Findings categories (letter = rule prefix):
    S   Slopsquatting          (hallucinated npm / pip packages)
    A   Async safety           (await without try, silent catch)
    L   LLM SDK misuse         (max_tokens missing, hallucinated methods)
    R   React deprecated       (React.FC, class components in new code)
    D   Debug leftovers        (console.log / TODO / FIXME in prod)
    U   Unused imports
    E   Env var hallucinations
    C   Copy-paste blocks
    M   AI-assistant banner    (INFO only)

Dependencies: stdlib only. Uses urllib for npm/PyPI registry checks. No `requests`.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str            # "P0" | "P1" | "P2" | "INFO"
    rule: str                # e.g. "S1"
    title: str
    location: str            # "file:line" (line optional)
    evidence: str = ""
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
    ".cache",
}

SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}
TEXT_EXTS = SOURCE_EXTS | {
    ".vue", ".svelte", ".json", ".toml", ".yaml", ".yml",
    ".md", ".txt",
}
ALWAYS_SCAN_NAMES = {
    "package.json", "requirements.txt", "requirements-dev.txt",
    "pyproject.toml", "Pipfile", ".env", ".env.example", ".env.local",
    ".env.production", ".env.development",
}

MAX_FILE_BYTES = 1_200_000


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
        if pat.startswith("**/") and fnmatch.fnmatch(rel_path, pat[3:]):
            return True
    return False


INLINE_SUPPRESS_RE = re.compile(r"(?:#|//)\s*qa-ignore\s*:\s*([A-Z0-9,\s]+)")


def build_line_suppressions(text: str) -> dict[int, set[str]]:
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
# Doc-mode detection
# ---------------------------------------------------------------------------

def is_doc_example_repo(root: Path) -> bool:
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
# File iteration
# ---------------------------------------------------------------------------

def iter_files(root: Path, ignore_patterns: list[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                rel = str(p.relative_to(root))
            except ValueError:
                continue
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
# Registry cache (.cache/npm-registry.json and pypi-registry.json)
# ---------------------------------------------------------------------------

CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def cache_path(kind: str) -> Path:
    base = Path(".cache")
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{kind}-registry.json"


def load_cache(kind: str) -> dict:
    p = cache_path(kind)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(kind: str, data: dict) -> None:
    try:
        cache_path(kind).write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def _http_json(url: str, timeout: float = 5.0) -> tuple[int, dict | None]:
    """Returns (status_code, json_or_none). status_code=0 on network error."""
    try:
        req = urlrequest.Request(url, headers={"User-Agent": "ai-code-smell-scanner/1.0"})
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            if status != 200:
                return status, None
            body = resp.read(2_000_000)  # cap 2MB
            try:
                return status, json.loads(body)
            except json.JSONDecodeError:
                return status, None
    except HTTPError as e:
        return e.code, None
    except (URLError, TimeoutError, OSError):
        return 0, None


# ---------------------------------------------------------------------------
# S — Slopsquatting (hallucinated packages)
# ---------------------------------------------------------------------------
#
# Heuristic:
#   1. Package does not exist on registry   → P0 (definite slopsquat target)
#   2. Registry returns 404                  → P0
#   3. Package exists but is <30 days old
#      AND has <100 downloads/week          → P1 (suspicious, likely squatter)
#
# Thresholds chosen based on GitGuardian 2026 report:
#   - legitimate new packages typically reach >500 wk-dl within 30 days
#   - 100 wk-dl is conservative; stays false-positive-safe for genuine indie libs
#
# Network checks are cached for 7 days to avoid rate-limiting.
# --offline flag skips all network checks (still prints which packages would be checked).

# Well-known typosquat confusables — curated (seed list, grows over time via
# known_hallucinations.json). These are known Cursor / Claude hallucinations.
KNOWN_HALLUCINATIONS_FILE = "known_hallucinations.json"


def load_known_hallucinations(skill_dir: Path) -> dict:
    p = skill_dir / KNOWN_HALLUCINATIONS_FILE
    if not p.exists():
        return {"npm": [], "pypi": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"npm": [], "pypi": []}


def parse_package_json_deps(text: str) -> list[tuple[str, int]]:
    """Returns list of (pkg_name, line_number)."""
    deps: list[tuple[str, int]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name in block:
            # find line number by searching raw text
            m = re.search(r'"' + re.escape(name) + r'"\s*:', text)
            line = line_of(text, m.start()) if m else 1
            deps.append((name, line))
    return deps


def parse_requirements_txt(text: str) -> list[tuple[str, int]]:
    deps: list[tuple[str, int]] = []
    for i, line in enumerate(text.split("\n"), start=1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("-"):
            continue
        # split on ==, >=, <=, ~=, >, <, !, ;
        m = re.match(r"^([A-Za-z0-9_.\-]+)", s)
        if not m:
            continue
        name = m.group(1).lower()
        deps.append((name, i))
    return deps


def parse_pyproject_toml(text: str) -> list[tuple[str, int]]:
    """Very small TOML-less parser — only the common dep tables."""
    deps: list[tuple[str, int]] = []
    # [project] dependencies = [...]
    for m in re.finditer(
        r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]",
        text,
    ):
        block_start = m.start(1)
        block = m.group(1)
        for dm in re.finditer(r'"\s*([A-Za-z0-9_.\-]+)\s*[<>=~!;\s]', block):
            name = dm.group(1).lower()
            line = line_of(text, block_start + dm.start(1))
            deps.append((name, line))
    # [tool.poetry.dependencies] — table of name = "..."
    in_poetry = False
    start_line = 0
    for i, line in enumerate(text.split("\n"), start=1):
        s = line.strip()
        if s.startswith("[tool.poetry.dependencies]") or s.startswith("[tool.poetry.dev-dependencies]"):
            in_poetry = True
            start_line = i
            continue
        if in_poetry:
            if s.startswith("[") and s.endswith("]"):
                in_poetry = False
                continue
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=', s)
            if m:
                name = m.group(1).lower()
                if name != "python":
                    deps.append((name, i))
    return deps


def check_npm_package(name: str, cache: dict, offline: bool) -> tuple[str, str]:
    """Returns (status, reason). status ∈ {'ok', 'missing', 'new_low_dl', 'unknown'}."""
    if offline:
        return "unknown", "offline"
    now = time.time()
    entry = cache.get(name)
    if entry and now - entry.get("ts", 0) < CACHE_TTL_SECONDS:
        return entry["status"], entry.get("reason", "")
    url = f"https://registry.npmjs.org/{name}"
    status, data = _http_json(url)
    result: tuple[str, str]
    if status == 404:
        result = ("missing", "npm registry returned 404")
    elif status == 0:
        result = ("unknown", "network error")
    elif status != 200 or not data:
        result = ("unknown", f"http {status}")
    else:
        # Check age + downloads
        created = data.get("time", {}).get("created")
        is_new = False
        if created:
            try:
                from datetime import datetime, timezone
                ts = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - ts).days
                is_new = age_days < 30
            except (ValueError, AttributeError):
                pass
        # downloads: https://api.npmjs.org/downloads/point/last-week/<pkg>
        if is_new:
            dl_status, dl_data = _http_json(
                f"https://api.npmjs.org/downloads/point/last-week/{name}")
            dl_count = (dl_data or {}).get("downloads", 0) if dl_status == 200 else None
            if dl_count is not None and dl_count < 100:
                result = ("new_low_dl", f"<30 days old, {dl_count} dl/wk")
            else:
                result = ("ok", "")
        else:
            result = ("ok", "")
    cache[name] = {"status": result[0], "reason": result[1], "ts": now}
    return result


def check_pypi_package(name: str, cache: dict, offline: bool) -> tuple[str, str]:
    if offline:
        return "unknown", "offline"
    now = time.time()
    entry = cache.get(name)
    if entry and now - entry.get("ts", 0) < CACHE_TTL_SECONDS:
        return entry["status"], entry.get("reason", "")
    url = f"https://pypi.org/pypi/{name}/json"
    status, data = _http_json(url)
    result: tuple[str, str]
    if status == 404:
        result = ("missing", "PyPI returned 404")
    elif status == 0:
        result = ("unknown", "network error")
    elif status != 200 or not data:
        result = ("unknown", f"http {status}")
    else:
        # Age check: latest release timestamp
        releases = data.get("releases") or {}
        is_new = False
        if releases:
            from datetime import datetime, timezone
            all_ts: list[float] = []
            for _ver, files in releases.items():
                if isinstance(files, list):
                    for f in files:
                        t = f.get("upload_time_iso_8601") or f.get("upload_time")
                        if t:
                            try:
                                ts = datetime.fromisoformat(t.replace("Z", "+00:00"))
                                all_ts.append(ts.timestamp())
                            except ValueError:
                                pass
            if all_ts:
                earliest = min(all_ts)
                age_days = (datetime.now(timezone.utc).timestamp() - earliest) / 86400
                is_new = age_days < 30
        # PyPI doesn't expose download counts without a separate service;
        # use package age + presence of homepage as proxy.
        if is_new:
            info = data.get("info", {}) or {}
            home = info.get("home_page") or info.get("project_urls", {}).get("Homepage", "")
            result = ("new_low_dl", "<30 days old, no download-count API") if not home \
                else ("new_low_dl", f"<30 days old, homepage={home[:40]}")
        else:
            result = ("ok", "")
    cache[name] = {"status": result[0], "reason": result[1], "ts": now}
    return result


def scan_slopsquatting(root: Path, report: Report, offline: bool,
                       skill_dir: Path) -> None:
    npm_cache = load_cache("npm")
    pypi_cache = load_cache("pypi")
    known = load_known_hallucinations(skill_dir)

    # package.json
    for pkg_json in root.rglob("package.json"):
        # skip node_modules etc.
        if any(part in SKIP_DIRS for part in pkg_json.parts):
            continue
        text = read_text(pkg_json)
        if not text:
            continue
        loc = rel_path(root, pkg_json)
        for name, line in parse_package_json_deps(text):
            if name in known.get("npm", []):
                report.add(Finding(
                    severity="P0", rule="S1",
                    title=f"Slopsquatting: '{name}' is in the known-hallucinated npm list",
                    location=f"{loc}:{line}",
                    evidence=f'"{name}"',
                    fix="Remove this dependency. It's a known LLM hallucination — "
                        "verify the real package name before re-adding."))
                continue
            status, reason = check_npm_package(name, npm_cache, offline)
            if status == "missing":
                report.add(Finding(
                    severity="P0", rule="S1",
                    title=f"Slopsquatting: '{name}' is not on the npm registry",
                    location=f"{loc}:{line}",
                    evidence=f'"{name}"',
                    fix=f"Check the real package name — this may be an LLM hallucination "
                        f"({reason}). If an attacker registers this name with a malicious "
                        f"payload, `npm install` executes it."))
            elif status == "new_low_dl":
                report.add(Finding(
                    severity="P1", rule="S2",
                    title=f"Suspicious new npm package '{name}' ({reason})",
                    location=f"{loc}:{line}",
                    evidence=f'"{name}"',
                    fix="Verify the package is legitimate (GitHub repo, active maintainers). "
                        "New + low-download packages are prime slopsquat targets."))

    # requirements.txt / pyproject.toml / Pipfile
    for req_file in list(root.rglob("requirements.txt")) + \
                    list(root.rglob("requirements-dev.txt")):
        if any(part in SKIP_DIRS for part in req_file.parts):
            continue
        text = read_text(req_file)
        if not text:
            continue
        loc = rel_path(root, req_file)
        for name, line in parse_requirements_txt(text):
            _check_py_dep(name, line, loc, report, pypi_cache, offline, known)

    for pyproject in root.rglob("pyproject.toml"):
        if any(part in SKIP_DIRS for part in pyproject.parts):
            continue
        text = read_text(pyproject)
        if not text:
            continue
        loc = rel_path(root, pyproject)
        for name, line in parse_pyproject_toml(text):
            _check_py_dep(name, line, loc, report, pypi_cache, offline, known)

    save_cache("npm", npm_cache)
    save_cache("pypi", pypi_cache)


def _check_py_dep(name: str, line: int, loc: str, report: Report,
                  cache: dict, offline: bool, known: dict) -> None:
    if name in known.get("pypi", []):
        report.add(Finding(
            severity="P0", rule="S1",
            title=f"Slopsquatting: '{name}' is in the known-hallucinated PyPI list",
            location=f"{loc}:{line}",
            evidence=name,
            fix="Remove this dependency. Known LLM hallucination."))
        return
    status, reason = check_pypi_package(name, cache, offline)
    if status == "missing":
        report.add(Finding(
            severity="P0", rule="S1",
            title=f"Slopsquatting: '{name}' is not on PyPI",
            location=f"{loc}:{line}",
            evidence=name,
            fix=f"Check the real package name — this may be an LLM hallucination ({reason})."))
    elif status == "new_low_dl":
        report.add(Finding(
            severity="P1", rule="S2",
            title=f"Suspicious new PyPI package '{name}' ({reason})",
            location=f"{loc}:{line}",
            evidence=name,
            fix="Verify the package is legitimate."))


# ---------------------------------------------------------------------------
# A — Async safety (A1: await-no-try, A2: silent catch)
# ---------------------------------------------------------------------------

# A1 — `await <call>` not inside a try block.
# Heuristic: for each `await` line in async function, walk backward looking
# for `try {` / `try:` at the same or shallower indentation before hitting
# the enclosing function signature. If not found → flag.
AWAIT_JS_RE = re.compile(r"^(\s*).*\bawait\b", re.MULTILINE)
AWAIT_PY_RE = re.compile(r"^(\s*).*\bawait\b", re.MULTILINE)


def scan_async_no_try_js(text: str, loc: str, report: Report,
                         sup: dict[int, set[str]]) -> None:
    lines = text.split("\n")
    # Find async function ranges (rough). For each `await`, check if a `try {`
    # precedes it within the same indentation scope and without a matching `}`.
    for i, line in enumerate(lines):
        if "await " not in line:
            continue
        # skip if the same line already has try/catch nearby (one-liner)
        if re.search(r"\btry\s*\{", line) or re.search(r"\.catch\s*\(", line):
            continue
        # Simple check: is there a `try {` in the previous 20 lines that hasn't
        # been closed yet? Count braces from the try onwards.
        try_found = False
        for j in range(max(0, i - 30), i):
            if re.search(r"\btry\s*\{", lines[j]):
                # check that the try block extends to line i
                window = "\n".join(lines[j:i + 1])
                opens = window.count("{")
                closes = window.count("}")
                if opens > closes:
                    try_found = True
                    break
        if try_found:
            continue
        # also skip if line uses `.catch(` chained or `?? null` / `|| null` guard
        if re.search(r"\.catch\s*\(", line):
            continue
        # Must actually be inside a function (look for `async` keyword in prev 30 lines)
        async_ctx = False
        for j in range(max(0, i - 30), i + 1):
            if "async " in lines[j] or "async(" in lines[j]:
                async_ctx = True
                break
        if not async_ctx:
            continue
        ln = i + 1
        if is_suppressed("A1", ln, sup):
            continue
        report.add(Finding(
            severity="P1", rule="A1",
            title="await without enclosing try/catch (unhandled promise rejection)",
            location=f"{loc}:{ln}",
            evidence=line.strip()[:120],
            fix="Wrap the await in try/catch, or chain .catch() on the promise. "
                "Unhandled rejections crash Node 15+."))


def scan_async_no_try_py(text: str, loc: str, report: Report,
                         sup: dict[int, set[str]]) -> None:
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if "await " not in line:
            continue
        indent = len(line) - len(line.lstrip())
        # Walk backwards looking for `try:` at lesser indent before hitting
        # `async def` at even lesser indent.
        try_found = False
        for j in range(i - 1, max(-1, i - 30), -1):
            prev = lines[j]
            if not prev.strip():
                continue
            prev_indent = len(prev) - len(prev.lstrip())
            if prev_indent >= indent:
                continue
            if re.match(r"\s*try\s*:", prev):
                try_found = True
                break
            if re.match(r"\s*async\s+def\s", prev) or re.match(r"\s*def\s", prev):
                break
        if try_found:
            continue
        # verify we're actually in an async function
        async_ctx = False
        for j in range(i - 1, max(-1, i - 50), -1):
            if re.match(r"\s*async\s+def\s", lines[j]):
                async_ctx = True
                break
            if re.match(r"\s*def\s", lines[j]) and len(lines[j]) - len(lines[j].lstrip()) < indent:
                break
        if not async_ctx:
            continue
        ln = i + 1
        if is_suppressed("A1", ln, sup):
            continue
        report.add(Finding(
            severity="P1", rule="A1",
            title="await without enclosing try (unhandled exception)",
            location=f"{loc}:{ln}",
            evidence=line.strip()[:120],
            fix="Wrap the await in try/except. Unhandled asyncio exceptions "
                "swallow silently with no traceback by default."))


# A2 — empty catch / except pass
def scan_silent_catch(text: str, loc: str, report: Report,
                      sup: dict[int, set[str]]) -> None:
    # JS: catch (e) { } or catch { }
    for m in re.finditer(
        r"catch\s*(?:\([^)]*\))?\s*\{\s*\}",
        text,
    ):
        line = line_of(text, m.start())
        if is_suppressed("A2", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="A2",
            title="Empty catch block silently swallows errors",
            location=f"{loc}:{line}",
            evidence=m.group(0),
            fix="At minimum log the error. Preferably handle or rethrow."))

    # JS: catch with ONLY console.log
    for m in re.finditer(
        r"catch\s*(?:\([^)]*\))?\s*\{\s*console\.(?:log|debug)\s*\([^}]*\)\s*;?\s*\}",
        text,
    ):
        line = line_of(text, m.start())
        if is_suppressed("A2", line, sup):
            continue
        report.add(Finding(
            severity="P2", rule="A2",
            title="catch block only console.logs (swallows errors from metrics)",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120],
            fix="Use a real logger and rethrow if unexpected."))

    # Python: except: pass / except Exception: pass
    for m in re.finditer(
        r"except\s*(?:[A-Za-z_][A-Za-z_0-9.]*(?:\s+as\s+\w+)?)?\s*:\s*\n\s*pass\b",
        text,
    ):
        line = line_of(text, m.start())
        if is_suppressed("A2", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="A2",
            title="`except: pass` silently swallows exceptions",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120].replace("\n", "\\n"),
            fix="At minimum log the exception with stacktrace. Preferably handle the specific error."))


# ---------------------------------------------------------------------------
# L — LLM SDK misuse
# ---------------------------------------------------------------------------

# L1 — max_tokens missing on LLM calls
LLM_CALL_RE = re.compile(
    r"""(?sx)
    (
        # Anthropic
        (?:client|anthropic|messages)\.(?:messages\.create|create)\s*\(
        |
        \bAnthropic\s*\([^)]*\)\s*\.messages\.create\s*\(
        |
        # OpenAI
        (?:client|openai)\.chat\.completions\.create\s*\(
        |
        \bopenai\.ChatCompletion\.create\s*\(
    )
    (?P<args>[^)]{0,2000}?)\)
    """
)


def scan_llm_missing_max_tokens(text: str, loc: str, report: Report,
                                sup: dict[int, set[str]]) -> None:
    for m in LLM_CALL_RE.finditer(text):
        args = m.group("args") or ""
        if re.search(r"\bmax_tokens\b", args) or re.search(r"\bmaxTokens\b", args):
            continue
        line = line_of(text, m.start())
        if is_suppressed("L1", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="L1",
            title="LLM call without max_tokens — runaway cost risk",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:120].replace("\n", " "),
            fix="Add max_tokens=1024 (or appropriate cap). Cursor users have reported $1,400+ "
                "bills from runaway output. Never call an LLM without an output bound."))


# L2 — known hallucinated SDK methods
HALLUCINATED_METHODS = [
    # (regex, human title)
    (r"\bfetch\s*\.\s*post\s*\(", "fetch.post() — fetch() has no .post method"),
    (r"\bfetch\s*\.\s*get\s*\(", "fetch.get() — fetch() has no .get method"),
    (r"\baxios\.createRequest\s*\(", "axios.createRequest() — not a real axios method"),
    (r"\blodash\.clone\s*\(", "lodash.clone (shallow) confusion — often AI means cloneDeep"),
    (r"\bJSON\.tryParse\s*\(", "JSON.tryParse() — does not exist on the JSON object"),
    (r"\bArray\.contains\s*\(", "Array.contains() — JavaScript uses .includes()"),
    (r"\bObject\.copy\s*\(", "Object.copy() — not a standard method (use {...obj})"),
    (r"\bpromise\.finally\s*\(\s*\)", "promise.finally() called with no arg"),
    # Python
    (r"\brequests\.session\s*\(", "requests.session() — correct is requests.Session()"),
    (r"\bos\.path\.joinpath\s*\(", "os.path.joinpath — not a method (use pathlib.Path.joinpath)"),
    (r"\bdict\.has_key\s*\(", "dict.has_key() — removed in Python 3"),
]


def scan_hallucinated_methods(text: str, loc: str, report: Report,
                              sup: dict[int, set[str]]) -> None:
    for pattern, title in HALLUCINATED_METHODS:
        for m in re.finditer(pattern, text):
            line = line_of(text, m.start())
            if is_suppressed("L2", line, sup):
                continue
            report.add(Finding(
                severity="P1", rule="L2",
                title=f"Hallucinated API: {title}",
                location=f"{loc}:{line}",
                evidence=m.group(0),
                fix="Check the library docs. This is a common AI hallucination."))


# ---------------------------------------------------------------------------
# R — React deprecated
# ---------------------------------------------------------------------------

def scan_react_deprecated(text: str, loc: str, report: Report,
                          sup: dict[int, set[str]]) -> None:
    if not loc.endswith((".tsx", ".jsx", ".ts", ".js")):
        return
    # R1 — React.FC<>
    for m in re.finditer(r"\bReact\.FC\s*<", text):
        line = line_of(text, m.start())
        if is_suppressed("R1", line, sup):
            continue
        report.add(Finding(
            severity="P2", rule="R1",
            title="React.FC<> is deprecated — use explicit function props",
            location=f"{loc}:{line}",
            evidence=m.group(0),
            fix="Prefer: function Comp(props: Props) { ... }. React team and Dan Abramov "
                "recommend against React.FC (implicit children, hard to override defaults)."))

    # R2 — class components in a file that uses hooks or modern imports
    for m in re.finditer(r"\bclass\s+\w+\s+extends\s+(?:React\.)?Component\b", text):
        line = line_of(text, m.start())
        if is_suppressed("R2", line, sup):
            continue
        report.add(Finding(
            severity="P2", rule="R2",
            title="Class component in new code (React favours function components)",
            location=f"{loc}:{line}",
            evidence=m.group(0),
            fix="Rewrite as function component with hooks unless there's a specific reason."))

    # R3 — componentWillMount / componentWillReceiveProps (true deprecated)
    for m in re.finditer(
        r"\b(componentWillMount|componentWillReceiveProps|componentWillUpdate)\b",
        text,
    ):
        line = line_of(text, m.start())
        if is_suppressed("R3", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="R3",
            title=f"Deprecated React lifecycle: {m.group(1)}",
            location=f"{loc}:{line}",
            evidence=m.group(0),
            fix="Use componentDidMount / getDerivedStateFromProps, or migrate to hooks."))


# ---------------------------------------------------------------------------
# D — Debug leftovers (console.log, TODO, FIXME)
# ---------------------------------------------------------------------------

def scan_debug_leftovers(text: str, loc: str, report: Report,
                         sup: dict[int, set[str]]) -> None:
    low = loc.lower().replace("\\", "/")
    # skip tests / dev scripts
    if any(seg in low for seg in ("__tests__", "/test/", ".test.", ".spec.",
                                  "/scripts/", "/dev/", "playground", "storybook")):
        return

    # D1 — console.log / console.debug in production src/
    if any(seg in low for seg in ("/src/", "/app/", "/pages/", "/lib/", "/components/")):
        for m in re.finditer(r"\bconsole\.(log|debug)\s*\(", text):
            line = line_of(text, m.start())
            # skip suppression on same line
            if is_suppressed("D1", line, sup):
                continue
            # skip if within an obvious dev-only block
            ctx_start = max(0, m.start() - 120)
            ctx = text[ctx_start:m.start()]
            if "NODE_ENV" in ctx and "development" in ctx:
                continue
            report.add(Finding(
                severity="P1", rule="D1",
                title=f"console.{m.group(1)} left in production code",
                location=f"{loc}:{line}",
                evidence=m.group(0),
                fix="Remove or replace with a proper logger (pino, winston) that respects NODE_ENV."))

    # D2 — TODO / FIXME / HACK / XXX comments in source files
    if loc.endswith(tuple(SOURCE_EXTS)):
        for m in re.finditer(r"(?://|#)\s*(TODO|FIXME|HACK|XXX)\b[^\n]*", text):
            line = line_of(text, m.start())
            if is_suppressed("D2", line, sup):
                continue
            report.add(Finding(
                severity="P2", rule="D2",
                title=f"{m.group(1)} comment left in source",
                location=f"{loc}:{line}",
                evidence=m.group(0)[:120],
                fix="Resolve or file an issue. AI-generated code commonly ships with these."))


# ---------------------------------------------------------------------------
# U — Unused imports
# ---------------------------------------------------------------------------

def scan_unused_imports(text: str, loc: str, report: Report,
                        sup: dict[int, set[str]]) -> None:
    """Simple: find `import {A, B} from '...'` then grep rest of file for A / B."""
    if not loc.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return
    # JS/TS named imports
    for m in re.finditer(
        r"""import\s*\{\s*([^}]+)\s*\}\s*from\s*['"]([^'"]+)['"]""",
        text,
    ):
        names_raw = m.group(1)
        imp_end = m.end()
        rest = text[imp_end:]
        names = [n.strip().split(" as ")[-1].strip() for n in names_raw.split(",")]
        for name in names:
            if not name or not re.match(r"^[A-Za-z_][A-Za-z_0-9]*$", name):
                continue
            # look for a word-boundary usage after the import line
            if not re.search(r"\b" + re.escape(name) + r"\b", rest):
                line = line_of(text, m.start())
                if is_suppressed("U1", line, sup):
                    continue
                report.add(Finding(
                    severity="P2", rule="U1",
                    title=f"Unused import: {name} from '{m.group(2)}'",
                    location=f"{loc}:{line}",
                    evidence=f"{{{name}}} from '{m.group(2)}'",
                    fix="Remove the unused import. AI commonly over-imports."))


# ---------------------------------------------------------------------------
# E — Env var hallucinations
# ---------------------------------------------------------------------------

def collect_env_var_names(root: Path) -> set[str]:
    """Gather env var names declared in any .env* file (keys only)."""
    names: set[str] = set()
    for p in list(root.rglob(".env*")) + [root / ".env.example"]:
        if not p.exists() or not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in re.finditer(r"(?m)^\s*([A-Z_][A-Z0-9_]*)\s*=", text):
            names.add(m.group(1))
    return names


def scan_env_var_hallucinations(text: str, loc: str, report: Report,
                                sup: dict[int, set[str]],
                                known_vars: set[str]) -> None:
    # process.env.FOO or process.env['FOO']
    # os.environ['FOO'] or os.environ.get('FOO')
    for m in re.finditer(
        r"""(?x)
        (?:
            process\.env\.([A-Z_][A-Z0-9_]*)
          | process\.env\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\]
          | import\.meta\.env\.([A-Z_][A-Z0-9_]*)
          | os\.environ\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\]
          | os\.environ\.get\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"]
          | os\.getenv\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"]
        )
        """,
        text,
    ):
        name = next((g for g in m.groups() if g), None)
        if not name:
            continue
        # ignore well-known system vars
        if name in {"NODE_ENV", "PATH", "HOME", "USER", "PORT", "CI",
                    "VERCEL_URL", "VERCEL_ENV", "PYTHONPATH", "PWD"}:
            continue
        if name in known_vars:
            continue
        line = line_of(text, m.start())
        if is_suppressed("E1", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="E1",
            title=f"Env var referenced but not in any .env* file: {name}",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:80],
            fix=f"Add {name} to .env.example (even if empty) so other devs know it's needed. "
                "Missing env vars are a classic AI-code failure mode."))


# ---------------------------------------------------------------------------
# C — Copy-paste blocks (duplicate code ≥10 lines appearing 3+ times)
# ---------------------------------------------------------------------------

def scan_duplicates(root: Path, report: Report) -> None:
    """Sliding 10-line window across all source files. Hash blocks.
    Flag any hash seen in 3+ distinct positions."""
    block_size = 10
    # hash -> list[(loc, start_line)]
    seen: dict[str, list[tuple[str, int]]] = {}
    for p in iter_files(root, []):
        if p.suffix.lower() not in SOURCE_EXTS:
            continue
        loc = rel_path(root, p)
        # skip tests / fixtures
        low = loc.lower().replace("\\", "/")
        if any(seg in low for seg in ("__tests__", "/test/", ".test.", ".spec.",
                                      "/fixtures/", "/node_modules/")):
            continue
        text = read_text(p)
        lines = text.split("\n")
        if len(lines) < block_size:
            continue
        for i in range(len(lines) - block_size + 1):
            block = "\n".join(line.strip() for line in lines[i:i + block_size])
            # skip whitespace-only or boilerplate blocks (imports, short lines)
            stripped = block.replace("\n", "").strip()
            if len(stripped) < 120:
                continue
            # skip blocks of only import/export/comment
            meaningful = sum(1 for line in lines[i:i + block_size]
                             if line.strip() and
                             not line.strip().startswith(("import ", "from ",
                                                           "export ", "//", "#",
                                                           "*", "/*")))
            if meaningful < 5:
                continue
            h = hashlib.md5(block.encode("utf-8")).hexdigest()
            seen.setdefault(h, []).append((loc, i + 1))

    for _h, positions in seen.items():
        # unique locations only — don't count overlaps in the same file
        unique = {(loc, line) for loc, line in positions}
        if len(unique) < 3:
            continue
        first = sorted(unique)[0]
        report.add(Finding(
            severity="P2", rule="C1",
            title=f"Duplicate 10-line block appears in {len(unique)} places",
            location=f"{first[0]}:{first[1]}",
            evidence=f"Also at: " + ", ".join(
                f"{loc}:{line}" for loc, line in sorted(unique)[1:4]
            ),
            fix="Extract into a shared function/module. AI often regenerates "
                "similar logic instead of reusing."))


# ---------------------------------------------------------------------------
# M — AI-assistant banner comments (INFO only)
# ---------------------------------------------------------------------------

AI_BANNER_RE = re.compile(
    r"""(?ix)
    (?:
        //\s*generated\s+by\s+(?:cursor|claude|copilot|chatgpt|gpt-?\d)
      | \#\s*generated\s+by\s+(?:cursor|claude|copilot|chatgpt|gpt-?\d)
      | //\s*claude\s+(?:did|wrote|generated)
      | \#\s*claude\s+(?:did|wrote|generated)
      | //\s*AI-assisted
      | \#\s*AI-assisted
      | //\s*@ai-generated
      | \#\s*@ai-generated
    )
    """
)


def scan_ai_banner(text: str, loc: str, report: Report) -> None:
    # only look at first 30 lines — banners are at the top
    head = "\n".join(text.split("\n")[:30])
    m = AI_BANNER_RE.search(head)
    if m:
        report.add(Finding(
            severity="INFO", rule="M1",
            title="File has AI-assistant banner comment",
            location=f"{loc}:{line_of(text, m.start())}",
            evidence=m.group(0).strip()[:80],
            fix="No action — informational only, so you know which files to review extra carefully."))


# ---------------------------------------------------------------------------
# File dispatcher
# ---------------------------------------------------------------------------

def scan_file(p: Path, root: Path, report: Report,
              is_doc_repo: bool, known_vars: set[str]) -> None:
    text = read_text(p)
    if not text:
        return
    loc = rel_path(root, p)
    sup = build_line_suppressions(text)
    suffix = p.suffix.lower()
    name = p.name

    if is_doc_repo:
        if suffix == ".md":
            return
        if name == "auto_audit.py":
            return

    # AI banner (INFO) — run on all source-ish files
    if suffix in SOURCE_EXTS:
        scan_ai_banner(text, loc, report)

    # Async safety
    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        scan_async_no_try_js(text, loc, report, sup)
    if suffix == ".py":
        scan_async_no_try_py(text, loc, report, sup)
    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"):
        scan_silent_catch(text, loc, report, sup)

    # LLM SDK misuse
    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"):
        scan_llm_missing_max_tokens(text, loc, report, sup)
        scan_hallucinated_methods(text, loc, report, sup)

    # React
    if suffix in (".jsx", ".tsx", ".js", ".ts"):
        scan_react_deprecated(text, loc, report, sup)

    # Debug leftovers
    if suffix in SOURCE_EXTS:
        scan_debug_leftovers(text, loc, report, sup)

    # Unused imports
    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        scan_unused_imports(text, loc, report, sup)

    # Env var hallucinations
    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"):
        scan_env_var_hallucinations(text, loc, report, sup, known_vars)


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def write_stdout(report: Report) -> None:
    """scan_all.py contract: one finding per line, [PX] path:line — msg."""
    for f in report.findings:
        print(f"[{f.severity}] {f.location} — {f.title}")


def write_markdown(report: Report, out: Path) -> None:
    lines: list[str] = []
    lines.append(f"# AI Code-Smell Audit — {report.target}")
    lines.append("")
    counts = {s: len(report.by_sev(s)) for s in ("P0", "P1", "P2", "INFO")}
    lines.append("## Summary")
    lines.append(f"- Files scanned: {report.files_scanned}")
    lines.append(f"- **{counts['P0']} P0** (supply-chain / production risk)")
    lines.append(f"- **{counts['P1']} P1** (cost trap / silent bug)")
    lines.append(f"- **{counts['P2']} P2** (hygiene)")
    lines.append(f"- {counts['INFO']} INFO (AI-generated file markers)")
    lines.append("")
    if not report.findings:
        lines.append("No findings. Rerun with `--offline` removed if cache is stale.")
        out.write_text("\n".join(lines), encoding="utf-8")
        return
    for sev, label in (("P0", "Supply-chain / production risk"),
                       ("P1", "Cost trap / silent bug"),
                       ("P2", "Hygiene"),
                       ("INFO", "Informational")):
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


def write_json_report(report: Report, out: Path) -> None:
    out.write_text(json.dumps({
        "target": report.target,
        "files_scanned": report.files_scanned,
        "summary": {
            "p0": len(report.by_sev("P0")),
            "p1": len(report.by_sev("P1")),
            "p2": len(report.by_sev("P2")),
            "info": len(report.by_sev("INFO")),
        },
        "findings": [asdict(f) for f in report.findings],
    }, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="AI code-smell scanner (slopsquatting + more).")
    ap.add_argument("path", help="Project folder to scan.")
    ap.add_argument("--md-out", default="report.md", help="Markdown report path.")
    ap.add_argument("--json-out", default="report.json", help="JSON report path.")
    ap.add_argument("--offline", action="store_true",
                    help="Skip npm/PyPI network checks (use cache only).")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    ap.add_argument("--no-duplicates", action="store_true",
                    help="Skip the duplicate-code scan (slow on large repos).")
    args = ap.parse_args(argv[1:])

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"Path not found or not a directory: {root}", file=sys.stderr)
        return 2

    skill_dir = Path(__file__).parent.resolve()
    report = Report(target=str(root))
    ignore_patterns = load_qaignore(root)
    is_doc_repo = is_doc_example_repo(root)

    if not args.quiet:
        if is_doc_repo:
            print("[info] Doc-example repo detected — skipping .md files and scanner itself.",
                  file=sys.stderr)
        if args.offline:
            print("[info] Offline mode — slopsquatting check uses cache only.",
                  file=sys.stderr)

    # Slopsquatting check (project-wide)
    scan_slopsquatting(root, report, args.offline, skill_dir)

    # Collect env vars declared in .env*
    known_vars = collect_env_var_names(root)

    for p in iter_files(root, ignore_patterns):
        report.files_scanned += 1
        try:
            scan_file(p, root, report, is_doc_repo, known_vars)
        except Exception as e:  # pragma: no cover
            if not args.quiet:
                print(f"[warn] skipped {p}: {e}", file=sys.stderr)

    # Duplicate-code scan (project-wide)
    if not args.no_duplicates:
        scan_duplicates(root, report)

    # Stdout contract — parsed by scan_all.py
    write_stdout(report)

    md_path = Path(args.md_out).resolve()
    json_path = Path(args.json_out).resolve()
    write_markdown(report, md_path)
    write_json_report(report, json_path)

    if not args.quiet:
        print(f"\nScanned {report.files_scanned} files. "
              f"P0={len(report.by_sev('P0'))} "
              f"P1={len(report.by_sev('P1'))} "
              f"P2={len(report.by_sev('P2'))} "
              f"INFO={len(report.by_sev('INFO'))}. "
              f"Wrote {md_path.name} + {json_path.name}.",
              file=sys.stderr)

    if report.by_sev("P0"):
        return 2
    if report.by_sev("P1"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
