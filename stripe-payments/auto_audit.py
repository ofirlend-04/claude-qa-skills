#!/usr/bin/env python3
"""
Stripe / payments QA scanner.

Usage:
    python3 auto_audit.py <target_path> [--json]
    python3 auto_audit.py <target_path> --md-out report.md --json-out report.json

Finds 13 classes of payment-integration bugs:
    P1  Webhook signature not verified          (CVE-2026-21894 class)
    P2  Webhook idempotency missing             (double-charge risk)
    P3  Express raw-body parsing wrong          (breaks sig verification)
    P4  Hardcoded sk_test_ / pk_test_           (test key in prod code)
    P5  Live Stripe key committed               (sk_live_ / rk_live_)
    P6  Client-side amount / price calculation  (user edits $10 -> $1)
    P7  PaymentIntent missing automatic_payment_methods
    P8  Subscription update without proration_behavior
    P9  RevenueCat logIn() ordering bug
    P10 Missing refund / dispute webhook handlers
    P11 Missing "Restore Purchases" in paywall
    P12 3DS / SCA not handled (confirmCardPayment missing)
    P13 Pricing as hardcoded strings (not via Stripe Price API)

Stdout line format (required by scan_all.py):
    [P0] path:line — message
    [P1] path:line — message
    [P2] path:line — message

Exit codes:
    0   scan completed (may have findings)
    1   findings exist but scan succeeded  (same as 0 from scan_all's POV)
    2   scan could not run (bad target, unreadable dir)
"""

from __future__ import annotations

import argparse
import json
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
    severity: str          # P0 | P1 | P2
    rule: str              # e.g. "S1"
    title: str             # short message
    location: str          # "path:line" or "path"
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
# File iteration
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", ".turbo", ".svelte-kit",
    "dist", "build", "out", "coverage", ".vercel", ".venv", "venv",
    "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
    "target", "Pods", "DerivedData", ".gradle", ".idea", ".vscode",
    "xcarchive", "DerivedData",
}

TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".html", ".htm",
    ".yaml", ".yml", ".toml",
    ".env", ".json",
    ".md", ".txt",
    ".swift", ".kt",
}

ALWAYS_SCAN_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.test", ".env.staging", "Dockerfile",
}

MAX_FILE_BYTES = 1_200_000
REDACT_AFTER = 8


def rel_path(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def is_vendor_path(rel: str) -> bool:
    """Paths we should never scan for Stripe code — built bundles, dist artifacts, IDE."""
    low = rel.lower().replace("\\", "/")
    return any(seg in low for seg in (
        "/node_modules/", "/dist/", "/build/", "/.next/",
        "/.vercel/", "/xcarchive/", "/deriveddata/",
        "/public/assets/",   # Capacitor copies a minified bundle here
        ".min.js", ".bundle.js",
    ))


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                       and not d.startswith(".venv")]
        for name in filenames:
            p = Path(dirpath) / name
            rel = rel_path(root, p)
            if is_vendor_path(rel):
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


def redact(value: str) -> str:
    if len(value) <= REDACT_AFTER:
        return "***"
    return f"{value[:REDACT_AFTER]}***"


# Inline suppression: `# qa-ignore: S1` or `// qa-ignore: S4,S6`
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


PLACEHOLDER_WORDS = (
    "your_", "your-", "placeholder", "replace_me", "replaceme",
    "changeme", "example", "dummy", "fake", "xxxxxxxx",
    "abcdefgh", "sk_live_xxxx", "sk_test_xxxx", "pk_test_xxxx",
    "todo",
)


def looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    return any(p in v for p in PLACEHOLDER_WORDS)


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


_LINE_COMMENT_RE = re.compile(r"(?m)(?:^|\s)//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_PY_COMMENT_RE = re.compile(r"(?m)(?:^|\s)#[^\n]*")


def strip_comments(text: str, is_python: bool = False) -> str:
    """Return the text with // and /* */ comments replaced by whitespace of the
    same length (line numbers preserved). Used by checks that look for
    identifier mentions — so a comment like `// event.id goes here` doesn't
    count as real code."""
    if is_python:
        out = _PY_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)
    else:
        out = _LINE_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)
        out = _BLOCK_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), out)
    return out


def is_test_or_fixture(rel: str) -> bool:
    low = rel.lower().replace("\\", "/")
    return any(seg in low for seg in (
        "/tests/", "/test/", "/__tests__/", "/fixtures/", "/fixture/",
        "/spec/", "/specs/", ".test.", ".spec.",
    ))


# ---------------------------------------------------------------------------
# Classifiers — what is this file?
# ---------------------------------------------------------------------------

WEBHOOK_PATH_RE = re.compile(
    r"""['"](/[^'"]*(?:webhooks?/stripe|stripe/webhooks?|stripe-webhook)[^'"]*)['"]""",
    re.IGNORECASE,
)

# Any file mentioning stripe + webhook + event
def mentions_stripe_webhook(text: str) -> bool:
    low = text.lower()
    return ("stripe" in low) and ("webhook" in low or "signature" in low
                                  or "constructevent" in low or "construct_event" in low)


def mentions_stripe(text: str) -> bool:
    return "stripe" in text.lower()


# ---------------------------------------------------------------------------
# S1 — Stripe webhook signature not verified
# ---------------------------------------------------------------------------

VERIFY_MARKERS = (
    "stripe.webhooks.constructEvent",
    "Webhook.constructEvent",
    "webhook.constructEvent",
    "stripe.Webhook.construct_event",
    "Webhook.construct_event",
    "construct_event(",
    "verifyHeader(",               # stripe-node alternative
    "verify_header(",
)

def scan_webhook_signature(text: str, loc: str, report: Report,
                           sup: dict[int, set[str]]) -> None:
    # Find any Stripe webhook route
    webhook_hits = list(WEBHOOK_PATH_RE.finditer(text))
    # Also accept files that are *named* stripe-webhook / webhook/stripe and mention Stripe
    named_webhook = (("webhook" in loc.lower() and "stripe" in loc.lower())
                     or "stripe_webhook" in loc.lower()
                     or "stripe-webhook" in loc.lower())
    if not webhook_hits and not (named_webhook and mentions_stripe_webhook(text)):
        return

    has_verify = any(m in text for m in VERIFY_MARKERS)
    if has_verify:
        return

    if webhook_hits:
        m = webhook_hits[0]
        line = line_of(text, m.start())
        evidence = m.group(1)
    else:
        line = 1
        evidence = loc

    if is_suppressed("S1", line, sup):
        return

    report.add(Finding(
        severity="P0", rule="S1",
        title="Stripe webhook endpoint has no signature verification (CVE-2026-21894 class)",
        location=f"{loc}:{line}",
        evidence=evidence[:120],
        fix=("Call stripe.webhooks.constructEvent(rawBody, sig, endpointSecret) "
             "before trusting the payload. In Python: stripe.Webhook.construct_event(...). "
             "Without it, anyone can POST fake payment_intent.succeeded events."),
    ))


# ---------------------------------------------------------------------------
# S2 — Webhook idempotency missing
# ---------------------------------------------------------------------------

def scan_webhook_idempotency(text: str, loc: str, report: Report,
                             sup: dict[int, set[str]]) -> None:
    """Flag webhook handlers that never reference event.id / event['id'] / event_id
    for deduplication. Stripe retries: same event can arrive multiple times."""
    if not mentions_stripe_webhook(text):
        return
    is_py = loc.endswith(".py")
    code = strip_comments(text, is_python=is_py)
    # Is this actually a handler? Look for event.type / event['type'] dispatch
    handles_events = bool(re.search(r"event\s*(?:\.|\[)\s*['\"]?type", code))
    if not handles_events:
        return
    # Look for event.id / event["id"] / event_id stored somewhere.
    # Use regex with word-boundary so `event.data` does NOT count as `event.id`.
    idempotency_re = re.compile(
        r"""(?x)
        (?:
            event\s*\.\s*id\b           # event.id  (not event.data)
          | event\s*\[\s*['"]id['"]\s*\]  # event['id'] / event["id"]
          | \bevent_id\b
          | \bprocessed_events?\b
          | \bwebhook_events?\b
          | \bidempotenc[yi]\w*\b
          | \balready[_]?[Pp]rocessed\b
        )
        """
    )
    if idempotency_re.search(code):
        return
    # find first event.type to locate line (from original text so line numbers stay accurate)
    m = re.search(r"event\s*(?:\.|\[)\s*['\"]?type", text) or re.search(r"webhook", text, re.I)
    line = line_of(text, m.start()) if m else 1
    if is_suppressed("S2", line, sup):
        return
    report.add(Finding(
        severity="P1", rule="S2",
        title="Stripe webhook handler does not dedupe by event.id (double-charge risk)",
        location=f"{loc}:{line}",
        evidence="event.type switch without event.id check",
        fix=("Store processed event.id in a dedupe table (Redis SET NX, Postgres UNIQUE). "
             "Stripe retries on non-2xx for up to 3 days — same event arrives many times."),
    ))


# ---------------------------------------------------------------------------
# S3 — Express raw body parsing wrong
# ---------------------------------------------------------------------------

EXPRESS_JSON_BEFORE_WEBHOOK_RE = re.compile(
    r"""
    app\.use\s*\(\s*express\.json\s*\(\s*\)\s*\)   # global express.json()
    .*?                                            # ...then later...
    (?:app|router)\.post\s*\(\s*['"][^'"]*(webhook|stripe)[^'"]*['"]
    """,
    re.DOTALL | re.IGNORECASE | re.VERBOSE,
)

# Good pattern: webhook route uses bodyParser.raw / express.raw
def scan_express_raw_body(text: str, loc: str, report: Report,
                          sup: dict[int, set[str]]) -> None:
    if "express" not in text.lower() or not mentions_stripe(text):
        return
    has_global_json = bool(re.search(r"app\.use\s*\(\s*express\.json\s*\(", text))
    has_webhook_route = bool(re.search(
        r"""(?:app|router)\.post\s*\(\s*['"][^'"]*(?:webhook|stripe)[^'"]*['"]""",
        text, re.IGNORECASE))
    if not (has_global_json and has_webhook_route):
        return
    # Acceptable fix: route uses express.raw / bodyParser.raw as middleware
    uses_raw_body = bool(re.search(
        r"""(?:express|bodyParser)\.raw\s*\(\s*\{[^}]*type\s*:\s*['"]application/json['"]""",
        text))
    if uses_raw_body:
        return
    m = EXPRESS_JSON_BEFORE_WEBHOOK_RE.search(text)
    if not m:
        # Still flag if we found both pieces — order unknown but high suspicion
        m = re.search(r"app\.use\s*\(\s*express\.json", text)
    if not m:
        return
    line = line_of(text, m.start())
    if is_suppressed("S3", line, sup):
        return
    report.add(Finding(
        severity="P0", rule="S3",
        title="express.json() parses webhook body before Stripe signature verification (breaks signing)",
        location=f"{loc}:{line}",
        evidence=m.group(0)[:120].replace("\n", " "),
        fix=("Mount the Stripe webhook route BEFORE app.use(express.json()), with "
             "express.raw({ type: 'application/json' }) as its body parser. "
             "constructEvent() needs the raw body bytes exactly as sent."),
    ))


# ---------------------------------------------------------------------------
# S4 — Hardcoded sk_test_ / pk_test_
# ---------------------------------------------------------------------------

TEST_KEY_RE = re.compile(r"(sk_test_[A-Za-z0-9]{16,}|pk_test_[A-Za-z0-9]{16,}|rk_test_[A-Za-z0-9]{16,})")

def scan_test_keys(text: str, loc: str, report: Report,
                   sup: dict[int, set[str]]) -> None:
    if is_test_or_fixture(loc):
        return
    for m in TEST_KEY_RE.finditer(text):
        value = m.group(1)
        if looks_like_placeholder(value):
            continue
        line = line_of(text, m.start())
        if is_suppressed("S4", line, sup):
            continue
        # pk_test_ in client code is LESS severe (publishable), but still wrong env
        severity = "P0" if value.startswith("sk_") or value.startswith("rk_") else "P1"
        report.add(Finding(
            severity=severity, rule="S4",
            title=f"Hardcoded Stripe test key ({value[:7]}...) in source",
            location=f"{loc}:{line}",
            evidence=redact(value),
            fix=("Move to env var. Never commit test keys — they let anyone browse your test "
                 "customers / subscriptions via the Stripe API."),
        ))


# ---------------------------------------------------------------------------
# S5 — Live Stripe key committed
# ---------------------------------------------------------------------------

LIVE_KEY_RE = re.compile(r"(sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,})")

def scan_live_keys(text: str, loc: str, report: Report,
                   sup: dict[int, set[str]]) -> None:
    for m in LIVE_KEY_RE.finditer(text):
        value = m.group(1)
        if looks_like_placeholder(value):
            continue
        line = line_of(text, m.start())
        if is_suppressed("S5", line, sup):
            continue
        report.add(Finding(
            severity="P0", rule="S5",
            title=f"LIVE Stripe secret key ({value[:8]}...) in source — rotate NOW",
            location=f"{loc}:{line}",
            evidence=redact(value),
            fix=("Rotate the key at dashboard.stripe.com/apikeys immediately. "
                 "Assume it has been scraped. Run `git log -p | grep sk_live_` to confirm "
                 "blast radius; if it ever hit a public branch, use git-filter-repo to purge history."),
        ))


# ---------------------------------------------------------------------------
# S6 — Client-side amount / price calculation
# ---------------------------------------------------------------------------

# `amount:` / `unit_amount:` set from a client-side variable that came from form/input/state
# Two-stage: (1) find a Stripe checkout/PaymentIntent call, (2) within the next ~800 chars,
# look for any `amount:` or `unit_amount:` field with a non-literal value.
STRIPE_CALL_RE = re.compile(
    r"""(?ix)
    (?:createCheckoutSession
      |paymentIntents\.create
      |PaymentIntent\.create
      |stripe\.PaymentIntent\.create
      |checkout\.sessions\.create
      |stripe\.checkout\.sessions\.create)
    \s*\(
    """
)

AMOUNT_FIELD_RE = re.compile(
    r"""(?ix)
    \b(?:unit_amount|amount)\s*:\s*
    (?P<expr>[^,}\n]{1,200})
    """
)

def looks_dynamic_amount(expr: str) -> bool:
    e = expr.strip()
    # Direct numeric literal or referencing a priceId is fine
    if re.fullmatch(r"\d+(_?\d+)*", e):
        return False
    if e.startswith("'") or e.startswith('"') or e.startswith("`"):
        return False  # string literal — probably a price ID, not our concern
    # Obvious risky shapes
    bad_markers = (
        "form.", "input.", "state.", "req.body", "req.query", "params.",
        "localStorage", "sessionStorage", "searchParams", "query.",
        "$(", "document.getElementById", "e.target.value", "useState",
        "quantity *", "qty *", "* price", "price *", "parseInt(req",
        "parseFloat(req", "Number(req",
    )
    if any(b in e for b in bad_markers):
        return True
    # a bare identifier like `amount: userAmount` is suspicious in a client file
    if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", e) and e not in ("amount", "total", "price"):
        # only flag when file context suggests client (we check outside)
        return True
    return False


def scan_client_amount(text: str, loc: str, report: Report,
                       sup: dict[int, set[str]]) -> None:
    if not mentions_stripe(text):
        return
    for call_m in STRIPE_CALL_RE.finditer(text):
        # search window = next 1500 chars after the opening paren
        window_start = call_m.end()
        window = text[window_start:window_start + 1500]
        for am in AMOUNT_FIELD_RE.finditer(window):
            expr = am.group("expr")
            if not looks_dynamic_amount(expr):
                continue
            abs_offset = window_start + am.start()
            line = line_of(text, abs_offset)
            if is_suppressed("S6", line, sup):
                continue
            field = am.group(0).split(":")[0].strip()
            report.add(Finding(
                severity="P0", rule="S6",
                title="Stripe amount built from client-side / request input (user can edit the price)",
                location=f"{loc}:{line}",
                evidence=f"{field}: {expr.strip()[:80]}",
                fix=("Compute the amount server-side from a trusted source (Stripe Price ID, "
                     "a product table keyed by SKU). Never accept `amount` from req.body / client state. "
                     "Classic indie bug: user DevTools $9.99 -> $0.99, gets product."),
            ))
            break   # one finding per Stripe call is enough


# ---------------------------------------------------------------------------
# S7 — PaymentIntent missing automatic_payment_methods
# ---------------------------------------------------------------------------

PAYMENT_INTENT_CALL_RE = re.compile(
    r"""(?ix)
    (?:paymentIntents\.create|PaymentIntent\.create|stripe\.PaymentIntent\.create)
    \s*\(
    """
)

def scan_payment_intent_apm(text: str, loc: str, report: Report,
                            sup: dict[int, set[str]]) -> None:
    for m in PAYMENT_INTENT_CALL_RE.finditer(text):
        body = _balanced_call_body(text, m.end())
        if "automatic_payment_methods" in body:
            continue
        # payment_method_types explicitly listed is the legacy alternative — allow
        if "payment_method_types" in body:
            continue
        line = line_of(text, m.start())
        if is_suppressed("S7", line, sup):
            continue
        report.add(Finding(
            severity="P2", rule="S7",
            title="PaymentIntent created without automatic_payment_methods.enabled (Apple Pay / Google Pay won't appear)",
            location=f"{loc}:{line}",
            evidence=(m.group(0) + body[:80]).replace("\n", " "),
            fix=("Add `automatic_payment_methods: { enabled: true }` to the create call. "
                 "Stripe will surface all eligible methods (Apple Pay, Google Pay, Link, SEPA, iDEAL) "
                 "based on region. Without it you leak conversion on mobile."),
        ))


# ---------------------------------------------------------------------------
# S8 — Subscription update without proration_behavior
# ---------------------------------------------------------------------------

SUB_UPDATE_CALL_RE = re.compile(
    r"""(?ix)
    (?:subscriptions\.update|Subscription\.modify|Subscription\.update)
    \s*\(
    """
)

def _balanced_call_body(text: str, after_open_paren: int, max_chars: int = 2000) -> str:
    """Return the substring inside the call's outermost parentheses, bounded."""
    depth = 1
    i = after_open_paren
    end = min(len(text), after_open_paren + max_chars)
    while i < end and depth > 0:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[after_open_paren:i]
        i += 1
    return text[after_open_paren:end]


def scan_subscription_proration(text: str, loc: str, report: Report,
                                sup: dict[int, set[str]]) -> None:
    for m in SUB_UPDATE_CALL_RE.finditer(text):
        body = _balanced_call_body(text, m.end())
        # flag only when `items` is being modified — that's when proration matters
        if "items" not in body:
            continue
        if "proration_behavior" in body:
            continue
        line = line_of(text, m.start())
        if is_suppressed("S8", line, sup):
            continue
        report.add(Finding(
            severity="P1", rule="S8",
            title="Subscription items updated without proration_behavior (customer billing surprises)",
            location=f"{loc}:{line}",
            evidence=(m.group(0) + body[:80]).replace("\n", " "),
            fix=("Set proration_behavior explicitly: 'create_prorations' (default, gives credit), "
                 "'always_invoice' (immediate charge), or 'none'. Silent proration = support tickets."),
        ))


# ---------------------------------------------------------------------------
# S9 — RevenueCat logIn() ordering bug
# ---------------------------------------------------------------------------

def scan_rc_login_order(text: str, loc: str, report: Report,
                        sup: dict[int, set[str]]) -> None:
    """Flag Purchases.purchasePackage / purchaseStoreProduct happening in a file
    that never calls Purchases.logIn() — or calls it AFTER the purchase.
    Real bug: RevenueCat App User ID must be set before purchase or
    entitlements won't sync across devices."""
    if "Purchases." not in text:
        return
    has_purchase = "Purchases.purchasePackage" in text or "Purchases.purchaseStoreProduct" in text
    if not has_purchase:
        return
    has_configure = "Purchases.configure" in text
    has_login = "Purchases.logIn(" in text or "Purchases.login(" in text
    # If configure is present but logIn is not — only a bug when the app has
    # its own user identity (most do). Flag P1 — ambiguous otherwise.
    if has_configure and not has_login:
        # Only flag if the project has an auth system (heuristic: grep below, but we
        # can only see this file. Safer: flag P2 — maintainer should confirm.)
        line = 1
        m = re.search(r"Purchases\.configure", text)
        if m:
            line = line_of(text, m.start())
        if is_suppressed("S9", line, sup):
            return
        report.add(Finding(
            severity="P2", rule="S9",
            title="RevenueCat configure() without logIn() — entitlements won't follow a user across devices",
            location=f"{loc}:{line}",
            evidence="Purchases.configure without Purchases.logIn()",
            fix=("Call Purchases.logIn({ appUserID: yourUserId }) as soon as the user logs in, "
                 "BEFORE any purchase flow. Otherwise the purchase is tied to an anonymous ID "
                 "and restores on a new device fail."),
        ))
        return
    # If both present, check order: logIn must appear before purchasePackage in source
    if has_login and has_purchase:
        login_idx = -1
        for m in re.finditer(r"Purchases\.(?:logIn|login)\s*\(", text):
            login_idx = m.start()
            break
        purchase_idx = -1
        for m in re.finditer(r"Purchases\.(?:purchasePackage|purchaseStoreProduct)\s*\(", text):
            purchase_idx = m.start()
            break
        # If the two are in separate functions, source order is not meaningful —
        # only flag when the SAME function contains both and logIn is AFTER purchase.
        # Heuristic: same enclosing function if both occur within 600 chars.
        if 0 < purchase_idx < login_idx and login_idx - purchase_idx < 600:
            line = line_of(text, login_idx)
            if is_suppressed("S9", line, sup):
                return
            report.add(Finding(
                severity="P0", rule="S9",
                title="RevenueCat Purchases.logIn() called AFTER purchasePackage() — entitlement mismatch",
                location=f"{loc}:{line}",
                evidence="logIn appears after purchase in the same block",
                fix=("Move Purchases.logIn() before any purchasePackage/purchaseStoreProduct call. "
                     "The purchase is attributed to whatever App User ID is active at purchase time."),
            ))


# ---------------------------------------------------------------------------
# S10 — Missing refund / dispute handlers
# ---------------------------------------------------------------------------

REFUND_EVENTS = ("charge.refunded", "charge.dispute.created",
                 "charge.dispute.funds_withdrawn", "charge.dispute.closed")

def scan_missing_refund_handler(text: str, loc: str, report: Report,
                                sup: dict[int, set[str]]) -> None:
    """Only runs on files that look like a Stripe webhook handler.
    Flags if no refund / dispute event is handled."""
    if not mentions_stripe_webhook(text):
        return
    is_py = loc.endswith(".py")
    code = strip_comments(text, is_python=is_py)
    # Must look like a real handler — event.type switch
    if not re.search(r"event\s*(?:\.|\[)\s*['\"]?type", code):
        return
    # Check for any refund / dispute event string (only in code, not in comments)
    if any(ev in code for ev in REFUND_EVENTS):
        return
    m = re.search(r"event\s*(?:\.|\[)\s*['\"]?type", text)
    line = line_of(text, m.start()) if m else 1
    if is_suppressed("S10", line, sup):
        return
    report.add(Finding(
        severity="P2", rule="S10",
        title="Stripe webhook handler does not react to charge.refunded / charge.dispute.created",
        location=f"{loc}:{line}",
        evidence="no charge.refunded or charge.dispute.* branch",
        fix=("Handle charge.refunded (downgrade entitlement / refund internal credits) and "
             "charge.dispute.created (freeze account, notify team). Required for most compliance "
             "regimes (PSD2, card network rules) and critical for retention analytics."),
    ))


# ---------------------------------------------------------------------------
# S11 — Missing "Restore Purchases" button
# ---------------------------------------------------------------------------

PAYWALL_FILE_MARKERS = (
    "paywall", "pricing", "subscription", "upgrade", "premium",
    "PurchaseView", "SubscriptionView", "PaywallView",
)

def looks_like_paywall_file(loc: str, text: str) -> bool:
    low = loc.lower()
    if any(m in low for m in ("paywall", "pricing", "subscription", "upgrade")):
        return True
    low_text = text.lower()
    # File that calls purchasePackage / createCheckoutSession counts as paywall UI
    if "purchasepackage" in low_text or "purchasestoreproduct" in low_text:
        return True
    if "createcheckoutsession" in low_text:
        return True
    return False


def scan_restore_purchases(text: str, loc: str, report: Report,
                           sup: dict[int, set[str]]) -> None:
    # only applies to UI / client files
    suffix = Path(loc).suffix.lower()
    if suffix not in (".jsx", ".tsx", ".vue", ".svelte", ".swift", ".kt", ".js", ".ts"):
        return
    if not looks_like_paywall_file(loc, text):
        return
    is_py = loc.endswith(".py")
    code = strip_comments(text, is_python=is_py)
    # Skip if this is a library / data module (no JSX-ish rendering)
    has_ui = any(tag in code for tag in ("<div", "<View", "<button", "<Button",
                                         "NavigationView", "VStack", "Scaffold",
                                         "return (", "render(", "createElement"))
    if not has_ui:
        return
    # Require the marker to appear as a JS/Swift identifier or function call,
    # not just in a code comment or doc string. The .()= context check
    # discriminates code from freeform English.
    restore_re = re.compile(
        r"""(?x)
        (?:
            \b(?:restorePurchases|restore_purchases|restoreTransactions)\s*\(
          | \.\s*restorePurchases\b
          | \brestoreCompletedTransactions\b
          | >\s*Restore\s+Purchases?\s*<       # visible UI text as JSX children
          | ['"]Restore\s+Purchases?['"]       # UI string literal
          | \{\s*[^}]*\brestorePurchases\b     # `{ restorePurchases }` import / destructure
          | import[^;]*\brestorePurchases\b    # import restorePurchases from ...
        )
        """
    )
    if restore_re.search(code):
        return
    line = 1
    m = re.search(r"(purchasePackage|createCheckoutSession|purchaseStoreProduct)", text)
    if m:
        line = line_of(text, m.start())
    if is_suppressed("S11", line, sup):
        return
    report.add(Finding(
        severity="P0", rule="S11",
        title='Paywall has no "Restore Purchases" button (Apple Guideline 3.1.1 rejection)',
        location=f"{loc}:{line}",
        evidence="purchase call without restorePurchases/restoreTransactions",
        fix=('Add a "Restore Purchases" button that calls Purchases.restorePurchases() '
             '(RevenueCat) or SKPaymentQueue.default().restoreCompletedTransactions() (StoreKit). '
             'Apple WILL reject without it. Required on Google Play too.'),
    ))


# ---------------------------------------------------------------------------
# S12 — 3DS / SCA not handled
# ---------------------------------------------------------------------------

def scan_sca(text: str, loc: str, report: Report,
             sup: dict[int, set[str]]) -> None:
    """If the code calls paymentIntent.confirm()/confirm_payment but never
    handles `requires_action` / handleNextAction / confirmCardPayment, EU customers
    with SCA-required cards will fail silently."""
    if not mentions_stripe(text):
        return
    uses_confirm = bool(re.search(
        r"""(paymentIntent\.confirm|paymentIntents\.confirm|PaymentIntent\.confirm)""",
        text))
    if not uses_confirm:
        return
    handles_sca = any(m in text for m in (
        "handleNextAction", "confirmCardPayment", "handle_next_action",
        "requires_action", "next_action",
        "handleCardAction",
    ))
    if handles_sca:
        return
    m = re.search(
        r"""(paymentIntent\.confirm|paymentIntents\.confirm|PaymentIntent\.confirm)""",
        text)
    if not m:
        return
    line = line_of(text, m.start())
    if is_suppressed("S12", line, sup):
        return
    report.add(Finding(
        severity="P1", rule="S12",
        title="paymentIntent.confirm() without handling requires_action / 3DS (EU SCA will fail)",
        location=f"{loc}:{line}",
        evidence=m.group(0),
        fix=("Check the returned PaymentIntent status: if 'requires_action', call "
             "stripe.confirmCardPayment() (client-side) or handleNextAction() to trigger 3DS. "
             "PSD2 makes this mandatory in the EU/UK — EU customers currently fail silently."),
    ))


# ---------------------------------------------------------------------------
# S13 — Hardcoded prices in UI strings
# ---------------------------------------------------------------------------

HARDCODED_PRICE_RE = re.compile(
    r""">[^<]*\$\s?\d+(?:\.\d{1,2})?\s?(?:/\s?(?:mo|month|yr|year|wk|week))[^<]*<""",
    re.IGNORECASE,
)

def scan_hardcoded_prices(text: str, loc: str, report: Report,
                          sup: dict[int, set[str]]) -> None:
    suffix = Path(loc).suffix.lower()
    if suffix not in (".jsx", ".tsx", ".vue", ".svelte", ".html"):
        return
    if not looks_like_paywall_file(loc, text):
        return
    # Only a real concern if Stripe / RevenueCat Price IDs are used nearby
    uses_price_api = ("price_" in text or "offerings" in text.lower()
                      or "getOfferings" in text or "Purchases.getOfferings" in text)
    if not uses_price_api:
        return
    for m in HARDCODED_PRICE_RE.finditer(text):
        line = line_of(text, m.start())
        if is_suppressed("S13", line, sup):
            continue
        report.add(Finding(
            severity="P2", rule="S13",
            title="Price displayed as a hardcoded string while Stripe/RC Price API is in use (drift risk)",
            location=f"{loc}:{line}",
            evidence=m.group(0)[:80],
            fix=("Pull the display price from the same Stripe Price / RevenueCat Offering you "
                 "charge against. Use Intl.NumberFormat for formatting. "
                 "Hardcoded strings drift from what the user is actually billed."),
        ))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def scan_file(p: Path, root: Path, report: Report, is_doc_repo: bool) -> None:
    text = read_text(p)
    if not text:
        return
    loc = rel_path(root, p)
    # In doc-example mode, skip the skill's own docs + scanner
    if is_doc_repo:
        suffix = p.suffix.lower()
        name = p.name
        if suffix == ".md":
            return
        if name == "auto_audit.py":
            return
    sup = build_line_suppressions(text)

    # Secret scans run on everything text-ish (env files included)
    scan_test_keys(text, loc, report, sup)
    scan_live_keys(text, loc, report, sup)

    suffix = p.suffix.lower()
    # Stripe code lives in JS/TS/Python — skip markup for server checks
    if suffix in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        scan_webhook_signature(text, loc, report, sup)
        scan_webhook_idempotency(text, loc, report, sup)
        scan_missing_refund_handler(text, loc, report, sup)
        scan_client_amount(text, loc, report, sup)
        scan_payment_intent_apm(text, loc, report, sup)
        scan_subscription_proration(text, loc, report, sup)
        scan_sca(text, loc, report, sup)
        scan_rc_login_order(text, loc, report, sup)

    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        scan_express_raw_body(text, loc, report, sup)

    # Paywall UI checks — only on UI files
    scan_restore_purchases(text, loc, report, sup)
    scan_hardcoded_prices(text, loc, report, sup)


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def print_stdout(report: Report) -> None:
    """Required format for scan_all.py:
        [P0] path:line — message
    """
    order = {"P0": 0, "P1": 1, "P2": 2}
    findings = sorted(report.findings, key=lambda f: (order.get(f.severity, 9), f.location))
    for f in findings:
        print(f"[{f.severity}] {f.location} — {f.title}")


def write_markdown(report: Report, out: Path) -> None:
    lines: list[str] = []
    lines.append(f"# Stripe / Payments Audit — {report.target}")
    lines.append("")
    counts = {s: len(report.by_sev(s)) for s in ("P0", "P1", "P2")}
    lines.append("## Summary")
    lines.append(f"- Files scanned: {report.files_scanned}")
    lines.append(f"- **{counts['P0']} P0** (production risk — rotate / fix before shipping)")
    lines.append(f"- **{counts['P1']} P1** (financial risk)")
    lines.append(f"- **{counts['P2']} P2** (hardening / conversion)")
    lines.append("")
    if not report.findings:
        lines.append("No findings. Payment flow scanner is clean.")
        lines.append("")
        lines.append("Run the manual `checklist.md` items before going live.")
        out.write_text("\n".join(lines), encoding="utf-8")
        return
    for sev, label in (("P0", "Production risk"),
                       ("P1", "Financial risk"),
                       ("P2", "Hardening / conversion")):
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
    ap = argparse.ArgumentParser(
        description="Stripe / payments vulnerability scanner.")
    ap.add_argument("path", help="Project folder to scan.")
    ap.add_argument("--md-out",
                    default=str(Path(__file__).parent / "report.md"),
                    help="Markdown report path (default: next to this script).")
    ap.add_argument("--json-out",
                    default=str(Path(__file__).parent / "report.json"),
                    help="JSON report path.")
    ap.add_argument("--json", action="store_true",
                    help="Also emit JSON on stdout (after the [Pn] lines).")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv[1:])

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"Path not found or not a directory: {root}", file=sys.stderr)
        return 2

    report = Report(target=str(root))
    is_doc_repo = is_doc_example_repo(root)
    if is_doc_repo and not args.quiet:
        print("[info] Doc-example repo detected — skipping pattern .md and scanner source.",
              file=sys.stderr)

    for p in iter_files(root):
        report.files_scanned += 1
        try:
            scan_file(p, root, report, is_doc_repo)
        except Exception as e:  # pragma: no cover
            if not args.quiet:
                print(f"[warn] skipped {p}: {e}", file=sys.stderr)

    print_stdout(report)

    md_path = Path(args.md_out).resolve()
    json_path = Path(args.json_out).resolve()
    try:
        write_markdown(report, md_path)
        write_json(report, json_path)
    except OSError as e:
        print(f"[warn] could not write report files: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps({
            "summary": {s: len(report.by_sev(s)) for s in ("P0", "P1", "P2")},
            "findings": [asdict(f) for f in report.findings],
        }, indent=2))

    if report.by_sev("P0") or report.by_sev("P1") or report.by_sev("P2"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
