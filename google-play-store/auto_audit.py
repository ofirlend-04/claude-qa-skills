#!/usr/bin/env python3
"""Automated Google Play Store pre-submission audit.

Usage:
    python3 auto_audit.py /path/to/app_folder [--json]

Runs 13 deterministic checks based on the April 2026 Google Play policy
landscape. Scans AndroidManifest.xml, build.gradle, capacitor.config.ts/json,
and package.json.

Outputs:
  - stdout lines in the `[P0] path:line — message` format (for scan_all.py)
  - report.md in the skill directory (for Claude Code integration)

Every finding cites a real evidence URL (see patterns/*.md).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Directories we never want to walk into.
SKIP_DIRS = {
    "node_modules", ".gradle", "build", ".git", "dist", "out", ".venv",
    "venv", ".next", ".turbo", ".idea", "Pods", "DerivedData", "captures",
}

# Play Store current + near-future targetSdk requirements.
# Evidence: https://developer.android.com/google/play/requirements/target-sdk
TARGET_SDK_CURRENT = 34   # required since Aug 2024 for existing apps
TARGET_SDK_NEXT = 35      # required Aug 2025
TARGET_SDK_2026 = 36      # announced for late 2026 cycle

# Sensitive permissions that trigger Play Console Permissions Declaration.
SMS_PERMS = {"READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH"}
CALL_LOG_PERMS = {"READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS"}
BG_LOCATION_PERMS = {"ACCESS_BACKGROUND_LOCATION"}
BROAD_STORAGE_PERMS = {"MANAGE_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"}

# Package-name substrings that commonly trigger deceptive-app takedowns.
# Evidence: Play Store Policy — Impersonation
IMPERSONATION_SUBSTRINGS = {
    "whatsapp", "instagram", "tiktok", "facebook", "messenger", "gmail",
    "youtube", "netflix", "spotify", "telegram", "snapchat", "twitter",
    "googlepay", "paypal", "venmo", "cashapp", "zoom",
}

# Keywords that suggest the app sells digital content → Play Billing required.
BILLING_UI_HINTS = re.compile(
    r"subscrib|paywall|premium|upgrade|unlock\s*pro|pro\s*plan|monthly|annual",
    re.IGNORECASE,
)

# Accessibility-service legitimate use keywords — if the app genuinely
# helps people with disabilities, the BIND_ACCESSIBILITY_SERVICE permission
# is fine. We look for these in README / package.json description.
A11Y_LEGITIMATE_HINTS = re.compile(
    r"screen\s*reader|talk\s*back|braille|low.vision|disabilit|accessib|"
    r"hard.of.hearing|dyslex|autism|adhd.*assist|motor.impair",
    re.IGNORECASE,
)

# Foreground service types required on Android 14+ (targetSdk 34+).
# Evidence: https://developer.android.com/about/versions/14/changes/fgs-types-required
VALID_FGS_TYPES = {
    "camera", "connectedDevice", "dataSync", "health", "location",
    "mediaPlayback", "mediaProcessing", "mediaProjection", "microphone",
    "phoneCall", "remoteMessaging", "shortService", "specialUse", "systemExempted",
}

# Secret patterns (same shape as security skill but narrowed to values that
# typically appear in Android config files).
SECRET_PATTERNS = [
    ("Google API key",       re.compile(r"AIza[A-Za-z0-9_\-]{35}")),
    ("AWS access key",       re.compile(r"AKIA[A-Z0-9]{16}")),
    ("Stripe secret key",    re.compile(r"sk_live_[A-Za-z0-9]{16,}")),
    ("Stripe publishable",   re.compile(r"pk_live_[A-Za-z0-9]{16,}")),
    ("RevenueCat key",       re.compile(r"goog_[A-Za-z0-9]{16,}")),
    ("OpenAI key",           re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Anthropic key",        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("Firebase key (long)",  re.compile(r"1//0[A-Za-z0-9_\-]{40,}")),
]


# ────────────────────────────────────────────────────────────────────────────
# Data structures
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str               # P0 | P1 | P2 | INFO
    file: str                   # relative path (+ :line if known)
    line: Optional[int]
    pattern: str                # short pattern id (matches patterns/*.md)
    message: str
    fix: str = ""
    evidence: str = ""          # URL

    def stdout_line(self, root: Path) -> str:
        loc = self.file
        if self.line:
            loc = f"{loc}:{self.line}"
        return f"[{self.severity}] {loc} — {self.message}"


@dataclass
class AuditResult:
    app_dir: Path
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)  # informational (e.g. "no android folder")

    def add(self, f: Finding) -> None:
        self.findings.append(f)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def _read(p: Path) -> Optional[str]:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def _find_files(root: Path, filename: str, max_results: int = 5) -> List[Path]:
    """Recursively locate files by basename, skipping SKIP_DIRS."""
    results: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if filename in filenames:
            results.append(Path(dirpath) / filename)
            if len(results) >= max_results:
                return results
    return results


def _find_manifest(app: Path) -> Optional[Path]:
    # Capacitor convention: android/app/src/main/AndroidManifest.xml
    # Bare Android: app/src/main/AndroidManifest.xml
    candidates = [
        app / "android/app/src/main/AndroidManifest.xml",
        app / "app/src/main/AndroidManifest.xml",
    ]
    for c in candidates:
        if c.exists():
            return c
    # Fallback: first-found anywhere
    found = _find_files(app, "AndroidManifest.xml", max_results=1)
    return found[0] if found else None


def _find_gradle(app: Path) -> Optional[Path]:
    candidates = [
        app / "android/app/build.gradle",
        app / "app/build.gradle",
        app / "android/app/build.gradle.kts",
        app / "app/build.gradle.kts",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _parse_manifest(manifest_path: Path) -> Tuple[Optional[ET.Element], str]:
    """Returns (root or None, raw text). Parsing failures return (None, raw)."""
    raw = _read(manifest_path) or ""
    try:
        root = ET.fromstring(raw)
        return root, raw
    except ET.ParseError:
        return None, raw


def _manifest_permissions(root: ET.Element) -> List[Tuple[str, ET.Element]]:
    """Returns list of (short_permission_name, element)."""
    out = []
    for perm in root.findall("uses-permission"):
        name = perm.get(f"{ANDROID_NS}name") or ""
        short = name.rsplit(".", 1)[-1]
        out.append((short, perm))
    return out


def _line_in_manifest(raw: str, perm_full: str) -> Optional[int]:
    m = re.search(re.escape(perm_full), raw)
    return _line_of(raw, m.start()) if m else None


# ────────────────────────────────────────────────────────────────────────────
# Individual checks
# ────────────────────────────────────────────────────────────────────────────

def check_manifest_permissions(result: AuditResult, manifest: Path, root: ET.Element, raw: str) -> None:
    """Patterns 2, 3, 4, 5, 11 — permission-driven Play policies."""
    rel = _rel(manifest, result.app_dir)
    perms = _manifest_permissions(root)
    perm_names = {name for name, _ in perms}
    full_perm_map = {name: el.get(f"{ANDROID_NS}name", "") for name, el in perms}

    # Pattern 2 — SMS without DEFAULT_HANDLER intent-filter
    sms_present = SMS_PERMS & perm_names
    if sms_present:
        # The app should register as default SMS handler. Look for SMS_DELIVER
        # intent-filter anywhere in the manifest.
        has_default_handler = "android.provider.Telephony.SMS_DELIVER" in raw
        if not has_default_handler:
            line = _line_in_manifest(raw, full_perm_map[next(iter(sms_present))])
            result.add(Finding(
                severity="P0",
                file=rel, line=line,
                pattern="sms-permissions-without-default-handler",
                message=(
                    f"SMS permission(s) {sorted(sms_present)} declared but app is not the default SMS handler "
                    f"(no SMS_DELIVER intent-filter) — Google Play will reject"
                ),
                fix=(
                    "Either (a) remove SMS permissions, (b) become the default SMS handler by adding "
                    "SMS_DELIVER / WAP_PUSH_DELIVER / SERVICE intent-filters, or (c) submit a Permissions "
                    "Declaration form in Play Console with a compelling justification"
                ),
                evidence="https://support.google.com/googleplay/android-developer/answer/10208820",
            ))

    # Pattern 3 — CALL_LOG without permissions declaration
    call_log_present = CALL_LOG_PERMS & perm_names
    if call_log_present:
        line = _line_in_manifest(raw, full_perm_map[next(iter(call_log_present))])
        result.add(Finding(
            severity="P0",
            file=rel, line=line,
            pattern="call-log-permissions-without-justification",
            message=(
                f"Call Log permission(s) {sorted(call_log_present)} declared — requires a submitted "
                f"Permissions Declaration form in Play Console, not just manifest entry"
            ),
            fix=(
                "Play Console → App Content → Sensitive app permissions → fill Call Log declaration. "
                "Rejection is automatic without it."
            ),
            evidence="https://support.google.com/googleplay/android-developer/answer/10208820",
        ))

    # Pattern 5 — ACCESS_BACKGROUND_LOCATION
    bg_loc_present = BG_LOCATION_PERMS & perm_names
    if bg_loc_present:
        line = _line_in_manifest(raw, full_perm_map[next(iter(bg_loc_present))])
        # Look for any prominent-disclosure string resources or rationale docs
        manifest_dir = manifest.parent
        has_rationale = False
        for f in manifest_dir.rglob("*.xml"):
            if "res/values" in str(f) or "strings.xml" in f.name:
                txt = _read(f) or ""
                if re.search(r"background.*location|location.*background|prominent.*disclosure", txt, re.IGNORECASE):
                    has_rationale = True
                    break
        if not has_rationale:
            result.add(Finding(
                severity="P0",
                file=rel, line=line,
                pattern="background-location-without-prominent-disclosure",
                message=(
                    "ACCESS_BACKGROUND_LOCATION declared but no prominent-disclosure string / rationale found "
                    "— Play Console rejects (or suspends) without in-app disclosure + Console declaration"
                ),
                fix=(
                    "Add an in-app prominent disclosure BEFORE requesting the permission, show why "
                    "background location is necessary, and complete the Play Console Location Permissions form. "
                    "Without this Google remediated 200k+ apps in 2023."
                ),
                evidence="https://support.google.com/googleplay/android-developer/answer/9799150",
            ))

    # Pattern 11 — Broad storage permissions
    broad_storage = BROAD_STORAGE_PERMS & perm_names
    if broad_storage:
        line = _line_in_manifest(raw, full_perm_map[next(iter(broad_storage))])
        bad = sorted(broad_storage)
        sev = "P0" if "MANAGE_EXTERNAL_STORAGE" in broad_storage else "P1"
        result.add(Finding(
            severity=sev,
            file=rel, line=line,
            pattern="broad-storage-permission",
            message=(
                f"Broad storage permission {bad} — new apps using MANAGE_EXTERNAL_STORAGE must pass the "
                f"All Files Access declaration; WRITE_EXTERNAL_STORAGE is ignored on API 30+"
            ),
            fix=(
                "Use Scoped Storage (MediaStore / SAF / ACTION_OPEN_DOCUMENT) instead. If you truly need "
                "MANAGE_EXTERNAL_STORAGE (file manager, backup app), file the All Files Access declaration."
            ),
            evidence="https://support.google.com/googleplay/android-developer/answer/10467955",
        ))


def check_accessibility_service(result: AuditResult, manifest: Path, root: ET.Element, raw: str,
                                 pkg_json_txt: str) -> None:
    """Pattern 4 — ACCESSIBILITY_SERVICE misuse."""
    rel = _rel(manifest, result.app_dir)

    # Find <service ... android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
    has_a11y_service = False
    for svc in root.findall(".//service"):
        perm = svc.get(f"{ANDROID_NS}permission") or ""
        if "BIND_ACCESSIBILITY_SERVICE" in perm:
            has_a11y_service = True
            break
    if not has_a11y_service and "BIND_ACCESSIBILITY_SERVICE" in raw:
        has_a11y_service = True

    if not has_a11y_service:
        return

    # Heuristic: is the app plausibly a disability-assistive tool?
    # Inspect README + package.json description.
    readme_paths = [
        result.app_dir / "README.md",
        result.app_dir / "readme.md",
    ]
    combined = pkg_json_txt
    for rp in readme_paths:
        if rp.exists():
            combined += "\n" + (_read(rp) or "")

    legit = bool(A11Y_LEGITIMATE_HINTS.search(combined))
    line = None
    m = re.search(r"BIND_ACCESSIBILITY_SERVICE", raw)
    if m:
        line = _line_of(raw, m.start())

    severity = "P1" if legit else "P0"
    msg_suffix = (
        " (README/package.json mentions disability-assistive use — still must submit Accessibility "
        "API declaration in Play Console)"
        if legit else
        " and the app's README / package.json does not describe a disability-assistive use case — "
        "dominant Play rejection category in 2025-2026"
    )
    result.add(Finding(
        severity=severity,
        file=rel, line=line,
        pattern="accessibility-service-misuse",
        message=f"BIND_ACCESSIBILITY_SERVICE declared{msg_suffix}",
        fix=(
            "If the app is NOT an assistive-tech product, remove the AccessibilityService entirely. "
            "If it IS, submit the Accessibility API Declaration in Play Console with a video showing the "
            "disability-assistive use case."
        ),
        evidence="https://support.google.com/googleplay/android-developer/answer/10964491",
    ))


def check_target_sdk(result: AuditResult, gradle: Path) -> None:
    """Pattern 6 — targetSdkVersion requirement."""
    rel = _rel(gradle, result.app_dir)
    txt = _read(gradle) or ""
    # Match targetSdkVersion N, targetSdk N, targetSdkVersion = N, and Kotlin DSL
    m = re.search(r"targetSdk(?:Version)?\s*[=\s]\s*(\d+)", txt)
    if not m:
        result.add(Finding(
            severity="P1",
            file=rel, line=None,
            pattern="target-sdk-not-found",
            message="Could not locate targetSdk / targetSdkVersion in build.gradle — required for submission",
            fix="Add `targetSdkVersion 36` (or the latest required value) inside defaultConfig.",
            evidence="https://developer.android.com/google/play/requirements/target-sdk",
        ))
        return

    sdk = int(m.group(1))
    line = _line_of(txt, m.start())
    if sdk < TARGET_SDK_CURRENT:
        result.add(Finding(
            severity="P0",
            file=rel, line=line,
            pattern="target-sdk-too-old",
            message=(
                f"targetSdkVersion {sdk} — Play Store blocks uploads below {TARGET_SDK_CURRENT} "
                f"(Aug 2024 rule); < {TARGET_SDK_NEXT} blocks updates since Aug 2025"
            ),
            fix=f"Bump to targetSdkVersion {TARGET_SDK_2026} and re-test.",
            evidence="https://developer.android.com/google/play/requirements/target-sdk",
        ))
    elif sdk < TARGET_SDK_NEXT:
        result.add(Finding(
            severity="P0",
            file=rel, line=line,
            pattern="target-sdk-too-old",
            message=(
                f"targetSdkVersion {sdk} — below the Aug 2025 minimum of {TARGET_SDK_NEXT}, "
                f"Play Console blocks updates"
            ),
            fix=f"Bump to targetSdkVersion {TARGET_SDK_2026}.",
            evidence="https://developer.android.com/google/play/requirements/target-sdk",
        ))
    elif sdk < TARGET_SDK_2026:
        result.add(Finding(
            severity="P1",
            file=rel, line=line,
            pattern="target-sdk-behind-latest",
            message=(
                f"targetSdkVersion {sdk} — below the {TARGET_SDK_2026} level required for new apps "
                f"in the 2026 cycle; bump proactively"
            ),
            fix=f"Bump to targetSdkVersion {TARGET_SDK_2026}.",
            evidence="https://developer.android.com/google/play/requirements/target-sdk",
        ))


def check_privacy_policy(result: AuditResult, pkg_json_txt: str, capacitor_cfg_txt: str) -> None:
    """Pattern 7 — privacy-policy URL presence."""
    # Look for a privacy-policy URL in package.json, capacitor.config.*, env, or README.
    candidates = [
        ("package.json", pkg_json_txt),
        ("capacitor.config.*", capacitor_cfg_txt),
    ]
    for name in ("README.md", "readme.md", ".env.example", ".env"):
        p = result.app_dir / name
        if p.exists():
            candidates.append((name, _read(p) or ""))

    url_re = re.compile(r"https?://[^\s\"'<>]*priva[a-z]*[^\s\"'<>]*", re.IGNORECASE)
    env_re = re.compile(r"PRIVACY_POLICY_URL\s*=\s*\S+")

    has_url = False
    for _, txt in candidates:
        if url_re.search(txt) or env_re.search(txt):
            has_url = True
            break

    if not has_url:
        result.add(Finding(
            severity="P1",
            file="package.json", line=None,
            pattern="privacy-policy-missing",
            message=(
                "No privacy-policy URL found in package.json / capacitor.config / README / .env — "
                "Play Console requires a reachable privacy-policy URL for apps that handle personal data"
            ),
            fix=(
                "Publish a privacy policy (e.g. on your domain or GitHub Pages) and add the URL to Play "
                "Console → App Content → Privacy Policy. Also reference it in-app on your About screen."
            ),
            evidence="https://support.google.com/googleplay/android-developer/answer/9859455",
        ))


def check_impersonation(result: AuditResult, pkg_json_txt: str, manifest_raw: str) -> None:
    """Pattern 8 — deceptive package/app-name similarity."""
    try:
        pkg = json.loads(pkg_json_txt) if pkg_json_txt else {}
    except json.JSONDecodeError:
        pkg = {}
    name = (pkg.get("name") or "").lower()

    # Also check applicationId in manifest package=""
    m = re.search(r'package\s*=\s*"([^"]+)"', manifest_raw)
    app_id = (m.group(1) if m else "").lower()

    haystack = f"{name} {app_id}"
    hit = next((s for s in IMPERSONATION_SUBSTRINGS if s in haystack), None)
    if hit:
        result.add(Finding(
            severity="P1",
            file="package.json", line=None,
            pattern="deceptive-package-name",
            message=(
                f"Package name / applicationId contains the substring '{hit}' which matches a well-known "
                f"brand — Play Store removes impersonation apps without warning"
            ),
            fix=(
                f"Rename to avoid the '{hit}' substring, or prepare documented brand authorization if you "
                f"genuinely own/license the name. The Deceptive Behavior policy treats this as zero-tolerance."
            ),
            evidence="https://support.google.com/googleplay/android-developer/answer/9888077",
        ))


def check_billing(result: AuditResult, pkg_json_txt: str, app_dir: Path) -> None:
    """Pattern 9 — subscription UI present but no Google Play billing library."""
    try:
        pkg = json.loads(pkg_json_txt) if pkg_json_txt else {}
    except json.JSONDecodeError:
        pkg = {}
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

    # Billing SDKs considered compliant on Capacitor apps.
    BILLING_LIBS = [
        "@revenuecat/purchases-capacitor",
        "capacitor-revenuecat",
        "cordova-plugin-purchase",
        "com.android.billingclient",
    ]
    has_billing = any(lib in deps or any(lib in k for k in deps) for lib in BILLING_LIBS)

    # Also, bare native Android projects: look for implementation 'com.android.billingclient:billing'
    if not has_billing:
        gradle = _find_gradle(app_dir)
        if gradle:
            gtxt = _read(gradle) or ""
            if "com.android.billingclient" in gtxt:
                has_billing = True

    if has_billing:
        return

    # Look for subscription/paywall keywords in src/ (depth-limited)
    src_dirs = [app_dir / "src", app_dir / "www", app_dir / "app/src/main/java"]
    hit_file: Optional[Path] = None
    hit_line: Optional[int] = None
    for d in src_dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.is_dir():
                continue
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".kt", ".java", ".vue"}:
                continue
            txt = _read(p)
            if not txt:
                continue
            m = BILLING_UI_HINTS.search(txt)
            if m:
                hit_file = p
                hit_line = _line_of(txt, m.start())
                break
        if hit_file:
            break

    if hit_file:
        result.add(Finding(
            severity="P0",
            file=_rel(hit_file, result.app_dir), line=hit_line,
            pattern="subscription-ui-without-play-billing",
            message=(
                "App contains paywall / subscription UI but no Google Play Billing library "
                "(RevenueCat-capacitor, cordova-plugin-purchase, or billingclient) is declared"
            ),
            fix=(
                "Add @revenuecat/purchases-capacitor OR com.android.billingclient:billing. Charging for "
                "digital content outside Play Billing is an instant ban (Payments Policy)."
            ),
            evidence="https://support.google.com/googleplay/android-developer/answer/9858738",
        ))


def check_foreground_service(result: AuditResult, manifest: Path, root: ET.Element, raw: str,
                              gradle_path: Optional[Path]) -> None:
    """Pattern 10 — <service> without foregroundServiceType on targetSdk 34+."""
    rel = _rel(manifest, result.app_dir)

    # FGS types are required from targetSdk 34+. If the app is currently below
    # 34 we still surface the issue as P1 since the Play Store will force them
    # to upgrade; the missing types will crash once bumped.
    target_sdk = None
    if gradle_path:
        gtxt = _read(gradle_path) or ""
        m = re.search(r"targetSdk(?:Version)?\s*[=\s]\s*(\d+)", gtxt)
        if m:
            target_sdk = int(m.group(1))
    will_crash = target_sdk is None or target_sdk >= 34

    # FOREGROUND_SERVICE permission is a strong hint the app uses FGS.
    needs_fgs_check = "android.permission.FOREGROUND_SERVICE" in raw

    for svc in root.findall(".//service"):
        fgs_type = svc.get(f"{ANDROID_NS}foregroundServiceType")
        svc_name = svc.get(f"{ANDROID_NS}name", "")
        # If permission granted but no foregroundServiceType AND the service hasn't
        # explicitly been marked as non-FGS, flag it.
        if needs_fgs_check and not fgs_type:
            # Skip AccessibilityService — it's flagged by its own check, and
            # AccessibilityService isn't a foreground service.
            perm = svc.get(f"{ANDROID_NS}permission") or ""
            if "BIND_ACCESSIBILITY_SERVICE" in perm:
                continue
            # Find line number
            m = re.search(re.escape(svc_name), raw) if svc_name else None
            line = _line_of(raw, m.start()) if m else None
            sev = "P1" if will_crash else "P2"
            suffix = (
                "app crashes with MissingForegroundServiceTypeException on Android 14+"
                if will_crash else
                "will crash once the app upgrades to targetSdk 34 (required by Play)"
            )
            result.add(Finding(
                severity=sev,
                file=rel, line=line,
                pattern="foreground-service-type-missing",
                message=(
                    f"<service android:name=\"{svc_name}\"> has no android:foregroundServiceType — "
                    f"required on targetSdk 34+; {suffix}"
                ),
                fix=(
                    "Add android:foregroundServiceType=\"...\" matching the service's purpose. Valid "
                    "values: " + ", ".join(sorted(VALID_FGS_TYPES)) + "."
                ),
                evidence="https://developer.android.com/about/versions/14/changes/fgs-types-required",
            ))
        elif fgs_type and fgs_type not in VALID_FGS_TYPES:
            m = re.search(re.escape(fgs_type), raw)
            line = _line_of(raw, m.start()) if m else None
            result.add(Finding(
                severity="P1",
                file=rel, line=line,
                pattern="foreground-service-type-invalid",
                message=f"foregroundServiceType=\"{fgs_type}\" is not a valid Android 14 value",
                fix="Pick one of: " + ", ".join(sorted(VALID_FGS_TYPES)),
                evidence="https://developer.android.com/about/versions/14/changes/fgs-types-required",
            ))


def check_hardcoded_secrets(result: AuditResult) -> None:
    """Pattern 12 — hardcoded secrets in manifest, strings.xml, build.gradle."""
    candidates: List[Path] = []
    manifest = _find_manifest(result.app_dir)
    if manifest:
        candidates.append(manifest)
    candidates += _find_files(result.app_dir, "strings.xml", max_results=10)
    gradle = _find_gradle(result.app_dir)
    if gradle:
        candidates.append(gradle)
    for name in ("gradle.properties", "local.properties", "google-services.json"):
        candidates += _find_files(result.app_dir, name, max_results=3)

    for p in candidates:
        txt = _read(p)
        if not txt:
            continue
        # google-services.json always contains an AIza key — that's expected.
        # Flag only if the file is tracked AND also contains a service-account private_key.
        if p.name == "google-services.json":
            if "private_key" in txt or "BEGIN PRIVATE KEY" in txt:
                result.add(Finding(
                    severity="P0",
                    file=_rel(p, result.app_dir), line=None,
                    pattern="service-account-in-google-services-json",
                    message="google-services.json contains a private_key — do not ship service-account credentials",
                    fix="Strip private_key. Client config should only carry public keys + project ID.",
                    evidence="https://firebase.google.com/docs/projects/api-keys",
                ))
            continue
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(txt):
                line = _line_of(txt, m.start())
                result.add(Finding(
                    severity="P0",
                    file=_rel(p, result.app_dir), line=line,
                    pattern="hardcoded-secret",
                    message=f"{label} literal found in {p.name} — rotate immediately and move to gradle.properties / secure storage",
                    fix=(
                        "1) Rotate the key in the provider dashboard. 2) Move it to `~/.gradle/gradle.properties` or "
                        "a CI secret. 3) Reference via BuildConfig / manifestPlaceholders, never literal strings."
                    ),
                    evidence="https://developer.android.com/studio/build/shrink-code",
                ))


def check_data_safety_vs_sdk(result: AuditResult, manifest_raw: str, pkg_json_txt: str,
                              gradle_path: Optional[Path]) -> None:
    """Pattern 1 — Data Safety declaration vs actual SDK usage diff (April 15 2026)."""
    # We don't have access to the Play Console declaration file on disk, so we
    # surface signals that commonly cause the April-2026 Data-Safety mismatch
    # rejection: SDKs known to collect/transmit data where no data-safety JSON
    # has been declared in the repo.
    try:
        pkg = json.loads(pkg_json_txt) if pkg_json_txt else {}
    except json.JSONDecodeError:
        pkg = {}
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

    # NOTE: we deliberately exclude RevenueCat from this list because every
    # RevenueCat app discloses "Purchase history" and the common workflow
    # handles that. We focus on SDKs that trigger the April-2026 mismatch:
    # Firebase Analytics, ads, tracking SDKs, crash reporting that gathers PII.
    DATA_COLLECTING_SDKS = {
        "firebase": ["@react-native-firebase", "firebase", "@capacitor-firebase"],
        "analytics (amplitude/mixpanel/segment)": ["amplitude", "mixpanel", "@segment/analytics"],
        "ads": ["@capacitor-community/admob", "react-native-google-mobile-ads"],
        "crash reporting": ["@sentry/capacitor", "@bugsnag", "@datadog"],
    }
    detected = []
    for label, libs in DATA_COLLECTING_SDKS.items():
        for lib in libs:
            if any(lib in k for k in deps):
                detected.append((label, lib))
                break

    # Check gradle for similar signals
    if gradle_path:
        gtxt = _read(gradle_path) or ""
        if "com.google.firebase" in gtxt and not any(d[0].startswith("firebase") for d in detected):
            detected.append(("firebase", "com.google.firebase"))
        if "com.google.android.gms:play-services-ads" in gtxt:
            detected.append(("ads", "play-services-ads"))

    if not detected:
        return

    # Check for declared Data Safety file in repo (some teams keep one)
    ds_file = None
    for name in ("data-safety.json", "data_safety.json", "PLAY_DATA_SAFETY.md"):
        found = _find_files(result.app_dir, name, max_results=1)
        if found:
            ds_file = found[0]
            break

    if ds_file is None:
        labels = ", ".join(sorted({d[0] for d in detected}))
        result.add(Finding(
            severity="P0",
            file="package.json", line=None,
            pattern="data-safety-declaration-vs-sdk-diff",
            message=(
                f"Data-collecting SDKs detected ({labels}) but no data-safety.json / PLAY_DATA_SAFETY.md "
                f"found in repo — the April 15 2026 Data Safety update rejects apps whose Play Console "
                f"declaration doesn't match real SDK data flows"
            ),
            fix=(
                "1) Enumerate every SDK and what it collects. 2) Update Play Console → App Content → "
                "Data Safety to match. 3) Commit a PLAY_DATA_SAFETY.md alongside the code so future "
                "audits catch drift."
            ),
            evidence="https://support.google.com/googleplay/android-developer/answer/10787469",
        ))


# ────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ────────────────────────────────────────────────────────────────────────────

def audit(app_dir: Path) -> AuditResult:
    result = AuditResult(app_dir=app_dir)

    if not app_dir.exists():
        result.notes.append(f"target path does not exist: {app_dir}")
        return result

    manifest_path = _find_manifest(app_dir)
    gradle_path = _find_gradle(app_dir)
    pkg_json_path = app_dir / "package.json"
    pkg_json_txt = _read(pkg_json_path) or ""

    # Capacitor config (could be .ts, .js, or .json)
    cap_txt = ""
    for name in ("capacitor.config.ts", "capacitor.config.js", "capacitor.config.json"):
        p = app_dir / name
        if p.exists():
            cap_txt = _read(p) or ""
            break

    if not manifest_path and not gradle_path:
        # No Android surface — nothing to audit.
        result.notes.append(
            "No AndroidManifest.xml or android/app/build.gradle found; skipping Android checks."
        )
        # But we can still run the privacy-policy check at project level if a
        # package.json exists and suggests a mobile app.
        if pkg_json_path.exists():
            check_privacy_policy(result, pkg_json_txt, cap_txt)
        return result

    manifest_root: Optional[ET.Element] = None
    manifest_raw = ""
    if manifest_path:
        manifest_root, manifest_raw = _parse_manifest(manifest_path)
        if manifest_root is None:
            result.add(Finding(
                severity="P1",
                file=_rel(manifest_path, app_dir), line=None,
                pattern="manifest-parse-error",
                message="AndroidManifest.xml could not be parsed as XML — fix syntax before submitting",
                fix="Open the manifest in Android Studio to surface the parser error.",
                evidence="https://developer.android.com/guide/topics/manifest/manifest-intro",
            ))

    # Run checks (skip gracefully if their inputs are missing)
    if manifest_root is not None and manifest_path is not None:
        check_manifest_permissions(result, manifest_path, manifest_root, manifest_raw)
        check_accessibility_service(result, manifest_path, manifest_root, manifest_raw, pkg_json_txt)
        check_foreground_service(result, manifest_path, manifest_root, manifest_raw, gradle_path)

    if gradle_path is not None:
        check_target_sdk(result, gradle_path)

    check_privacy_policy(result, pkg_json_txt, cap_txt)
    check_impersonation(result, pkg_json_txt, manifest_raw)
    check_billing(result, pkg_json_txt, app_dir)
    check_hardcoded_secrets(result)
    check_data_safety_vs_sdk(result, manifest_raw, pkg_json_txt, gradle_path)

    return result


# ────────────────────────────────────────────────────────────────────────────
# Report rendering
# ────────────────────────────────────────────────────────────────────────────

def format_markdown(result: AuditResult) -> str:
    total = len(result.findings)
    by_sev = {"P0": [], "P1": [], "P2": [], "INFO": []}
    for f in result.findings:
        by_sev.setdefault(f.severity, []).append(f)

    emoji = "🟢" if total == 0 else ("🟡" if not by_sev["P0"] else "🔴")
    name = result.app_dir.name

    out: List[str] = []
    out.append(f"# {emoji} Google Play Store Audit — {name}")
    out.append("")
    out.append(f"**Target:** `{result.app_dir}`")
    out.append(f"**Total findings:** {total} "
               f"({len(by_sev['P0'])} P0, {len(by_sev['P1'])} P1, {len(by_sev['P2'])} P2)")
    out.append("")

    if result.notes:
        out.append("## Notes")
        for n in result.notes:
            out.append(f"- {n}")
        out.append("")

    labels = [
        ("P0", "🔴 Blocking (P0) — Play Console will reject or suspend"),
        ("P1", "🟡 Likely (P1) — probable rejection or policy strike"),
        ("P2", "🟢 Possible (P2) — review manually"),
    ]
    for sev, label in labels:
        items = by_sev.get(sev, [])
        if not items:
            continue
        out.append(f"## {label}")
        out.append("")
        for i, f in enumerate(items, 1):
            loc = f.file + (f":{f.line}" if f.line else "")
            out.append(f"### {sev}.{i} [{f.pattern}] {f.message}")
            out.append(f"- **Location:** `{loc}`")
            if f.fix:
                out.append(f"- **Fix:** {f.fix}")
            if f.evidence:
                out.append(f"- **Evidence:** {f.evidence}")
            out.append("")

    if total == 0:
        out.append("## No automated findings")
        out.append("")
        out.append("Run `checklist.md` manually before submitting — screenshots, store listing, "
                   "target-country compliance, and Data Safety answers cannot be detected automatically.")

    return "\n".join(out) + "\n"


def format_json(result: AuditResult) -> str:
    payload = {
        "target": str(result.app_dir),
        "notes": result.notes,
        "findings": [asdict(f) for f in result.findings],
        "summary": {
            "P0": sum(1 for f in result.findings if f.severity == "P0"),
            "P1": sum(1 for f in result.findings if f.severity == "P1"),
            "P2": sum(1 for f in result.findings if f.severity == "P2"),
        },
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Google Play Store pre-submission audit")
    p.add_argument("target", help="Path to the app root (contains android/ or capacitor.config.*)")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of stdout findings")
    p.add_argument("--no-report", action="store_true", help="Do not write report.md in the skill dir")
    args = p.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"[ERROR] target not found: {target}", file=sys.stderr)
        return 2

    try:
        result = audit(target)
    except Exception as e:  # defensive: never crash scan_all.py
        print(f"[ERROR] audit crashed: {e}", file=sys.stderr)
        return 2

    # 1. stdout in the standard [PX] path:line — message format.
    if args.json:
        print(format_json(result))
    else:
        for f in result.findings:
            print(f.stdout_line(target))

    # 2. report.md in the skill dir (match apple-app-store convention)
    if not args.no_report:
        try:
            report_path = Path(__file__).parent / "report.md"
            report_path.write_text(format_markdown(result), encoding="utf-8")
        except OSError:
            pass  # best-effort

    # Exit code contract: 0 = no findings, 1 = findings but scan OK, 2 = crash
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
