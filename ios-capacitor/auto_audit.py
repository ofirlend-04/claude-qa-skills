#!/usr/bin/env python3
"""Automated Capacitor + iOS code quality audit.

Usage:
    python auto_audit.py /path/to/app_folder

Runs 20 deterministic checks based on real bugs from 30+ shipped apps.
Outputs markdown report with file:line locations.

This is the CODE-QUALITY audit (crashes, broken purchases, stale sync, misconfig).
For App Store review guideline risk, use ../apple-app-store/auto_audit.py.
"""
import json
import os
import re
import sys
from pathlib import Path


# ---------- helpers ----------

def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def find_first(patterns, root: Path, names):
    """Return first existing path from root matching any of the candidate names."""
    for n in names:
        p = root / n
        if p.exists():
            return p
    return None


def plist_get(text: str, key: str) -> str | None:
    """Very small plist value getter for <key>K</key><string>V</string>."""
    m = re.search(
        rf"<key>{re.escape(key)}</key>\s*<string>([^<]*)</string>", text
    )
    return m.group(1) if m else None


def plist_has_key(text: str, key: str) -> bool:
    return re.search(rf"<key>{re.escape(key)}</key>", text) is not None


# ---------- audit ----------

def audit(app_dir: str) -> dict:
    app = Path(app_dir)
    issues = {"p0": [], "p1": [], "p2": []}

    src = app / "src"
    rc = find_first(None, app, ["src/rc.js", "src/rc.ts"])
    app_jsx = find_first(None, app, ["src/App.jsx", "src/App.tsx", "src/App.js"])
    main_jsx = find_first(None, app, ["src/main.jsx", "src/main.tsx"])
    info_plist = find_first(None, app, ["ios/App/App/Info.plist"])
    pbxproj = find_first(None, app, ["ios/App/App.xcodeproj/project.pbxproj"])
    cap_cfg = find_first(
        None, app,
        ["capacitor.config.ts", "capacitor.config.js", "capacitor.config.json"]
    )
    pkg_json = find_first(None, app, ["package.json"])
    ios_public = app / "ios/App/App/public"

    rc_txt = read(rc) if rc else ""
    jsx_txt = read(app_jsx) if app_jsx else ""
    main_txt = read(main_jsx) if main_jsx else ""
    info_txt = read(info_plist) if info_plist else ""
    pbx_txt = read(pbxproj) if pbxproj else ""
    cap_txt = read(cap_cfg) if cap_cfg else ""
    pkg_txt = read(pkg_json) if pkg_json else ""

    # Aggregate all JS/JSX/TS text for broad checks (bounded)
    all_src_text = ""
    all_src_files: list[tuple[Path, str]] = []
    if src.exists():
        for p in src.rglob("*"):
            if p.suffix in {".js", ".jsx", ".ts", ".tsx"} and p.is_file():
                t = read(p)
                all_src_text += "\n" + t
                all_src_files.append((p, t))

    # ---- 1. RC_API_KEY placeholder ----
    if rc_txt:
        m = re.search(r"YOUR_\w+|PLACEHOLDER|REPLACE_ME|<RC_KEY>", rc_txt)
        if m:
            issues["p0"].append({
                "n": 1, "title": "RC_API_KEY is a placeholder",
                "file": f"{rc.relative_to(app)}:{line_of(rc_txt, m.start())}",
                "fix": "Replace with real app_xxxxxxxxx from RevenueCat dashboard.",
            })

        # ---- 2. Missing getProducts / purchaseStoreProduct fallback ----
        if "getProducts" not in rc_txt and "purchaseStoreProduct" not in rc_txt:
            issues["p0"].append({
                "n": 2, "title": "rc.js missing StoreKit fallback",
                "file": str(rc.relative_to(app)),
                "fix": "Add Purchases.getProducts + purchaseStoreProduct fallback "
                       "when offerings.current is null.",
            })

        # ---- 14. offerings.current used without a fallback path ----
        if "offerings.current" in rc_txt and "getProducts" not in rc_txt:
            issues["p0"].append({
                "n": 14, "title": "offerings.current has no fallback — dead paywall in sandbox",
                "file": str(rc.relative_to(app)),
                "fix": "Add getProducts fallback (see pattern 2).",
            })

    # ---- 3. Hardcoded purchasePackage('annual'|'monthly'|'yearly') ----
    for path, t in all_src_files:
        for m in re.finditer(
            r"purchasePackage\(\s*['\"](annual|monthly|yearly)['\"]", t
        ):
            issues["p0"].append({
                "n": 3, "title": f"purchasePackage('{m.group(1)}') hardcoded",
                "file": f"{path.relative_to(app)}:{line_of(t, m.start())}",
                "fix": "purchasePackage(selectedPlan || 'annual')",
            })

    # ---- 4. premium: true / isPremium: true in initial state ----
    for path, t in all_src_files:
        for m in re.finditer(
            r"\b(premium|isPremium|isPro)\s*:\s*true\b", t
        ):
            # Allow `premium: true` inside an if-branch that follows checkPremium
            line_text = t.split("\n")[line_of(t, m.start()) - 1]
            if "checkPremium" in line_text or "setIsPremium" in line_text:
                continue
            issues["p0"].append({
                "n": 4, "title": f"{m.group(1)} hardcoded to true in state",
                "file": f"{path.relative_to(app)}:{line_of(t, m.start())}",
                "fix": f"{m.group(1)}: false — flip true only after checkPremium().",
            })

    # ---- 5. cap sync stale (src newer than ios/App/App/public) ----
    if ios_public.exists() and src.exists():
        try:
            public_mtime = max(
                (p.stat().st_mtime for p in ios_public.rglob("*") if p.is_file()),
                default=0,
            )
            newer_src = [
                p for p in src.rglob("*")
                if p.is_file()
                and p.suffix in {".js", ".jsx", ".ts", ".tsx", ".css", ".html"}
                and p.stat().st_mtime > public_mtime + 2
            ]
            if newer_src:
                issues["p1"].append({
                    "n": 5, "title": "cap sync is stale — src/ newer than ios/App/App/public/",
                    "file": str(newer_src[0].relative_to(app)),
                    "fix": "Run: npm run build && npx cap sync ios",
                })
        except Exception:
            pass
    elif src.exists() and not ios_public.exists():
        issues["p1"].append({
            "n": 5, "title": "ios/App/App/public missing — cap sync never ran",
            "file": "ios/App/App/",
            "fix": "Run: npm run build && npx cap sync ios",
        })

    # ---- 6. Info.plist missing ITSAppUsesNonExemptEncryption ----
    if info_txt and not plist_has_key(info_txt, "ITSAppUsesNonExemptEncryption"):
        issues["p1"].append({
            "n": 6, "title": "Info.plist missing ITSAppUsesNonExemptEncryption",
            "file": str(info_plist.relative_to(app)),
            "fix": "Add <key>ITSAppUsesNonExemptEncryption</key><false/>",
        })

    # ---- 7. Bundle ID mismatch ----
    cap_app_id = None
    if cap_txt:
        m = re.search(r"appId\s*:\s*['\"]([^'\"]+)['\"]", cap_txt)
        if not m and cap_cfg.suffix == ".json":
            try:
                cap_app_id = json.loads(cap_txt).get("appId")
            except Exception:
                pass
        elif m:
            cap_app_id = m.group(1)

    pbx_bundle_ids = list(
        set(re.findall(r"PRODUCT_BUNDLE_IDENTIFIER\s*=\s*([^;\s]+);", pbx_txt))
    )
    if cap_app_id and pbx_bundle_ids:
        mismatches = [b for b in pbx_bundle_ids if b.strip('"') != cap_app_id]
        if mismatches:
            issues["p0"].append({
                "n": 7, "title": "Bundle ID mismatch",
                "file": f"capacitor.config vs project.pbxproj",
                "fix": f"capacitor={cap_app_id} vs xcode={', '.join(mismatches)}. "
                       "Pick one, fix both, cap sync.",
            })

    # ---- 8. WiFi scan without NSLocalNetworkUsageDescription ----
    scans_network = bool(
        re.search(
            r"Bonjour|NetworkDevices|net\.scan|wifi.?scan|local.?network",
            all_src_text, re.IGNORECASE,
        )
    )
    if scans_network and info_txt and not plist_has_key(
        info_txt, "NSLocalNetworkUsageDescription"
    ):
        issues["p0"].append({
            "n": 8, "title": "Local network scan without NSLocalNetworkUsageDescription",
            "file": str(info_plist.relative_to(app)) if info_plist else "Info.plist",
            "fix": "Add NSLocalNetworkUsageDescription + NSBonjourServices to Info.plist.",
        })

    # ---- 9. Notifications plugin used but no NSUserNotificationsUsageDescription ----
    has_notifs = (
        "@capacitor/local-notifications" in pkg_txt
        or "@capacitor/push-notifications" in pkg_txt
    )
    if has_notifs and info_txt and not plist_has_key(
        info_txt, "NSUserNotificationsUsageDescription"
    ):
        issues["p1"].append({
            "n": 9, "title": "Notifications plugin used without NSUserNotificationsUsageDescription",
            "file": str(info_plist.relative_to(app)) if info_plist else "Info.plist",
            "fix": "Add NSUserNotificationsUsageDescription to Info.plist.",
        })

    # ---- 10. Deprecated trigger API ----
    for path, t in all_src_files:
        for m in re.finditer(r"trigger\s*:\s*\{\s*at\s*:", t):
            issues["p1"].append({
                "n": 10, "title": "LocalNotifications using deprecated `trigger: { at }`",
                "file": f"{path.relative_to(app)}:{line_of(t, m.start())}",
                "fix": "Rename `trigger` -> `schedule`: schedule: { at: new Date(...) }",
            })

    # ---- 11 & 18. CFBundleDisplayName ----
    if info_txt:
        display_name = plist_get(info_txt, "CFBundleDisplayName") or ""
        if display_name:
            if any(ord(c) > 127 for c in display_name):
                issues["p1"].append({
                    "n": 18, "title": f"CFBundleDisplayName contains non-ASCII/emoji: '{display_name}'",
                    "file": str(info_plist.relative_to(app)),
                    "fix": "Remove emoji/non-ASCII from CFBundleDisplayName.",
                })
            if len(display_name) > 12:
                issues["p1"].append({
                    "n": 11, "title": f"CFBundleDisplayName too long ({len(display_name)} chars): '{display_name}'",
                    "file": str(info_plist.relative_to(app)),
                    "fix": "Shorten to <= 12 chars to avoid home-screen truncation.",
                })

    # ---- 12. TARGETED_DEVICE_FAMILY = "1,2" with narrow maxWidth ----
    if '"1,2"' in pbx_txt:
        narrow = None
        for path, t in all_src_files:
            m = re.search(r"maxWidth\s*:\s*['\"]?(\d+)(px)?['\"]?", t)
            if m and int(m.group(1)) < 600:
                narrow = (path, m.group(1), m.start(), t)
                break
        if narrow:
            path, w, idx, t = narrow
            issues["p1"].append({
                "n": 12, "title": f"TARGETED_DEVICE_FAMILY='1,2' but root maxWidth={w}px",
                "file": f"{path.relative_to(app)}:{line_of(t, idx)}",
                "fix": "Either set TARGETED_DEVICE_FAMILY='1' or add responsive layout >=768px.",
            })

    # ---- 13. ErrorBoundary missing ----
    if all_src_text and not re.search(
        r"ErrorBoundary|componentDidCatch|getDerivedStateFromError", all_src_text
    ):
        issues["p1"].append({
            "n": 13, "title": "No React ErrorBoundary anywhere in src/",
            "file": "src/",
            "fix": "Wrap <App/> in an ErrorBoundary in main.jsx to avoid white-screen crashes.",
        })

    # ---- 16. localhost URL in source ----
    for path, t in all_src_files:
        for m in re.finditer(r"https?://(localhost|127\.0\.0\.1|[a-z0-9-]+\.ngrok\.[a-z]+)", t):
            issues["p1"].append({
                "n": 16, "title": f"Dev URL leaked into source: {m.group(0)}",
                "file": f"{path.relative_to(app)}:{line_of(t, m.start())}",
                "fix": "Replace with production URL (privacy policy, terms, API).",
            })
            break  # one per file

    # ---- 17. Lifetime references without matching RC product ----
    lifetime_hits = []
    for path, t in all_src_files:
        for m in re.finditer(
            r"lifetime|forever|לכל החיים|חד פעמי|one-time|pay once",
            t, re.IGNORECASE,
        ):
            lifetime_hits.append((path, line_of(t, m.start()), m.group(0)))
            break
    rc_has_lifetime = bool(
        re.search(r"lifetime\s*:\s*['\"]", rc_txt, re.IGNORECASE)
    )
    if lifetime_hits and not rc_has_lifetime:
        path, ln, word = lifetime_hits[0]
        issues["p1"].append({
            "n": 17, "title": f"Lifetime plan shown in UI ('{word}') but no 'lifetime' entry in PRODUCT_IDS",
            "file": f"{path.relative_to(app)}:{ln}",
            "fix": "Either remove lifetime UI or add a lifetime product in RC + PRODUCT_IDS.",
        })

    # ---- 19. CURRENT_PROJECT_VERSION suspiciously low ----
    cpvs = re.findall(r"CURRENT_PROJECT_VERSION\s*=\s*(\d+)", pbx_txt)
    if cpvs:
        try:
            if min(int(v) for v in cpvs) <= 1:
                issues["p2"].append({
                    "n": 19, "title": f"CURRENT_PROJECT_VERSION = {min(int(v) for v in cpvs)} — bump before resubmit",
                    "file": str(pbxproj.relative_to(app)),
                    "fix": "Increment CURRENT_PROJECT_VERSION each upload.",
                })
        except ValueError:
            pass

    # ---- 20. MARKETING_VERSION vs rejection note ----
    rejection_notes = list(app.glob("*REJECTION*")) + list(app.glob("*rejection*"))
    mvs = re.findall(r"MARKETING_VERSION\s*=\s*([\d.]+)", pbx_txt)
    if rejection_notes and mvs and all(v == "1.0" for v in mvs):
        issues["p1"].append({
            "n": 20, "title": "Rejection notes present but MARKETING_VERSION still 1.0",
            "file": str(pbxproj.relative_to(app)) if pbxproj else "project.pbxproj",
            "fix": "Bump MARKETING_VERSION (e.g. 1.0 -> 1.1) for the resubmission.",
        })

    return issues


# ---------- report ----------

def format_report(app_name: str, issues: dict) -> str:
    total = sum(len(v) for v in issues.values())
    status = "OK" if total == 0 else ("WARN" if not issues["p0"] else "BLOCK")

    out = [f"# Capacitor iOS QA — {app_name}  [{status}]\n"]
    out.append(
        f"**Total:** {total} issues "
        f"({len(issues['p0'])} P0, {len(issues['p1'])} P1, {len(issues['p2'])} P2)\n"
    )

    labels = [
        ("p0", "P0 — Crash / Broken Purchase (must fix before any build)"),
        ("p1", "P1 — Rejection risk / Broken feature"),
        ("p2", "P2 — Warnings / Cleanup"),
    ]
    for tier, label in labels:
        if not issues[tier]:
            continue
        out.append(f"\n## {label}\n")
        for i, item in enumerate(issues[tier], 1):
            out.append(f"### {i}. [Pattern #{item['n']}] {item['title']}")
            out.append(f"- **File:** `{item['file']}`")
            out.append(f"- **Fix:** {item['fix']}\n")

    out.append("\n## Manual checks (not detectable from code)\n")
    out.append("- [ ] RevenueCat dashboard has `current` offering with attached products")
    out.append("- [ ] Entitlement has products attached (RC dashboard)")
    out.append("- [ ] CURRENT_PROJECT_VERSION incremented since last ASC upload")
    out.append("- [ ] MARKETING_VERSION bumped since last rejection")
    out.append("- [ ] `npx cap sync ios` run after every JS change")
    out.append("- [ ] Subscription products submitted WITH the app binary in ASC")

    return "\n".join(out) + "\n"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python auto_audit.py /path/to/app_folder")
        sys.exit(1)

    app_dir = sys.argv[1]
    if not Path(app_dir).is_dir():
        print(f"Not a directory: {app_dir}")
        sys.exit(1)

    app_name = os.path.basename(os.path.abspath(app_dir))
    issues = audit(app_dir)
    print(format_report(app_name, issues))

    # Exit code: 2 if any P0, 1 if any P1, 0 otherwise
    if issues["p0"]:
        sys.exit(2)
    if issues["p1"]:
        sys.exit(1)
    sys.exit(0)
