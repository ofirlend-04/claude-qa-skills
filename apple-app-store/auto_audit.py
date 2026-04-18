#!/usr/bin/env python3
"""Automated Apple App Store pre-submission audit.

Usage:
    python auto_audit.py /path/to/app_folder

Runs 10 deterministic checks based on real rejection patterns.
Outputs markdown report with file:line locations.
"""
import os
import re
import sys
from pathlib import Path


def audit(app_dir: str) -> dict:
    app = Path(app_dir)
    issues = {"p0": [], "p1": [], "p2": []}

    # 1. RC key placeholder
    rc = app / "src/rc.js"
    if rc.exists():
        txt = rc.read_text()
        if "YOUR_" in txt or "PLACEHOLDER" in txt:
            m = re.search(r"YOUR_\w+|PLACEHOLDER", txt)
            line = txt[:m.start()].count("\n") + 1 if m else 1
            issues["p0"].append({
                "file": f"src/rc.js:{line}", "rule": "2.1(b)",
                "issue": "Placeholder API key", "fix": "Create RC app, use real key"
            })

        # 2. No getProducts fallback
        if "getProducts" not in txt and "Purchases.getProducts" not in txt:
            issues["p1"].append({
                "file": "src/rc.js", "rule": "2.1(b)",
                "issue": "No StoreKit fallback when offerings empty",
                "fix": "Add getProducts() fallback in purchasePackage"
            })

    # 3. Hardcoded 'annual' in purchase
    app_jsx = app / "src/App.jsx"
    if app_jsx.exists():
        txt = app_jsx.read_text()

        for m in re.finditer(r"purchasePackage\(['\"]annual['\"]", txt):
            line = txt[:m.start()].count("\n") + 1
            issues["p0"].append({
                "file": f"src/App.jsx:{line}", "rule": "2.1(a)",
                "issue": "purchasePackage('annual') hardcoded",
                "fix": "purchasePackage(selectedPlan || 'annual')"
            })

        # 4. Lifetime references
        for pattern in [r"lifetime", r"forever", r"לנצח", r"חד פעמי", r"one-time"]:
            for m in re.finditer(pattern, txt, re.IGNORECASE):
                line = txt[:m.start()].count("\n") + 1
                # Skip if in comment
                line_text = txt.split("\n")[line-1]
                if "//" in line_text[:line_text.find(pattern)] if pattern in line_text else False:
                    continue
                issues["p1"].append({
                    "file": f"src/App.jsx:{line}", "rule": "2.1(b)",
                    "issue": f"Lifetime reference: '{pattern}'",
                    "fix": "Remove — no matching IAP product"
                })
                break  # Just one per pattern

        # 5. Button not disabled
        if "<button" in txt and "disabled={" not in txt:
            if "Subscribe" in txt or "Start Trial" in txt or "paywall" in txt.lower():
                issues["p1"].append({
                    "file": "src/App.jsx", "rule": "2.1(b)",
                    "issue": "Paywall button may not have disabled state",
                    "fix": "Add disabled={plans.length === 0}"
                })

        # 6. Premium hardcoded true
        for m in re.finditer(r"premium:\s*true|isPremium:\s*true", txt):
            line = txt[:m.start()].count("\n") + 1
            issues["p0"].append({
                "file": f"src/App.jsx:{line}", "rule": "2.1(a)",
                "issue": "Premium/isPremium hardcoded to true",
                "fix": "Set to false; only true after checkPremium()"
            })

        # 7. EULA/Terms link in paywall
        if "paywall" in txt.lower() and not re.search(r"terms.*of.*use|privacy.*policy|תנאי.*שימוש", txt, re.IGNORECASE):
            issues["p1"].append({
                "file": "src/App.jsx", "rule": "3.1.2(c)",
                "issue": "Paywall may be missing Terms/Privacy link",
                "fix": "Add clickable Terms of Use link in paywall"
            })

    # 9. iPad support + narrow container
    pbxproj = app / "ios/App/App.xcodeproj/project.pbxproj"
    if pbxproj.exists():
        txt = pbxproj.read_text()
        if '"1,2"' in txt and app_jsx.exists():
            jsx_txt = app_jsx.read_text()
            if re.search(r"maxWidth:\s*['\"]*\d+['\"]*", jsx_txt):
                max_w = re.search(r"maxWidth:\s*['\"]*(\d+)", jsx_txt)
                if max_w and int(max_w.group(1)) < 600:
                    issues["p1"].append({
                        "file": "ios/App/App.xcodeproj/project.pbxproj", "rule": "4",
                        "issue": f"iPad supported but maxWidth {max_w.group(1)}px (tiny on iPad)",
                        "fix": "Either set TARGETED_DEVICE_FAMILY = \"1\" or add responsive CSS"
                    })

    # 10. usesNonExemptEncryption
    info_plist = app / "ios/App/App/Info.plist"
    if info_plist.exists():
        txt = info_plist.read_text()
        if "ITSAppUsesNonExemptEncryption" not in txt:
            issues["p1"].append({
                "file": "ios/App/App/Info.plist", "rule": "Submission",
                "issue": "ITSAppUsesNonExemptEncryption not set",
                "fix": "Add <key>ITSAppUsesNonExemptEncryption</key><false/>"
            })

    return issues


def format_report(app_name: str, issues: dict) -> str:
    total = sum(len(v) for v in issues.values())
    emoji = "🟢" if total == 0 else ("🟡" if not issues["p0"] else "🔴")

    md = f"# {emoji} Apple App Store Audit — {app_name}\n\n"
    md += f"**Total issues:** {total} ({len(issues['p0'])} P0, {len(issues['p1'])} P1, {len(issues['p2'])} P2)\n\n"

    for tier, label in [("p0", "🔴 Blocking (P0) — will be rejected"),
                         ("p1", "🟡 Likely (P1) — probably rejected"),
                         ("p2", "🟢 Possible (P2) — review manually")]:
        if issues[tier]:
            md += f"## {label}\n\n"
            for i, item in enumerate(issues[tier], 1):
                md += f"### {i}. {item['issue']}\n"
                md += f"- **File:** `{item['file']}`\n"
                md += f"- **Rule:** Guideline {item['rule']}\n"
                md += f"- **Fix:** {item['fix']}\n\n"

    if total == 0:
        md += "## ✅ No blocking issues found\n\n"
        md += "Manual checks still needed:\n"
        md += "- [ ] Screenshots show app in use (not splash/login)\n"
        md += "- [ ] IAP subscriptions have review screenshots in ASC\n"
        md += "- [ ] App name doesn't imply kids content (Guideline 2.3.8)\n"
        md += "- [ ] Medical apps have citations + disclaimers\n"

    return md


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python auto_audit.py /path/to/app_folder")
        sys.exit(1)

    app_dir = sys.argv[1]
    app_name = os.path.basename(os.path.abspath(app_dir))
    issues = audit(app_dir)
    print(format_report(app_name, issues))
