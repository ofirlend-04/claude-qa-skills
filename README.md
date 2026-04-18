# Claude QA Skills

> Specialized QA auditors for Claude Code. Built from 30+ real production failures.

Every rule in this repo was extracted from an actual bug that cost us time.
No generic "best practices" — only patterns that bit us in production.

## Skills

| Skill | What it finds | Evidence |
|-------|---------------|----------|
| [`apple-app-store`](./apple-app-store/) | App Store rejection risks before submission | 30+ real rejections we fixed |
| [`ios-capacitor`](./ios-capacitor/) | Capacitor + RevenueCat + iOS code quality bugs | 36 shipped apps |
| [`web-ui`](./web-ui/) | a11y + RTL + performance + SEO. **RTL/Hebrew first-class.** | JARVIS dashboard, Editox editor, landing pages |

## Proven on first run

We ran these against our own code. Here's what they found:

```
ios-capacitor auto_audit  →  36 apps scanned in 30 seconds
  - 6 apps: StoreKit fallback missing (P0 — crashes purchase)
  - 26 apps: Bundle ID mismatch between capacitor.config and Xcode
  - 36 apps: ErrorBoundary missing (white-screen crashes)
  - 36 apps: Info.plist missing usage descriptions

web-ui auto_audit  →  Editox v5-editor scanned
  - 34 × dir="rtl" missing on Hebrew text
  - 27 × icon buttons without aria-label
  - 24 × onClick on <div> (not keyboard-accessible)
  - 85 P0 findings total, with file:line
```

**30 seconds of scanning caught bugs that would have cost us weeks of App Store re-submissions.**

## Quick start

### With Claude Code (auto-load on file match)
```bash
cd ~/.claude/skills
git clone https://github.com/YOUR_USERNAME/claude-qa-skills
```

Skills auto-load when Claude detects matching file patterns:
- Open a Capacitor app → `ios-capacitor` auto-loads
- Edit HTML/TSX → `web-ui` auto-loads
- Review app_protfolio → `apple-app-store` auto-loads

### Standalone (run the Python scanners)
```bash
# Apple App Store pre-submission audit
python3 apple-app-store/auto_audit.py /path/to/capacitor/app

# Capacitor iOS code review
python3 ios-capacitor/auto_audit.py /path/to/capacitor/app

# Web UI audit (folder or URL)
python3 web-ui/auto_audit.py ./my-nextjs-project
python3 web-ui/auto_audit.py https://mysite.com
```

Exit codes: `2` if any P0, `1` if any P1, `0` if clean — perfect for CI.

## What makes this different

### 1. Evidence-based
Every rule references a real incident. Example:
```markdown
### Pattern #1: RC_API_KEY = 'YOUR_RC_KEY_HERE'
**Incident:** WiFi Guardian, April 9 2026 — Apple rejected because
placeholder key meant purchases never worked in sandbox.
```

### 2. Executable
Scripts that run. Not just documentation.

### 3. RTL/Hebrew first-class (web-ui)
Nobody else checks Hebrew layouts. axe-core has basic `lang` checks. Lighthouse ignores it.
We check:
- `dir="rtl"` presence
- `margin-left` / `padding-right` instead of `-start`/`-end`
- Font stack supports Hebrew
- Dates formatted for `he-IL` locale
- Icons that should flip (arrows, carets)

### 4. Claude Code native
Skills have YAML frontmatter that tells Claude when to auto-activate.

## Contributing

Found a production bug you wish a QA tool caught? Open a PR with:
1. One-paragraph incident story (dated, what broke)
2. Bad code example
3. Good code example
4. Detection regex or script
5. Severity classification (P0/P1/P2)

## License

MIT. Use freely. If this saves you from an Apple rejection, consider starring the repo.

## About

Built by [@ofirlend-04](https://github.com/ofirlend-04) while shipping [Editox](https://editox.ai) (AI video editing) and 30+ iOS apps.
Most of these rules came from Apple rejections we fixed the hard way.
