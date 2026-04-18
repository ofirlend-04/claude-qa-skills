# web-ui QA skill

Finds broken links, accessibility violations, RTL bugs, responsive issues, performance problems, SEO gaps, leaked secrets, and dead code in any web project.

**Specialised for Hebrew/RTL.** Most web QA tools assume English. This one doesn't.

## Layout

```
web-ui/
├── SKILL.md                # Claude Code skill definition — 50+ rules
├── auto_audit.py           # Static + live HTTP scanner (Python)
├── playwright_checks.js    # Browser-based scanner (Node/Playwright + axe-core)
├── checklist.md            # Manual human checklist
├── patterns/               # Real-bug pattern library (detailed)
└── examples/               # Before/after HTML snippets
```

## Quick start

### Python scanner (zero-browser)

```bash
pip install -r requirements.txt
# Scan a live URL
python auto_audit.py https://mysite.com
# Scan a source folder
python auto_audit.py ./my-nextjs-app
```

Outputs `report.md` (human) + `report.json` (machine) in the current directory.

### Browser scanner (full fidelity)

```bash
npm install playwright @axe-core/playwright
npx playwright install chromium
node playwright_checks.js https://mysite.com
```

Outputs findings appended to `report.md` plus `screenshots/{mobile,tablet,desktop}.png`.

### Manual

Open `checklist.md` and work through it for things scripts can't catch (copy, UX flow, screen reader output).

## How Claude uses it

When you open an HTML/JSX/TSX file, Claude Code auto-loads `SKILL.md`. Ask:

> audit my website for accessibility and RTL bugs

Claude will:

1. Run `auto_audit.py` on the project root.
2. Optionally run `playwright_checks.js` against localhost or staging.
3. Read the generated `report.md` and elaborate with context-aware findings.
4. Apply fixes on request, using the patterns in `patterns/` as templates.

## Rules

See `SKILL.md` for the full rule library (50+ rules, labelled A1–G6). Each rule cites WCAG where applicable, with severity (P0/P1/P2) and a real-bug link.

## Extending

Found a new bug in your own project? Add it:

1. Write a pattern file in `patterns/pattern-<slug>.md` with title, bad code, good code, how to detect, severity.
2. If it's script-detectable, add a check to `auto_audit.py` or `playwright_checks.js`.
3. Add a one-liner to the rule library in `SKILL.md`.
