# How to Add a New Skill

Every skill in this repo follows the same shape so the multi-skill runner
(`scan_all.py`) and the GitHub Action can invoke them uniformly.

## Folder Structure

```
qa-skills/
  my-new-skill/
    SKILL.md          # Claude Code frontmatter + human docs
    auto_audit.py     # Executable scanner — REQUIRED
    patterns/         # One .md per pattern (docs, not code)
      pattern-a.md
      pattern-b.md
    checklist.md      # Manual items the auto scan doesn't cover
    example_report.md # What the user gets out
    README.md         # Short overview
```

## Required: `auto_audit.py`

Invocation contract:
```
python3 auto_audit.py <target_path> [--json]
```

Output contract (stdout, one finding per line):
```
[P0] src/rc.js:42 — RevenueCat API key uses placeholder
[P1] src/App.jsx:114 — Button missing aria-label
[P2] README.md — project lacks privacy policy link
```

Severity: `P0` / `P1` / `P2` / `INFO`. Format enforced by regex:
```
^\[(P[012]|INFO)\]\s+<path>(?::<line>)?\s+—\s+<message>$
```

Exit codes:
- `0` — scan completed, findings or not
- `1` — findings exist but scan succeeded (treated same as 0 by `scan_all.py`)
- `2` — scan could not run (bad target, missing deps)

## Required: `SKILL.md`

Frontmatter (Claude Code format):
```yaml
---
name: my-new-skill
description: One-line what it scans for. Use when <triggers>.
triggers:
  - "check my stripe integration"
  - "audit payments"
  - files matching: "**/stripe.js", "**/webhooks.py"
---
```

Body:
1. What it scans for (plain English)
2. The N patterns it detects (numbered list, each with: bug pattern, fix, grep rule, severity)
3. False-positive guidance
4. Related skills (e.g. "pair with `security` for secrets")

## Writing Patterns (the body of work)

Each pattern in `patterns/pattern-name.md`:

```markdown
# [Pattern Name]

**Severity:** P0/P1/P2
**Guideline/CVE:** [if applicable]
**Real evidence:** [URL to Reddit/HN/blog where this bit someone]

## Bug
[code example]

## Fix
[code example]

## Detection rule
[grep regex OR AST rule OR file check]

## False positives
- [case 1]
```

## Testing a New Skill

1. Write 3 test cases in `tests/fixtures/` — one with bug, one clean, one ambiguous
2. `python3 auto_audit.py tests/fixtures/with-bug/` → should print ≥1 finding
3. `python3 auto_audit.py tests/fixtures/clean/` → should print 0 findings
4. Run with `scan_all.py` from repo root to verify integration

## Common Pitfalls

- **Avoid false positives more than false negatives.** A noisy scanner gets ignored.
- **Every pattern must cite real evidence.** If you can't find a Reddit/HN/blog link, the pattern doesn't belong.
- **Never modify user code.** Scanners are read-only.
- **Skip `node_modules/`, `.git/`, `dist/`, `build/`, `.venv/`, `venv/` by default.**
- **Respect `.qaignore`** — a line-by-line suppressor format:
  ```
  src/legacy.js
  src/third-party/**
  ```

## Skills Roadmap (April 2026)

| Skill | Status | Priority |
|-------|--------|----------|
| apple-app-store | ✅ shipped (10 patterns) | — |
| ios-capacitor | ✅ shipped (12 patterns) | — |
| web-ui | ✅ shipped (9 patterns) | — |
| security | ✅ shipped (10 patterns) | — |
| pentest-scanner | ✅ shipped (free OSS, 7 patterns) | — |
| **google-play-store** | 🔄 next | P0 |
| **stripe-integration** | 🔄 next | P0 |
| **ai-code-smell** | 🔄 next | P1 |
| **compliance-gdpr** | 🔄 next | P1 |
| **revenuecat-audit** | 🔄 next | P1 |
| **seo-audit** | idea | P2 |
| **performance-audit** | idea | P2 |
