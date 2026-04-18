# google-play-store — QA Skill

Pre-submission audit for Android / Capacitor apps targeting Google Play. Based on the **April 2026** policy landscape (Data Safety enforcement, target-SDK escalator, ACCESSIBILITY_SERVICE crackdown, SMS/Call Log gating, background location).

Detects **12 rejection patterns** — every one cited with a real Google policy URL or Reddit rejection thread.

## Quick start

```bash
# Run against a Capacitor app
python3 auto_audit.py /path/to/my-capacitor-app

# JSON output (for CI / scan_all.py)
python3 auto_audit.py /path/to/my-capacitor-app --json

# Don't write report.md
python3 auto_audit.py /path/to/my-capacitor-app --no-report
```

Exit codes: `0` no findings, `1` findings present, `2` audit crashed.

## Outputs

- **stdout** — one finding per line in the `[P0] path:line — message` format. Consumed by `../scan_all.py`.
- **report.md** — written in the skill directory; pretty markdown for humans / Claude Code.

## The 12 patterns

| # | Pattern | Severity | Policy |
|---|---------|----------|--------|
| 1 | Data Safety declaration vs SDK diff | P0 | Data Safety (Apr 15, 2026) |
| 2 | SMS perms without default-handler | P0 | SMS and Call Log Policy |
| 3 | CALL_LOG perms without justification | P0 | SMS and Call Log Policy |
| 4 | ACCESSIBILITY_SERVICE misuse | P0/P1 | Accessibility API Policy |
| 5 | Background location without disclosure | P0 | Location Permissions Policy |
| 6 | targetSdkVersion too old | P0/P1 | Target API Level Requirements |
| 7 | Privacy policy URL missing | P1 | User Data Policy |
| 8 | Deceptive package name | P1 | Impersonation Policy |
| 9 | Subscription UI without Play Billing | P0 | Payments Policy |
| 10 | Foreground service type missing | P1/P2 | Android 14 FGS types |
| 11 | Broad storage permission | P0/P1 | All Files Access Policy |
| 12 | Hardcoded API keys / secrets | P0 | Security hygiene |

See `patterns/*.md` for per-pattern detail and `checklist.md` for manual items.

## Fixtures

```
tests/fixtures/with-bug/   # triggers all 12 findings
tests/fixtures/clean/      # exits 0, no findings
```

## Layout

```
google-play-store/
├── SKILL.md              # frontmatter + docs (Claude Code)
├── auto_audit.py         # deterministic scanner
├── patterns/             # one .md per pattern
├── checklist.md          # manual items
├── example_report.md     # sample output
├── README.md             # this file
└── tests/fixtures/       # with-bug + clean
```

## Related skills

- `apple-app-store` — iOS counterpart (10 patterns).
- `ios-capacitor` — shared Capacitor plumbing.
- `security` — broader secret scanning.
