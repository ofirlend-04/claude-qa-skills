---
name: test-plan-generator
description: Produce a professional Test Plan (scope, test cases, entry/exit criteria, defect flow) for a web/app project. Uses findings from other QA skills as input. Exports Markdown + CSV (TestRail/Xray) + JSON.
triggers:
  - "generate test plan"
  - "create QA plan"
  - "build test cases"
  - "תוכנית בדיקות"
  - files matching: "**/test-plan.md", "**/qa-plan.yaml"
---

# Test Plan Generator

Produces a formal Test Plan following the industry-standard structure:

1. **Scope + Out-of-Scope** — what we test, what we deliberately skip
2. **Test Types** — functional, UI/UX, cross-browser, regression, a11y, security
3. **Test Cases** — TC-NNN with: title, pre-conditions, steps, expected result, status
4. **Entry + Exit Criteria** — when to start testing, when to stop
5. **Defect Management** — lifecycle: report → triage → fix → re-test → close

## Input sources (chain-of-QA)

This skill doesn't scan from scratch — it aggregates outputs from our other skills:

- `apple-app-store` → test cases per Apple Guideline violation
- `ios-capacitor` → test cases per Capacitor pattern
- `web-ui` → test cases per a11y/RTL/perf finding
- `security` → test cases per security rule (A1-K1)
- `google-play-store` → Android-specific test cases
- `stripe-payments` → payment flow test cases
- `ai-code-smell` → test cases for AI-generated bug patterns
- Generic regression suite — produced from user flows detected in the codebase

## CLI

```
python3 auto_audit.py <target> [options]

Options:
  --scan-first            Run all other skills first, then generate cases
  --findings-json PATH    Use a pre-existing scan JSON
  --platforms LIST        ios,android,web,pwa  (default: auto-detect)
  --browsers LIST         chrome,safari,firefox,edge,mobile-safari,mobile-chrome
  --language {en,he,both} Default: auto-detect from target
  --format {md,csv,json}  Default: md (writes all 3)
  --out DIR               Default: <target>/test-plan/
```

## Output structure

```
<target>/test-plan/
├── TEST_PLAN.md          ← human-readable, full doc
├── TEST_PLAN.he.md       ← Hebrew version (if language=he or both)
├── test_cases.csv        ← TestRail / Xray import format
├── test_cases.json       ← machine-readable for CI
└── defect_template.md    ← Jira/Linear template for bug reports
```

## Test case schema

Every test case follows:

```yaml
id: TC-001
title: Verify login with valid credentials
category: functional       # functional | ui | a11y | security | perf | cross-browser | regression
priority: P0               # P0 (blocker) | P1 (high) | P2 (medium) | P3 (low)
source: manual             # manual | generated-from-finding | user-flow-detected
trigger_finding: E2        # (optional) which scan finding spawned this case
platforms: [web, mobile]
browsers: [chrome, safari]
pre_conditions:
  - User account exists in the test DB
  - Dev server is running on http://localhost:3000
steps:
  - "Navigate to /login"
  - "Enter email: testuser@example.com"
  - "Enter password: ValidPass123"
  - "Click 'Sign in'"
expected_result: |
  - User is redirected to /dashboard within 2 seconds
  - Session cookie is set with HttpOnly + Secure flags
  - Welcome message shows user's first name
status: Not Run            # Not Run | Pass | Fail | Blocked | Skip
defect_id: null            # filled if Fail
notes: ""
```

## Entry / Exit criteria template

**Entry (conditions to START testing):**
- Code freeze on feature branch
- Target scanned with ≤5 P0 scan findings
- Staging env reachable + seeded with test data
- Test Plan approved by product lead

**Exit (conditions to APPROVE release):**
- 100% of P0 test cases pass
- ≥95% of P1 test cases pass
- 0 open Blocker/Critical defects
- All Fail cases have linked defect IDs
- Regression suite green on main branch

## Defect lifecycle

Every defect found during test execution:

```
[Reported] → [Triaged by PM/lead]
            → priority: P0/P1/P2/P3
            → severity: Blocker/Critical/Major/Minor
         → [Assigned to dev]
         → [In Progress]
         → [Fixed] → [Ready for Re-test]
         → [Re-tested by QA]
            → Pass → [Closed]
            → Fail → back to [In Progress] with regression note
```

## Hebrew / RTL support

When `--language he`:

- Steps written in Hebrew with `dir="rtl"` markers in Markdown
- CSV uses UTF-8 BOM for Excel compatibility
- Test case IDs stay Latin (TC-001) for cross-tool portability
- Category names localized: "פונקציונלי" / "עיצוב" / "אבטחה" / "רגרסיה"

## What this skill does NOT do

- Execute tests (that's the QA runner's job)
- Generate test data/fixtures (that's a separate concern)
- Replace human judgment on scope — it suggests a plan, you approve it

## Integration with scan_all.py

```bash
python3 scan_all.py <target> --emit-test-plan
```

Triggers: full scan → for each finding, generate matching TC → append to the
baseline regression suite → write test-plan files. One command, full Test
Plan from zero.
