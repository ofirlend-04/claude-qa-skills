# stripe-payments

Claude Code QA skill for Stripe / RevenueCat payment-integration bugs.

## What it catches

13 real bug patterns — each backed by either a Stripe doc, Apple guideline, CVE class, or a documented indie post-mortem:

| Rule | Severity | Bug |
|------|----------|-----|
| S1   | P0 | Stripe webhook signature not verified (CVE-2026-21894 class) |
| S2   | P1 | Webhook handler without idempotency dedupe |
| S3   | P0 | Express `express.json()` before webhook route (breaks signing) |
| S4   | P0/P1 | Hardcoded `sk_test_` / `pk_test_` in non-test source |
| S5   | P0 | `sk_live_` committed to source |
| S6   | P0 | Stripe `amount` computed from client / request body |
| S7   | P2 | PaymentIntent without `automatic_payment_methods` |
| S8   | P1 | Subscription update without `proration_behavior` |
| S9   | P0/P2 | RevenueCat `logIn()` missing or called after purchase |
| S10  | P2 | Webhook handler with no `charge.refunded` / `charge.dispute.created` branch |
| S11  | P0 | Paywall missing "Restore Purchases" (Apple 3.1.1) |
| S12  | P1 | `paymentIntent.confirm()` without 3DS / SCA handling |
| S13  | P2 | Hardcoded price strings alongside Stripe Price API |

## Usage

```bash
python3 auto_audit.py /path/to/project
# → [Pn] file:line — message on stdout
# → report.md + report.json next to this script
```

Exit codes: `0` clean, `1` findings, `2` bad target.

## Triggers (Claude Code)

- "audit stripe"
- "check payment"
- "review webhooks"
- "paywall review"
- files matching `**/webhook*.{ts,js,py}`, `**/stripe*.{ts,js,py}`, `**/paywall*.{tsx,jsx,swift,kt}`, `**/rc.{js,ts}`.

## Language support

- Python (FastAPI, Flask, raw `stripe` SDK)
- JavaScript / TypeScript (Express, Next.js API routes, React / React Native UI)
- Swift (paywall UI only — Restore Purchases check)
- Kotlin (paywall UI only — Restore Purchases check)

## False-positive controls

- Skips `node_modules/`, `dist/`, `build/`, `.next/`, `.venv/`, `xcarchive/`, `public/assets/`, minified bundles.
- Skips test fixtures (`tests/`, `__tests__/`, `fixtures/`, `*.test.*`, `*.spec.*`) for the test-key rule.
- Inline `// qa-ignore: S1,S3` on a line suppresses those rules for that line + the next.
- Doc-example mode: if the scan target is the qa-skills repo itself, skips `.md` files + this scanner source.

## Related

- `security` — missing auth + rate limits on webhook routes.
- `apple-app-store` — broader IAP / App Review coverage; pairs with S11.
