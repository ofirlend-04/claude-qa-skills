---
name: stripe-payments
description: Finds payment-integration bugs that cause chargebacks, lost revenue, App Store rejection, and payment forgery. Detects unverified Stripe webhooks (CVE-2026-21894 class), client-side price calculation, live keys in source, missing Restore Purchases, broken 3DS/SCA handling, RevenueCat logIn() ordering bugs, webhook idempotency, refund/dispute handler gaps, and more. Covers both Stripe (Python/FastAPI, Flask, Express/Next.js) and RevenueCat (iOS/Capacitor) flows.
triggers:
  - "audit stripe"
  - "check payment"
  - "review webhooks"
  - "payment audit"
  - "stripe integration review"
  - "revenuecat audit"
  - "paywall review"
  - files matching: "**/webhook*.{ts,js,py}", "**/stripe*.{ts,js,py}", "**/paywall*.{tsx,jsx,swift,kt}", "**/rc.{js,ts}", "**/subscription*.{ts,js,py}"
---

# Stripe / Payments QA

You are a senior payments engineer who has watched indie devs take real damage: users editing `$9.99` to `$0.99` in DevTools, attackers forging `payment_intent.succeeded` webhooks, Apple rejecting apps for missing "Restore Purchases", EU customers failing silently on SCA. This skill catches the 13 real bugs that most "Stripe tutorials" skip over.

Every rule ties to documented evidence: Stripe's own docs, Apple's App Review Guidelines, a real CVE class, or a specific indie-dev post-mortem.

## Your Job

1. If given a folder path, run `auto_audit.py <folder>`. It emits `[Pn] file:line — msg` on stdout + `report.md` + `report.json`.
2. Read `report.md`. Add context-aware findings the scanner can't infer (e.g. "this route has no auth either — pair with security skill").
3. Produce a **prioritised report** with severity (P0/P1/P2), `file:line`, redacted evidence, and the exact fix.
4. For every finding, cite the rule ID (S1..S13) from the library below.

**Do:** redact secrets to prefix + `***`. Always.
**Do:** cross-reference with `security` skill — webhook auth + rate limiting are paired concerns.
**Don't:** fabricate findings. If the pattern isn't in the library, skip it.

## Severity Rubric

- **P0 — Production risk.** Payment forgery, live keys in source, Apple will reject, user can edit price. Fix before shipping.
- **P1 — Financial risk.** Double-charges from webhook replay, silent SCA failures in EU, subscription billing surprises. Revenue leaks.
- **P2 — Conversion / hardening.** Missing Apple Pay, hardcoded prices drifting from Stripe, missing refund handlers.

---

## Rule Library — 13 Real Bug Patterns

### S1. Stripe webhook signature not verified — P0
**Pattern:** A route like `/webhook/stripe` or `/stripe/webhook` (Express / FastAPI / Flask) that does NOT call `stripe.webhooks.constructEvent(body, sig, secret)` (or the Python equivalent `stripe.Webhook.construct_event`).
**Why P0:** attacker POSTs a fake `payment_intent.succeeded` event, your app grants a paid entitlement. This is the **CVE-2026-21894 class** bug. Stripe has patched their SDK to refuse unsigned events — but only if you call the constructor. Every few months a post-mortem hits HN (Stripe themselves wrote a blog "we can't protect you if you don't verify signatures").
**Fix:**
```python
sig = request.headers["Stripe-Signature"]
event = stripe.Webhook.construct_event(request.data, sig, endpoint_secret)
```
See `patterns/webhook-signature.md`.

### S2. Webhook idempotency missing — P1
**Pattern:** The handler dispatches on `event.type` but never stores `event.id` for dedupe.
**Why P1:** Stripe retries on any non-2xx response for up to 3 days. If your handler processes `invoice.paid` twice, the user gets credited twice. Stripe's docs literally call this out.
**Fix:** insert `event.id` into a `processed_webhook_events` table with `UNIQUE` constraint; return early on conflict.
See `patterns/webhook-idempotency.md`.

### S3. Express raw-body parsing wrong — P0
**Pattern:** `app.use(express.json())` applied globally BEFORE the webhook route, without `express.raw({ type: 'application/json' })` on the webhook specifically.
**Why P0:** `constructEvent()` hashes the exact bytes Stripe sent. Once `express.json()` parses the body, JSON key order / whitespace changes and the HMAC fails — **every webhook call returns 400 and your app never learns about paid users**. Appears to work in dev, silently breaks in prod. Stripe docs have a dedicated Express example for this.
**Fix:** mount the webhook route with `express.raw(...)` BEFORE `app.use(express.json())`.
See `patterns/express-raw-body.md`.

### S4. Hardcoded `sk_test_` / `pk_test_` in non-test source — P0 (sk/rk) / P1 (pk)
**Pattern:** `sk_test_`, `rk_test_` or `pk_test_` string literal in a source file outside `tests/`.
**Why:** test secret keys (`sk_test_`) can browse your test customers and subscriptions via the Stripe API. Test publishable keys in production code means the wrong environment is wired up.
**Fix:** move to env var. Use `sk_test_` only in local/dev env files; never commit.

### S5. Live Stripe key committed — P0
**Pattern:** `sk_live_` or `rk_live_` anywhere in source.
**Why:** GitGuardian 2025 report: average indie incident = ~$800 of fraud + a weekend of incident response. Bots scrape new GitHub commits within 60 seconds.
**Fix:** rotate at dashboard.stripe.com/apikeys, move to env / secret manager, `git filter-repo` to purge history if it ever hit a public branch.

### S6. Client-side amount / price calculation — P0
**Pattern:** `stripe.checkout.sessions.create({ amount: req.body.amount })` or the same shape in React state / form input.
**Why P0:** user opens DevTools, edits `amount: 999` → `amount: 99`, checkout succeeds. Literally the top indie-SaaS bug on Reddit r/SaaS.
**Fix:** compute `amount` server-side from a trusted source — look up Stripe `price_XXX` by product SKU, server-side. Never accept `amount` from the client.
See `patterns/client-side-amount.md`.

### S7. PaymentIntent missing `automatic_payment_methods.enabled` — P2
**Pattern:** `paymentIntents.create({ ... })` without either `automatic_payment_methods` or an explicit `payment_method_types` array.
**Why P2:** Apple Pay / Google Pay / Link won't appear → 15–30% conversion drop on mobile.
**Fix:** `automatic_payment_methods: { enabled: true }`.

### S8. Subscription update without `proration_behavior` — P1
**Pattern:** `stripe.subscriptions.update(id, { items: [...] })` with no `proration_behavior`.
**Why P1:** Stripe silently prorates, customer gets an unexpected invoice / credit, support ticket volume spikes. Always be explicit.
**Fix:** set `proration_behavior: 'create_prorations' | 'always_invoice' | 'none'` explicitly.

### S9. RevenueCat `Purchases.logIn()` called AFTER purchase — P0 (ordering) / P2 (missing)
**Pattern (P0):** in the same function, `Purchases.purchasePackage(...)` appears before `Purchases.logIn(...)`.
**Pattern (P2):** `Purchases.configure(...)` present but `Purchases.logIn()` never called and the app has user accounts.
**Why:** the App User ID at purchase time is what Stripe/Apple store the entitlement against. Wrong ID = purchase doesn't follow user across devices, restores fail.
**Fix:** call `Purchases.logIn({ appUserID })` immediately after user login, before any purchase.

### S10. Missing refund / dispute webhook handler — P2
**Pattern:** a Stripe webhook handler that dispatches on `event.type` but has no branch for `charge.refunded` / `charge.dispute.created`.
**Why P2:** required for proper entitlement revocation, for PSD2/card-network compliance, and for accurate MRR / churn analytics.
**Fix:** handle `charge.refunded` (downgrade entitlement), `charge.dispute.created` (freeze account, page the team).

### S11. Paywall missing "Restore Purchases" button — P0
**Pattern:** a paywall file (`paywall*.tsx/swift/kt`, or any file calling `Purchases.purchasePackage` / `createCheckoutSession`) with UI markup but no `restorePurchases` / `restoreTransactions` / "Restore" text.
**Why P0:** Apple App Review Guideline 3.1.1 — guaranteed rejection. Google Play equivalent for subscription restoration.
**Fix:** add a button calling `Purchases.restorePurchases()` (RC) or `SKPaymentQueue.default().restoreCompletedTransactions()` (StoreKit).

### S12. 3DS / SCA not handled — P1
**Pattern:** `paymentIntent.confirm(...)` or `paymentIntents.confirm(...)` without subsequently handling `requires_action` / `handleNextAction` / `confirmCardPayment` / `handleCardAction`.
**Why P1:** EU/UK customers with SCA-required cards fail silently. PSD2 compliance.
**Fix:** check `paymentIntent.status === 'requires_action'` and invoke `stripe.confirmCardPayment()` on the client (or the Python/Node equivalent `handleNextAction`).

### S13. Hardcoded prices in UI strings — P2
**Pattern:** `<div>$9.99/month</div>` in a paywall file where the app also uses `price_XXX` or `getOfferings()`.
**Why P2:** price drift between UI and actual charge → chargebacks and bad reviews when Stripe / RevenueCat price changes but UI doesn't.
**Fix:** format the display price from the same `Price` / `Offering` you charge against.

---

## How to Run

```bash
python3 auto_audit.py /path/to/project
# emits [Pn] file:line — msg on stdout, + report.md + report.json
```

Exit codes:
- `0` — clean
- `1` — findings exist (any severity)
- `2` — couldn't run (bad path / unreadable dir)

Inline suppression: `// qa-ignore: S7,S13` on the line above the match (also applies to the match line).

## False-Positive Guidance

- **Stripe-adjacent but not Stripe:** Shopify / Paddle / LemonSqueezy webhooks look similar; this scanner only flags files that mention "stripe" — the mention check is the guard.
- **RevenueCat rc.js files without user auth:** S9 (missing logIn) fires P2 because we can't tell from a single file whether the app has user accounts. If the app is purely anonymous (no login flow), suppress with `// qa-ignore: S9`.
- **Internal/admin routes:** S1 will fire on any `/webhook/stripe` route without `constructEvent`. If the route is intentionally unsigned internal traffic (behind mTLS / IP allowlist), suppress and document why.
- **Test fixtures:** the scanner skips `tests/`, `__tests__/`, `fixtures/`, `*.test.*`, `*.spec.*` — if a `sk_test_` leaks into a fixture, S4 won't fire.

## Related Skills

- `security` — webhook endpoints often also lack auth + rate limit (C-rules + K-rules).
- `apple-app-store` — pairs with S11 (Restore Purchases) for full 3.1.1 coverage.
- `revenuecat-audit` (roadmap) — deeper RC-specific entitlement / sandbox bugs.
