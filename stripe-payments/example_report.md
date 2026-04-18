# Stripe / Payments Audit — /example/project

## Summary
- Files scanned: 182
- **3 P0** (production risk — rotate / fix before shipping)
- **2 P1** (financial risk)
- **1 P2** (hardening / conversion)

## P0 — Production risk

### P0.1 [S1] Stripe webhook endpoint has no signature verification (CVE-2026-21894 class)
- **Location:** `server/routes/webhooks.js:17`
- **Evidence:** `/api/webhook/stripe`
- **Fix:** Call `stripe.webhooks.constructEvent(rawBody, sig, endpointSecret)` before trusting the payload. Without it, anyone can POST fake `payment_intent.succeeded` events.

### P0.2 [S6] Stripe amount built from client-side / request input (user can edit the price)
- **Location:** `server/checkout.ts:42`
- **Evidence:** `amount: req.body.amount`
- **Fix:** Compute the amount server-side from a trusted source (Stripe Price ID, a product table keyed by SKU). Never accept `amount` from req.body / client state.

### P0.3 [S11] Paywall has no "Restore Purchases" button (Apple Guideline 3.1.1 rejection)
- **Location:** `mobile/src/Paywall.tsx:88`
- **Evidence:** purchasePackage call without restorePurchases/restoreTransactions
- **Fix:** Add a "Restore Purchases" button that calls `Purchases.restorePurchases()`. Apple will reject the build without it.

## P1 — Financial risk

### P1.1 [S2] Stripe webhook handler does not dedupe by event.id (double-charge risk)
- **Location:** `server/routes/webhooks.js:28`
- **Evidence:** event.type switch without event.id check
- **Fix:** Store processed event.id in a dedupe table (UNIQUE constraint). Stripe retries for up to 3 days — same event arrives many times.

### P1.2 [S12] paymentIntent.confirm() without handling requires_action / 3DS (EU SCA will fail)
- **Location:** `mobile/src/Checkout.tsx:61`
- **Evidence:** `paymentIntent.confirm`
- **Fix:** Check returned status — if `requires_action`, call `stripe.confirmCardPayment()`. PSD2 mandatory in EU/UK.

## P2 — Hardening / conversion

### P2.1 [S7] PaymentIntent created without automatic_payment_methods.enabled
- **Location:** `server/checkout.ts:40`
- **Evidence:** `paymentIntents.create({ amount: ..., currency: 'usd' })`
- **Fix:** Add `automatic_payment_methods: { enabled: true }` — enables Apple Pay / Google Pay / Link / SEPA based on customer region.

## Manual follow-ups

Run the full `checklist.md`:
- Verify webhook endpoint is registered in dashboard.stripe.com/webhooks.
- Replay test (`stripe trigger payment_intent.succeeded` twice — second time must no-op).
- Cross-device restore test on two physical devices.
