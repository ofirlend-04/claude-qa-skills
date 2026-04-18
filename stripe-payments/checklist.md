# Stripe / Payments — Manual Checklist

Things the scanner cannot know by reading code alone. Run before any production release.

## Stripe Dashboard

- [ ] **Webhook endpoints configured** — dashboard.stripe.com/webhooks lists your production URL, with events `payment_intent.succeeded`, `invoice.paid`, `customer.subscription.*`, `charge.refunded`, `charge.dispute.created`.
- [ ] **Webhook signing secret rotated** after any developer with prod access leaves.
- [ ] **API version pinned** — lock to a specific Stripe API version in code (`stripe.api_version = '2024-11-20.acacia'`). Otherwise Stripe upgrades you silently and object shapes drift.
- [ ] **Restricted keys for non-root tasks** — read-only dashboards should use `rk_live_` scoped keys, not `sk_live_`.
- [ ] **Team access audited** — remove ex-employees from Stripe account. `Business settings > Team`.

## Testing

- [ ] **Stripe CLI replay** — `stripe trigger payment_intent.succeeded`, verify handler.
- [ ] **Signature-fail test** — send an unsigned POST to the webhook route; expect 400.
- [ ] **Replay test (idempotency)** — send the same event twice; expect handler to skip the second.
- [ ] **Test 3DS cards** — `4000 0025 0000 3155` (EU SCA required); verify flow completes.
- [ ] **Decline cards** — `4000 0000 0000 0002` (generic decline); verify UI shows a useful error.
- [ ] **Insufficient funds** — `4000 0000 0000 9995`; verify UI does not charge + shows a message.
- [ ] **Cross-device restore** (mobile) — purchase on device A, log in on device B, tap Restore, verify entitlement restored.

## Legal / Compliance

- [ ] **Terms of service** includes refund policy + subscription auto-renew language.
- [ ] **Privacy policy** names Stripe + RevenueCat as subprocessors (GDPR Art. 28).
- [ ] **Pricing page** shows VAT / tax inclusion state ("prices include VAT" for EU).
- [ ] **Apple / Google subscription metadata** matches your own: price, duration, name.

## Analytics / Alerting

- [ ] **Alert on webhook 5xx rate** > 1% — silent errors here = lost revenue.
- [ ] **Alert on new `charge.dispute.created`** — Slack / email on first dispute.
- [ ] **MRR / churn reported from Stripe, not from your own DB** — single source of truth.
- [ ] **Stripe Sigma (or BI dashboard)** set up for failed-payment retries, grace period exits.

## Deploy Gates

- [ ] No `sk_test_` in production environment variables.
- [ ] `STRIPE_WEBHOOK_SECRET` set in prod; webhook route rejects all traffic when unset.
- [ ] Deployment runs `python3 auto_audit.py` in CI; blocks merge on any P0.

## Beyond scope (flag separately)

- [ ] **Subscription pause / cancel flow** — make sure users can self-serve.
- [ ] **Tax handling** — Stripe Tax or manual VAT? Confirm configuration.
- [ ] **Dunning emails** (failed payment retries) — owned by who? Stripe built-in or Mailchimp?
