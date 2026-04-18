# Missing Refund / Dispute Webhook Handler

**Severity:** P2
**Evidence:** Stripe docs — "Disputes and fraud". Card network chargeback rules. PSD2 Article 73 (immediate refund right).

## Bug

Your webhook handler only cares about the happy path:

```python
@app.post("/stripe/webhook")
async def handler(req: Request):
    event = verify(req)
    if event["type"] == "payment_intent.succeeded":
        await grant_pro(event["data"]["object"]["metadata"]["user_id"])
    elif event["type"] == "invoice.paid":
        await extend_subscription(...)
    # refunds? disputes? silence.
```

When Stripe issues a refund (customer support, automatic retry failure), the user keeps Pro access for free. When a dispute fires, you don't know until your Stripe balance goes negative.

## Fix

```python
REFUND_EVENTS = (
    "charge.refunded",
    "charge.dispute.created",
    "charge.dispute.funds_withdrawn",
    "charge.dispute.closed",
)

@app.post("/stripe/webhook")
async def handler(req: Request):
    event = verify(req)
    et = event["type"]
    if et == "payment_intent.succeeded":
        await grant_pro(event["data"]["object"]["metadata"]["user_id"])
    elif et == "charge.refunded":
        await downgrade_user(event["data"]["object"]["customer"])
    elif et == "charge.dispute.created":
        await freeze_account(event["data"]["object"]["customer"])
        await page_team("dispute:" + event["id"])
    elif et == "charge.dispute.funds_withdrawn":
        await mark_writeoff(event["data"]["object"])
```

Don't forget to enable these events in dashboard.stripe.com/webhooks.

## Detection rule

Stripe webhook handler (file mentions stripe + webhook + event.type dispatch) that references NONE of: `charge.refunded`, `charge.dispute.created`, `charge.dispute.funds_withdrawn`, `charge.dispute.closed`.

→ P2.

## False positives

- App has no refund policy (rare, inadvisable) — still flag, still fix.
- Refund logic lives in a separate admin tool rather than the webhook — acceptable, but add `// qa-ignore: S10` and a comment pointing at the admin file.
