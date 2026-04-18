# Stripe Webhook Signature Not Verified

**Severity:** P0
**Evidence:** Stripe docs — "Verify webhook signatures" (stripe.com/docs/webhooks/signatures). Multiple 2024–2025 HN post-mortems ("someone's forging our payment webhooks"). CVE-2026-21894 class — forged payload grants fake entitlement.

## Bug

```javascript
// Express — NO signature check
app.post('/webhook/stripe', express.json(), async (req, res) => {
  const event = req.body;                         // attacker-controlled JSON!
  if (event.type === 'payment_intent.succeeded') {
    await grantEntitlement(event.data.object.metadata.userId);
  }
  res.sendStatus(200);
});
```

```python
# FastAPI — NO signature check
@app.post("/stripe/webhook")
async def stripe_webhook(req: Request):
    event = await req.json()                       # attacker-controlled
    if event["type"] == "payment_intent.succeeded":
        await grant_entitlement(event["data"]["object"]["metadata"]["user_id"])
```

An attacker sends a hand-crafted POST with any body; your app believes them.

## Fix

```javascript
// Express — verified
app.post(
  '/webhook/stripe',
  express.raw({ type: 'application/json' }),      // raw body required
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body, sig, process.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (err) {
      return res.status(400).send(`Webhook signature failed: ${err.message}`);
    }
    // now trusted
    if (event.type === 'payment_intent.succeeded') {
      await grantEntitlement(event.data.object.metadata.userId);
    }
    res.sendStatus(200);
  },
);
```

```python
# FastAPI — verified
@app.post("/stripe/webhook")
async def stripe_webhook(req: Request):
    payload = await req.body()
    sig = req.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(
            payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"],
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="bad signature")
    if event["type"] == "payment_intent.succeeded":
        await grant_entitlement(event["data"]["object"]["metadata"]["user_id"])
```

## Detection rule

- Grep webhook routes: `/webhook/stripe` / `/stripe/webhook` / filename containing `stripe` + `webhook`.
- Require one of: `stripe.webhooks.constructEvent`, `stripe.Webhook.construct_event`, `Webhook.constructEvent`, `construct_event(`, `verifyHeader(`.
- Missing → P0.

## False positives

- Internal-only webhook behind mTLS / IP allowlist — suppress with `// qa-ignore: S1` and document in a comment.
- Dev sandbox where you intentionally accept unsigned events — gate on `NODE_ENV` in code.
