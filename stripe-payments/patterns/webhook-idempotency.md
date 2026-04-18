# Webhook Idempotency Missing

**Severity:** P1
**Evidence:** Stripe docs — "Handle duplicate events" (stripe.com/docs/webhooks#handle-duplicate-events). Stripe retries on any non-2xx for up to 3 days.

## Bug

```python
@app.post("/stripe/webhook")
async def handler(req: Request):
    event = verify(req)
    if event["type"] == "invoice.paid":
        amount = event["data"]["object"]["amount_paid"]
        await credit_user(amount)          # runs N times if Stripe retries
    return {"ok": True}
```

If your handler returns 500 once (DB hiccup, timeout), Stripe retries. Or Stripe can simply deliver the same event twice by design. Each retry re-credits the user.

## Fix

```python
@app.post("/stripe/webhook")
async def handler(req: Request):
    event = verify(req)
    # dedupe using Postgres UNIQUE(event_id)
    try:
        await db.execute(
            "INSERT INTO webhook_events (id) VALUES ($1)", event["id"])
    except UniqueViolation:
        return {"ok": True, "duplicate": True}
    # ...safe to process
```

Or with Redis:
```python
seen = await redis.set(f"webhook:{event['id']}", "1", nx=True, ex=7*24*3600)
if not seen:
    return {"ok": True, "duplicate": True}
```

## Detection rule

A file that:
1. Mentions `stripe` + `webhook` (case-insensitive).
2. Dispatches on `event.type` (or `event["type"]`).
3. Does NOT reference any of: `event.id`, `event['id']`, `event["id"]`, `event_id`, `processed_events`, `webhook_events`, `idempotency`.

→ P1.

## False positives

- Handler that hands off immediately to a queue (SQS / Pub/Sub) where the queue handles dedupe — suppress on the enqueue line with `# qa-ignore: S2`.
- Read-only handlers (e.g. logging `customer.created` to analytics without DB writes) — safe to ignore, but note the intent in code.
