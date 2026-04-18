# Client-Side Amount / Price Calculation

**Severity:** P0
**Evidence:** Reddit r/SaaS ("user edited price in devtools"), Indie Hackers post-mortems, OWASP Web Security Testing Guide (WSTG-BUSL-09 "client-side validation").

## Bug

```javascript
// React — amount comes from component state the user controls
const handleCheckout = async () => {
  const session = await fetch('/api/create-checkout-session', {
    method: 'POST',
    body: JSON.stringify({ amount: cart.total, productId }),
  }).then(r => r.json());
  window.location = session.url;
};
```

```typescript
// server — trusts req.body.amount
app.post('/api/create-checkout-session', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: 'Pro plan' },
        unit_amount: req.body.amount,      // ← user-controlled
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: '...',
    cancel_url: '...',
  });
  res.json({ url: session.url });
});
```

User opens DevTools → Network → resends the request with `amount: 99`. Pays $0.99 for a $99 product. Stripe does not and cannot know this was wrong.

## Fix — server-side price lookup

```typescript
const PLANS = {
  pro:    { priceId: 'price_1PYxxx', unit_amount: 9900 },  // $99.00
  basic:  { priceId: 'price_1PYyyy', unit_amount: 2900 },
} as const;

app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const plan = PLANS[req.body.plan];
  if (!plan) return res.status(400).send('unknown plan');
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: plan.priceId, quantity: 1 }],  // Stripe fills the amount
    mode: 'subscription',
    success_url: '...',
    cancel_url: '...',
  });
  res.json({ url: session.url });
});
```

Use `price: 'price_XXX'` (the Stripe Price ID) — the amount is locked on Stripe's side, the client never sees or controls it.

## Detection rule

Inside `stripe.checkout.sessions.create(...)`, `paymentIntents.create(...)`, or `PaymentIntent.create(...)`:
- An `amount:` field whose value is NOT a numeric literal.
- The value references any of: `form.`, `input.`, `state.`, `req.body`, `req.query`, `params.`, `localStorage`, `searchParams`, `parseInt(req...)`, `Number(req...)`, `e.target.value`, or is a bare identifier.

→ P0.

## False positives

- Server-side computed amount sourced from an internal `cart.total` that is itself recomputed from DB — the scanner can't distinguish. If you've verified the amount is recomputed server-side from trusted data, add `// qa-ignore: S6` on the `amount:` line.
- Variable-donation widgets (intentional): user IS supposed to choose — OK, but at minimum enforce a `max` on the server.
