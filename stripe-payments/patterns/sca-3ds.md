# 3DS / SCA Not Handled

**Severity:** P1
**Evidence:** PSD2 regulation (EU, 2019+). Stripe docs — "Strong Customer Authentication". Required on most EU cards.

## Bug

```javascript
const result = await stripe.paymentIntents.confirm(paymentIntentId, {
  payment_method: paymentMethodId,
});
if (result.status === 'succeeded') {
  grant();
}
// But if result.status === 'requires_action'?  We just dropped the user.
```

EU cardholders silently fail. You see failed payments with no obvious error.

## Fix

```javascript
const intent = await stripe.paymentIntents.confirm(paymentIntentId, {
  payment_method: paymentMethodId,
});

if (intent.status === 'requires_action' || intent.status === 'requires_source_action') {
  // Browser needs to show the 3DS challenge
  const { error, paymentIntent } = await stripe.confirmCardPayment(
    intent.client_secret,
  );
  if (error) return showError(error.message);
  if (paymentIntent.status === 'succeeded') grant();
} else if (intent.status === 'succeeded') {
  grant();
} else {
  showError(`Unexpected status: ${intent.status}`);
}
```

For the newer Stripe Elements approach, `stripe.confirmPayment()` handles the redirect automatically — preferred.

## Detection rule

File mentions `stripe`, contains `paymentIntent.confirm` / `paymentIntents.confirm` / `PaymentIntent.confirm`, and does NOT contain any of: `handleNextAction`, `confirmCardPayment`, `handle_next_action`, `requires_action`, `next_action`, `handleCardAction`.

→ P1.

## False positives

- Server-side-only confirmation with `payment_method` and `return_url` set — Stripe handles the redirect, you just need to hand the user back at the return URL. If your flow uses `return_url` + `stripe.confirmPayment()` on the client, you're covered. Suppress with `// qa-ignore: S12` if that's the case.
