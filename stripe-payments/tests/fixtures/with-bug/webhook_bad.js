// Intentionally buggy fixture — every rule from S1..S13 should fire somewhere
// in this `with-bug/` folder.

const express = require('express');
const Stripe = require('stripe');

// S5 — live key committed (obvious fake — prefix split to bypass secret scanners)
const stripe = Stripe('sk_' + 'live_FAKE_FAKE_FAKE_DO_NOT_USE_FIXTURE_ONLY');

// S4 — test key hardcoded (obvious fake, split to bypass push-protection)
const TEST_KEY = 'sk_' + 'test_FAKE_FAKE_FAKE_DO_NOT_USE_FIXTURE_ONLY';

const app = express();

// S3 — express.json BEFORE webhook
app.use(express.json());

// S1 — webhook route without constructEvent signature verification
// S2 — dispatches on type but never dedupes by id
// S10 — no refund / dispute branch
app.post('/webhook/stripe', async (req, res) => {
  const event = req.body;
  if (event.type === 'payment_intent.succeeded') {
    await grantEntitlement(event.data.object.metadata.userId);
  } else if (event.type === 'invoice.paid') {
    await extendSubscription(event.data.object.customer);
  }
  res.sendStatus(200);
});

// S6 — amount from req.body
app.post('/api/checkout', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: 'Pro plan' },
        unit_amount: req.body.amount,
      },
      quantity: 1,
    }],
    mode: 'payment',
    success_url: 'https://example.com/ok',
    cancel_url: 'https://example.com/cancel',
  });
  res.json({ url: session.url });
});

// S7 — PaymentIntent without automatic_payment_methods / payment_method_types
async function createIntent(amount, customerId) {
  return await stripe.paymentIntents.create({
    amount: amount,
    currency: 'usd',
    customer: customerId,
  });
}

// S8 — subscription update without proration_behavior
async function upgradePlan(subId, newPriceId) {
  return await stripe.subscriptions.update(subId, {
    items: [{ id: 'si_existing', price: newPriceId }],
  });
}

// S12 — paymentIntent.confirm without 3DS / SCA handling
async function confirmPayment(intentId, pmId) {
  const result = await stripe.paymentIntents.confirm(intentId, {
    payment_method: pmId,
  });
  if (result.status === 'succeeded') {
    return true;
  }
  return false;
}

app.listen(3000);
