// Clean fixture — scanner should report zero findings.

const express = require('express');
const Stripe = require('stripe');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

const app = express();

// 1. Webhook FIRST with raw body
app.post(
  '/webhook/stripe',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, WEBHOOK_SECRET);
    } catch (err) {
      return res.status(400).send(`bad sig: ${err.message}`);
    }

    // idempotency
    const inserted = await db.query(
      'INSERT INTO webhook_events (id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id',
      [event.id],
    );
    if (inserted.rowCount === 0) {
      return res.json({ ok: true, duplicate: true });
    }

    switch (event.type) {
      case 'payment_intent.succeeded':
        await grantEntitlement(event.data.object.metadata.userId);
        break;
      case 'invoice.paid':
        await extendSubscription(event.data.object.customer);
        break;
      case 'charge.refunded':
        await downgradeUser(event.data.object.customer);
        break;
      case 'charge.dispute.created':
        await freezeAccount(event.data.object.customer);
        break;
    }
    res.sendStatus(200);
  },
);

// 2. Global JSON parser for everything else
app.use(express.json());

// Server-side price lookup — client cannot control amount
const PLANS = {
  pro: 'price_1PYxxxREDACTED_pro',
  basic: 'price_1PYyyyREDACTED_basic',
};

app.post('/api/checkout', requireAuth, async (req, res) => {
  const priceId = PLANS[req.body.plan];
  if (!priceId) return res.status(400).send('unknown plan');
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: priceId, quantity: 1 }],
    mode: 'subscription',
    success_url: 'https://example.com/ok',
    cancel_url: 'https://example.com/cancel',
  });
  res.json({ url: session.url });
});

async function createIntent(amount, customerId) {
  return await stripe.paymentIntents.create({
    amount,
    currency: 'usd',
    customer: customerId,
    automatic_payment_methods: { enabled: true },
  });
}

async function upgradePlan(subId, newPriceId) {
  return await stripe.subscriptions.update(subId, {
    items: [{ id: 'si_existing', price: newPriceId }],
    proration_behavior: 'create_prorations',
  });
}

async function confirmPayment(intentId, pmId) {
  const result = await stripe.paymentIntents.confirm(intentId, {
    payment_method: pmId,
  });
  if (result.status === 'requires_action') {
    // client handles 3DS via confirmCardPayment
    return { requiresAction: true, clientSecret: result.client_secret };
  }
  return { succeeded: result.status === 'succeeded' };
}

app.listen(3000);
