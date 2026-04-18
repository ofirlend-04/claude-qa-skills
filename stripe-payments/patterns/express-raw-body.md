# Express Raw-Body Parsing Wrong

**Severity:** P0
**Evidence:** Stripe docs — "Integrate with Stripe webhooks" (Node.js / Express example). Reddit r/node: "Stripe signature verification fails in production" — consistently same root cause.

## Bug

```javascript
const app = express();
app.use(express.json());                      // parses ALL bodies as JSON first

app.post('/webhook/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  // req.body is now a parsed object — constructEvent needs the raw Buffer!
  const event = stripe.webhooks.constructEvent(
    req.body, sig, process.env.STRIPE_WEBHOOK_SECRET,
  );  // throws "No signatures found matching the expected signature"
});
```

Works in dev (your own test events pass through); breaks silently in production because Express's JSON parser re-serializes with different whitespace / key order → HMAC doesn't match.

## Fix — mount webhook route with raw body BEFORE global JSON

```javascript
const app = express();

// 1. Stripe webhook — raw body, mounted FIRST
app.post(
  '/webhook/stripe',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(
      req.body, sig, process.env.STRIPE_WEBHOOK_SECRET,
    );
    // ...
  },
);

// 2. Global JSON parser for everything else
app.use(express.json());
```

## Detection rule

File contains `express`, mentions `stripe`, and:
1. Has `app.use(express.json())`.
2. Has `(app|router).post('/.../(webhook|stripe)/...')`.
3. Does NOT have `(express|bodyParser).raw({ type: 'application/json' })` mounted as middleware.

→ P0.

## False positives

- Next.js App Router API routes (`app/api/webhooks/stripe/route.ts`) use a different body-parser mechanism (`export const runtime = 'nodejs'` + reading `await req.text()`). This scanner doesn't fire on Next.js routes because they lack `app.use(express.json())`.
- Custom framework that passes raw bytes — suppress with `// qa-ignore: S3` on the `app.use(express.json())` line.
