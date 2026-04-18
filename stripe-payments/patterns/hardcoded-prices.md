# Hardcoded Price Strings in UI

**Severity:** P2
**Evidence:** Stripe docs — "Manage products and prices" (recommends Price API as source of truth). RevenueCat docs — "Offerings" (same philosophy).

## Bug

```tsx
// Paywall.tsx
<div className="price">$9.99 / month</div>
<Button onClick={() => stripe.redirectToCheckout({
  sessionId: await createSession({ priceId: 'price_1PYxxx' }),
})}>Subscribe</Button>
```

Later you bump the plan to $12.99 in the Stripe dashboard (creating a new `price_...`). Someone updates the code to use the new Price ID but forgets the UI string. New users see "$9.99" in the paywall, get billed $12.99 on the card statement. Chargebacks incoming.

## Fix

```tsx
// Fetch price from the same source you charge against
const offering = await Purchases.getOfferings();     // RevenueCat
const pkg = offering.current.monthly;
<div className="price">
  {new Intl.NumberFormat(locale, {
    style: 'currency', currency: pkg.product.currencyCode,
  }).format(pkg.product.price)}
   / month
</div>
```

For Stripe Checkout with Price IDs, fetch `stripe.prices.retrieve(priceId)` on the server and pass `unit_amount / 100` to the UI.

## Detection rule

File is a paywall UI (filename match or calls `purchasePackage` / `createCheckoutSession`) AND uses Price API (`price_`, `offerings`, `getOfferings`) AND contains a literal like `>$9.99/month<`.

→ P2.

## False positives

- Marketing page that intentionally shows "starts at $X" — OK, but verify it matches at least one active price.
- Price hardcoded AND Price ID hardcoded together AND the two agree — still flag so they stay in sync in future changes.
