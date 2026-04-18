# Pattern #17 — "Lifetime" plan in UI without a matching RC product

**Severity:** P1 (Apple rejection 2.1(b) — tapped lifetime, nothing happened)

## Story

Early CalmQuest builds had a three-tier paywall — Monthly, Yearly, Lifetime. When we replaced the IAP with a subscription-only model, we removed the `lifetime` product from App Store Connect and RevenueCat. Nobody remembered to remove the Lifetime card from the paywall UI.

Apple reviewer tapped Lifetime → `purchasePackage('lifetime')` → `PRODUCT_IDS.lifetime` was `undefined` → `getProducts({ productIdentifiers: [undefined] })` threw → button did nothing. Rejection.

Same pattern appeared in Hebrew translations as "לכל החיים" / "חד פעמי" — harder to grep for if you only check English.

## Bad code

```jsx
// src/App.jsx paywall
const plans = [
  { id: 'monthly', label: 'Monthly', price: '$4.99' },
  { id: 'annual', label: 'Yearly', price: '$29.99' },
  { id: 'lifetime', label: 'Lifetime', price: '$59.99' },  // <-- no RC product
];
```

```js
// src/rc.js
const PRODUCT_IDS = {
  monthly: 'calmquest_monthly',
  annual: 'calmquest_yearly',
  // no lifetime entry
};
```

## Good code — either remove UI

```jsx
const plans = [
  { id: 'monthly', label: 'Monthly' },
  { id: 'annual', label: 'Yearly' },
];
```

## Or add the product

```js
const PRODUCT_IDS = {
  monthly: 'calmquest_monthly',
  annual: 'calmquest_yearly',
  lifetime: 'calmquest_lifetime',   // must also exist in ASC + RC
};
```

…and create the non-consumable IAP in ASC, attach to the entitlement in RC.

## Detection

```bash
# Find lifetime references in UI
grep -rniE "lifetime|forever|לכל החיים|חד פעמי|one-time|pay once" src/

# Then check rc.js for a matching key
grep -nE "lifetime\s*:\s*['\"]" src/rc.js
```

If UI has it and `src/rc.js` does not → P1.

## Languages we've seen lifetime text in

- English: `lifetime`, `forever`, `one-time`, `pay once`
- Hebrew: `לכל החיים`, `חד פעמי`, `לנצח`
- Spanish: `de por vida`, `para siempre`
- Arabic: `مدى الحياة`

If the app supports multiple locales, grep all translation files, not just English.
