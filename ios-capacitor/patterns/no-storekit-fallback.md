# Pattern #2 — rc.js missing StoreKit fallback

**Severity:** P0 (dead paywall in sandbox, rejection)
**Apple guideline (if it ships):** 2.1(b)

## Story

On April 9, 2026, WiFi Guardian was rejected because the Apple reviewer tapped "Subscribe Now" on an iPad and "no action followed". We reproduced it in sandbox: `Purchases.getOfferings()` returned `{ current: null }` because the RC dashboard didn't have a "current" offering marked. The purchase path had no StoreKit fallback — it just threw `No offerings available` and returned silently.

Every app we've shipped since then has a direct `getProducts` + `purchaseStoreProduct` fallback. It saved Luna, BabyBloom, and CoreFloor from the same rejection.

## Bad code

```js
export async function purchasePackage(packageType) {
  const { offerings } = await Purchases.getOfferings();
  const current = offerings?.current;
  if (current) {
    const pkg = packageType === 'monthly' ? current.monthly : current.annual;
    const { customerInfo } = await Purchases.purchasePackage({ aPackage: pkg });
    return customerInfo.entitlements.active[ENTITLEMENT_ID] !== undefined;
  }
  throw new Error('No offerings');  // dead end
}
```

## Good code

```js
export async function purchasePackage(packageType) {
  try {
    // Path A: offerings
    const { offerings } = await Purchases.getOfferings();
    const current = offerings?.current;
    if (current) {
      let pkg = null;
      if (packageType === 'monthly') pkg = current.monthly;
      else if (packageType === 'annual' || packageType === 'yearly') pkg = current.annual;
      else pkg = current.annual || current.availablePackages?.[0];
      if (pkg) {
        const { customerInfo } = await Purchases.purchasePackage({ aPackage: pkg });
        return customerInfo.entitlements.active[ENTITLEMENT_ID] !== undefined;
      }
    }
    // Path B: direct StoreKit fallback (works even without RC dashboard config)
    const productId = PRODUCT_IDS[packageType] || PRODUCT_IDS.annual;
    const { products } = await Purchases.getProducts({ productIdentifiers: [productId] });
    if (products?.length) {
      const { customerInfo } = await Purchases.purchaseStoreProduct({ product: products[0] });
      return customerInfo.entitlements.active[ENTITLEMENT_ID] !== undefined;
    }
    throw new Error('No products available');
  } catch (e) {
    if (e.code === 1 || e.message?.includes('cancel')) return false;
    throw e;
  }
}
```

Do the same in `getOfferings()` so the paywall UI can display prices when offerings are empty.

## Detection

```bash
grep -nE "getProducts|purchaseStoreProduct" src/rc.js || echo "MISSING"
```

If either is absent from `src/rc.js`, flag as P0.

## Why this matters

RC dashboards drift. Offerings get unpublished. Products get paused. Sandbox behaves differently from production. The StoreKit fallback means **as long as the product exists in ASC, the purchase will work** — even if every other layer is misconfigured.
