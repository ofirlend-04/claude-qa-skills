# Restore Purchases Button Missing

**Severity:** P0
**Evidence:** Apple App Review Guideline 3.1.1 ("Apps enabling IAP must provide a Restore Purchases mechanism"). Google Play subscription policy equivalent.

## Bug

```tsx
// Paywall.tsx — no Restore option
export default function Paywall() {
  return (
    <View>
      <Text>Unlock Pro</Text>
      <Button title="Subscribe — $9.99/mo" onPress={handleSubscribe} />
      <Button title="Cancel" onPress={close} />
    </View>
  );
}
```

Apple rejection is automatic on first submission.

## Fix

```tsx
import { Purchases } from '@revenuecat/purchases-capacitor';

export default function Paywall() {
  const handleRestore = async () => {
    const { customerInfo } = await Purchases.restorePurchases();
    if (customerInfo.entitlements.active['pro']) {
      navigate('/home');
    } else {
      toast('No active purchases found on this Apple ID.');
    }
  };

  return (
    <View>
      <Text>Unlock Pro</Text>
      <Button title="Subscribe — $9.99/mo" onPress={handleSubscribe} />
      <Button title="Restore Purchases" onPress={handleRestore} />
      <Button title="Cancel" onPress={close} />
    </View>
  );
}
```

For native StoreKit: `SKPaymentQueue.default().restoreCompletedTransactions()`.
For Stripe-backed paywalls on web: a "Restore" action that re-fetches subscription status from the server via the user's account.

## Detection rule

File passes the paywall heuristic (filename or contents match `paywall`, `pricing`, `subscription`, `upgrade`, or calls `Purchases.purchasePackage` / `createCheckoutSession`) AND contains UI markup (`<View`, `<div`, `<Button`, `VStack`, etc.) AND does NOT contain any of: `restorePurchases`, `restore_purchases`, `Restore Purchases`, `restoreTransactions`.

→ P0.

## False positives

- A paywall that only exists on web where the "account" page is the restore mechanism — suppress with `// qa-ignore: S11` and add a link to the account page.
- Non-iOS paywall (Android-only app) — still required by Google Play for subscriptions. Don't suppress blindly.
