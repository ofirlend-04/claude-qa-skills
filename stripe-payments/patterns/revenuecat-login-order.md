# RevenueCat logIn() Ordering Bug

**Severity:** P0 (wrong order) / P2 (missing entirely when app has user accounts)
**Evidence:** RevenueCat docs — "Identifying Users" (rev.cat/docs/customers/user-ids). RC community forum thread "purchase doesn't restore after login" — recurring.

## Bug

```javascript
// Wrong — purchase happens with anonymous App User ID
async function subscribe(pkg) {
  const { customerInfo } = await Purchases.purchasePackage({ aPackage: pkg });
  // user logs in AFTER — entitlement is stuck on the anonymous $RCAnonymousID
  await Purchases.logIn({ appUserID: authedUser.id });
}
```

```javascript
// Also wrong — configure without ever calling logIn
await Purchases.configure({ apiKey: RC_API_KEY });
// ...user logs into your app via Supabase, but we never tell RC
// ...later:
await Purchases.purchasePackage({ aPackage: pkg });
// entitlement attached to $RCAnonymousID — doesn't follow the Supabase user
```

When the user reinstalls the app or switches devices, `Purchases.restorePurchases()` restores NOTHING — the entitlement was tied to an anonymous ID that's now gone.

## Fix

```javascript
// 1. Configure once on app boot
await Purchases.configure({ apiKey: RC_API_KEY });

// 2. As SOON as the user is authenticated in your own system
//    (e.g. right after Supabase sign-in), sync the ID to RevenueCat.
authClient.onAuthStateChange(async (event, session) => {
  if (event === 'SIGNED_IN' && session?.user) {
    await Purchases.logIn({ appUserID: session.user.id });
  } else if (event === 'SIGNED_OUT') {
    await Purchases.logOut();
  }
});

// 3. NOW the purchase is attributed to the right user
await Purchases.purchasePackage({ aPackage: pkg });
```

## Detection rule

File mentions `Purchases.`:

**Case 1 (P0 — wrong order):** same file has `Purchases.purchasePackage` / `Purchases.purchaseStoreProduct` appearing in source BEFORE `Purchases.logIn(`, AND the two are within 600 characters of each other (same block heuristic).

**Case 2 (P2 — missing):** `Purchases.configure` is present but `Purchases.logIn` never appears in the file.

## False positives

- App is intentionally anonymous (no user accounts anywhere) — suppress S9 with `// qa-ignore: S9` on the configure line; RC's anonymous IDs are fine.
- `logIn()` happens in a different module (auth service) that this file imports — the scanner can't see across files. If you have a separate `authService.ts` that calls `Purchases.logIn()` on login, add `// qa-ignore: S9` on the rc.js configure line.
