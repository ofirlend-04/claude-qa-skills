# Pattern 9 — Subscription UI without Google Play Billing

**Severity:** P0
**Policy:** Payments policy
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/9858738
- https://android-developers.googleblog.com/2024/09/play-billing-enforcement.html
- https://www.reddit.com/r/androiddev/comments/1boeqof/rejected_for_using_stripe_instead_of_play_billing/

## Story

If the app sells digital content (in-app features, subscriptions, virtual goods), it **must** use Google Play Billing. Using Stripe / PayPal / a web checkout is an instant ban under the Payments Policy (Play's equivalent of Apple 3.1.1). We've seen dev's own email receipts cited as evidence during review.

## Bad

React paywall with `<button>Subscribe — $9.99/month</button>` and the app's dependencies contain only `@capacitor/core` — no `@revenuecat/purchases-capacitor`, `cordova-plugin-purchase`, or `com.android.billingclient:billing`.

## Good

```json
{
  "dependencies": {
    "@revenuecat/purchases-capacitor": "^8.0.0"
  }
}
```

…wired into the paywall via `Purchases.purchasePackage(pkg)`.

## Detection rule

Search `src/`, `www/`, `app/src/main/java/` for `subscrib|paywall|premium|upgrade|pro\s*plan|monthly|annual`. If a match is found AND neither `package.json` nor `build.gradle` declare any of:
- `@revenuecat/purchases-capacitor`
- `capacitor-revenuecat`
- `cordova-plugin-purchase`
- `com.android.billingclient`

…flag P0.

## False positives

- Enterprise apps that sell only physical goods / services (Play Billing not required for physical). Scanner will still flag; suppress via `.qaignore`.
- Sites listing "Premium" tiers as a marketing page but not actually selling. Rare.
