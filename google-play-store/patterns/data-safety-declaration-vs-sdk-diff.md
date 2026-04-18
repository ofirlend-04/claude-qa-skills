# Pattern 1 — Data Safety declaration vs actual SDK usage diff

**Severity:** P0
**Policy:** Data Safety (Play Console) — April 15, 2026 update
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/10787469
- https://primetestlab.com/blog/google-play-app-rejection-rate-2026
- https://android-developers.googleblog.com/2024/04/data-safety-enforcement.html

## Story

April 15, 2026: Google tightened Data Safety enforcement. Reviewers now diff the declaration against observed network traffic + bundled SDKs during static analysis. If Firebase Analytics is embedded but the declaration says "no data collected", the submission is rejected with an automated email referencing the SDK SHA. primetestlab reports this as the single fastest-growing rejection category in 2026.

## Bad

`package.json` contains `firebase`, `amplitude-js`, `@sentry/capacitor`. Play Console declaration was left on the default "We do not collect any data" because nobody filled it in.

## Good

A `PLAY_DATA_SAFETY.md` (or `data-safety.json`) committed to the repo, enumerating:

```
- firebase-analytics → collects: Device IDs, App interactions; purpose: Analytics; shared: No
- @sentry/capacitor  → collects: Crash logs, Device IDs; purpose: Crash reporting; shared: With Sentry
- @revenuecat       → collects: Purchase history, User ID; purpose: Purchases; shared: With RevenueCat
```

And the Play Console declaration matches, line for line.

## Detection rule

Scan `package.json` + `build.gradle` for SDKs in the `DATA_COLLECTING_SDKS` list (Firebase, Amplitude, Mixpanel, Segment, Sentry, AdMob, Bugsnag, Datadog). If any match AND no `PLAY_DATA_SAFETY.md` / `data-safety.json` exists in the repo, flag P0.

## False positives

- RevenueCat alone — intentionally excluded; "Purchase history" is always declared.
- SDKs used only in tests — we don't distinguish `devDependencies` because some are imported at build time for release too; verify manually.
