# Capacitor iOS Manual QA Checklist

Run `python auto_audit.py /path/to/app` first. Then walk this list for everything grep can't see.

## RevenueCat

- [ ] `src/rc.js` has a **real** `RC_API_KEY` (starts with `app` + 10+ chars)
- [ ] `ENTITLEMENT_ID` matches the entitlement name in RC dashboard (e.g. `luna_pro`)
- [ ] `PRODUCT_IDS` keys (`monthly`, `annual`, `yearly`) match ASC product IDs
- [ ] `Purchases.configure({ apiKey })` is called once on app launch, before any UI that shows prices
- [ ] `purchasePackage()` has both offerings path AND `getProducts` / `purchaseStoreProduct` fallback
- [ ] `restorePurchases()` exists and is wired to a Restore button
- [ ] RC dashboard has a **current** offering
- [ ] The current offering has both monthly and annual packages attached
- [ ] Each product is attached to the entitlement in RC dashboard
- [ ] If UI shows "Lifetime": there's a `lifetime` key in `PRODUCT_IDS` AND a lifetime product in ASC AND it's attached to RC

## State / Purchase Logic

- [ ] No `premium: true` / `isPremium: true` / `isPro: true` in initial React state
- [ ] Premium is set ONLY after `await checkPremium()` returns true
- [ ] No `purchasePackage('annual')` / `purchasePackage('monthly')` — selected plan is passed as a variable
- [ ] Paywall Subscribe button is `disabled` while offerings are loading
- [ ] Error from `purchasePackage` is caught and user sees a message (not a white screen)

## Bundle / Build Config

- [ ] `capacitor.config.(ts|js|json)` `appId` == `PRODUCT_BUNDLE_IDENTIFIER` in `ios/App/App.xcodeproj/project.pbxproj`
- [ ] `appName` in capacitor config matches `CFBundleDisplayName` in Info.plist (minor variations OK)
- [ ] `CFBundleDisplayName` is <= 12 chars and pure ASCII (no emoji)
- [ ] `CURRENT_PROJECT_VERSION` bumped vs last ASC upload
- [ ] `MARKETING_VERSION` bumped for resubmissions
- [ ] `TARGETED_DEVICE_FAMILY` is `"1"` (iPhone only) unless app has real iPad layout

## Info.plist

- [ ] `ITSAppUsesNonExemptEncryption` = `<false/>` (unless you use custom crypto)
- [ ] If using LocalNotifications / PushNotifications → `NSUserNotificationsUsageDescription`
- [ ] If scanning WiFi / Bonjour → `NSLocalNetworkUsageDescription` + `NSBonjourServices`
- [ ] If using camera → `NSCameraUsageDescription`
- [ ] If using photos → `NSPhotoLibraryUsageDescription`
- [ ] If using location → `NSLocationWhenInUseUsageDescription`
- [ ] If using HealthKit → `NSHealthShareUsageDescription` + `NSHealthUpdateUsageDescription`
- [ ] If using microphone → `NSMicrophoneUsageDescription`
- [ ] All usage descriptions are user-friendly sentences (not "used by app")

## Capacitor Sync

- [ ] `npm run build` runs clean (no warnings about missing env)
- [ ] `npx cap sync ios` was run AFTER the last JS change
- [ ] `ios/App/App/public/` mtime is >= `dist/` mtime
- [ ] `Podfile.lock` committed and matches `package.json` Capacitor versions

## Notifications

- [ ] `LocalNotifications.schedule` uses `schedule: { at: date }` (not deprecated `trigger: { at }`)
- [ ] Notification permissions requested AFTER user onboarding (not on first launch)
- [ ] Icons (`ic_stat_icon`) exist in `ios/App/App/Assets.xcassets/`

## Error Handling

- [ ] `src/main.jsx` wraps `<App />` in an `ErrorBoundary`
- [ ] `ErrorBoundary` shows a retry button, not a blank screen
- [ ] Async purchase errors are caught and surfaced to the user
- [ ] No `localhost`, `127.0.0.1`, or `ngrok` URLs in production code

## Pre-Upload Checklist

- [ ] App launches on iPhone 17 Pro Max (iOS 26.4) simulator
- [ ] App launches on iPad Air simulator (if `TARGETED_DEVICE_FAMILY='1,2'`)
- [ ] Paywall opens and loads prices (not empty)
- [ ] Sandbox purchase completes end-to-end
- [ ] Restore purchases works
- [ ] All TestFlight crash reports addressed
