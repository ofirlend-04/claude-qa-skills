# Pattern #7 — Bundle ID mismatch between Capacitor config and Xcode project

**Severity:** P0 (RevenueCat loads wrong config, push silent, ASC upload fails)

## Story

An early Luna build had `appId: "com.ofirapps.luna"` in `capacitor.config.json` but `PRODUCT_BUNDLE_IDENTIFIER = com.luna.app` in `project.pbxproj`. Consequences:

- RevenueCat matched by bundle id → returned WiFiGuardian's offerings (nonsense).
- Push notifications registered against a bundle that had no APNs cert.
- ASC rejected the upload — the binary's bundle id didn't match the app record.

The fix was a 5-line diff, but the debugging took half a day because each symptom looked like a different bug.

## Bad config

```json
// capacitor.config.json
{ "appId": "com.ofirapps.luna" }
```

```
// ios/App/App.xcodeproj/project.pbxproj
PRODUCT_BUNDLE_IDENTIFIER = com.luna.app;
```

## Good config

Both must match exactly. Pick the ASC app record's bundle id as the source of truth:

```json
// capacitor.config.json
{ "appId": "com.ofirapps.luna" }
```

```
// project.pbxproj — in BOTH Debug and Release configurations
PRODUCT_BUNDLE_IDENTIFIER = com.ofirapps.luna;
```

Then:

```bash
npx cap sync ios
```

## Detection

```bash
# Extract from capacitor config
cap_id=$(grep -oE '"appId"\s*:\s*"[^"]+"' capacitor.config.json | cut -d'"' -f4)
# Extract from pbxproj
pbx_ids=$(grep PRODUCT_BUNDLE_IDENTIFIER ios/App/App.xcodeproj/project.pbxproj | sort -u)
echo "capacitor: $cap_id"
echo "xcode: $pbx_ids"
# Any mismatch = P0
```

## Related traps

- `capacitor.config.ts` (TypeScript) uses `appId: '...'` — different grep.
- Some teams set different bundle ids per Xcode configuration (Debug vs Release). Both must match.
- App group entitlements, associated domains, and Sign In with Apple all key off the bundle id. Mismatch cascades.
