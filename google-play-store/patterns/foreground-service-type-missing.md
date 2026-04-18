# Pattern 10 — Foreground service type missing (Android 14+)

**Severity:** P1 (P2 while targetSdk < 34)
**Policy:** Android 14 behavioural change — FGS types required
**Real evidence:**
- https://developer.android.com/about/versions/14/changes/fgs-types-required
- https://android-developers.googleblog.com/2023/06/android-14-behavior-changes-part-1.html
- https://issuetracker.google.com/issues/285167119

## Story

Android 14 (API 34) added `MissingForegroundServiceTypeException`: any foreground service started without an explicit `android:foregroundServiceType` crashes the app immediately. Play Console won't reject the submission, but once the app is bumped to targetSdk 34 (required anyway) it will ship broken.

## Bad

```xml
<service
    android:name=".BackgroundSyncService"
    android:exported="false" />
```

The app also declares `<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />`.

## Good

```xml
<service
    android:name=".BackgroundSyncService"
    android:foregroundServiceType="dataSync"
    android:exported="false" />
```

Valid types: `camera`, `connectedDevice`, `dataSync`, `health`, `location`, `mediaPlayback`, `mediaProcessing`, `mediaProjection`, `microphone`, `phoneCall`, `remoteMessaging`, `shortService`, `specialUse`, `systemExempted`.

## Detection rule

Manifest declares `FOREGROUND_SERVICE` permission. For every `<service>` without a `foregroundServiceType` attribute AND whose permission is not `BIND_ACCESSIBILITY_SERVICE` (accessibility services are not FGS), flag. Severity upgrades to P1 once targetSdk ≥ 34 or no targetSdk is declared.

## False positives

- Services that are *never* promoted to foreground (only `startService()` / bound). Scanner can't tell statically — use `.qaignore` to suppress.
- Plugins that declare their own FGS via runtime registration. Verify manually.
