# Pattern 6 — targetSdkVersion below the Play requirement

**Severity:** P0 (< 34), P0 (< 35), P1 (< 36)
**Policy:** Target API level requirements
**Real evidence:**
- https://developer.android.com/google/play/requirements/target-sdk
- https://support.google.com/googleplay/android-developer/answer/11926878
- https://android-developers.googleblog.com/2024/08/target-api-level-requirements-2024.html

## Story

Google phases in new target-SDK requirements every August:

- **Aug 2024** — new apps / updates must target **API 34** (Android 14).
- **Aug 2025** — existing apps blocked from updates if `< 35` (Android 15).
- **2026 cycle** — expected `36` (Android 16) minimum.

Upload to Play Console is **blocked**, not just warned.

## Bad

```groovy
android {
    defaultConfig {
        targetSdkVersion 30   // too low — upload blocked since Aug 2024
    }
}
```

## Good

```groovy
android {
    namespace 'com.example.app'
    compileSdkVersion 36

    defaultConfig {
        minSdkVersion 24
        targetSdkVersion 36
    }
}
```

## Detection rule

Regex `targetSdk(?:Version)?\s*[=\s]\s*(\d+)` in `build.gradle(.kts)`. Compare captured integer against `TARGET_SDK_CURRENT=34`, `TARGET_SDK_NEXT=35`, `TARGET_SDK_2026=36`.

## False positives

- Apps targeting Wear OS / Auto / TV — they sometimes lag by one release. Check the Play Console category; suppress via `.qaignore` if so.
