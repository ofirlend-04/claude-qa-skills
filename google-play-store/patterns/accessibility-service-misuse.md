# Pattern 4 — ACCESSIBILITY_SERVICE misuse

**Severity:** P0 (downgraded to P1 if app is plausibly assistive)
**Policy:** Accessibility API policy
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/10964491
- https://android-developers.googleblog.com/2024/05/accessibility-policy-clarifications.html
- https://www.reddit.com/r/androiddev/comments/172sg9e/google_play_rejected_my_app_for_using/
- https://techcrunch.com/2024/06/google-tightens-accessibility-service-rules/

## Story

ACCESSIBILITY_SERVICE has been the single most abused Android permission — used for auto-clickers, ad-blockers, password managers, call recorders. The 2024-2026 crackdown caused the largest wave of Play takedowns since the 2019 SMS policy. As of the updated policy, apps must:

1. Be genuinely for people with disabilities (or declare another qualifying use), AND
2. Submit an Accessibility API declaration video in Play Console showing the disability-assistive flow.

## Bad

```xml
<service
    android:name=".AutoTapAccessibilityService"
    android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
    android:exported="true">
    <intent-filter>
        <action android:name="android.accessibilityservice.AccessibilityService" />
    </intent-filter>
    <meta-data
        android:name="android.accessibilityservice"
        android:resource="@xml/accessibility_service_config" />
</service>
```

…inside an app whose README says "Automate repetitive UI tapping tasks."

## Good

Either:
- Remove the service entirely and redesign (e.g. ask the user to use their OS's built-in accessibility tools), OR
- Be genuinely assistive (screen reader, low-vision aid, AAC tool) AND submit the declaration video in Play Console.

## Detection rule

Manifest contains `<service ... android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">`. Scanner checks README + package.json description for disability-assistive keywords (`screen reader`, `talk back`, `low vision`, `disability`, `accessibility`, `dyslex`, `ADHD assist`, `motor impair`). Hit → P1. Miss → P0.

## False positives

- Apps that genuinely help with disabilities but whose README doesn't mention it. Easy fix: add a paragraph to README describing the disability-assistive use case, or suppress via `.qaignore`.
