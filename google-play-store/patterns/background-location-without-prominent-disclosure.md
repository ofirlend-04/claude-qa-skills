# Pattern 5 — Background location without prominent disclosure

**Severity:** P0
**Policy:** Location Permissions policy
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/9799150
- https://android-developers.googleblog.com/2019/10/giving-users-more-transparency-and.html (Google remediated 200k+ apps in 2023)
- https://www.reddit.com/r/androiddev/comments/13cwwyh/rejected_again_for_background_location/

## Story

`ACCESS_BACKGROUND_LOCATION` was introduced in API 29. Google requires that **before** the runtime permission dialog, the app show a prominent in-app disclosure explaining why background location is needed, with an option to decline without closing the app. Background location declaration in Play Console is also required. Failing either = rejection / suspension.

## Bad

```xml
<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
```

…with no `strings.xml` rationale, no prominent-disclosure dialog, no Play Console declaration.

## Good

Prominent disclosure shown once on app start, BEFORE requesting the permission:

```xml
<string name="background_location_disclosure">
    RouteTracker collects location data in the background to calculate your daily cycling distance even when the app is closed. We never sell or share this data. You can turn this off at any time in Settings.
</string>
```

Then request permission with `ActivityCompat.requestPermissions(..., ACCESS_BACKGROUND_LOCATION)` after the user taps "Allow" in the disclosure dialog.

## Detection rule

Manifest declares `ACCESS_BACKGROUND_LOCATION`. Scan `res/values*/strings.xml` for any string containing "background location", "location background", or "prominent disclosure". No hit → P0.

## False positives

- Apps that show the disclosure via TypeScript / Compose without a strings.xml key. Workaround: add the rationale string resource even if unused, or suppress via `.qaignore`.
