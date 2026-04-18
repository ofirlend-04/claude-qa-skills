# Pattern 12 — Hardcoded API keys / secrets in Android config

**Severity:** P0
**Policy:** Safe and secure use of third-party services + general security hygiene
**Real evidence:**
- https://developer.android.com/studio/build/shrink-code
- https://security.googleblog.com/2024/11/api-key-exposure-top-10-android-risks.html
- https://www.trendmicro.com/en_us/research/22/f/1000-apps-exposing-api-keys-and-secrets.html
- https://blog.mindedsecurity.com/2025/03/hardcoded-secrets-in-android-builds.html

## Story

A Trend Micro 2022 audit found ~1,000 Play Store apps exposing API keys in their APK. The situation is worse in 2025-2026 because Capacitor apps often copy web-era keys straight into `BuildConfig`. The Google API key alone is enough for an attacker to rack up billing charges on your Maps / Translate / Vertex account.

Play Console's Pre-Launch Report includes a secret scan — findings block the release track automatically.

## Bad

```xml
<!-- AndroidManifest.xml -->
<meta-data
    android:name="com.google.android.geo.API_KEY"
    android:value="AIzaSyA1234567890abcdefghijklmnopqrstuvw" />
```

```groovy
// build.gradle
buildConfigField "String", "OPENAI_API_KEY", "\"sk-abcdefghijklmnopqrstuvwxyz1234567890\""
```

```xml
<!-- strings.xml -->
<string name="stripe_secret">sk_live_51ABCDEF…</string>
```

## Good

Put the key in `~/.gradle/gradle.properties` (outside the repo):

```
OPENAI_API_KEY=sk-…
```

Reference it via `BuildConfig`:

```groovy
defaultConfig {
    buildConfigField "String", "OPENAI_API_KEY", "\"${project.properties['OPENAI_API_KEY']}\""
}
```

For the Maps API key, use manifestPlaceholders:

```groovy
defaultConfig {
    manifestPlaceholders = [googleMapsApiKey: project.properties['GOOGLE_MAPS_API_KEY']]
}
```

```xml
<meta-data android:name="com.google.android.geo.API_KEY" android:value="${googleMapsApiKey}" />
```

## Detection rule

Regex-scan `AndroidManifest.xml`, every `strings.xml`, `build.gradle`, `gradle.properties`, `local.properties`, `google-services.json` for:
- `AIza[A-Za-z0-9_\-]{35}` (Google API key)
- `AKIA[A-Z0-9]{16}` (AWS)
- `sk_live_…`, `pk_live_…` (Stripe)
- `goog_…` (RevenueCat Android)
- `sk-…`, `sk-ant-…` (LLM providers)
- `1//0…{40,}` (long-lived Google tokens)

`google-services.json` is special-cased: it legitimately contains `AIza…` keys. Only flag when it ALSO contains a `private_key` (leaked service account).

## False positives

- Test keys intended for debug builds only — move them into `src/debug/` flavour.
- `google-services.json` with only public keys — intentionally exempted.
