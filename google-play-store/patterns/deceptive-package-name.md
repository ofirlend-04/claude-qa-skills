# Pattern 8 — Deceptive package name / impersonation risk

**Severity:** P1
**Policy:** Impersonation + Deceptive Behavior
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/9888077
- https://android-developers.googleblog.com/2024/03/deceptive-behavior-policy-2024.html
- https://www.bleepingcomputer.com/news/security/google-play-removed-2000-impersonation-apps-in-2025/

## Story

Brand impersonation is zero-tolerance. Package ids containing `whatsapp`, `instagram`, `tiktok`, `facebook`, `messenger`, `gmail`, `youtube`, `netflix`, `spotify`, `telegram`, `snapchat`, `twitter`, `googlepay`, `paypal`, `venmo`, `cashapp`, `zoom` get removed without warning. The first-party brands have a persistent scan.

## Bad

```json
{ "name": "whatsapp-messenger-lite" }
```

```xml
<manifest package="com.example.whatsapp.clone">
```

## Good

Rename to a distinctive brand. If you have a legitimate license, prepare brand authorisation documentation — but expect a takedown first, appeal later.

## Detection rule

Substring match the `name` field of `package.json` and the `package` attribute of `AndroidManifest.xml` against the `IMPERSONATION_SUBSTRINGS` list.

## False positives

- Official first-party apps (e.g. you work for Meta). Scanner still flags; trivial to suppress.
- Innocuous substrings like "zoom" in a photography app ("zoomcam"). Review manually.
