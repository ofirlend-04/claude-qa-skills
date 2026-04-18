# Pattern #6 — Info.plist missing ITSAppUsesNonExemptEncryption

**Severity:** P1 (ASC upload blocker / runtime prompt on every build)
**Apple:** Export compliance / App Store Connect submission.

## Story

On April 5, 2026, DoFast's automated build pipeline failed at upload with:

> ITMS-90683: Missing Purpose String — ITSAppUsesNonExemptEncryption is missing.

We had been manually answering the export-compliance question in ASC for every build, which is slow and breaks CI. Adding the key to `Info.plist` once fixes it forever.

## Bad Info.plist

```xml
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>DoFast</string>
  <!-- no encryption declaration -->
</dict>
</plist>
```

## Good Info.plist

```xml
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>DoFast</string>
  <key>ITSAppUsesNonExemptEncryption</key>
  <false/>
</dict>
</plist>
```

Use `<false/>` for apps that only use HTTPS (the standard-library exemption). Use `<true/>` only if you ship custom crypto code, in which case you also need an Encryption Registration Number from the Bureau of Industry and Security.

For Capacitor apps using only `fetch`, RevenueCat, Firebase, etc., `<false/>` is correct.

## Detection

```bash
grep -c ITSAppUsesNonExemptEncryption ios/App/App/Info.plist
# Must be >= 1
```

## Fix

Open `ios/App/App/Info.plist` in any editor, add before `</dict>`:

```xml
<key>ITSAppUsesNonExemptEncryption</key>
<false/>
```

No rebuild needed — Info.plist changes are picked up on next archive.
