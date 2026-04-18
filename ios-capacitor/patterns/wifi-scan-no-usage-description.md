# Pattern #8 — WiFi / local network scan without NSLocalNetworkUsageDescription

**Severity:** P0 (instant crash the moment you scan)
**Apple guideline:** 5.1.1 (privacy descriptions)

## Story

On April 6, 2026, WiFi Guardian's first submission crashed the moment the reviewer tapped "Start Scan". The crash log showed:

> `This app has crashed because it attempted to access privacy-sensitive data without a usage description. The app's Info.plist must contain an NSLocalNetworkUsageDescription key.`

iOS 14+ requires explicit permission for ANY local network access — even `navigator.onLine`-adjacent code that enumerates Bonjour services. The crash is a hard trap in `TCC` before your JS even runs.

## Bad Info.plist

```xml
<!-- No local network entry, but src/ calls NetworkDevices.scan() -->
```

## Good Info.plist

```xml
<key>NSLocalNetworkUsageDescription</key>
<string>Hidden Cam Detector scans your local network to find connected devices and alert you to anything suspicious.</string>
<key>NSBonjourServices</key>
<array>
  <string>_http._tcp</string>
  <string>_https._tcp</string>
  <string>_airplay._tcp</string>
  <string>_raop._tcp</string>
</array>
```

`NSBonjourServices` must list the service types your app actually scans for — iOS enforces this list.

## Detection

1. Does the app scan? Look for:
   ```bash
   grep -rnE "Bonjour|NetworkDevices|net\.scan|wifi.?scan|local.?network" src/
   ```
2. If yes, Info.plist must contain both `NSLocalNetworkUsageDescription` and `NSBonjourServices`.

## Fix workflow

1. Add both keys to `ios/App/App/Info.plist`.
2. Delete the app from the device/simulator (iOS caches the denial).
3. Rebuild — iOS shows the native permission prompt on first scan.
4. If user denies → provide a fallback screen, don't retry the scan.

## Related apps

- **WiFi Guardian / Hidden Cam Detector** — the canonical case.
- Any "find my AirPlay device", "scan my printer", "smart home remote" app falls into this trap.
