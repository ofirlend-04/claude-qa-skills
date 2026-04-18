# Pattern #11 & #18 — CFBundleDisplayName problems (length, emoji)

**Severity:** P1 (home-screen truncation, ASC upload rejection for emoji)

## Story

### Truncation — WiFi Guardian, April 6, 2026

Apple review comment:
> Guideline 2.3.8 — Name Mismatch. App Store name: "Hidden Cam Detector: WiFi Scan". Device name: "Hidden Cam Detector" (truncated to "Hidden Cam…" on home screen).

iOS trims the home-screen label around 11–13 chars (device-dependent). "Hidden Cam Detector" (19 chars) showed as "Hidden Cam…", which no longer matched the ASC name. Double-fail.

### Emoji — early Luna build

ASC upload rejected with:
> ERROR ITMS-90036: Invalid character in CFBundleDisplayName — value contains characters that are not allowed.

The build had `<string> Luna</string>` with a leading moon emoji. Apple's bundle validator rejects non-ASCII display names, even though iOS itself renders them fine.

## Bad Info.plist

```xml
<key>CFBundleDisplayName</key>
<string>Hidden Cam Detector</string>        <!-- 19 chars -->

<key>CFBundleDisplayName</key>
<string> Luna</string>                       <!-- emoji -->
```

## Good Info.plist

```xml
<key>CFBundleDisplayName</key>
<string>Hidden Cam</string>                  <!-- 10 chars -->

<key>CFBundleDisplayName</key>
<string>Luna</string>                        <!-- ASCII -->
```

Rules of thumb:
- **Length:** `<= 12` characters for home-screen safety. Longer is OK if you also match ASC name exactly and accept truncation.
- **Emoji / non-ASCII:** never in `CFBundleDisplayName`. Use emoji in screenshots and descriptions only.

## Detection

```python
# In Info.plist: extract CFBundleDisplayName string
import re, sys, pathlib
txt = pathlib.Path('ios/App/App/Info.plist').read_text()
m = re.search(r'<key>CFBundleDisplayName</key>\s*<string>([^<]+)</string>', txt)
name = m.group(1) if m else ''
if any(ord(c) > 127 for c in name):
    print(f'BAD: non-ASCII in "{name}"')
if len(name) > 12:
    print(f'WARN: {len(name)} chars — may truncate on home screen')
```

## Fix

1. Open `ios/App/App/Info.plist`.
2. Set `CFBundleDisplayName` to a short, pure-ASCII name that matches what you'll use as the ASC display name.
3. If you want a fancy marketing name ("Luna: Period Tracker RPG") — put it in the **ASC product name** field, not in Info.plist.
