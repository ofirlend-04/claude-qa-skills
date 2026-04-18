# Pattern 7 — Privacy policy URL missing

**Severity:** P1
**Policy:** User Data policy — Privacy Policy
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/9859455
- https://orufy.com/blog/webtonative/google-play-app-rejection-reasons (top rejection reason)
- https://www.reddit.com/r/androiddev/comments/13hqw6p/i_keep_getting_rejected_for_privacy_policy/

## Story

Every app that handles personal or sensitive user data must have a privacy policy URL on the store listing AND in-app (if the app has account-based features). Missing or 404 URL → Play Console blocks submission. This is the #1 rejection reason on orufy's telemetry for indie devs.

## Bad

`package.json` has no `privacy` URL. README has no privacy section. `.env` has no `PRIVACY_POLICY_URL`. Dev uploads anyway — rejected.

## Good

Either in `package.json`:

```json
{
  "name": "cleanapp",
  "description": "Privacy policy: https://example.com/privacy",
  "homepage": "https://example.com"
}
```

Or in `.env.example`:

```
PRIVACY_POLICY_URL=https://example.com/privacy
```

Or a paragraph in README pointing at the published policy. Scanner accepts any URL that contains `priva` (case insensitive).

## Detection rule

Grep `package.json`, `capacitor.config.{ts,js,json}`, `README.md`, `.env`, `.env.example` for:
- `https?://…priva…` URL, OR
- `PRIVACY_POLICY_URL=` env-var key.

No match → P1.

## False positives

- Apps whose privacy policy URL lives only in Play Console metadata (not in code). Scanner will flag; suppress via `.qaignore`.
