# Pattern #1 — RC_API_KEY is a placeholder

**Severity:** P0 (broken purchase flow, rejection)
**Apple guideline (if it ships):** 2.1(b) — "We couldn't find your in-app purchases."

## Story

On April 3, 2026, Luna was rejected by Apple because the reviewer tapped "Subscribe" and nothing happened. Investigation showed `src/rc.js` had shipped with:

```js
const RC_API_KEY = 'YOUR_RC_KEY_HERE';
```

`Purchases.configure()` silently failed in RevenueCat 6.x when given a placeholder — no exception, just no offerings ever loaded. The paywall rendered, the Subscribe button was tappable, but no StoreKit sheet ever appeared.

The same bug appeared in early WiFiGuardian, BabyBloom, and MigraineLog builds. It's the single most common P0 we've shipped.

## Bad code

```js
// src/rc.js
const RC_API_KEY = 'YOUR_RC_KEY_HERE';        // placeholder
const RC_API_KEY = '';                         // empty
const RC_API_KEY = '<YOUR_KEY>';               // template
const RC_API_KEY = process.env.VITE_RC_KEY;    // undefined in prod build
```

## Good code

```js
// src/rc.js
// Key comes from the RevenueCat dashboard → Project → API keys → Apple public key
const RC_API_KEY = 'appf2fe689299';
```

For multi-env setups use a build-time constant, not a runtime env var, since Capacitor iOS runs from a static bundle:

```js
// vite.config.js
define: { 'import.meta.env.VITE_RC_KEY': JSON.stringify('appf2fe689299') }
```

## Detection

```bash
grep -nE "YOUR_|PLACEHOLDER|REPLACE_ME|<RC_KEY>|^const RC_API_KEY = ['\"]['\"]" src/rc.js
```

If the key is shorter than 12 chars or doesn't start with `app`, flag it too.

## Fix workflow

1. Log into RevenueCat → pick the app's project.
2. Copy the **Apple public key** (starts with `app`, ~14 chars).
3. Paste into `src/rc.js`.
4. Run `npm run build && npx cap sync ios`.
5. Smoke test with a sandbox Apple ID — Subscribe button should trigger the StoreKit sheet within 1 second.
