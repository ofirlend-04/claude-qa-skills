# Pattern #4 — `premium: true` in initial React state

**Severity:** P0 (Apple sees all features unlocked — "can't find your IAPs")
**Apple guideline:** 2.1(b)

## Story

On April 3, 2026, Luna was rejected with:
> Guideline 2.1(b) — We were unable to find any in-app purchases within your app.

Root cause in `src/App.jsx`:

```jsx
const [state, setState] = useState({
  premium: true,   // left over from debugging
  // ...
});
```

The reviewer opened the app, everything was already unlocked, and no paywall was ever triggered. To Apple, this looks like the app has no IAPs at all.

We had shipped this exact bug in CalmQuest (earlier), then repeated it in Luna.

## Bad code

```jsx
const [state, setState] = useState({ premium: true });
```

Also bad:

```jsx
const [isPremium, setIsPremium] = useState(true);
const [isPro, setIsPro] = useState(true);
```

## Good code

```jsx
const [state, setState] = useState({ premium: false });

useEffect(() => {
  checkPremium().then(isPremium => {
    setState(s => ({ ...s, premium: isPremium }));
  });
}, []);
```

The premium flag starts **false**. It only flips true after `checkPremium()` verifies an active entitlement from RevenueCat.

## Detection

```bash
grep -rnE "\b(premium|isPremium|isPro)\s*:\s*true\b" src/
grep -rnE "useState\(\s*true\s*\).*[Pp]remium" src/
```

## Why this keeps happening

- During development, you flip premium to `true` to test gated features.
- You forget to flip it back before shipping.
- Vite/React Fast Refresh hides the issue — you're always logged in with dev state.

## Prevention

Add a dev-only override instead of flipping the initial state:

```jsx
const [state, setState] = useState({ premium: false });
// One-liner dev override — grep-able, easy to remove
if (import.meta.env.DEV && localStorage.DEV_PREMIUM === '1') {
  state.premium = true;
}
```

Then `DEV_PREMIUM` can stay in localStorage on your simulator; shipping code is always `false` by default.
