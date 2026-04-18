# Pattern: Console errors on page load

**Rule:** G2
**Severity:** P0
**Seen in:** Editox v5-editor, JARVIS dashboard activity page

## The bug

Opening a page and seeing red in the console means something is broken that you haven't noticed. Either:

1. Code that's crashing silently (caught or swallowed by React error boundary).
2. Networks requests failing.
3. Deprecated API warnings that will become errors.
4. Noisy third-party scripts that will mask real bugs.

If the console is noisy on every load, the next real bug will hide in the noise.

### Bad examples

```
TypeError: Cannot read properties of undefined (reading 'map')  at ActivityList.tsx:45
```
→ SSR fetched data that's null on first render.

```
Failed to load resource: /api/legacy-endpoint 404
```
→ Dead API call the client no longer needs.

```
Warning: Each child in a list should have a unique "key" prop.
```
→ React will perform poorly.

```
[Vue warn]: Missing required prop: "title"
```
→ Component contract broken, render will be wrong.

```
A11y: <img> missing alt attribute
```
→ Accessibility bug.

```
Content Security Policy: The page's settings blocked the loading of a resource
```
→ Legitimate CSP violation OR your CSP is wrong.

```
[Violation] 'click' handler took 412ms
```
→ Performance problem.

## The fix

### React / Next.js — narrow down

```tsx
// Add a boundary to catch crashes that would otherwise silently break
import { ErrorBoundary } from 'react-error-boundary';

<ErrorBoundary fallback={<ErrorCard />} onError={(err) => console.error('BOUNDARY', err)}>
  <ActivityList />
</ErrorBoundary>
```

Then in dev, make every error fatal:

```ts
// _app.tsx or app/layout.tsx
if (process.env.NODE_ENV !== 'production') {
  const origError = console.error;
  console.error = (...args) => {
    origError(...args);
    // Optional: throw to force a visible crash in dev
    throw new Error(args.join(' '));
  };
}
```

### Null-safe data access

```tsx
// Bad: crashes when data is undefined on first paint
{activity.items.map(...)}

// Good: fallback to [] until loaded
{(activity?.items ?? []).map(...)}
```

### Remove dead endpoints

Search for every `fetch(`, `axios.`, `useQuery`, `useSWR` in the client and verify each endpoint returns 200.

### Silence noisy third-party warnings correctly

Don't globally silence. If Segment or GA is spamming, file a bug upstream and wrap in a guarded loader:

```ts
function loadAnalytics() {
  if (!window.__CONSENT_GIVEN) return;  // GDPR / cookie policy
  // ...
}
```

## How to detect

**`playwright_checks.js`** captures `page.on('console', ...)` during `page.goto(url)` and flags any error or warning as a finding.

**CI step:** Fail the build if the console has any `error` on the homepage:

```js
page.on('console', (msg) => {
  if (msg.type() === 'error') {
    throw new Error(`Console error: ${msg.text()}`);
  }
});
```

**Manual:** Open DevTools → Console → clear → hard reload (Cmd+Shift+R). Zero red, zero yellow before shipping.

## Related rules

- G6 (dead backend endpoints)
- A8 (aria-hidden blocking focus)
