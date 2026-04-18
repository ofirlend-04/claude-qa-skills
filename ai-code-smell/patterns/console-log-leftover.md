# `console.log` / Debug Leftovers in Production

**Severity:** P1 (D1 — console.log in src/), P2 (D2 — TODO/FIXME)
**Real evidence:**
- [Knostic — mishandling of secrets in AI code](https://knostic.ai/)
- Tibsar AI-code blog — "AI models leave debug prints everywhere".

## Bug

```ts
// src/api/checkout.ts
export async function createCheckout(userId: string) {
  console.log("creating checkout for", userId);    // leaks PII into browser console + server logs
  const res = await stripe.checkout.sessions.create({ /* ... */ });
  console.debug("stripe res", res);                  // leaks session details
  // TODO: handle errors
  return res;
}
```

`console.log` in prod is:
1. **PII leakage** — logs carry user IDs, tokens, etc.
2. **Performance** — serialising objects on every request.
3. **Professionalism** — customers open devtools and see "debug stuff working?"

`TODO` / `FIXME` comments ship to prod because AI writes them by default.

## Fix

```ts
import { logger } from "@/lib/logger";

export async function createCheckout(userId: string) {
  logger.info({ userId }, "creating checkout");
  const res = await stripe.checkout.sessions.create({ /* ... */ });
  return res;
}
```

If you want debug output only in dev:

```ts
if (process.env.NODE_ENV !== "production") {
  console.log("debug", res);
}
```

## Detection rule

- D1 — `\bconsole\.(log|debug)\s*\(` inside files under `src/`, `app/`, `pages/`, `lib/`, `components/`. Skip tests, storybook, `/scripts/`, `/dev/`.
- D2 — `(?://|#)\s*(TODO|FIXME|HACK|XXX)\b` in source files.

Scanner de-duplicates and skips blocks wrapped in a `NODE_ENV !== 'production'` check within the last 120 chars.

## False positives

- Intentional logging in a CLI (not a web app). Add `.qaignore` entry.
- A custom `console.log` wrapper that routes to a real logger. Rename it.
