# Pattern: API key leaked in client bundle

**Rule:** F2
**Severity:** P0
**Seen in:** Nearly shipped OpenAI key in a landing page "AI demo" widget

## The bug

In a Next.js / Vite / CRA app, anything that ends up in the client bundle is public. Browsers download it, view-source shows it, attackers grep it.

Common leaks:

1. Hard-coded string in a component.
2. Env var prefixed with `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_` — those are **compile-time inlined** into the client bundle.
3. Key passed as prop from a server component to a client component.

### Bad

```tsx
// app/ai-demo/page.tsx  (client component)
'use client';
import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: 'sk-proj-abc123...xyz',
  dangerouslyAllowBrowser: true,
});
```

### Also bad

```bash
# .env.local
NEXT_PUBLIC_OPENAI_KEY=sk-proj-abc123...xyz
```

```tsx
const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY });
```

`NEXT_PUBLIC_` = shipped to the browser. Also bad.

### Also bad

```tsx
// Firebase config is usually fine to expose EXCEPT for service-account keys
const firebaseConfig = {
  apiKey: 'AIza...',        // OK — Firebase web key is scoped by App Check / rules
  privateKey: '-----BEGIN PRIVATE KEY-----\n...',  // NOT OK — service account
};
```

Read the docs for each service. Stripe `pk_live_` is OK public; `sk_live_` is not.

## The fix

Keep the secret server-side. The browser calls your server; your server calls the external API.

### Next.js (App Router)

```ts
// app/api/ai/route.ts  (server)
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_KEY });  // note: no NEXT_PUBLIC_

export async function POST(req: Request) {
  const { prompt } = await req.json();
  const res = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: prompt }],
  });
  return Response.json({ text: res.choices[0].message.content });
}
```

```tsx
// app/ai-demo/page.tsx  (client)
'use client';
import { useState } from 'react';

export default function Page() {
  const [out, setOut] = useState('');
  async function run(prompt: string) {
    const res = await fetch('/api/ai', { method: 'POST', body: JSON.stringify({ prompt }) });
    const { text } = await res.json();
    setOut(text);
  }
  // ...
}
```

### Protect the server route

The public API is now `/api/ai`. Don't let anyone hit it unlimited:

- Add rate limiting (Upstash Ratelimit, Vercel rate limit).
- Require auth if the user needs to be signed in.
- Add a hCaptcha / Cloudflare Turnstile for anonymous demos.

### If it's already leaked

1. **Rotate the key immediately.** Revoke the old one in the provider dashboard.
2. `git log -p -S'sk-' -- .` to confirm blast radius.
3. Rewrite history if the key was in a public repo (`git-filter-repo --replace-text`), force-push, and notify the provider.
4. Monitor usage logs for a week for any unauthorised activity.

## How to detect

**Static:**

```bash
# Regex each secret format
grep -rnE '(sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.env*' .
```

`auto_audit.py` runs these regex checks automatically.

**Runtime:** After deploy, view-source the page, copy the JS bundle URLs, `curl` each and grep for the patterns. Or use a service like GitGuardian / TruffleHog.

**Prevention:**

- Pre-commit hook with `gitleaks` or `detect-secrets`.
- CI step that fails if the bundle contains any `sk-` prefix.
- Code review rule: any new `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` env var requires reviewer sign-off.

## Related rules

- F1 (missing security headers)
- F3 (localStorage for sensitive data)
