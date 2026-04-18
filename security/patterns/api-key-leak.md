# Pattern: API key leaked in client-bundled source

**Rules:** A1–A9, B1–B4
**Severity:** P0
**Seen in:** Near-miss OpenAI leak in a Next.js landing page's "AI demo" widget. Public GitHub repo pushed with a real `sk-proj-...` key in `.env.example` — scraped by bots within 90 seconds.

## Incident story

**2026-02-12 — indie dev, public GitHub repo.** The dev had a commit `chore: add env example` that included a valid OpenAI key (accidentally copied from `.env.local` instead of redacting). Within 90 seconds a scraper bot picked it up. Within 6 hours the bot had spent **$4,200** hitting `gpt-4o` with throwaway prompts. OpenAI's anomaly detection eventually killed the key at hour 11. The provider refunded most of it, but the dev lost a weekend + had to rotate every key in the project.

**Same class of bug — different shape (2025-11):** a startup wrapped their OpenAI key with `NEXT_PUBLIC_OPENAI_KEY` because "otherwise the client can't use it". The entire bundle shipped the key to every visitor. Anyone viewing the source saw it.

## Bad code

### Hardcoded in a client component

```tsx
// app/ai-demo/page.tsx  (client component)
'use client';
import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: 'sk-proj-abc123...xyz',
  dangerouslyAllowBrowser: true,
});
```

### Wrapped in a public prefix

```bash
# .env.local
NEXT_PUBLIC_OPENAI_KEY=sk-proj-abc123...xyz
```

```tsx
const client = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY,
  dangerouslyAllowBrowser: true,
});
```

`NEXT_PUBLIC_`, `VITE_`, and `REACT_APP_` are compile-time inlined into the client bundle. The build tool substitutes the literal string. The browser reads it. Game over.

### `fetch()` from client to provider directly

```tsx
// Still bad — even if key comes from "backend", it has to be in memory to sign the request.
await fetch('https://api.openai.com/v1/chat/completions', {
  headers: { Authorization: `Bearer ${someKey}` },
  body: JSON.stringify({ model: 'gpt-4o-mini', messages: [...] }),
});
```

## Good code

Keep the secret server-side. Browser calls your server; your server calls the external API.

### Next.js (App Router)

```ts
// app/api/ai/route.ts  (SERVER, no NEXT_PUBLIC_)
import OpenAI from 'openai';
import { NextRequest, NextResponse } from 'next/server';

const openai = new OpenAI({ apiKey: process.env.OPENAI_KEY });

export async function POST(req: NextRequest) {
  // 1. Authenticate
  const user = await getUserFromCookie(req);
  if (!user) return NextResponse.json({ error: 'unauthorised' }, { status: 401 });

  // 2. Rate limit
  const { success } = await ratelimit.limit(user.id);
  if (!success) return NextResponse.json({ error: 'rate limited' }, { status: 429 });

  // 3. Validate
  const { prompt } = await req.json();
  if (typeof prompt !== 'string' || prompt.length > 4000) {
    return NextResponse.json({ error: 'bad prompt' }, { status: 400 });
  }

  const res = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: prompt }],
  });
  return NextResponse.json({ text: res.choices[0].message.content });
}
```

```tsx
// app/ai-demo/page.tsx  (CLIENT)
'use client';
export default function Page() {
  async function run(prompt: string) {
    const res = await fetch('/api/ai', {
      method: 'POST',
      body: JSON.stringify({ prompt }),
    });
    const { text } = await res.json();
    return text;
  }
  // ...
}
```

## Detection

**Regex (used by `auto_audit.py`):**

```
OpenAI:     sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}
Anthropic:  sk-ant-[A-Za-z0-9_-]{95,}
Google:     AIza[0-9A-Za-z_-]{35}
GitHub:     ghp_[A-Za-z0-9]{36}  or  github_pat_[A-Za-z0-9_]{82}
Stripe:     sk_live_[A-Za-z0-9]{24,}
AWS:        AKIA[A-Z0-9]{16}
Slack:      xox[baprs]-[A-Za-z0-9-]{10,}
```

Run regex over **everything except** `node_modules`, `.git`, `dist`, `.next`, etc.

Also flag:
- `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` with a value matching any of the above
- `fetch(` to an LLM provider hostname from a `.tsx`/`.jsx`/client-side `.ts`/`.js`
- `dangerouslyAllowBrowser: true`

**Runtime check:**

```bash
# Download the deployed bundle and grep it
curl -s https://your.site | grep -oE 'src="[^"]*\.js"' | \
  while read src; do
    url=$(echo "$src" | sed 's/src="//;s/"$//')
    curl -s "https://your.site$url" | grep -nE 'sk-|AIza|pk_live_'
  done
```

## If it's already leaked

1. **Rotate the key immediately** in the provider dashboard. Every second it lives is money.
2. `git log --all -p -S 'sk-'` — confirm blast radius, every commit / branch / tag the key lived in.
3. If the key was in a **public** repo: `git-filter-repo --replace-text replacements.txt`, force-push, notify the provider.
4. Monitor provider usage logs for 14 days.
5. Post-mortem: add a pre-commit hook (`gitleaks`) and a CI step that fails if the built bundle contains the patterns.

## Prevention

- **Pre-commit:** install `gitleaks` or `detect-secrets`.
  ```bash
  brew install gitleaks
  gitleaks protect --staged
  ```
- **CI:** run `gitleaks detect` + `auto_audit.py` on every PR.
- **Code review rule:** any new `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` requires explicit reviewer sign-off.
- **Provider side:** set a **hard budget cap** in OpenAI / Anthropic / Google dashboards. You lose the key? You also lose $X max.

## References

- OWASP ASVS V2 — Authentication
- [OpenAI — API key best practices](https://platform.openai.com/docs/guides/production-best-practices/api-keys)
- [Vercel — Environment variables](https://vercel.com/docs/projects/environment-variables)
- CVE-style disclosures for leaked keys: thousands per year, GitGuardian State of Secrets report.
