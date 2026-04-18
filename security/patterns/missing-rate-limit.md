# Pattern: Sensitive endpoint without rate limiting

**Rule:** K1 (+ G5 for LLM bill-stealing, + C1/C2/C3 when combined with missing auth)
**Severity:** P1 (P0 if no auth either)
**Seen in:** "v1" of every small-team SaaS. Rate limiting is always "we'll add it before launch".

## Incident story

**2026-02 — solo-dev SaaS with an AI writing tool.** `/api/generate` was auth'd (good), but had no per-user rate limit. A disgruntled trialist signed up with 50 burner emails, wrote a shell loop that generated 10 requests/second per email. In 4 hours they burnt $1,100 of OpenAI quota. The dev's budget cap was $2,000/mo; they hit it, service went down, all legitimate users were locked out for the rest of the month.

## Why rate limits matter

- **Bill stealing** on LLM/payment endpoints: attacker doesn't care about your data, just your budget.
- **Brute force** on login / password reset / OTP endpoints: 100k attempts at "Password123!" against 100k users.
- **Scraping** — competitor downloads your whole catalogue via your public search API.
- **Denial of wallet** — serverless / Cloud Run autoscales, attacker DDoSes, AWS bill explodes.

## Bad code

### FastAPI — no limit

```python
@app.post("/generate")
async def generate(req: GenerateRequest, user=Depends(get_current_user)):
    return await openai_call(req.prompt)
# Auth is there. But a paying user can run a forever-loop.
```

### Express — no limit

```ts
app.post('/api/login', async (req, res) => {
  const user = await authenticate(req.body.email, req.body.password);
  if (!user) return res.status(401).send();
  res.json({ token: signJwt(user) });
});
// Brute force attack: 10 req/s for a month = 26M guesses.
```

## Good code

### FastAPI with `slowapi`

```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def user_key(request):
    user = getattr(request.state, "user", None)
    return user.id if user else get_remote_address(request)

@app.post("/generate")
@limiter.limit("20/minute", key_func=user_key)
async def generate(request: Request, req: GenerateRequest,
                   user=Depends(get_current_user)):
    return await openai_call(req.prompt)
```

### Flask with `flask-limiter`

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200/hour"],
)

@app.post("/api/login")
@limiter.limit("10/minute")   # tighter for auth
def login():
    ...
```

### Express with `express-rate-limit` + Redis

```ts
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { createClient } from 'redis';

const client = createClient({ url: process.env.REDIS_URL });
await client.connect();

const loginLimiter = rateLimit({
  store: new RedisStore({ sendCommand: (...args) => client.sendCommand(args) }),
  windowMs: 60_000,
  max: 10,
  keyGenerator: req => req.ip,
  standardHeaders: true,
});

app.post('/api/login', loginLimiter, loginHandler);

const genLimiter = rateLimit({
  store: new RedisStore({ sendCommand: (...args) => client.sendCommand(args) }),
  windowMs: 60_000,
  max: 20,
  keyGenerator: req => req.user?.id ?? req.ip,
});

app.post('/api/generate', requireAuth, genLimiter, generateHandler);
```

### Next.js / Edge — Upstash Ratelimit

```ts
// lib/ratelimit.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

export const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(20, '1 m'),
});

// app/api/generate/route.ts
import { ratelimit } from '@/lib/ratelimit';

export async function POST(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: 'unauthorised' }, { status: 401 });

  const { success, reset } = await ratelimit.limit(user.id);
  if (!success) {
    return Response.json({ error: 'rate limited' }, {
      status: 429,
      headers: { 'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)) },
    });
  }
  // ...
}
```

## Layered protection

**Not just rate limit. Also:**

1. **Per-user budget cap** — LLM provider spend > $X this month → endpoint disabled until next cycle or manual unlock.
2. **Exponential back-off** on auth failures (5 wrong passwords → 30s lockout → 5min → etc.).
3. **CAPTCHA / Turnstile** for unauthenticated forms.
4. **Provider-level budget alerts** — last line of defence (OpenAI, Anthropic, Google, Stripe all have them).
5. **CDN-level rate limit** — Vercel, Cloudflare can block IPs before hitting your code.

## Detection

`auto_audit.py` rule K1 is heuristic: if a file touches `openai`/`anthropic`/`stripe`/`login`/`reset_password` **and** has no reference to a known limiter (`@limiter.limit`, `express-rate-limit`, `slowapi`, `rateLimit(`, `Ratelimit.`, `@ratelimit`), flag it.

## References

- [OWASP ASVS V11 — Business Logic](https://owasp.org/www-project-application-security-verification-standard/)
- [Upstash — Rate limiting patterns](https://upstash.com/docs/redis/sdks/ratelimit-ts/gettingstarted)
- [Cloudflare — Rate limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)
