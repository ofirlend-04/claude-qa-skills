# Pattern: CORS allows any origin

**Rules:** D1, D2, D3
**Severity:** P0 (with credentials) / P1 (without)
**Seen in:** Flask prototypes that "work on localhost and break everywhere else" — `CORS(app, origins="*")` is the usual fix.

## Incident story

**2025-07 — B2B SaaS dashboard.** Backend was Flask with `CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)`. Modern browsers actually block `*` + credentials, but a badly behaved older browser extension didn't, and the company's own mobile app used a WebView that happily trusted the origin. A phishing page hosted at `app-billings.example` scripted the dashboard's API with the user's session cookie and transferred subscription ownership to the attacker.

## Why wildcard CORS is risky

- **`*` alone** (no credentials) is merely *disrespectful* — attackers can read your public API from their page, which may still give them info you didn't intend.
- **`*` + `supports_credentials=True`** is a spec violation; browsers block it — but some clients don't. If your server trusts the cookie, the mitigation is browser-side only.
- **Echoing the `Origin` header** (lots of "fix" snippets on StackOverflow) is even worse — it's effectively `*` for every caller while *also* passing browser credential checks.

## Bad code

### Flask-CORS

```python
from flask_cors import CORS
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
```

### FastAPI

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,   # spec-illegal but sometimes "works"
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Express

```ts
import cors from 'cors';
app.use(cors({ origin: true, credentials: true }));
// origin: true echoes the request Origin. Worst possible setting.
```

### Socket.IO

```python
sio = socketio.AsyncServer(cors_allowed_origins="*")
```

### Raw headers

```python
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"     # P1
    return resp
```

## Good code

### Flask

```python
from flask_cors import CORS

CORS(
    app,
    resources={r"/api/*": {"origins": [
        "https://app.mycompany.com",
        "https://staging.mycompany.com",
    ]}},
    supports_credentials=True,
)
```

### FastAPI

```python
ALLOWED = {
    "https://app.mycompany.com",
    "https://staging.mycompany.com",
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### Express

```ts
import cors from 'cors';

const allowed = new Set([
  'https://app.mycompany.com',
  'https://staging.mycompany.com',
]);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);   // same-origin / server-to-server
    if (allowed.has(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'));
  },
  credentials: true,
}));
```

### Public API without credentials

If the API is genuinely public (no cookies, no auth):

```python
# FastAPI
CORSMiddleware(
    allow_origins=["*"],
    allow_credentials=False,    # critical
    allow_methods=["GET"],
    allow_headers=[],
)
```

## Detection

`auto_audit.py` flags:

```regex
CORS\s*\([^)]*origins\s*[=:]\s*['"]?\*
CORSMiddleware\s*[,)][^)]*allow_origins\s*=\s*\[\s*['"]\*['"]
cors_allowed_origins\s*=\s*['"]\*['"]
Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*
```

## Runtime test

```bash
curl -i -X OPTIONS https://your.site/api/sensitive \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST"

# Look for:
#   Access-Control-Allow-Origin: https://evil.example   <-- BAD
#   (or no ACAO header)
# If the server echoes the Origin, it's effectively `*` and any site can read responses.
```

## References

- [MDN — CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [OWASP — Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CORS: the good, the bad, the ugly (2024 talk)](https://owasp.org/)
