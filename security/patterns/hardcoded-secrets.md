# Pattern: Hardcoded secrets / credentials in source

**Rule:** A10 (generic) — A1–A9 for provider-specific variants.
**Severity:** P0 for real secrets; P1 for generic "looks like a secret" hits.
**Seen in:** Every codebase that ever onboarded a new hire without a secret manager.

## Incident story

**Classic pattern**, variations every year. A typical one from 2025: a startup's `Dockerfile` had `ENV DB_PASSWORD=P@ssw0rd123!`. The image was pushed to a public Docker Hub repo "for convenience". Someone scanning Docker Hub with `trufflehog docker` found it two days later. Database pwned.

## Why it keeps happening

- **"It's just for dev"** → gets committed → migrates to prod.
- **"Just a placeholder"** → real secret swaps in, never noticed.
- **Copy-paste from a colleague's Slack** → secret now in git history + Slack history.
- **Dockerfile `ENV` / `ARG`** — the value persists in the image layers even if later `unset`.

## Bad code

### Literal in source

```python
DATABASE_URL = "postgres://user:P@ssw0rd@prod-db.internal:5432/app"
JWT_SECRET   = "supersecretkey123"
```

```ts
const config = {
  apiKey: 'abcdef0123456789abcdef0123456789abcdef01',
  endpoint: 'https://api.provider.com',
};
```

### Dockerfile

```dockerfile
# Dockerfile
ENV DATABASE_URL=postgres://user:real-password@db:5432/prod
ENV STRIPE_KEY=sk_live_abc123...
```

### docker-compose.yml

```yaml
services:
  db:
    environment:
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: admin    # default creds, will hit the internet sooner or later
```

### CI configs

```yaml
# .github/workflows/deploy.yml — BAD
env:
  API_KEY: "ak-live-123..."   # committed
```

## Good code

### 12-factor env vars

```python
import os
DATABASE_URL = os.environ["DATABASE_URL"]     # fails loudly if missing
JWT_SECRET   = os.environ["JWT_SECRET"]
```

### `.env` file (gitignored) for local dev

```bash
# .env       (gitignored)
DATABASE_URL=postgres://localhost/app_dev
JWT_SECRET=local-dev-only-do-not-reuse

# .env.example (committed, placeholders only)
DATABASE_URL=
JWT_SECRET=
```

`.gitignore`:

```
.env
.env.*
!.env.example
```

### Secret manager for production

- **AWS:** Secrets Manager + IAM.
- **GCP:** Secret Manager + service account with `secretmanager.secretAccessor`.
- **Vercel / Netlify:** Environment Variables UI. Not `NEXT_PUBLIC_` unless it's a public value (Firebase web config).
- **Kubernetes:** Sealed Secrets / External Secrets Operator.

### Dockerfile — don't bake secrets

```dockerfile
# BUILD stage — nothing secret here
FROM node:20 AS build
WORKDIR /app
COPY package*.json .
RUN npm ci
COPY . .
RUN npm run build

# RUNTIME — read from env at startup
FROM node:20-slim
WORKDIR /app
COPY --from=build /app/dist ./dist
CMD ["node", "dist/server.js"]
# DATABASE_URL etc. provided by orchestrator (k8s/ECS/Cloud Run/Vercel) at runtime.
```

### CI — use provider secrets

```yaml
# GitHub Actions — GOOD
jobs:
  deploy:
    steps:
      - run: ./deploy.sh
        env:
          API_KEY: ${{ secrets.API_KEY }}
```

## Detection

`auto_audit.py` A10 heuristic:

```regex
\b(password|passwd|pwd|api[_-]?key|apikey|secret|token|authorization|auth[_-]?key)
\s*[:=]\s*(['"])([^'"]{16,})\2
```

Plus entropy check (>3.5 bits/char) and placeholder filter (ignores `YOUR_KEY_HERE`, etc.).

**Also use `gitleaks`:**

```bash
brew install gitleaks
gitleaks detect --source . --verbose
```

## If you committed a real secret

1. **Rotate it now.** Every second is more exposure.
2. `git log --all -p -S '<the_secret>'` — confirm blast radius (branches, tags).
3. If the repo was ever public: `git-filter-repo --replace-text replacements.txt`. This rewrites history. Force-push. Notify all collaborators + CI.
4. Check the provider's audit logs for anomalous activity since the secret was first committed.

## Prevention

- **Pre-commit hook:**
  ```bash
  cat > .git/hooks/pre-commit <<'EOF'
  #!/bin/bash
  gitleaks protect --staged --verbose --redact || exit 1
  EOF
  chmod +x .git/hooks/pre-commit
  ```
- **Use `direnv`** for per-project `.envrc` that loads from a keychain.
- **Review rule:** every PR that changes a config file gets a "secrets?" checkbox.
- **Budget cap** at every provider — limits blast radius of a leak.

## References

- [The Twelve-Factor App — Config](https://12factor.net/config)
- [GitGuardian State of Secrets Sprawl](https://www.gitguardian.com/state-of-secrets-sprawl)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
