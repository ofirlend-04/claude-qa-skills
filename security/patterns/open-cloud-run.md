# Pattern: Cloud Run service deployed `--allow-unauthenticated` with sensitive backend

**Rule:** C4 (+ G5 when the sensitive backend is an LLM)
**Severity:** P0
**Seen in:** Almost every "deploy Gemini to Cloud Run" tutorial from 2024–2025.

## Incident story

**2026-01 — solo dev shipping a Gemini-powered content generator.** Tutorial said:

```bash
gcloud run deploy content-bot \
  --source . \
  --region=us-central1 \
  --allow-unauthenticated
```

The service accepted a JSON `{ prompt }` and returned Gemini's reply. The dev posted a demo link on Twitter. Someone noticed `/generate` took unauthenticated POSTs. 48 hours later the Google Cloud Billing alert fired — **$2,800** in Gemini API usage. The service had no auth, no rate limit, no budget.

## Why this happens

`--allow-unauthenticated` is needed for a truly public website. But most "backend APIs" aren't websites — they're programmatic endpoints that expect the caller to prove who they are. Devs copy-paste the flag from tutorials, don't realise the difference, and ship.

## Bad code

```bash
# deploy.sh
gcloud run deploy llm-proxy \
  --source . \
  --region=us-central1 \
  --allow-unauthenticated       # <-- P0
```

```yaml
# service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: llm-proxy
spec:
  template:
    spec:
      containers:
        - image: gcr.io/project/llm-proxy
# ...deployed with:
# gcloud run services set-iam-policy llm-proxy policy.yaml
# where policy.yaml grants run.invoker to allUsers
```

```json
// policy.yaml
{
  "bindings": [
    { "role": "roles/run.invoker", "members": ["allUsers"] }
  ]
}
```

## Good options

### Option A: True IAM (service-to-service, CLI, Cloud Scheduler)

```bash
gcloud run deploy llm-proxy --no-allow-unauthenticated

# Then grant invoker to a specific service account
gcloud run services add-iam-policy-binding llm-proxy \
  --member="serviceAccount:frontend@proj.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

Caller must send an identity token:
```bash
TOKEN=$(gcloud auth print-identity-token)
curl -H "Authorization: Bearer $TOKEN" https://llm-proxy-xxx.a.run.app/generate
```

### Option B: App-level auth (public website fronted by custom auth)

If the service genuinely needs to be called from an unauthenticated browser (e.g. a user-facing AI demo), add auth at the application layer:

```python
# main.py (Flask on Cloud Run)
import os
from flask import Flask, request, jsonify, abort
from slowapi import Limiter
from slowapi.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["20/hour"])

API_KEY = os.environ["PUBLIC_API_KEY"]  # issued via your website sign-up flow
MAX_PROMPT = 2000

@app.post("/generate")
@limiter.limit("5 per minute")
def generate():
    if request.headers.get("X-API-Key") != API_KEY:
        abort(401)
    prompt = request.json.get("prompt", "")
    if not isinstance(prompt, str) or len(prompt) > MAX_PROMPT:
        abort(400)
    return jsonify(call_gemini(prompt))
```

Plus **set a budget cap** in GCP:

```bash
gcloud billing budgets create --billing-account=ACCT \
  --display-name="llm-proxy cap" \
  --budget-amount=50USD \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0
```

### Option C: Front with Firebase Authentication / Identity-Aware Proxy

Cloud Run + IAP means GCP enforces auth for you before the request ever reaches your service.

## Detection

`auto_audit.py` flags in YAML, shell, and Terraform:

```regex
--allow-unauthenticated\b
members?\s*[:=]\s*[\[\"\']allUsers
roles/run\.invoker.*allUsers
```

Also manual:

```bash
# List open services
gcloud run services list --format='value(metadata.name,status.url)' | \
  while read name url; do
    policy=$(gcloud run services get-iam-policy "$name" --format=json)
    if echo "$policy" | grep -q '"allUsers"'; then
      echo "OPEN: $name $url"
    fi
  done
```

## If it's already open

1. Run the test: `curl -X POST <url>/your-endpoint -d '{}'`. If it responds 200 without auth, it's exposed.
2. Check billing dashboard NOW for anomalies. Set a budget alert if you haven't.
3. Flip to `--no-allow-unauthenticated` OR add app-level auth. **Don't just remove the URL from your README — it's in the GCP project URL scheme and easily scannable.**
4. Rotate any secrets the service exposes (Secret Manager, env vars).

## References

- [Cloud Run — Authentication](https://cloud.google.com/run/docs/authenticating/overview)
- [Firebase App Check for Cloud Run](https://firebase.google.com/docs/app-check/cloud-run)
- [GCP Budgets and alerts](https://cloud.google.com/billing/docs/how-to/budgets)
