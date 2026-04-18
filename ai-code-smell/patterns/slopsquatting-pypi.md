# Slopsquatting — Hallucinated PyPI Packages

**Severity:** P0
**Real evidence:**
- [Rescana — AI hallucinated deps 2025 slopsquatting](https://www.rescana.com/post/ai-hallucinated-dependencies-in-pypi-and-npm-the-2025-slopsquatting-supply-chain-risk-explained)
- [Help Net Security — package hallucination](https://www.helpnetsecurity.com/2025/04/14/package-hallucination-slopsquatting-malicious-code/)
- [DevOps.com — AI slopsquatting](https://devops.com/)

## Bug

```txt
# requirements.txt
openai==1.50.0
pandas==2.1.0
pydantic-jsonlogic==0.3.1   # ← does this actually exist on PyPI?
```

`pip install` — PyPI packages run arbitrary `setup.py` code at install time. Slopsquatted packages historically have:
- Credential exfiltration (AWS, GCP, `.aws/credentials`, `.ssh/id_rsa`)
- Reverse shells (C2 check-in)
- Cryptominers

## Fix

Verify every dep on PyPI:

```bash
grep -vE '^(#|$|-)' requirements.txt | awk '{print $1}' | cut -d= -f1 | \
  while read pkg; do
    curl -sf "https://pypi.org/pypi/$pkg/json" > /dev/null || echo "MISSING: $pkg"
  done
```

Or use this scanner.

## Detection rule

- Parse `requirements.txt`, `requirements-dev.txt`, `pyproject.toml` (`[project].dependencies`, `[tool.poetry.dependencies]`).
- `GET https://pypi.org/pypi/<name>/json`
- 404 → **P0**
- 200 + all releases <30 days old → **P1 suspicious**

## False positives

- Private index deps (`--index-url https://pypi.mycompany.com`) — scanner only checks public PyPI. Use `.qaignore`.
- Editable installs (`-e ./packages/foo`) — scanner skips lines starting with `-`.

## Calibration

PyPI doesn't expose download counts without a separate service (BigQuery mirror / pepy.tech). We use **package age + homepage presence** as a proxy:
- New + no homepage → flag.
- New + has homepage → flag at P1 (still suspicious, but legitimate indie libs often have a GitHub repo URL).

This is more conservative than the npm check. We accept more false negatives here to avoid flagging legitimate fast-moving Python libs.
