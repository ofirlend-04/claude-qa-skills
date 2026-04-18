# AI Code-Smell — Manual Checklist

Things `auto_audit.py` can't catch reliably. Run through these when reviewing a PR that was mostly AI-generated.

## Supply chain

- [ ] Run scanner WITHOUT `--offline` and review every `[P0] S1` slopsquat finding. Registry 404 = package does not exist.
- [ ] For every new dep, visit its GitHub repo. Check: >1 maintainer? Last commit <30 days? Open issues with responses?
- [ ] `npm audit` / `pip-audit` for transitive CVEs — separate concern from slopsquatting.
- [ ] If using Yarn/pnpm, check `resolutions` / `overrides` — AI doesn't know your lockfile conventions.

## LLM wiring

- [ ] Every LLM call has `max_tokens` AND a timeout (separate — scanner only checks `max_tokens`).
- [ ] Retry logic has a max-retry ceiling. An agent loop with uncapped retries is a bill-stealer.
- [ ] System prompts don't interpolate user input (see `security` skill rule G1).
- [ ] Streaming endpoints have client-side cutoffs (don't trust client to disconnect).
- [ ] Costs tracked per user — unexpected $1,400 bills come from one user abusing a public endpoint.

## Async correctness

- [ ] `Promise.all` / `asyncio.gather` — if one rejects, are partial results handled?
- [ ] Database connection pools: every `.connect()` has a matching `.release()` in finally?
- [ ] AbortController / cancellation tokens wired through agent loops?

## React hygiene

- [ ] `useEffect(() => {...}, [])` — does the body reference state that isn't in deps? (stale closure)
- [ ] `useCallback` / `useMemo` used where they actually matter, not reflexively everywhere.
- [ ] Server Components vs Client Components correctly tagged (`"use client"` where needed).

## Env / secrets

- [ ] `.env.example` is committed and contains every referenced var (scanner checks this).
- [ ] No secrets in `.env.example` — placeholder values only.
- [ ] `NEXT_PUBLIC_*` / `VITE_*` vars don't leak secrets (see `security` skill rule B1).

## Dead code & duplication

- [ ] Unused imports flagged by scanner — actually remove or tree-shake.
- [ ] Duplicate blocks (scanner `C1`) — extract shared function.
- [ ] TODOs — resolve, link to an issue, or delete.

## AI banner

- [ ] For every file tagged INFO `M1`, do a full human read-through. These are high-risk files.

## Rate limiting

- [ ] Every endpoint that spends money (LLM, Stripe, SMS, email) has rate limiting — scanner covers this via the `security` skill K1 rule.
