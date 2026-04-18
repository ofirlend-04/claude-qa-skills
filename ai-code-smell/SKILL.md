---
name: ai-code-smell
description: Detects patterns specific to AI-generated code (Claude / Cursor / Copilot). Flagship detection is slopsquatting — hallucinated npm/pip packages that attackers register with malicious payloads (5–33% hallucination rate per GitGuardian 2026). Also catches async-without-try, missing max_tokens on LLM calls, deprecated React patterns, console.log left in prod, unused imports, env var hallucinations, hallucinated API methods, silent catch blocks, and duplicate code.
triggers:
  - "ai code audit"
  - "slopsquatting check"
  - "claude code review"
  - "cursor code review"
  - "ai-generated code smells"
  - "hallucinated package check"
  - files matching: "package.json", "requirements.txt", "pyproject.toml", "*.ts", "*.tsx", "*.js", "*.jsx", "*.py"
---

# AI Code-Smell Scanner

You are an AI-code reviewer. You audit code the way a senior engineer reviewing a Claude-generated PR would. Traditional linters (ESLint, Ruff) catch syntax-level bugs. SAST catches injection. **You catch the things specific to how LLMs fail:** hallucinated package names (slopsquatting is the 2026 supply-chain attack vector), missing `max_tokens` (Cursor users hit with $1,400+ bills), async without try/catch (unhandled rejections crash Node), silent catch blocks, deprecated React patterns pulled from stale training data, and env vars that only exist in the model's imagination.

Every rule here is tied to a real incident or published research.

## Your Job

1. Run `python3 auto_audit.py <folder>`. It emits `report.md`, `report.json`, and streams `[PX] file:line — msg` lines to stdout (parsed by `scan_all.py`).
2. Default mode hits the npm + PyPI registries to verify every dependency; add `--offline` to skip network.
3. Read `report.md` and add context findings the scanner can't infer (library-specific smells, architectural AI tells).
4. Produce a prioritised report with severity (P0/P1/P2/INFO), `file:line` locations, and fixes.

**Do:** trust the network-backed slopsquat finding — registry 404 means the package literally does not exist and an attacker can squat it.
**Don't:** modify target projects — read-only.

## Severity Rubric

- **P0 — Supply-chain / production risk.** Slopsquatted package, known hallucination, `componentWillMount` on a live route.
- **P1 — Cost trap / silent bug.** Missing `max_tokens`, `except: pass`, async without try/catch, hallucinated SDK methods, env var drift.
- **P2 — Hygiene.** `React.FC<>`, unused imports, TODO/FIXME leftovers, duplicate blocks, `console.log` leftovers (down-graded when gated by NODE_ENV).
- **INFO — Informational.** AI-assistant banner comment detected — just a marker, no action needed.

---

## Rule Library — AI Code Smells

### S. Slopsquatting (hallucinated packages)

#### S1. Hallucinated npm package — P0
**Pattern:** dependency name in `package.json` that returns 404 from `https://registry.npmjs.org/<name>`.
**Attack vector:** LLMs hallucinate package names 5–33% of the time. Attackers monitor AI tools + GitHub commits, register the hallucinated names, and publish malicious payloads. `npm install` runs `postinstall` scripts. **Real case (Jan 2026):** `react-codeshift` was squatted on npm.
**Defense:** verify every dep against the registry before install.
**Evidence:** [GitGuardian 2026 report](https://blog.gitguardian.com/) · [Trend Micro slopsquatting](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/slopsquatting-when-ai-agents-hallucinate-malicious-packages) · [Aikido slopsquatting](https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks).
See `patterns/slopsquatting-npm.md`.

#### S1. Hallucinated pip package — P0
**Pattern:** dependency name in `requirements.txt` / `pyproject.toml` not on PyPI.
**Evidence:** [Rescana 2025 slopsquatting report](https://www.rescana.com/post/ai-hallucinated-dependencies-in-pypi-and-npm-the-2025-slopsquatting-supply-chain-risk-explained) · [Help Net Security](https://www.helpnetsecurity.com/2025/04/14/package-hallucination-slopsquatting-malicious-code/).
See `patterns/slopsquatting-pypi.md`.

#### S2. Suspicious new package — P1
**Heuristic:** package exists but is <30 days old AND <100 downloads/week (npm only; PyPI lacks a simple dl API, uses homepage-presence proxy).
**Why:** legitimate new packages typically hit >500 wk-dl fast; sub-100 at month-1 is a likely squatter. Threshold conservatively chosen to minimise false positives on genuine indie libs.
**Defense:** human review — does it have a GitHub repo, active maintainers, an issue tracker?

### A. Async safety

#### A1. `await` without enclosing try/catch — P1
**Bug pattern:**
```ts
async function run() {
  const data = await fetchThing();   // unhandled rejection
  return data.items;
}
```
AI models skip error handling by default — they optimise for "reads well".
**Fix:** wrap in try/catch or chain `.catch()`. In Node 15+ unhandled rejections crash the process.
**Evidence:** [dev.to — AI code breaks in prod](https://dev.to/pockit_tools/why-ai-generated-code-breaks-in-production-a-deep-debugging-guide-5cfk) · [arxiv 2512.05239 AI-bug survey].
See `patterns/async-without-try.md`.

#### A2. Silent catch / `except: pass` — P1
**Bug pattern:** `catch (e) { }` or `except: pass` — AI cop-out when it doesn't know the error type.
**Fix:** log at minimum. Preferably handle specific errors.
**Evidence:** [ranger.net common AI bugs](https://www.ranger.net/post/common-bugs-ai-generated-code-fixes).
See `patterns/silent-catch.md`.

### L. LLM SDK misuse

#### L1. `max_tokens` missing on LLM call — P1
**Bug pattern:** `client.messages.create({ model, messages })` without `max_tokens`. Anthropic and OpenAI both charge per output token. An LLM agent that loops on a malformed prompt will generate 4096 tokens per call forever.
**Real incident:** multiple 2025–2026 HN / Reddit posts — Cursor users racking up $1,400+ bills from runaway outputs.
**Fix:** always set `max_tokens=1024` (or appropriate ceiling).
See `patterns/llm-missing-max-tokens.md`.

#### L2. Hallucinated API methods — P1
**Bug pattern:** calls to methods that don't exist — `fetch.post()`, `axios.createRequest()`, `Array.contains()`, `dict.has_key()` (Python 2 only), `JSON.tryParse()`, `Object.copy()`. Curated list of known Cursor/Claude hallucinations.
**Evidence:** Reddit r/LocalLLaMA + HN threads on LLM API hallucinations.
See `patterns/hallucinated-api-methods.md`.

### R. React deprecated

#### R1. `React.FC<>` — P2
**Why:** deprecated community recommendation since 2022 (Dan Abramov, React team). Implicit children, hard to override defaults, adds nothing. AI keeps generating it from old training data.

#### R2. Class components in new code — P2
**Why:** React favours function components + hooks. A new class component is almost always a training-data artefact.

#### R3. `componentWillMount` / `componentWillReceiveProps` — P1
**Why:** actually deprecated since React 17. Removed in future versions.

### D. Debug leftovers

#### D1. `console.log` / `console.debug` in production src — P1
**Bug pattern:** `console.log('debug')` in `src/**`, `app/**`, `pages/**` (not tests, not dev-only blocks gated by `NODE_ENV`). AI loves to leave these in.
**Fix:** remove or replace with a proper logger.

#### D2. `TODO` / `FIXME` / `HACK` / `XXX` in source — P2
**Why:** AI ships "TODO: implement" lines routinely.
See `patterns/todo-fixme-leftovers.md`.

### U. Unused imports

#### U1. Named import never referenced — P2
**Heuristic:** parse `import { A, B } from '...'`; if `A` has zero word-boundary matches in the rest of the file, flag.
**Why it's AI-specific:** LLMs over-import (pull in everything they "might need"), then use half.

### E. Env var drift

#### E1. `process.env.FOO` / `os.environ['FOO']` with no `.env*` declaration — P1
**Bug pattern:** AI references env vars it invented. Deploy passes locally, crashes in prod.
**Detect:** gather env var names from every `.env*` file in the repo; flag any referenced var not in that set (excluding well-known system vars).
**Evidence:** [Knostic — mishandling of secrets](https://knostic.ai/) · hyperdev "the ENV file that wasn't".
See `patterns/env-var-hallucinations.md`.

### C. Copy-paste blocks

#### C1. 10-line block appearing 3+ times — P2
**Heuristic:** sliding 10-line MD5 window across all source files; flag blocks seen in 3+ distinct positions.
**Why it's AI-specific:** LLMs regenerate similar logic per-component rather than extracting a helper.

### M. AI-assistant banner

#### M1. `// Generated by Cursor` / `# Claude did this` / `AI-assisted` — INFO
Just a marker so the reviewer knows which files to scrutinise.

---

## How to Run

```bash
# Default (hits npm/PyPI with 7-day cache)
python3 auto_audit.py /path/to/project

# Offline (skip network, cache only)
python3 auto_audit.py /path/to/project --offline

# Skip the slower duplicate-block scan
python3 auto_audit.py /path/to/project --no-duplicates
```

**Exit codes:** `0` clean · `1` ≥1 P1 · `2` ≥1 P0 ← gate CI here.

**Ignore false positives:**
- `.qaignore` at repo root (one glob per line) — shared format with other skills.
- Inline: `// qa-ignore: L1,A1` (applies to that line and the next).

**Cache location:** `.cache/npm-registry.json`, `.cache/pypi-registry.json`. TTL 7 days. Safe to delete.

## Output Format

```markdown
# AI Code-Smell Audit — resonance_ai_v2/v5-editor

## Summary
- Files scanned: 214
- **2 P0** (supply-chain / production risk)
- **11 P1** (cost trap / silent bug)
- **7 P2** (hygiene)
- 3 INFO (AI-generated file markers)

## P0 — Supply-chain / production risk

### P0.1 [S1] Slopsquatting: 'react-codeshift' is not on the npm registry
- **Location:** `package.json:27`
- **Evidence:** `"react-codeshift"`
- **Fix:** Check real package name. Likely LLM hallucination.

## P1 — Cost trap / silent bug

### P1.1 [L1] LLM call without max_tokens — runaway cost risk
- **Location:** `src/lib/claude.ts:42`
- **Fix:** Add max_tokens=1024.
```

## Related Skills

- Pair with `security` for secrets / prompt injection.
- Pair with `web-ui` for client-side bundle audits.
- `pentest-scanner` for runtime checks.

## Don't

- Don't modify target projects — read-only.
- Don't flag anything not in the rule library. Add a pattern first with evidence.
- Don't treat `--offline` findings as ground truth — they skip the slopsquat network check.
- Respect `.qaignore`.
