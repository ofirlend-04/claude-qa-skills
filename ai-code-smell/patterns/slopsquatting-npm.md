# Slopsquatting — Hallucinated npm Packages

**Severity:** P0
**Real evidence:**
- [GitGuardian 2026 slopsquatting report](https://blog.gitguardian.com/)
- [Trend Micro — slopsquatting AI hallucinates malicious packages](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/slopsquatting-when-ai-agents-hallucinate-malicious-packages)
- [Aikido — slopsquatting AI package hallucination attacks](https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks)
- [DarkReading — AI code tools widely hallucinate packages](https://www.darkreading.com/application-security/ai-code-tools-widely-hallucinate-packages)
- Real case: `react-codeshift` squatted on npm (Jan 2026).

## Bug

Claude / Cursor / Copilot suggest a package that doesn't exist. Dev runs `npm install` — either it fails (best case) or the attacker has already registered that exact name with a malicious `postinstall` script.

```json
{
  "dependencies": {
    "react-codeshift": "^1.0.0"
  }
}
```

```bash
npm install
# → runs postinstall script
# → exfiltrates AWS keys, SSH keys, browser session from dev machine
```

## Fix

Before `npm install`, verify every dependency:

```bash
for pkg in $(jq -r '.dependencies | keys[]' package.json); do
  curl -sf "https://registry.npmjs.org/$pkg" > /dev/null || echo "MISSING: $pkg"
done
```

Or just run this scanner:

```bash
python3 auto_audit.py /path/to/project
```

## Detection rule

- For every key under `dependencies` / `devDependencies` / `peerDependencies` / `optionalDependencies` in `package.json`:
  - `GET https://registry.npmjs.org/<name>`
  - 404 → **P0 slopsquat candidate**
  - 200 + package age <30 days + <100 downloads/week → **P1 suspicious**

## False positives

- Private scoped packages (`@myco/foo`) behind an npm org — will 404 against public registry. Add to `.qaignore`:
  ```
  # qa-ignore: S1
  ```
  on the relevant line, or scope-exclude in `.qaignore`:
  ```
  package.json
  ```
- Yarn / pnpm workspaces — local path deps (`"foo": "workspace:*"`) resolve locally. Scanner already skips non-string dep values. Verify on your tree.

## Calibration

Threshold for "new + low download" was chosen as **<30 days + <100 wk-dl**:
- Most legitimate new npm libs (Tailwind, Next.js, Shadcn components) cross 500 wk-dl within 7 days.
- Attackers typically squat for ~60 days before detection (per Aikido research).
- 100 wk-dl is conservative — it will miss some squatters with bot-driven fake downloads, but keeps false-positive rate low on genuine indie tooling.
