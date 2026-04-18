# Pattern: `.env` file committed to the repo

**Rule:** J1
**Severity:** P0
**Seen in:** ~every developer's first project, periodically in shipped ones.

## Incident story

**2025-10 — open-source side project.** Author committed `.env` accidentally in the initial push. It contained:

```
STRIPE_KEY=sk_live_abc123...
SENDGRID_KEY=SG.xyz...
ANTHROPIC_KEY=sk-ant-api03-...
```

The repo got 200 stars on HN. GitGuardian emailed the author within 12 minutes of the first `git push`. The author force-pushed a new history and rotated the keys. But the original commit was already cached by several GitHub mirrors — the keys remained exposed for days on third-party copies.

## Why `.env` keeps getting committed

- New project, `.gitignore` not set up yet, `git add .` grabs everything.
- Someone adds the `.env` as "a template" — forgetting to rename to `.env.example`.
- A merge conflict resolver accepts `.env` from a side branch where it was (temporarily) tracked.
- Tool scaffolds (older Next.js versions, Create React App variants) didn't include `.env` in the default ignore.

## Bad state

```
$ git ls-files | grep env
.env
.env.local
.env.production
```

With `cat .env` showing real keys.

## Good state

```
$ cat .gitignore
# Secrets
.env
.env.*
!.env.example

$ git ls-files | grep env
.env.example
```

```
$ cat .env.example
DATABASE_URL=
STRIPE_KEY=
SENDGRID_KEY=
ANTHROPIC_KEY=
```

## Fixing it if already committed

### Step 1 — stop the bleeding

```bash
# Rotate every secret in the file. Right now. Every second costs you.
# Anthropic, OpenAI, Google, Stripe, SendGrid, GitHub — all have dashboards to revoke+reissue.
```

### Step 2 — remove from index

```bash
git rm --cached .env
echo ".env" >> .gitignore
echo ".env.*" >> .gitignore
echo "!.env.example" >> .gitignore
git add .gitignore
git commit -m "stop tracking .env"
```

At this point `.env` is no longer tracked, but it's still in every old commit's history.

### Step 3 — scrub history (only if you've rotated and truly need to)

```bash
# Make a backup
cp -r . ../repo-backup

# Install git-filter-repo (better than filter-branch)
pipx install git-filter-repo

# Remove .env from ALL commits
git filter-repo --path .env --invert-paths

# Force-push (coordinate with team!)
git push --force-with-lease origin main

# Tell collaborators to re-clone or reset hard; their local history still has it.
```

### Step 4 — belt and braces

```bash
# Use git-filter-repo to also scrub the secret values in case they appear elsewhere
cat > replacements.txt <<'EOF'
sk-ant-api03-abc...==>REDACTED
sk_live_abc...==>REDACTED
SG.xyz...==>REDACTED
EOF
git filter-repo --replace-text replacements.txt
```

### Step 5 — notify

- If the repo was ever public, assume the secret is compromised regardless of how fast you scrubbed. GitHub search, Sourcegraph, GitGuardian, Shhgit, archive.org, mirrors — any of them may have copies.
- Tell your security team and any compliance officers.
- Provider anomaly detection may contact you first.

## Detection

`auto_audit.py` rule J1:

1. List all `.env*` files in the repo.
2. Check `.gitignore` for coverage.
3. If a `.env` is present **and** not gitignored, P0.
4. If a `.env` **is** gitignored but still contains real secrets (A-patterns match, non-placeholder), P1 — confirm the file was never in history.

```bash
# Manual history check
git log --all -- .env
# If this returns commits, the file has been tracked at some point.
```

## Prevention

- **`.gitignore` template from day 1.** GitHub's `gitignore` templates cover most languages; review the "Environment" section.
- **Pre-commit hook** that refuses to stage `.env`:
  ```bash
  cat > .git/hooks/pre-commit <<'EOF'
  #!/bin/bash
  if git diff --cached --name-only | grep -qE '^\.env(\.|$)'; then
    echo "ERROR: refusing to commit .env. If you really need this, use git commit --no-verify."
    exit 1
  fi
  EOF
  chmod +x .git/hooks/pre-commit
  ```
- **Server-side push protection:** GitHub's Push Protection (paid on public repos for free, Enterprise for private) blocks commits containing known secret patterns.

## References

- [GitHub — Pushing to a repository with secret leaks](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
- [git-filter-repo docs](https://github.com/newren/git-filter-repo)
- [OWASP — Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
