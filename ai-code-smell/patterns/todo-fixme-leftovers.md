# TODO / FIXME / HACK / XXX Leftovers

**Severity:** P2
**Real evidence:**
- Every AI-code review ever. Claude in particular loves writing `// TODO: implement` and then not implementing.

## Bug

```ts
export async function sendEmail(to: string, body: string) {
  // TODO: add rate limiting
  // TODO: validate email format
  // FIXME: this breaks on long bodies
  await smtp.send({ to, body });
}
```

Ships to prod. TODOs accumulate. Nobody does an audit. Then one day something breaks and the trace includes "// FIXME: this breaks".

## Fix

- Resolve the TODO, or
- File an issue in your tracker and link it in the comment: `// TODO(#142): rate limit`, or
- Delete the TODO — not every incomplete thought needs to be committed.

## Detection rule

Regex over source files:
```
(?://|#)\s*(TODO|FIXME|HACK|XXX)\b
```

Skips files under `__tests__`, `/test/`, `.test.`, `.spec.`, `/scripts/`, `/dev/`.

## False positives

- Legitimate TODOs with tracking-system references: `// TODO(JIRA-123):` — we flag them anyway but the fix is fine ("already tracked").
- Code snippets in Markdown fixtures — scanner skips `.md`.
