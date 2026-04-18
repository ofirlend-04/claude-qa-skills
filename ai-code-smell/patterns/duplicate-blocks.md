# Duplicate Code Blocks (Copy-Paste Smell)

**Severity:** P2
**Real evidence:**
- Every refactoring book ever written ("Extract Function" — Fowler).
- AI-specific: LLMs regenerate similar logic per-call instead of noticing "I've seen this pattern already, extract it".

## Bug

Same 10-line block appears in 3+ files:

```ts
// src/pages/dashboard.tsx
const res = await fetch("/api/user");
if (!res.ok) {
  toast.error("Failed to load");
  return;
}
const data = await res.json();
if (!data.user) {
  toast.error("No user");
  return;
}
setUser(data.user);

// src/pages/profile.tsx — same block, different endpoint
// src/pages/settings.tsx — same block, different endpoint
```

## Fix

Extract:

```ts
async function fetchJson<T>(url: string): Promise<T | null> {
  const res = await fetch(url);
  if (!res.ok) { toast.error("Failed to load"); return null; }
  return res.json() as Promise<T>;
}
```

## Detection rule

- Sliding 10-line MD5 window across all source files.
- Strip whitespace, skip whitespace-only blocks.
- Require ≥5 "meaningful" lines (not `import`, `export`, comments) in the block.
- Flag any hash seen in 3+ distinct (file, start-line) positions.

## False positives

- Generated code (migrations, protobuf outputs). Add to `.qaignore`.
- Test setup / teardown repeated across test files. Scanner skips `__tests__` and test files.
- Imports lists — excluded by the "≥5 meaningful lines" rule.

## Calibration

Threshold (block_size=10, copies≥3) chosen to minimise noise:
- At 5 lines × 2 copies you catch everything; report becomes useless.
- At 10 × 3 you catch genuine repeated business logic while letting minor duplication slide.
