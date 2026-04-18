# Unused Imports

**Severity:** P2
**Real evidence:**
- Every AI-code review post mentions this. LLMs over-import because the model hedges on "what might be needed".

## Bug

```ts
import { useState, useEffect, useRef, useCallback, useMemo } from "react";

export function Widget() {
  const [n, setN] = useState(0);
  return <div>{n}</div>;
  // useEffect, useRef, useCallback, useMemo never referenced
}
```

Bundle size bloats, tree-shaking partially mitigates but doesn't eliminate.

## Fix

```ts
import { useState } from "react";

export function Widget() {
  const [n, setN] = useState(0);
  return <div>{n}</div>;
}
```

ESLint rule `@typescript-eslint/no-unused-vars` catches this if configured — many AI-generated codebases don't have ESLint configured strictly.

## Detection rule

For every `import { A, B, C } from '...'`, parse the named list, then for each name do `\bname\b` search over the rest of the file. Zero matches → flag.

## False positives

- Side-effect imports: `import "./globals.css"` — scanner only checks named imports.
- JSX element used as `<Icon />` — scanner searches by name, so `Icon` is found.
- Type-only imports re-exported from this file — will match `export { A }` naturally.
