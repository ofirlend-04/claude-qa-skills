# Async Without Try/Catch

**Severity:** P1
**Real evidence:**
- [dev.to — why AI code breaks in prod](https://dev.to/pockit_tools/why-ai-generated-code-breaks-in-production-a-deep-debugging-guide-5cfk)
- [arxiv 2512.05239 — AI-generated bugs survey]
- Node.js docs: "Unhandled promise rejections crash the process in Node 15+"

## Bug

```ts
async function fetchUser(id: string) {
  const res = await fetch(`/api/user/${id}`);   // network error → unhandled
  const json = await res.json();                // parse error → unhandled
  return json.name;
}
```

If either await throws, the rejection bubbles up. In Node 15+ this crashes the process. In the browser it becomes an `unhandledrejection` event usually swallowed by React's error boundary — if one exists.

## Fix

```ts
async function fetchUser(id: string) {
  try {
    const res = await fetch(`/api/user/${id}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    return json.name;
  } catch (err) {
    logger.error({ err, id }, "fetchUser failed");
    throw err;   // or return a sentinel; don't swallow
  }
}
```

## Detection rule

For each `await` occurrence in an async function, walk backward up to 30 lines looking for a `try {` that has not been closed by a matching `}`. If no enclosing try is found, flag.

Python equivalent: look for `try:` at a lesser indentation level before hitting the `async def`.

## False positives

- One-liner with `.catch(...)` chained — scanner already skips these.
- Functions at the top of a file that run inside `async function main()` which has its own try — scanner will walk up to 30 lines; deeper nesting may miss. Add `// qa-ignore: A1` to suppress.
- Test code using `await expect(...).rejects` — scanner skips `__tests__` and `*.test.*`.
