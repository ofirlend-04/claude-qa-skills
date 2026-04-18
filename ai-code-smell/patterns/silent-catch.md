# Silent Catch / `except: pass`

**Severity:** P1
**Real evidence:**
- [ranger.net — common bugs in AI-generated code](https://www.ranger.net/post/common-bugs-ai-generated-code-fixes)
- PEP 8 explicitly warns against bare `except`.

## Bug

AI cop-out when it doesn't know which exceptions to handle:

```ts
try {
  doThing();
} catch (e) {
  // TODO: handle
}
```

```py
try:
    do_thing()
except:
    pass
```

The error disappears. When prod breaks, there's no log, no metric, no trace.

## Fix

```ts
try {
  doThing();
} catch (e) {
  logger.error({ err: e }, "doThing failed");
  throw e;   // or handle specifically
}
```

```py
try:
    do_thing()
except SpecificError as e:
    logger.exception("do_thing failed")
    raise
```

## Detection rule

- `catch\s*(?:\([^)]*\))?\s*\{\s*\}` — empty catch.
- `catch { console.log(...) }` — only a console.log.
- `except:\s*\n\s*pass` — Python bare pass.

## False positives

- Intentional noise suppression in cleanup / teardown paths. Add `// qa-ignore: A2`.
- Catch that logs via a library call the scanner doesn't recognise. Fine to suppress.
