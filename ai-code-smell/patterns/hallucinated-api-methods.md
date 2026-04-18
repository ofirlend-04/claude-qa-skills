# Hallucinated API Methods

**Severity:** P1
**Real evidence:**
- Reddit r/LocalLLaMA + HN — ongoing threads of "Claude invented a method that doesn't exist".
- Common LLM failure mode: surface-level confusion between similar library APIs.

## Bug

Claude / Cursor / Copilot invent method names that sound plausible:

```js
fetch.post(url, body)               // ← fetch has no .post
axios.createRequest(opts)           // ← not a real axios method
[1,2,3].contains(2)                 // ← Python syntax leaking to JS; JS uses .includes()
JSON.tryParse(str)                  // ← doesn't exist
Object.copy(a, b)                   // ← use {...a, ...b}
promise.finally()                   // ← called with no callback does nothing useful
```

```py
requests.session()                  # ← lowercase. Correct: requests.Session()
my_dict.has_key('x')                # ← Python 2 only, removed in Py3
os.path.joinpath(a, b)              # ← no such method on os.path
```

In TypeScript the compiler catches some. In plain JS / dynamic Python they pass the linter and explode at runtime.

## Fix

Check library docs. Replace with the real API.

## Detection rule

Curated regex list (grows over time):

```py
HALLUCINATED_METHODS = [
    (r"\bfetch\s*\.\s*post\s*\(", ...),
    (r"\baxios\.createRequest\s*\(", ...),
    (r"\bArray\.contains\s*\(", ...),
    (r"\bJSON\.tryParse\s*\(", ...),
    (r"\bObject\.copy\s*\(", ...),
    (r"\brequests\.session\s*\(", ...),
    (r"\bdict\.has_key\s*\(", ...),
    ...
]
```

## False positives

- Your own class with a method named `contains`. Scanner looks for very specific global patterns (`Array.contains`, `JSON.tryParse`). A user-defined class shouldn't trigger.
- `fetch.post` on a custom fetch wrapper. Likely legitimate — but name your wrapper something other than `fetch` to avoid confusion.
