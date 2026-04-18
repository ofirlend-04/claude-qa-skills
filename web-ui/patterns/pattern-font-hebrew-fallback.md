# Pattern: Hebrew text falls back to Times New Roman

**Rule:** B8
**Severity:** P1
**Seen in:** Editox landing, CalmQuest web paywall

## The bug

`font-family: Poppins, sans-serif` — Poppins has no Hebrew glyphs. The browser silently falls back to the next entry in the stack. If that's `sans-serif`, macOS renders Hebrew in **Arial Hebrew** (fine), but Windows renders it in **Times New Roman** (serif, clashes with the rest of the UI). Result: Hebrew looks like a newspaper; English looks like a startup.

### Bad

```css
body {
  font-family: 'Poppins', sans-serif;
}
```

On Windows, Hebrew: Times New Roman.

### Also bad

```css
body {
  font-family: 'Inter', 'Roboto', Helvetica, Arial, sans-serif;
}
```

None of these include Hebrew glyphs. Fallback chain doesn't help.

## The fix

Include an explicit Hebrew-capable font **before** the generic fallback:

```css
body {
  font-family:
    'Poppins',              /* English primary */
    'Heebo',                /* Hebrew primary (same designer, matches Poppins proportions) */
    system-ui,
    -apple-system,
    'Segoe UI',
    Roboto,
    'Helvetica Neue',
    Arial,
    'Noto Sans Hebrew',
    sans-serif;
}
```

Good Hebrew fonts to pair with Latin fonts (free on Google Fonts):

| English font | Hebrew pair       |
|--------------|-------------------|
| Poppins      | **Heebo**         |
| Inter        | **Assistant**     |
| Roboto       | **Rubik**         |
| System UI    | **Noto Sans Hebrew** |
| Playfair     | **Frank Ruhl Libre** |

### Load both fonts properly

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet"
  href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&family=Heebo:wght@400;600&display=swap">
```

`display=swap` is mandatory (see rule D3).

### Unicode-range trick (advanced)

Tell the browser which font to use per script range — avoids downloading Heebo for English-only visitors:

```css
@font-face {
  font-family: 'AppFont';
  src: url('/fonts/Poppins.woff2') format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153; /* Latin */
  font-display: swap;
}
@font-face {
  font-family: 'AppFont';
  src: url('/fonts/Heebo.woff2') format('woff2');
  unicode-range: U+0590-05FF; /* Hebrew */
  font-display: swap;
}
body { font-family: 'AppFont', sans-serif; }
```

## How to detect

**Static:** Grep CSS for `font-family:` in any project containing Hebrew content. Check each stack for a Hebrew-capable font (Heebo, Assistant, Rubik, Noto Sans Hebrew, Arial Hebrew, system-ui).

**Visual:** Open the Hebrew page on Windows (or Windows emulator / BrowserStack). Inspect Hebrew text — what font is actually rendering? If it says `Times New Roman`, you have the bug.

**`auto_audit.py`** flags font stacks that lack a Hebrew-capable fallback.

## Related rules

- B1 (dir="rtl" missing)
- D3 (font-display: swap)
