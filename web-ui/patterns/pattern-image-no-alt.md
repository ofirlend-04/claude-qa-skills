# Pattern: Image missing alt text

**Rule:** A1
**Severity:** P0 (if informative), P2 (if decorative and marked correctly)
**WCAG:** 1.1.1 Non-text Content — Level A

## The bug

`<img src="...">` with no `alt` attribute. Screen readers announce the filename, which is meaningless (e.g. "IMG underscore 2045 dot J P E G"). Sighted users who hit a broken image see no fallback.

### Bad

```html
<img src="/hero.jpg">
<img src="/logo.png">
<img src="/icons/cart.svg">
```

### Also bad — lazy "alt" that describes the file, not the meaning

```html
<img src="/hero.jpg" alt="hero.jpg">
<img src="/logo.png" alt="image">
<img src="/icons/cart.svg" alt="cart icon">
```

"cart icon" is redundant — screen readers already announce it's an image. Describe the **function**.

## The fix

### If the image conveys information

Write alt text that replaces what a sighted user gets from the image:

```html
<img src="/hero.jpg"
     alt="Family using JARVIS to order groceries by voice">
<img src="/logo.png"
     alt="JARVIS">
<button>
  <img src="/icons/cart.svg" alt="Cart (3 items)">
</button>
```

### If the image is purely decorative

Use empty alt **and** (optionally) aria-hidden to remove it from the SR tree:

```html
<img src="/background-dots.svg" alt="" aria-hidden="true">
```

Empty `alt=""` is different from missing `alt` — it explicitly tells the SR "skip this".

### If there's a text alternative nearby

You don't need to duplicate. Use empty alt and let the caption speak:

```html
<figure>
  <img src="/chart.png" alt="">
  <figcaption>Monthly active users grew 40% Q1→Q2.</figcaption>
</figure>
```

### Hebrew

```html
<img src="/hero.jpg" alt="משפחה משתמשת ב-JARVIS להזמנת מצרכים בקול">
```

Match the page language. Don't put an English alt on a Hebrew page.

### Icon in a button

The alt on the image + the text of the button should **not** be redundant:

```html
<!-- Redundant: SR says "Delete Delete button" -->
<button>
  <img src="/trash.svg" alt="Delete">
  Delete
</button>

<!-- Better: let the button text speak -->
<button>
  <img src="/trash.svg" alt="">
  Delete
</button>
```

## How to detect

**Static:** `auto_audit.py` flags `<img>` tags without `alt`.

```bash
grep -rnE '<img\b[^>]*>' --include='*.html' --include='*.tsx' --include='*.jsx' . \
  | grep -vE '\balt\s*='
```

**Runtime:** axe-core via `playwright_checks.js` (`image-alt` rule).

**Review:** Every image on every page should pass the test: "Would a blind user miss meaning if this image didn't load?" If yes — needs descriptive alt. If no — `alt=""`.

## Related rules

- A3 (icon buttons without aria-label)
- G3 (broken image src)
