# Pattern: iOS zooms in when focusing an input

**Rule:** C3
**Severity:** P1
**Seen in:** Editox login, JARVIS dashboard mobile

## The bug

Tap a form input on iPhone Safari — the whole page zooms in by ~20%. The user has to pinch back out. This happens **only** when the input's computed `font-size` is below 16px.

Apple does this deliberately: "if the text is too small to read, zoom so the user can read what they type". Fine intent, terrible UX on a designed layout.

### Bad

```css
.form input {
  font-size: 14px;      /* triggers zoom */
  padding: 8px 12px;
}
```

```css
.form-small input {
  font-size: 0.875rem;  /* 14px with default root — also triggers */
}
```

## The fix

Set input font-size to at least 16px. If your design demands smaller, use `max`:

```css
.form input,
.form textarea,
.form select {
  font-size: max(16px, 1rem);
  padding: 8px 12px;
}
```

On a desktop-only breakpoint you can go smaller if you must, but keep ≥16px on mobile:

```css
input { font-size: 16px; }

@media (min-width: 1024px) {
  input { font-size: 14px; } /* safe on desktop — no iOS here */
}
```

### Alternative (hacky, not recommended)

Disable zoom entirely via viewport:

```html
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
```

This works but **breaks accessibility** — users who need to zoom can't. Don't do it unless you have a strong reason. Fixing the font-size is the right answer.

### Design-only smaller inputs

If the visual design really needs smaller inputs, compensate with `transform: scale()` on everything else:

```css
/* Don't. This is a maintenance nightmare. Just use 16px. */
```

## How to detect

**Static:** `auto_audit.py` flags CSS rules targeting `input`/`textarea`/`select` with `font-size < 16px`.

```bash
grep -rnE '(input|textarea|select)[^{]*\{[^}]*font-size\s*:\s*(1[0-5]|[0-9])px' --include='*.css' --include='*.scss' .
```

**Runtime:** Open the site on an actual iPhone (or Safari's Responsive Design Mode + iPhone preset). Tap each input. Does the page zoom? Bug.

**Gotchas:**
- Tailwind `text-sm` = 14px → triggers.
- Material UI default TextField is 16px → safe.
- Component libraries that use rem — check the actual computed value in DevTools.

## Related rules

- C1 (viewport meta missing)
- C4 (touch targets < 44px)
