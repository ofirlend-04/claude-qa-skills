# Pattern: Icon button missing aria-label

**Rule:** A3
**Severity:** P0
**WCAG:** 4.1.2 (Name, Role, Value) — Level A
**Seen in:** JARVIS dashboard hamburger menu, Editox toolbar icons

## The bug

A `<button>` whose only content is an SVG icon has no accessible name. Screen readers announce it as `"button"` with no hint what it does. Keyboard users see a focus ring on nothing.

### Bad

```jsx
<button onClick={toggleMenu}>
  <svg viewBox="0 0 24 24">
    <path d="M3 6h18M3 12h18M3 18h18" />
  </svg>
</button>
```

VoiceOver: *"button"*. User has no idea. Tested on iOS Safari — user left.

### Also bad

```jsx
<button onClick={close}>
  <i className="fa fa-times" />
</button>
```

Font icon is even worse — SRs read "times", which sounds like the number word, not "close".

## The fix

Add `aria-label` describing the **action**, not the icon:

```jsx
<button aria-label="Open navigation menu" onClick={toggleMenu}>
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M3 6h18M3 12h18M3 18h18" />
  </svg>
</button>
```

Mark the `<svg>` as `aria-hidden="true"` so SRs don't announce the icon in addition to the button.

### For toggles, make the state part of the label

```jsx
<button
  aria-label={isOpen ? 'Close menu' : 'Open menu'}
  aria-expanded={isOpen}
  aria-controls="main-nav"
  onClick={toggle}
>
  <MenuIcon aria-hidden="true" />
</button>
```

### Hebrew

```jsx
<button aria-label="פתיחת תפריט" onClick={toggleMenu}>
  <MenuIcon aria-hidden="true" />
</button>
```

Keep the label in the user's language — don't mix English labels into a Hebrew UI.

## How to detect

**Static:**

```bash
# JSX/TSX — button with only an SVG/icon child
grep -rnE '<button[^>]*>\s*<(svg|i|span)[^>]*(icon|svg)' --include='*.tsx' --include='*.jsx' src/
```

Or run `auto_audit.py` which flags any `<button>` whose body has no text and no `aria-label`.

**Runtime:** axe-core via `playwright_checks.js` catches this as `button-name`.

## Related rules

- A4 (form inputs without labels)
- G4 (empty focusable element)
