# Pattern: Horizontal scroll on mobile

**Rule:** C5
**Severity:** P0
**Seen in:** Editox landing page, CalmQuest web paywall

## The bug

On a 375px viewport, the page can scroll sideways. Usually 20-40px of dead space to the right. Looks unprofessional and often misaligns sticky headers.

Masking it with `overflow-x: hidden` on `<body>` **hides the symptom** — the content is still there, just clipped. That breaks anchor positioning and fixed elements, and the real bug is still in your layout.

### Bad — fixed width element

```css
.hero {
  width: 1200px;        /* overflows 375px viewport */
}
```

### Bad — `100vw` inside padded parent

```css
body { padding: 0 16px; }
.full-bleed { width: 100vw; margin-left: -16px; }  /* off by scrollbar width */
```

### Bad — negative margin that exceeds padding

```css
.container { padding: 16px; }
.bleed { margin: 0 -20px; }  /* 4px overflow */
```

### Bad — image at natural size

```html
<img src="giant-hero.png">  <!-- 2000px wide, no max-width -->
```

## The fix

### Step 1 — Find the culprit

In DevTools console:

```js
const viewport = window.innerWidth;
Array.from(document.querySelectorAll('*')).forEach((el) => {
  const rect = el.getBoundingClientRect();
  if (rect.right > viewport + 1) {
    console.log(Math.round(rect.right - viewport) + 'px over:', el);
  }
});
```

This lists every element extending past the viewport. Fix those, not `<body>`.

### Step 2 — Apply the right fix

| Cause                          | Fix                                                |
|--------------------------------|----------------------------------------------------|
| Fixed width container          | `max-width` + `width: 100%`                        |
| `100vw` inside padded parent   | `width: 100%` instead, or use CSS `calc(100vw - var(--sbw))` |
| Negative margin > parent pad   | Reduce the margin, or move the bleed to a parent  |
| Huge image                     | `img { max-width: 100%; height: auto; }`           |
| Long unbroken string (URL)     | `overflow-wrap: anywhere;`                         |
| `<pre>` or `<code>` block      | `white-space: pre-wrap; overflow-wrap: anywhere;`  |
| RTL + transformed element      | Check `transform: translateX(...)` values          |

### Step 3 — Global safety net (not a fix, a guardrail)

```css
html, body { overflow-x: clip; }  /* `clip` is safer than `hidden`, doesn't create a scroll container */
```

Add this **only after** the root cause is fixed. Otherwise you'll ship the underlying layout bug.

### Step 4 — Images default rule

```css
img, video, iframe, svg {
  max-width: 100%;
  height: auto;
}
```

Put this in your base stylesheet. Prevents 80% of mobile overflow bugs.

## How to detect

**`playwright_checks.js`** loads the page at 375px and compares `document.documentElement.scrollWidth` to `window.innerWidth`. If over by more than 1px → P0 finding.

**Manual:** Chrome DevTools → Toggle device toolbar → iPhone SE 375px. Scroll sideways. If you can, bug.

**Visual regression:** Take a screenshot at 375 per PR; compare with baseline. Any width change = review.

## Related rules

- C1 (viewport meta)
- C2 (fixed widths)
- C7 (images without max-width)
