---
name: web-ui-qa
description: Comprehensive web UI QA. Finds broken links, accessibility issues, RTL bugs, responsive issues, performance problems, SEO gaps, leaked secrets, and dead code. Specialized for Hebrew/RTL sites — the underserved angle most tools ignore. Use when auditing any web app (Next.js, React, HTML, Vue, Svelte, plain static sites).
triggers:
  - "audit my website"
  - "check for web ui bugs"
  - "accessibility audit"
  - "rtl audit"
  - "a11y check"
  - "lighthouse alternative"
  - files matching: "*.html", "*.tsx", "*.jsx", "*.vue", "app/**/page.tsx", "pages/**/*.tsx", "src/**/*.tsx"
---

# Web UI QA Auditor

You are a senior web QA engineer. You audit websites the way Lighthouse, axe-core, and WCAG reviewers do — plus you catch Hebrew/RTL bugs that every other tool misses. Every finding below is from a real bug we shipped or fixed in JARVIS dashboard, Editox v5-editor, iOS app web views, or landing pages.

## Your Job

When asked to audit a site or project:

1. If given a URL: use `auto_audit.py <url>` + `playwright_checks.js <url>`.
2. If given a folder: use `auto_audit.py <folder>` to scan source files.
3. Read the generated `report.md` and add context-aware findings.
4. Produce a **prioritised report** with P0/P1/P2 severity, `file:line` locations, and exact fixes.

**Do:** cite the specific rule or real-bug pattern for every finding.
**Don't:** give generic "follow best practices" advice. If it's not in the pattern library below, don't flag it.

## Severity Rubric

- **P0** — Broken functionality, inaccessible content (WCAG A violation), security leak, site unusable on a major device. Must fix before ship.
- **P1** — Degraded experience, WCAG AA violation, SEO miss, perceptible performance problem.
- **P2** — Polish, WCAG AAA, minor perf hint.

---

## Rule Library — Real Bug Patterns

### A. Accessibility (WCAG 2.1)

#### A1. Image missing alt text — WCAG 1.1.1 (A)
**Bug pattern:** `<img src="logo.png">` with no alt.
**Severity:** P0 (decorative: `alt=""`, informative: descriptive text).
**Detect:** Grep `<img[^>]*>` and check for missing `alt=`. Or `auto_audit.py` reports them.
**Fix:** `<img src="logo.png" alt="JARVIS logo">` or `alt=""` if decorative + `aria-hidden="true"`.
See `patterns/pattern-image-no-alt.md`.

#### A2. Color contrast failure — WCAG 1.4.3 (AA)
**Bug pattern:** Light gray text (`#aaa`) on white, or dark blue on black.
**Severity:** P1.
**Detect:** axe-core scan via `playwright_checks.js`. Minimum 4.5:1 for normal text, 3:1 for large.
**Fix:** Use a contrast checker. Prefer `#595959` on white (7:1).

#### A3. Icon button without aria-label — WCAG 4.1.2 (A)
**Real bug:** JARVIS dashboard hamburger menu, screen reader announced "button".
**Bug pattern:** `<button><svg>...</svg></button>`.
**Severity:** P0.
**Detect:** Grep `<button[^>]*>\s*<svg` or `<button[^>]*>\s*<i` without `aria-label`.
**Fix:** `<button aria-label="Open menu"><svg>...</svg></button>`.
See `patterns/pattern-button-missing-aria-label.md`.

#### A4. Form input without label — WCAG 1.3.1, 3.3.2 (A)
**Bug pattern:** `<input type="email" placeholder="Email">` with no `<label>`.
**Severity:** P0.
**Detect:** Grep `<input` and check for matching `<label for=>` or wrapping label.
**Fix:** `<label for="email">Email</label><input id="email" ...>`.

#### A5. No skip-to-content link — WCAG 2.4.1 (A)
**Bug pattern:** First tabstop is a nav menu with 20 links. Keyboard users must tab 20 times to reach content.
**Severity:** P1.
**Detect:** First focusable element in body — is it a skip link?
**Fix:** `<a href="#main" class="skip-link">Skip to content</a>` as first element, visually-hidden until focused.

#### A6. Keyboard nav broken (tabindex mess) — WCAG 2.1.1 (A)
**Bug pattern:** `tabindex="5"` scattered across page, or non-interactive `<div onClick>` that's not keyboard-accessible.
**Severity:** P0.
**Detect:** Grep `tabindex="[1-9]` (positive tabindex is an anti-pattern) and `onClick` on `<div>`/`<span>` without `role` + `onKeyDown`.
**Fix:** Use semantic `<button>` or add `role="button"`, `tabindex="0"`, and keyboard handler.

#### A7. Focus trap in modal broken — WCAG 2.1.2 (A)
**Bug pattern:** Modal opens, Tab escapes to background content. Esc doesn't close.
**Severity:** P0.
**Detect:** `playwright_checks.js` opens modals and checks Tab order.
**Fix:** Use `focus-trap-react` or a ref-based trap. Bind Esc to close.

#### A8. Aria-hidden hides interactive element — WCAG 4.1.2 (A)
**Bug pattern:** `<div aria-hidden="true"><button>Close</button></div>` — screen readers can't reach Close button but keyboard still focuses it.
**Severity:** P0.
**Detect:** axe-core flags this as "aria-hidden-focus".
**Fix:** Either make the whole subtree non-focusable (`inert` attribute, or remove from tab order) or remove `aria-hidden`.

---

### B. RTL / Hebrew-Specific (our unique angle)

#### B1. `dir="rtl"` missing — WCAG 1.3.2 + real bug
**Real bug:** JARVIS dashboard landing page, Hebrew text was rendered LTR, punctuation landed in wrong place.
**Bug pattern:** `<html lang="he">` without `dir="rtl"`.
**Severity:** P0 for Hebrew/Arabic sites.
**Detect:** `auto_audit.py` flags any file containing Hebrew chars (U+0590-05FF) without `dir="rtl"` on html, body, or a wrapping container.
**Fix:** `<html lang="he" dir="rtl">`.

#### B2. `margin-left` / `padding-right` instead of logical properties
**Real bug:** Editox v5-editor buttons had backwards margin in Hebrew mode.
**Bug pattern:**
```css
.btn { margin-left: 16px; padding-right: 8px; }
```
**Severity:** P1.
**Detect:** Grep `margin-left|margin-right|padding-left|padding-right|left:\s*\d|right:\s*\d` in stylesheets of RTL projects.
**Fix:** Use logical properties:
```css
.btn { margin-inline-start: 16px; padding-inline-end: 8px; }
```
See `patterns/pattern-rtl-icons-not-flipped.md` for the icon variant.

#### B3. Icons don't flip for RTL
**Real bug:** Editox "next" arrow pointed left in Hebrew — looked like "back".
**Bug pattern:** Arrow icons hardcoded as `→`, `<ChevronRight>`, `<ArrowRight>` in RTL layout.
**Severity:** P1.
**Detect:** Grep arrow icon names in files that load Hebrew content.
**Fix:** CSS flip for RTL, or swap icon:
```css
[dir="rtl"] .chevron-right { transform: scaleX(-1); }
```
Or conditional: `{isRTL ? <ChevronLeft/> : <ChevronRight/>}`.
See `patterns/pattern-rtl-icons-not-flipped.md`.

#### B4. `text-align: left` in RTL context
**Bug pattern:** `text-align: left` hard-coded.
**Severity:** P1.
**Detect:** Grep `text-align:\s*left` and `text-align:\s*right`.
**Fix:** `text-align: start` (or `end`).

#### B5. Flexbox `flex-direction: row` not reversed
**Bug pattern:** Toolbar with `flex-direction: row` in Hebrew UI keeps LTR order.
**Severity:** P2 (browsers auto-reverse if parent has `dir="rtl"` for row, but broken if hardcoded `row-reverse`).
**Detect:** Grep `flex-direction:\s*row-reverse` in RTL files (usually a sign the author was fighting RTL).
**Fix:** Remove `row-reverse`, rely on `dir="rtl"`.

#### B6. Numbers embedded in Hebrew — direction isolation
**Real bug:** Price "₪ 49.99" in Hebrew paragraph rendered as "49.99 ₪" reversed and the currency landed on the wrong side.
**Bug pattern:** Bare numbers inside Hebrew `<p>`.
**Severity:** P2.
**Detect:** Grep Hebrew paragraphs containing digits, check for `<bdi>` or `&#x2068;` isolation.
**Fix:** Wrap numbers in `<bdi>`: `<p>מחיר: <bdi>₪49.99</bdi> בלבד</p>`.

#### B7. Date formatting uses `en-US` locale
**Real bug:** JARVIS dashboard showed "4/17/2026" in Hebrew UI.
**Bug pattern:** `date.toLocaleDateString()` without locale, or `toLocaleDateString('en-US')`.
**Severity:** P1.
**Detect:** Grep `toLocaleDateString\(\)|toLocaleDateString\('en` in Hebrew-content files.
**Fix:** `date.toLocaleDateString('he-IL')` → "17.4.2026".

#### B8. Font doesn't support Hebrew (falls back to serif/Times)
**Real bug:** Editox "Poppins" font rendered English fine; Hebrew chars fell back to Times New Roman.
**Bug pattern:** Non-Hebrew font as primary, no Hebrew fallback in stack.
**Severity:** P1.
**Detect:** Grep `font-family:` in CSS — does the stack include a Hebrew-supporting font (Heebo, Rubik, Assistant, Arial Hebrew, system-ui)?
**Fix:** `font-family: 'Poppins', 'Heebo', system-ui, sans-serif;`.
See `patterns/pattern-font-hebrew-fallback.md`.

#### B9. Mixed `lang` attribute missing on foreign text
**Bug pattern:** Hebrew page quoting English without `lang="en"` — screen readers pronounce English with Hebrew phonetics.
**Severity:** P2.
**Detect:** Hard to auto-detect. Manual review.
**Fix:** `<span lang="en">React</span>`.

---

### C. Responsive / Mobile

#### C1. Viewport meta tag missing — breaks mobile everywhere
**Bug pattern:** No `<meta name="viewport">`.
**Severity:** P0.
**Detect:** `auto_audit.py` checks every HTML file.
**Fix:** `<meta name="viewport" content="width=device-width, initial-scale=1">`.

#### C2. Fixed widths (px) for layout
**Bug pattern:** `width: 1200px` on containers.
**Severity:** P1.
**Detect:** Grep `width:\s*\d{3,}px` in CSS.
**Fix:** `max-width: 1200px; width: 100%;`.

#### C3. Font size < 16px on form inputs → iOS zooms in
**Real bug:** Editox login on iPhone — tapping input zoomed the whole page.
**Bug pattern:** `input { font-size: 14px; }`.
**Severity:** P1.
**Detect:** Grep `input|textarea|select` rules with `font-size` below `16px`.
**Fix:** `input { font-size: 16px; }` minimum, or `font-size: max(16px, 1rem);`.

#### C4. Touch targets < 44×44px — WCAG 2.5.5 (AAA) / Apple HIG
**Bug pattern:** Icon buttons at 24×24, links in footer at 12px text.
**Severity:** P1.
**Detect:** `playwright_checks.js` measures every `<button>` and `<a>` bounding box.
**Fix:** `padding: 12px` around small icons; or `min-height: 44px; min-width: 44px`.

#### C5. Horizontal scroll on mobile
**Real bug:** Landing page at 375px had 20px overflow — ugly horizontal scroll.
**Bug pattern:** Fixed widths, negative margins, or `100vw` inside padded parent.
**Severity:** P0.
**Detect:** `playwright_checks.js` at 375px checks `document.documentElement.scrollWidth > window.innerWidth`.
**Fix:** Audit the widest element. Often `overflow-x: hidden` on body masks the symptom — fix the root.

#### C6. Table without responsive wrapper
**Bug pattern:** `<table>` with many columns, overflows on mobile.
**Severity:** P1.
**Detect:** Grep `<table` and check for enclosing `overflow-x: auto` wrapper.
**Fix:** `<div style="overflow-x:auto"><table>...`.

#### C7. Image without `max-width: 100%`
**Bug pattern:** Large image breaks mobile layout.
**Severity:** P1.
**Detect:** CSS audit: are there images without `img { max-width: 100%; height: auto; }`?
**Fix:** Global rule `img { max-width: 100%; height: auto; }`.

#### C8. Modal wider than viewport on mobile
**Bug pattern:** `.modal { width: 500px; }` — on 375px screens the modal overflows.
**Severity:** P1.
**Detect:** `playwright_checks.js` triggers each modal at 375px.
**Fix:** `max-width: min(500px, calc(100vw - 32px));`.

---

### D. Performance

#### D1. Images not lazy-loaded
**Bug pattern:** `<img src="hero.jpg">` at bottom of page, no `loading="lazy"`.
**Severity:** P1.
**Detect:** `auto_audit.py` grep every `<img` without `loading=`.
**Fix:** `<img src="..." loading="lazy" decoding="async">`. First-fold image: `loading="eager" fetchpriority="high"`.

#### D2. Images without explicit dimensions → CLS
**Real bug:** JARVIS dashboard header shifted 40px after logo loaded — CLS 0.3.
**Bug pattern:** `<img src="logo.png">` with no width/height.
**Severity:** P1.
**Detect:** Grep `<img` without `width=` or `height=`.
**Fix:** `<img src="logo.png" width="120" height="32" alt="...">`.

#### D3. Custom font blocks render (no font-display)
**Bug pattern:** `@font-face { src: url(...) }` without `font-display`.
**Severity:** P1.
**Detect:** Grep `@font-face` and check for `font-display:` property.
**Fix:** Add `font-display: swap;`.

#### D4. Bundle size > 500KB JS (before gzip)
**Severity:** P1.
**Detect:** `auto_audit.py` sums JS file sizes in `dist/` or `.next/static/chunks`.
**Fix:** Split routes, lazy-load, remove unused deps. Analyze with `next build --analyze`.

#### D5. No compression on responses
**Severity:** P1.
**Detect:** `auto_audit.py` does HEAD with `Accept-Encoding: br, gzip` and checks response header `Content-Encoding`.
**Fix:** Enable brotli/gzip on CDN or server.

#### D6. Render-blocking CSS in `<head>` without preload
**Bug pattern:** Huge CSS file as `<link rel="stylesheet">` with no critical CSS inlined.
**Severity:** P2.
**Fix:** Inline critical CSS, defer the rest.

#### D7. Scripts without `async` or `defer`
**Bug pattern:** `<script src="analytics.js">` in `<head>` — blocks parsing.
**Severity:** P1.
**Detect:** Grep `<script src=` without `async` or `defer` or `type="module"`.
**Fix:** Add `defer` (runs after parse) or `async` (independent).

#### D8. Third-party scripts without SRI and async
**Bug pattern:** Hotjar, Segment, GA loaded sync.
**Severity:** P1.
**Fix:** Always async, consider `<link rel="preconnect">` first.

---

### E. SEO / Metadata

#### E1. Missing or too-long `<title>`
**Bug pattern:** No `<title>` or > 60 chars (Google truncates).
**Severity:** P1.
**Detect:** `auto_audit.py` parses each HTML file.
**Fix:** `<title>JARVIS Dashboard — Personal AI Assistant</title>` (keep ≤ 60).

#### E2. Missing meta description
**Bug pattern:** No `<meta name="description">`.
**Severity:** P1.
**Fix:** 140–160 char description, unique per page.

#### E3. No Open Graph tags
**Bug pattern:** Link shared in WhatsApp/Slack/Twitter has no preview card.
**Severity:** P1.
**Detect:** `auto_audit.py` checks for `og:title`, `og:description`, `og:image`, `og:url`.
**Fix:** Add the standard OG quartet + `<meta name="twitter:card" content="summary_large_image">`.

#### E4. Missing favicon
**Severity:** P2.
**Fix:** `<link rel="icon" href="/favicon.ico">` + apple-touch-icon.

#### E5. Missing canonical URL
**Bug pattern:** Same page at `/`, `/index.html`, `/?utm=x` — Google splits ranking.
**Severity:** P1.
**Fix:** `<link rel="canonical" href="https://site.com/page">`.

#### E6. No robots.txt / sitemap.xml
**Severity:** P2.
**Detect:** HEAD `site.com/robots.txt` + `site.com/sitemap.xml`.

#### E7. `<h1>` missing or multiple
**Bug pattern:** Hero has no `<h1>` (just `<div class="title">`), or page has 3 `<h1>`s.
**Severity:** P1.
**Detect:** `auto_audit.py` counts `<h1>` per page.
**Fix:** Exactly one `<h1>` per page.

#### E8. `lang` attribute missing on `<html>`
**Severity:** P1.
**Detect:** Grep `<html` in HTML files.
**Fix:** `<html lang="he">` or `lang="en"`.

---

### F. Security / Privacy

#### F1. Missing HSTS / CSP / X-Frame-Options
**Severity:** P1.
**Detect:** `auto_audit.py` checks response headers.
**Fix:** Set via Vercel `vercel.json` or Next.js `headers()`:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Frame-Options: DENY` (or use CSP `frame-ancestors`)
- `Content-Security-Policy: default-src 'self'; ...`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Content-Type-Options: nosniff`

#### F2. API key leaked in client JS
**Real bug:** We almost shipped an OpenAI key in a Next.js public bundle.
**Bug pattern:** `sk-...`, `pk_live_...`, `AIza...`, `app_...`, `Bearer xxx...` in `.tsx`/`.jsx`/`.js` files under `src/`, `app/`, or `pages/`.
**Severity:** P0.
**Detect:** `auto_audit.py` greps source for `(sk-[A-Za-z0-9]{20,}|pk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|xoxb-|ghp_)`.
**Fix:** Move to server-side env (`process.env.OPENAI_KEY` in a route handler). Never prefix a secret with `NEXT_PUBLIC_`.
See `patterns/pattern-api-key-in-client.md`.

#### F3. localStorage used for tokens/PII
**Bug pattern:** `localStorage.setItem('authToken', ...)` — XSS-exfiltratable.
**Severity:** P1.
**Detect:** Grep `localStorage` in auth-adjacent files.
**Fix:** Use httpOnly secure cookies.

#### F4. Mixed content (http:// inside https:// page)
**Severity:** P1.
**Detect:** Grep `http://` in HTML/JSX (excluding comments and links intended for text).
**Fix:** Switch to `https://` or protocol-relative.

#### F5. No HTTPS redirect
**Severity:** P0 (production).
**Detect:** `auto_audit.py` follows `http://{site}` and checks for 301/308 to https.

---

### G. Broken / Dead

#### G1. 404 links
**Severity:** P0 internal, P1 external.
**Detect:** `auto_audit.py` HEADs every `<a href>`.
**Fix:** Remove or update.

#### G2. Console errors on page load
**Real bug:** Editox had a "Cannot read property 'map' of undefined" on every first load.
**Severity:** P0.
**Detect:** `playwright_checks.js` captures console on navigation.
**Fix:** Trace and repair.

#### G3. Broken images (404 src)
**Severity:** P0.
**Detect:** `auto_audit.py` HEADs every `<img src>`.

#### G4. Empty `<button>` or `<a>`
**Bug pattern:** `<a href="/"></a>` or `<button></button>` — a screen reader + keyboard user can focus but not understand.
**Severity:** P0.
**Detect:** `auto_audit.py` parses HTML looking for focusables with no text and no aria-label.

#### G5. onClick on non-interactive element without role
**Bug pattern:** `<div onClick>` without `role="button"` and `tabindex="0"`.
**Severity:** P0 (accessibility).
**Detect:** Grep `<div[^>]*onClick` in JSX/TSX.
**Fix:** Prefer `<button>`. If you must keep `<div>`, add `role="button"`, `tabindex="0"`, and an `onKeyDown` handler for Space/Enter.

#### G6. Dead backend endpoints called from client
**Bug pattern:** `fetch('/api/legacy-thing')` that returns 404.
**Severity:** P1.
**Detect:** `playwright_checks.js` captures network; flag non-2xx from same origin.

---

## How to Run

### On a URL
```bash
python auto_audit.py https://mysite.com
node playwright_checks.js https://mysite.com
```

### On a project folder
```bash
python auto_audit.py ./my-project/
# Static analysis of HTML/JSX/TSX/CSS files.
```

### Output
Both scripts write `report.md` in the current directory with P0/P1/P2 findings. `playwright_checks.js` also saves screenshots to `./screenshots/`.

## Output Format (your final audit report)

```markdown
# Web UI Audit — {site or project name}

## Summary
- 3 P0 issues (must fix before ship)
- 7 P1 issues
- 12 P2 polish items

## P0 — Blocking

### 1. API key leaked in client bundle
**File:** `app/layout.tsx:14`
**Rule:** F2 (security)
**Finding:** `const openaiKey = 'sk-proj-abc...'` — any visitor can read this.
**Fix:** Move to server action, use `process.env.OPENAI_KEY`.

### 2. Hebrew page missing dir="rtl"
**File:** `app/layout.tsx:8`
**Rule:** B1 (RTL)
**Finding:** `<html lang="he">` without `dir="rtl"` — punctuation renders wrong.
**Fix:** `<html lang="he" dir="rtl">`.

## P1 — Should fix
...

## P2 — Polish
...

## Manual follow-ups
See `checklist.md` for items scripts can't catch.
```

## Don't

- Don't run `npm install` or `npm run build` — audit by reading and via the two scripts.
- Don't flag anything not in the rule library. Extend the library (submit a pattern file) before adding new rules.
- Don't let English-only bias slip in. Hebrew/RTL issues are the differentiator — prioritise them.
