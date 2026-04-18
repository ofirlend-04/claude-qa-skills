# Web UI QA — Manual Checklist

Automation catches structure. Humans catch meaning. Work through this list after `auto_audit.py` and `playwright_checks.js` both pass.

Open the site in a real browser. Have Hebrew and English pages ready. Have a phone and a laptop. Have DevTools Lighthouse ready as a sanity check.

---

## 1. First impression (30 seconds)

- [ ] Page loads in under 3 seconds on throttled 4G (Chrome DevTools → Network → "Fast 4G").
- [ ] No layout shift after initial paint (fonts, images, ads don't jump the content).
- [ ] Nothing flashes the wrong color (FOUC — flash of unstyled content).
- [ ] Scroll all the way down — does anything break, stutter, or 404?
- [ ] Scroll back up — are sticky headers sticky? Do they cover content?

## 2. Content & copy

- [ ] Every headline makes sense without context.
- [ ] No lorem ipsum, `TODO`, `FIXME`, `[Replace this]`, or `undefined` on screen.
- [ ] Hebrew copy: direct, no stiff translations from English. Read aloud.
- [ ] English copy: no leftover Hebrew punctuation or reversed parens.
- [ ] Numbers, dates, currency formatted for the active locale.
- [ ] All CTAs use active verbs ("Start now", "הזמן עכשיו") — not "Click here".

## 3. Visual / layout

- [ ] Open at 375, 420, 768, 1024, 1440, 1920 widths. Every breakpoint looks intentional.
- [ ] No element touches the viewport edge on mobile (should have ≥ 16px padding).
- [ ] Images crisp on retina (check for `@2x` or SVG).
- [ ] Icons visually consistent (same stroke width, same family).
- [ ] Empty states exist (search with no results, empty list, etc).
- [ ] Loading states exist (skeleton or spinner — not blank).
- [ ] Error states exist (404 page, 500 page, network error component).

## 4. RTL / Hebrew-specific

- [ ] Open the Hebrew page. `<html dir="rtl">` is set.
- [ ] Toolbar / nav reads right-to-left in a natural order.
- [ ] Arrows point the right way (→ means "next" in RTL context means left-pointing).
- [ ] Bullet and numbered lists align to the right.
- [ ] Quotation marks appear on the correct side of the text.
- [ ] Numbers embedded in Hebrew don't reverse (use `<bdi>` if they do).
- [ ] Dates: format `dd/mm/yyyy` or `d.m.yyyy`, not `m/d/yyyy`.
- [ ] Currency: `₪` appears consistently before or after the amount, not flipping per paragraph.
- [ ] Hebrew font renders cleanly. No serif fallback. No `ף` / `ץ` / final-letter bugs.
- [ ] Switching locale English↔Hebrew doesn't break layout.
- [ ] Buttons/inputs padding looks symmetric in both directions.

## 5. Accessibility — manual

- [ ] Unplug the mouse. Tab through the whole page. Can you reach every interactive element?
- [ ] `Tab` order matches visual order (left→right top→bottom in LTR; right→left top→bottom in RTL).
- [ ] Focus ring visible on every focusable (not suppressed by `outline: none`).
- [ ] `Esc` closes modals. `Enter` submits forms. `Space` activates buttons.
- [ ] Run a screen reader (VoiceOver Cmd+F5 / NVDA / ChromeVox):
  - [ ] Landmarks announced (`<header>`, `<nav>`, `<main>`, `<footer>`).
  - [ ] Every link text makes sense out of context (no "Click here", "Read more").
  - [ ] Icon-only buttons announced by their aria-label, not "button".
  - [ ] Form errors announced when they appear (live region).
- [ ] Zoom to 200% (Cmd +). Content still usable, nothing cut off.
- [ ] Enable prefers-reduced-motion. Does the site stop animating?
- [ ] Disable JavaScript. Does critical content still render? (progressive enhancement)

## 6. Forms

- [ ] Every input has a visible label (placeholder is NOT a label).
- [ ] Required fields marked visually AND with `aria-required`.
- [ ] Validation errors: clear message, placed near the field, in red + icon (not only color).
- [ ] Autocomplete attributes set (`autocomplete="email"`, `"tel"`, `"name"`).
- [ ] Submit button shows loading state and is disabled during submit.
- [ ] Success state: clear message, not just a page reload.
- [ ] Error: form values preserved (user doesn't re-type).

## 7. Performance — real-world

- [ ] Lighthouse (Chrome DevTools) Performance ≥ 90 on mobile.
- [ ] Lighthouse Accessibility ≥ 95.
- [ ] LCP < 2.5s, CLS < 0.1, INP < 200ms.
- [ ] No render-blocking third-party scripts.
- [ ] Images served in WebP/AVIF where supported.
- [ ] Fonts subset + `font-display: swap`.
- [ ] Bundle size — run `next build` / `vite build` and check output; nothing obviously bloated.

## 8. SEO — manual

- [ ] Share the URL in WhatsApp, Slack, and Twitter. Preview card looks right.
- [ ] View source — `<title>` and `<meta description>` unique per page.
- [ ] Open `site.com/sitemap.xml` — valid XML, all pages listed.
- [ ] Open `site.com/robots.txt` — exists, doesn't accidentally block everything.
- [ ] Search `site:yoursite.com` in Google — pages indexed.
- [ ] Check Google Search Console → Coverage. No "excluded" pages that shouldn't be.

## 9. Security — manual

- [ ] Open DevTools → Sources. Grep the bundled JS for `sk-`, `AIza`, `pk_live_`, `Bearer `, your company name + "secret" — nothing leaked.
- [ ] DevTools → Application → Local Storage. No auth tokens, no PII.
- [ ] DevTools → Network. All requests HTTPS (no http:// mixed content).
- [ ] DevTools → Network → response headers on `/`. CSP, HSTS, X-Frame-Options present.
- [ ] Try submitting `<script>alert(1)</script>` in every text input — does the output escape it?

## 10. Cross-browser

- [ ] Safari (macOS + iOS) — date pickers, `:has()`, backdrop-filter.
- [ ] Firefox — flexbox/gap quirks, form styling.
- [ ] Chrome — baseline.
- [ ] Edge — should mirror Chrome, but screenshot it.

## 11. iOS / Android web views

If the site loads inside a native app (Capacitor, WebView):

- [ ] Safe areas respected (top notch, bottom home indicator).
- [ ] `100vh` works — iOS Safari shrinks viewport when URL bar appears.
- [ ] Pull-to-refresh doesn't bounce into unwanted page reload.
- [ ] Tapping form input doesn't zoom (see C3).
- [ ] Back gesture from edge works and doesn't get captured by carousel.

## 12. Dead code audit

- [ ] Grep the repo for `// TODO`, `console.log`, `debugger`, commented-out blocks.
- [ ] Run `depcheck` or `knip` — remove unused deps.
- [ ] Run `eslint --no-warn-ignored` — zero warnings.
- [ ] Check for obsolete A/B variants and feature flags that are now permanent.

## 13. Pre-ship

- [ ] Run `auto_audit.py https://staging...` — 0 P0, 0 P1.
- [ ] Run `playwright_checks.js https://staging...` — 0 P0, 0 P1.
- [ ] Eyeball screenshots at 375/768/1920.
- [ ] Show to one real user from the target audience. Don't coach. Watch them.
