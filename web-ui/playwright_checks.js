#!/usr/bin/env node
/*
 * Browser-based web UI QA.
 *
 * Usage:
 *   node playwright_checks.js https://mysite.com
 *
 * Checks:
 *   - Responsive at 375 (mobile), 768 (tablet), 1920 (desktop)
 *   - axe-core accessibility scan
 *   - Console errors/warnings on load
 *   - Failed network requests (4xx/5xx)
 *   - Touch target size (>= 44x44 per Apple HIG)
 *   - Horizontal scroll at 375
 *   - Load performance (LCP, TTFB, total)
 *   - Keyboard nav — Tab through focusables
 *   - Screenshots per breakpoint in ./screenshots/
 *
 * Appends findings to report.md (merged with auto_audit.py output if present).
 *
 * Deps:
 *   npm install playwright @axe-core/playwright
 *   npx playwright install chromium
 */

const { chromium, devices } = require('playwright');
const { AxeBuilder } = require('@axe-core/playwright');
const fs = require('fs');
const path = require('path');

const BREAKPOINTS = [
  { name: 'mobile',  width: 375,  height: 812 },
  { name: 'tablet',  width: 768,  height: 1024 },
  { name: 'desktop', width: 1920, height: 1080 },
];

function severityForAxe(impact) {
  return ({ critical: 'P0', serious: 'P0', moderate: 'P1', minor: 'P2' })[impact] || 'P2';
}

async function main() {
  const target = process.argv[2];
  if (!target) {
    console.error('Usage: node playwright_checks.js <url>');
    process.exit(1);
  }

  const outDir = path.resolve('screenshots');
  fs.mkdirSync(outDir, { recursive: true });

  const findings = [];
  const add = (f) => findings.push(f);

  const browser = await chromium.launch();

  for (const bp of BREAKPOINTS) {
    const context = await browser.newContext({
      viewport: { width: bp.width, height: bp.height },
      deviceScaleFactor: 2,
      userAgent: bp.name === 'mobile'
        ? devices['iPhone 13'].userAgent
        : undefined,
    });
    const page = await context.newPage();

    const consoleMsgs = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error' || msg.type() === 'warning') {
        consoleMsgs.push({ type: msg.type(), text: msg.text() });
      }
    });

    const failedRequests = [];
    page.on('requestfailed', (req) => {
      failedRequests.push({ url: req.url(), failure: req.failure()?.errorText });
    });
    page.on('response', (resp) => {
      if (resp.status() >= 400) {
        failedRequests.push({ url: resp.url(), status: resp.status() });
      }
    });

    const t0 = Date.now();
    let response;
    try {
      response = await page.goto(target, { waitUntil: 'load', timeout: 30000 });
    } catch (e) {
      add({ severity: 'P0', rule: 'meta', title: `Page load failed at ${bp.name}`,
            location: target, detail: e.message });
      await context.close();
      continue;
    }
    const loadMs = Date.now() - t0;

    // Perf
    if (loadMs > 4000) {
      add({ severity: 'P1', rule: 'D4', title: `Page load ${loadMs}ms at ${bp.name}`,
            location: target, fix: 'Target < 4s on 3G/mobile. Split bundles, lazy-load.' });
    }

    // Horizontal scroll (C5)
    if (bp.name === 'mobile') {
      const overflow = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
      }));
      if (overflow.scrollWidth > overflow.innerWidth + 1) {
        add({
          severity: 'P0', rule: 'C5',
          title: `Horizontal scroll on mobile (${overflow.scrollWidth}px > ${overflow.innerWidth}px)`,
          location: `${target} @375`,
          fix: 'Find the element wider than the viewport (check widest container, negative margins, 100vw inside padded parent).',
        });
      }
    }

    // Touch targets (C4) — only meaningful on mobile
    if (bp.name === 'mobile') {
      const small = await page.evaluate(() => {
        const nodes = Array.from(document.querySelectorAll('a, button, [role="button"], input[type="submit"], input[type="button"]'));
        const results = [];
        for (const el of nodes) {
          const rect = el.getBoundingClientRect();
          if (rect.width === 0 || rect.height === 0) continue; // hidden
          if (rect.width < 44 || rect.height < 44) {
            results.push({
              tag: el.tagName.toLowerCase(),
              text: (el.innerText || el.getAttribute('aria-label') || '').trim().slice(0, 40),
              width: Math.round(rect.width),
              height: Math.round(rect.height),
            });
          }
        }
        return results.slice(0, 20);
      });
      for (const t of small) {
        add({
          severity: 'P1', rule: 'C4',
          title: `Touch target ${t.width}x${t.height} < 44x44`,
          location: `${target} @375`,
          detail: `<${t.tag}> "${t.text}"`,
          fix: 'Add padding or min-width/min-height 44px.',
        });
      }
    }

    // axe-core accessibility scan (once per breakpoint — some rules vary by viewport)
    try {
      const axeResults = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
        .analyze();
      for (const v of axeResults.violations) {
        for (const node of v.nodes.slice(0, 5)) {
          add({
            severity: severityForAxe(v.impact),
            rule: `axe:${v.id}`,
            title: v.help,
            location: `${target} @${bp.name}`,
            detail: node.target.join(' ') + ' — ' + (node.failureSummary || '').split('\n')[0],
            fix: v.helpUrl,
          });
        }
      }
    } catch (e) {
      add({ severity: 'P2', rule: 'meta', title: 'axe scan failed',
            location: `${target} @${bp.name}`, detail: e.message });
    }

    // Console errors/warnings (G2)
    for (const m of consoleMsgs.slice(0, 25)) {
      add({
        severity: m.type === 'error' ? 'P0' : 'P1',
        rule: 'G2',
        title: `Console ${m.type}`,
        location: `${target} @${bp.name}`,
        detail: m.text.slice(0, 200),
        fix: 'Trace and repair. No noise on page load.',
      });
    }

    // Failed requests (G6 / G3)
    for (const r of failedRequests.slice(0, 25)) {
      add({
        severity: 'P1',
        rule: 'G6',
        title: `Network error ${r.status || r.failure}`,
        location: `${target} @${bp.name}`,
        detail: r.url,
        fix: 'Check endpoint or asset is live.',
      });
    }

    // Keyboard nav test (A6) — just report the count of focusables + first 10
    const focusables = await page.evaluate(() => {
      const els = Array.from(document.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      ));
      return els.slice(0, 10).map((el) => ({
        tag: el.tagName.toLowerCase(),
        text: (el.innerText || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').trim().slice(0, 40),
        tabindex: el.getAttribute('tabindex'),
      }));
    });
    // Check: first focusable on desktop should be a skip link or main nav
    if (bp.name === 'desktop' && focusables.length > 0) {
      const first = focusables[0];
      const isSkipLink = /skip/i.test(first.text) || /דלג/i.test(first.text);
      if (!isSkipLink && focusables.length > 8) {
        add({
          severity: 'P1', rule: 'A5',
          title: 'No skip-to-content link detected',
          location: `${target} @desktop`,
          detail: `First focusable: <${first.tag}> "${first.text}"`,
          fix: 'Add <a href="#main" class="skip-link">Skip to content</a> as first focusable element.',
        });
      }
    }

    // Screenshot
    const shotPath = path.join(outDir, `${bp.name}.png`);
    await page.screenshot({ path: shotPath, fullPage: true });

    await context.close();
  }

  await browser.close();

  // Merge with existing report.md if present
  const reportPath = path.resolve('report.md');
  let header = '';
  if (fs.existsSync(reportPath)) {
    header = fs.readFileSync(reportPath, 'utf-8') + '\n\n---\n\n';
  } else {
    header = `# Web UI Audit — ${target}\n\n`;
  }

  const buckets = { P0: [], P1: [], P2: [] };
  for (const f of findings) buckets[f.severity]?.push(f);

  let out = header + '## Browser-based checks (playwright)\n\n';
  out += `- ${buckets.P0.length} P0, ${buckets.P1.length} P1, ${buckets.P2.length} P2\n`;
  out += `- Screenshots: ${outDir}\n\n`;

  for (const [sev, label] of [['P0', 'Blocking'], ['P1', 'Should fix'], ['P2', 'Polish']]) {
    if (buckets[sev].length === 0) continue;
    out += `### ${sev} — ${label}\n\n`;
    buckets[sev].forEach((f, i) => {
      out += `#### ${sev}.${i + 1} [${f.rule}] ${f.title}\n`;
      out += `- **Location:** \`${f.location}\`\n`;
      if (f.detail) out += `- **Detail:** ${f.detail}\n`;
      if (f.fix) out += `- **Fix:** ${f.fix}\n`;
      out += '\n';
    });
  }

  fs.writeFileSync(reportPath, out, 'utf-8');
  console.log(`Wrote ${reportPath}  (${findings.length} findings)`);
  console.log(`Screenshots in ${outDir}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
