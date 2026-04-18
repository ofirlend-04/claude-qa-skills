# Pattern: Dates shown in US format on Hebrew UI

**Rule:** B7
**Severity:** P1
**Seen in:** JARVIS dashboard activity page, Editox export timestamps

## The bug

`new Date().toLocaleDateString()` uses the **user's browser locale** on the client, but the **server's locale** on SSR. On Vercel's edge the server locale is `en-US`, so SSR'd pages render "4/17/2026" — even for Israeli visitors — until hydration kicks in.

### Bad

```tsx
export function ActivityDate({ iso }: { iso: string }) {
  return <span>{new Date(iso).toLocaleDateString()}</span>;
}
```

SSR result: `4/17/2026`. Client: `17.4.2026`. Hydration mismatch warning in console.

### Also bad

```tsx
new Date(iso).toLocaleDateString('en-US');
```

Explicitly US — not what an Israeli user expects.

### Also bad

```tsx
iso.slice(0, 10); // "2026-04-17" — technically correct ISO, but looks weird in Hebrew body copy
```

## The fix

Pass the locale explicitly, matching the page language:

```tsx
export function ActivityDate({ iso, locale = 'he-IL' }: Props) {
  const d = new Date(iso);
  return <time dateTime={iso}>{d.toLocaleDateString(locale)}</time>;
}
```

### With time

```tsx
d.toLocaleString('he-IL', {
  day: '2-digit', month: '2-digit', year: 'numeric',
  hour: '2-digit', minute: '2-digit',
});
// "17.04.2026, 14:30"
```

### Relative time (better UX)

```tsx
const rtf = new Intl.RelativeTimeFormat('he-IL', { numeric: 'auto' });
rtf.format(-1, 'day');   // "אתמול"
rtf.format(-2, 'day');   // "לפני יומיים"
```

### For i18n apps — derive locale from context

```tsx
import { useLocale } from 'next-intl';

export function ActivityDate({ iso }: { iso: string }) {
  const locale = useLocale();  // 'he' or 'en'
  const intlLocale = locale === 'he' ? 'he-IL' : 'en-US';
  return <time dateTime={iso}>
    {new Date(iso).toLocaleDateString(intlLocale)}
  </time>;
}
```

### For server components — make it deterministic

Pass the locale prop from the request headers so SSR matches CSR:

```tsx
// app/[locale]/layout.tsx
export default function Layout({ params }: { params: { locale: string } }) {
  return <LocaleProvider value={params.locale}>...</LocaleProvider>;
}
```

## Always wrap in `<time>`

```tsx
<time dateTime={iso}>{formatted}</time>
```

Gives screen readers and search engines a machine-readable reference regardless of display format.

## How to detect

**Static:**

```bash
grep -rnE 'toLocaleDateString\(\s*(\)|['\''\"]en)' --include='*.tsx' --include='*.jsx' --include='*.ts' --include='*.js' .
```

`auto_audit.py` flags `toLocaleDateString()` (no args) and `toLocaleDateString('en-*')` in files containing Hebrew strings.

**Runtime:** Open the Hebrew page on a fresh browser (no locale preferences set). If dates render `M/D/YYYY`, bug. If SSR shows one format and client shows another, bug.

## Related rules

- B1 (dir="rtl")
- B6 (numbers in Hebrew text)
- B8 (Hebrew font fallback)
