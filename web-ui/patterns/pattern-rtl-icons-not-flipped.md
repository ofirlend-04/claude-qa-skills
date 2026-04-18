# Pattern: RTL icons don't flip (arrows point wrong way)

**Rule:** B3
**Severity:** P1
**Seen in:** Editox v5-editor, JARVIS dashboard activity page

## The bug

In a Hebrew interface, "next" buttons pointed left (`ChevronLeft`) while "previous" buttons pointed right. Users read it as "previous" and "next" reversed. Two users reported the flow was "broken" before we realised the icons were the bug.

### Bad

```tsx
import { ChevronRight, ChevronLeft } from 'lucide-react';

export function Pagination({ onNext, onPrev }: Props) {
  return (
    <div className="flex gap-2">
      <button onClick={onPrev}><ChevronLeft /></button>
      <button onClick={onNext}><ChevronRight /></button>
    </div>
  );
}
```

In RTL layout, `ChevronLeft` renders pointing left — but in RTL that means "forward". Users think it's "back".

## The fix

**Option 1 — CSS flip (simplest).** Flip the icon horizontally when inside an RTL container:

```css
[dir="rtl"] .flip-on-rtl {
  transform: scaleX(-1);
}
```

```tsx
<button onClick={onNext}>
  <ChevronRight className="flip-on-rtl" />
</button>
```

**Option 2 — Swap icon based on direction.**

```tsx
import { useRTL } from '@/hooks/useRTL';

export function Pagination({ onNext, onPrev }: Props) {
  const isRTL = useRTL();
  const Forward = isRTL ? ChevronLeft : ChevronRight;
  const Backward = isRTL ? ChevronRight : ChevronLeft;
  return (
    <div className="flex gap-2">
      <button aria-label="Previous" onClick={onPrev}><Backward /></button>
      <button aria-label="Next" onClick={onNext}><Forward /></button>
    </div>
  );
}
```

**Option 3 — Use logical/directional icons** like `ChevronStart` / `ChevronEnd` from your icon set if available.

## How to detect

- Grep for `ChevronRight`, `ChevronLeft`, `ArrowRight`, `ArrowLeft`, `→`, `←` inside files that also contain Hebrew text, or files loaded into an RTL layout.
- Visually: load the RTL page, identify every arrow. Ask "does this point in the direction I'd expect to move?"

## Related rules

- B2 (physical margin/padding vs logical)
- B4 (text-align left vs start)
