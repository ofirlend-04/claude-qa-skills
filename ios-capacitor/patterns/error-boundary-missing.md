# Pattern #13 — No React ErrorBoundary — white-screen crash on reviewer's device

**Severity:** P1 (Apple rejection 2.1(a) — "App crashed on iPhone 17 Pro Max")

## Story

On April 9, 2026, WiFi Guardian was rejected with:
> Guideline 2.1 — App crashed on launch on iPhone 17 Pro Max (iOS 26.4) and iPad Air.

The crash was a `TypeError: Cannot read property 'length' of undefined` in a localization array. On our devices it didn't repro because the locale was different. Without an ErrorBoundary, React unmounted the tree and showed a white screen. Apple's automated crash report flagged it as a hard crash.

One `<ErrorBoundary>` wrapper would have turned the rejection into a graceful "Something went wrong — Retry" screen.

## Bad main.jsx

```jsx
import { createRoot } from 'react-dom/client';
import App from './App';

createRoot(document.getElementById('root')).render(<App />);
```

Any uncaught error in any descendant → white screen → Apple sees a crash.

## Good main.jsx

```jsx
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

class ErrorBoundary extends React.Component {
  state = { error: null };
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error, info) {
    // Optional: send to Sentry/Bugsnag here
    console.error('App crash:', error, info);
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 24, textAlign: 'center' }}>
          <h2>Something went wrong</h2>
          <p style={{ opacity: 0.7 }}>{String(this.state.error.message || this.state.error)}</p>
          <button onClick={() => window.location.reload()}>Retry</button>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>
);
```

## Detection

```bash
grep -rnE "ErrorBoundary|componentDidCatch|getDerivedStateFromError" src/ || echo "MISSING"
```

## Why a plain try/catch isn't enough

- React only catches errors thrown **during rendering**, not in event handlers or async callbacks.
- An ErrorBoundary catches render-phase errors that would otherwise unmount the whole tree.
- For event handlers, wrap with try/catch + a state flag.
- For async, use `.catch()` and surface errors to the user — never swallow.
