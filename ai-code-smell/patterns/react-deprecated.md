# Deprecated React Patterns in New Code

**Severity:** P1 (R3), P2 (R1, R2)
**Real evidence:**
- [React docs — React.FC deprecation discussion](https://react.dev/)
- Dan Abramov: "We no longer recommend React.FC".
- [ranger.net — common AI bugs](https://www.ranger.net/post/common-bugs-ai-generated-code-fixes)
- [LogRocket — next era of React](https://blog.logrocket.com/)

## Bug

AI models trained on 2020–2022 code keep generating patterns that are now discouraged or removed:

```tsx
// R1 — React.FC deprecated (implicit children, hard to override defaults)
const Comp: React.FC<Props> = ({ name }) => <div>{name}</div>;

// R2 — class component in new code
class Widget extends React.Component {
  componentDidMount() { /* ... */ }
}

// R3 — actually deprecated & removed-in-future
class X extends React.Component {
  componentWillMount() { /* ... */ }
  componentWillReceiveProps() { /* ... */ }
}
```

## Fix

```tsx
// R1
function Comp({ name }: Props) {
  return <div>{name}</div>;
}

// R2 — function + hooks
function Widget() {
  useEffect(() => { /* ... */ }, []);
  return <div />;
}

// R3 — use componentDidMount / getDerivedStateFromProps, or migrate to hooks.
```

## Detection rule

- `\bReact\.FC\s*<` → R1 (P2)
- `\bclass\s+\w+\s+extends\s+(?:React\.)?Component\b` → R2 (P2)
- `\b(componentWillMount|componentWillReceiveProps|componentWillUpdate)\b` → R3 (P1)

## False positives

- Legacy file the team hasn't migrated yet. Add to `.qaignore`.
- Class component required by a specific third-party API (e.g. error boundaries). Suppress with `// qa-ignore: R2`.
