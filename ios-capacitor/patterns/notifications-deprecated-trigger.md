# Pattern #10 — LocalNotifications using deprecated `trigger: { at }` API

**Severity:** P1 (notifications silently never fire — user thinks the feature is broken)

## Story

On March 30, 2026, MorningRitual users complained their morning affirmations "stopped working" after the v1.2 update. We had upgraded `@capacitor/local-notifications` from v4 to v5 but kept the old v4 API:

```js
LocalNotifications.schedule({
  notifications: [{ id: 1, title: 'Good morning', trigger: { at: date } }]
});
```

No error. No warning. The schedule call resolved successfully. The notification simply never fired because v5 renamed `trigger` to `schedule`.

HabitDone had the same bug, found by a support email two weeks after release.

## Bad code (v4 syntax in v5+ plugin)

```js
await LocalNotifications.schedule({
  notifications: [{
    id: 1,
    title: 'Remember to log',
    body: '30 seconds, that's it.',
    trigger: { at: tomorrow9am }     // IGNORED in v5+
  }]
});
```

## Good code (v5+ syntax)

```js
await LocalNotifications.schedule({
  notifications: [{
    id: 1,
    title: 'Remember to log',
    body: '30 seconds, that's it.',
    schedule: { at: tomorrow9am, allowWhileIdle: true }
  }]
});
```

For recurring reminders:

```js
schedule: { every: 'day', on: { hour: 9, minute: 0 } }
```

## Detection

```bash
grep -rnE "trigger\s*:\s*\{\s*at\s*:" src/
```

Any hit is a P1.

## Fix workflow

1. Find every `trigger:` in the notifications scheduling code.
2. Rename to `schedule:`.
3. Run `npx cap sync ios`.
4. Test on a real device — simulator notification scheduling is unreliable.
5. Call `LocalNotifications.getPending()` after scheduling to confirm it queued.
