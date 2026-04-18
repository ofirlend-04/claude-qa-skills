# Pattern 3 — CALL_LOG permissions without justification

**Severity:** P0
**Policy:** SMS and Call Log Permissions Policy
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/10208820
- https://www.reddit.com/r/androiddev/comments/qjbtgq/rejected_for_read_call_log_even_though_we_are/

## Story

Call log policy has been in force since January 2019 but 2025-2026 saw stricter enforcement — including removals of apps that had the permission declared "just in case" without code that uses it.

## Bad

```xml
<uses-permission android:name="android.permission.READ_CALL_LOG" />
<uses-permission android:name="android.permission.WRITE_CALL_LOG" />
```

…with no Play Console Permissions Declaration form filled out.

## Good

- If you don't genuinely use the call log: **delete the permissions** (they often get pulled in transitively by old SDKs — audit with `./gradlew :app:dependencies`).
- If you do: file the declaration at Play Console → Policy → App content → Sensitive app permissions → Call Log.

## Detection rule

Manifest contains any of `READ_CALL_LOG`, `WRITE_CALL_LOG`, `PROCESS_OUTGOING_CALLS` → flag P0.

## False positives

- Dialer / Caller ID apps — these are the only categories allowed. Scanner still flags; reviewer just suppresses via `.qaignore`.
