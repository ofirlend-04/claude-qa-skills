# Patterns #19 & #20 — CURRENT_PROJECT_VERSION / MARKETING_VERSION not bumped

**Severity:** P1 (ASC upload rejected — "duplicate build", "same version as previous submission")

## Story

### Duplicate build — DoFast, April 2026

After fixing a rejection we ran `fastlane` and it failed at upload:
> ERROR ITMS-90061: Redundant Binary Upload. The bundle version cannot be the same as the previously uploaded version.

`CURRENT_PROJECT_VERSION = 3` was already used. Incrementing to 4 and re-archiving fixed it.

### Same marketing version — WiFi Guardian, April 2026

Resubmitted after a rejection with `MARKETING_VERSION = 1.0` still set (same as the rejected version). ASC blocked the upload:
> ERROR ITMS-90062: The value for key CFBundleShortVersionString must be a higher version than the previously approved version.

## Terminology

- `CFBundleShortVersionString` ← `MARKETING_VERSION` — user-facing version (e.g. `1.0`, `1.1`).
- `CFBundleVersion` ← `CURRENT_PROJECT_VERSION` — internal build number (integer).

Rules:
- Every **upload** must have a new `CURRENT_PROJECT_VERSION` (increment by 1).
- Every **resubmission after rejection** must also bump `MARKETING_VERSION` (at least `1.0 → 1.0.1`).
- For a new TestFlight build under the same version, only `CURRENT_PROJECT_VERSION` needs to change.

## Bad pbxproj (resubmitting after rejection)

```
CURRENT_PROJECT_VERSION = 3;
MARKETING_VERSION = 1.0;     # same as rejected version
```

## Good pbxproj

```
CURRENT_PROJECT_VERSION = 4;
MARKETING_VERSION = 1.0.1;
```

## Detection

```bash
grep -E "CURRENT_PROJECT_VERSION|MARKETING_VERSION" ios/App/App.xcodeproj/project.pbxproj | sort -u
```

Flag if:
- `CURRENT_PROJECT_VERSION = 1` on what is clearly not a first submission (commit history, rejection notes).
- A `REJECTION.md` / `apple_rejection_fixes.md` note exists and `MARKETING_VERSION` is still `1.0`.

## Automation

Use `fastlane` `increment_build_number` + `increment_version_number` in a pre-archive lane:

```ruby
lane :bump_build do
  increment_build_number(xcodeproj: "ios/App/App.xcodeproj")
end

lane :bump_patch do
  increment_version_number(xcodeproj: "ios/App/App.xcodeproj", bump_type: "patch")
end
```

Or a one-liner `agvtool`:

```bash
cd ios/App && agvtool next-version -all && agvtool new-marketing-version 1.0.1
```

## Why this keeps biting us

- Xcode's auto-increment is **off** by default.
- CI pipelines that archive from a clean clone always get the same version.
- Manual bumps get forgotten under time pressure after a rejection.
