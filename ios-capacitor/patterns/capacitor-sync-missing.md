# Pattern #5 — Missing `npx cap sync ios` after JS changes

**Severity:** P1 (iOS runs stale code — you ship bugs you "already fixed")

## Story

On April 7, 2026, we "fixed" the CalmQuest subscription button and resubmitted. Apple rejected it with the same bug message. Embarrassing investigation: we had run `npm run build` but not `npx cap sync ios`. Xcode archived the old `ios/App/App/public/` — the fix never reached the device.

Capacitor is a static-bundle runtime. The iOS app ships whatever is in `ios/App/App/public/` at archive time. If that directory is older than `dist/`, your fix doesn't exist on device.

## Bad workflow

```bash
# fix bug in src/App.jsx
npm run build
# archive in Xcode — ships old public/ 
```

## Good workflow

```bash
# fix bug in src/App.jsx
npm run build && npx cap sync ios
# now archive
```

Or better, make it one command in `package.json`:

```json
"scripts": {
  "ios": "vite build && cap sync ios",
  "ios:open": "npm run ios && cap open ios"
}
```

## Detection

Compare modification times:

```bash
# If src is newer than public, sync is stale
newest_src=$(find src -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.css' \) -print0 \
  | xargs -0 stat -f '%m' | sort -n | tail -1)
newest_pub=$(find ios/App/App/public -type f -print0 \
  | xargs -0 stat -f '%m' | sort -n | tail -1)
if [ "$newest_src" -gt "$newest_pub" ]; then
  echo "STALE — run: npx cap sync ios"
fi
```

Or simpler — if `ios/App/App/public/` doesn't exist, sync was **never** run.

## Related traps

- `cap sync` also re-runs `pod install`. If you added a new Capacitor plugin, sync is **mandatory**.
- The `dist/` directory from `vite build` is what gets copied. If the build failed silently (missing env var), the sync copies stale `dist/`.
- Xcode's "Clean Build Folder" does **not** clean `public/`. Re-sync is the only way.
