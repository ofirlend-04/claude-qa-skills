# Google Play Store — Manual Pre-Submission Checklist

Run `python3 auto_audit.py .` first. These are the things the scanner **can't** see (because they live in Play Console or only matter at runtime).

---

## 1. Play Console: App Content

- [ ] **Privacy Policy** URL published + returns 200 + contains the word "privacy" + lists every SDK.
- [ ] **App Access** — if parts of the app are behind login, provide a reviewer account (username/password/any OTP bypass). Missing this → rejected.
- [ ] **Ads** — declared Yes/No correctly. If Yes, AdMob / AppLovin / ironSource SDKs listed.
- [ ] **Content Rating** — IARC questionnaire answered; if the app has user-generated content say so.
- [ ] **Target Audience** — selected correctly. "Mixed ages" if age groups overlap.
- [ ] **Data Safety** — every bullet matches the SDKs actually bundled (Pattern 1).
- [ ] **News Apps** declaration (if applicable).
- [ ] **COVID-19** declaration (if health / contact-tracing).
- [ ] **Government Apps** declaration (if govt-affiliated).
- [ ] **Financial Features** declaration (if the app takes payments, lends money, acts as a crypto wallet/exchange, trades securities).
- [ ] **Health Apps** declaration (if medical / HIPAA / health-data).

## 2. Play Console: Sensitive Permissions Declarations

- [ ] Call Log declaration (if any CALL_LOG perm declared).
- [ ] SMS declaration (if SMS perm declared).
- [ ] All Files Access declaration (if MANAGE_EXTERNAL_STORAGE).
- [ ] Background Location declaration + walkthrough video.
- [ ] Accessibility API declaration + walkthrough video (highly scrutinised).
- [ ] Photo and Video Permissions declaration (for READ_MEDIA_IMAGES, READ_MEDIA_VIDEO).
- [ ] Package (App) Visibility declaration (for QUERY_ALL_PACKAGES).
- [ ] VPN Service declaration (if BIND_VPN_SERVICE).

## 3. Store Listing

- [ ] **Title** ≤ 30 chars, no keyword stuffing, no emoji, no ALL-CAPS.
- [ ] **Short description** ≤ 80 chars.
- [ ] **Full description** — no "best app ever" claims; no competitor trademarks; no "COVID" unless you're an official health org.
- [ ] **Feature graphic** 1024×500 — required.
- [ ] **Icon** 512×512 PNG, 32-bit, no alpha artifacts; doesn't look like a Google Play or system icon.
- [ ] **Screenshots** — minimum 2 phone, 16:9 or 9:16, 320-3840 pixels per side, show **app in use** (not splash, not login, not onboarding).
- [ ] Short description language matches app locale.
- [ ] No mentions of "beta" / "test" unless enrolled in open beta.
- [ ] No claims of being "official" / affiliated with a brand you don't own.
- [ ] **Promo video** (optional) 30-120s, YouTube-hosted.

## 4. Technical pre-checks

- [ ] `./gradlew bundleRelease` succeeds; AAB < 200 MB base.
- [ ] ProGuard / R8 enabled on release builds. Test the obfuscated build on a device.
- [ ] `targetSdkVersion` matches current requirement (Pattern 6).
- [ ] 64-bit support present (`abiFilters` includes `arm64-v8a` and `x86_64`).
- [ ] Android App Bundle (AAB), not APK, for new submissions.
- [ ] `android:allowBackup="false"` on the application tag (unless you've reviewed Auto Backup consequences).
- [ ] `android:usesCleartextTraffic="false"` (or a `network_security_config.xml` with a tight allowlist).
- [ ] `debuggable="false"` on release. Play Console rejects debuggable builds.
- [ ] Deep-link verification: all `android:autoVerify="true"` domains have `/.well-known/assetlinks.json` reachable.

## 5. Runtime smoke tests (physical or Firebase Test Lab)

- [ ] Install on Android 14 device (targetSdk 34+). Foreground services don't crash.
- [ ] Install on Android 15 device. No `MissingForegroundServiceTypeException` in logcat.
- [ ] Permission dialogs show your `usesPermissionSdk23` / runtime permission rationale dialog.
- [ ] Purchase flow opens the Play Billing sheet, completes in sandbox, restores on reinstall.
- [ ] Account deletion (required by Play): verify the in-app "Delete account" path works AND appears in the Play Console Data Deletion URL.
- [ ] `adb shell dumpsys package <pkg>` shows only the expected permissions granted.

## 6. Pre-Launch Report (Play Console)

- [ ] Upload the AAB to a closed-test track. Play Console Pre-Launch Report runs automatically.
- [ ] Review the "Security" tab — zero P0 findings.
- [ ] Review the "Stability" tab — zero ANRs.
- [ ] Review the "Accessibility" tab — no TalkBack failures on primary flows.
- [ ] Review the "Performance" tab — startup < 2s cold on the bottom-tier tested device.

## 7. Account & publishing

- [ ] Developer account verified (DUNS / government ID / phone).
- [ ] Payments profile set up if the app is paid or has IAP.
- [ ] Two-factor auth on the Google account.
- [ ] App signing enabled with Play App Signing (upload key ≠ app-signing key).
- [ ] Production release notes written, < 500 chars per locale.

## 8. Regional / regulatory

- [ ] **GDPR** — consent banner before any analytics / ads SDK call (Pattern 1 surfaces the SDK presence; consent flow is on you).
- [ ] **EU DSA** trader info — Play Console → App Content → Trader declaration.
- [ ] **India DPDP** — if shipping to India, data-localisation review.
- [ ] **UK AADC** — if app may be used by children.
- [ ] **US state privacy** (CCPA/CPRA, Virginia) — opt-out signal honoured.

## 9. After publish

- [ ] Monitor pre-launch-report crash cluster for 72 h.
- [ ] Watch Play Console Policy Status daily for the first week.
- [ ] If suspended: appeal via Play Console → Publishing → Appeal. Include evidence. Expect 3-7 days.

---

**If every box is checked and `auto_audit.py` returns no P0 or P1**, you're ready to submit.
