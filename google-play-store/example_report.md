# 🔴 Google Play Store Audit — whatsapp-messenger-lite

**Target:** `/path/to/whatsapp-messenger-lite`
**Total findings:** 13 (10 P0, 2 P1, 1 P2)

## 🔴 Blocking (P0) — Play Console will reject or suspend

### P0.1 [sms-permissions-without-default-handler] SMS permission(s) ['READ_SMS', 'SEND_SMS'] declared but app is not the default SMS handler (no SMS_DELIVER intent-filter) — Google Play will reject
- **Location:** `android/app/src/main/AndroidManifest.xml:7`
- **Fix:** Either (a) remove SMS permissions, (b) become the default SMS handler by adding SMS_DELIVER / WAP_PUSH_DELIVER / SERVICE intent-filters, or (c) submit a Permissions Declaration form in Play Console with a compelling justification
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/10208820

### P0.2 [call-log-permissions-without-justification] Call Log permission(s) ['READ_CALL_LOG', 'WRITE_CALL_LOG'] declared — requires a submitted Permissions Declaration form in Play Console, not just manifest entry
- **Location:** `android/app/src/main/AndroidManifest.xml:10`
- **Fix:** Play Console → App Content → Sensitive app permissions → fill Call Log declaration. Rejection is automatic without it.
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/10208820

### P0.3 [background-location-without-prominent-disclosure] ACCESS_BACKGROUND_LOCATION declared but no prominent-disclosure string / rationale found
- **Location:** `android/app/src/main/AndroidManifest.xml:14`
- **Fix:** Add an in-app prominent disclosure BEFORE requesting the permission, show why background location is necessary, and complete the Play Console Location Permissions form.
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/9799150

### P0.4 [broad-storage-permission] Broad storage permission ['MANAGE_EXTERNAL_STORAGE']
- **Location:** `android/app/src/main/AndroidManifest.xml:17`
- **Fix:** Use Scoped Storage (MediaStore / SAF / ACTION_OPEN_DOCUMENT) instead. If you truly need MANAGE_EXTERNAL_STORAGE, file the All Files Access declaration.
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/10467955

### P0.5 [accessibility-service-misuse] BIND_ACCESSIBILITY_SERVICE declared and the app's README / package.json does not describe a disability-assistive use case — dominant Play rejection category in 2025-2026
- **Location:** `android/app/src/main/AndroidManifest.xml:29`
- **Fix:** Remove the AccessibilityService entirely unless the app is genuinely assistive-tech. If so, submit the Accessibility API Declaration in Play Console with a video showing the disability-assistive use case.
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/10964491

### P0.6 [target-sdk-too-old] targetSdkVersion 30 — Play Store blocks uploads below 34 (Aug 2024 rule); < 35 blocks updates since Aug 2025
- **Location:** `android/app/build.gradle:11`
- **Fix:** Bump to targetSdkVersion 36 and re-test.
- **Evidence:** https://developer.android.com/google/play/requirements/target-sdk

### P0.7 [subscription-ui-without-play-billing] App contains paywall / subscription UI but no Google Play Billing library (RevenueCat-capacitor, cordova-plugin-purchase, or billingclient) is declared
- **Location:** `src/App.jsx:3`
- **Fix:** Add @revenuecat/purchases-capacitor OR com.android.billingclient:billing. Charging for digital content outside Play Billing is an instant ban (Payments Policy).
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/9858738

### P0.8 [hardcoded-secret] Google API key literal found in AndroidManifest.xml — rotate immediately and move to gradle.properties / secure storage
- **Location:** `android/app/src/main/AndroidManifest.xml:47`
- **Fix:** 1) Rotate the key in the provider dashboard. 2) Move it to `~/.gradle/gradle.properties` or a CI secret. 3) Reference via BuildConfig / manifestPlaceholders, never literal strings.
- **Evidence:** https://developer.android.com/studio/build/shrink-code

### P0.9 [hardcoded-secret] OpenAI key literal found in build.gradle
- **Location:** `android/app/build.gradle:19`
- **Fix:** Rotate + move to gradle.properties / CI secret.
- **Evidence:** https://developer.android.com/studio/build/shrink-code

### P0.10 [data-safety-declaration-vs-sdk-diff] Data-collecting SDKs detected (analytics (amplitude/mixpanel/segment), firebase) but no data-safety.json / PLAY_DATA_SAFETY.md found in repo — the April 15 2026 Data Safety update rejects apps whose Play Console declaration doesn't match real SDK data flows
- **Location:** `package.json`
- **Fix:** 1) Enumerate every SDK and what it collects. 2) Update Play Console → App Content → Data Safety to match. 3) Commit a PLAY_DATA_SAFETY.md alongside the code so future audits catch drift.
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/10787469

## 🟡 Likely (P1) — probable rejection or policy strike

### P1.1 [privacy-policy-missing] No privacy-policy URL found in package.json / capacitor.config / README / .env
- **Location:** `package.json`
- **Fix:** Publish a privacy policy and add the URL to Play Console → App Content → Privacy Policy.
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/9859455

### P1.2 [deceptive-package-name] Package name / applicationId contains the substring 'whatsapp' which matches a well-known brand — Play Store removes impersonation apps without warning
- **Location:** `package.json`
- **Fix:** Rename to avoid the 'whatsapp' substring.
- **Evidence:** https://support.google.com/googleplay/android-developer/answer/9888077

## 🟢 Possible (P2) — review manually

### P2.1 [foreground-service-type-missing] <service android:name=".BackgroundSyncService"> has no android:foregroundServiceType — required on targetSdk 34+; will crash once the app upgrades to targetSdk 34 (required by Play)
- **Location:** `android/app/src/main/AndroidManifest.xml:41`
- **Fix:** Add android:foregroundServiceType="dataSync" (or matching value).
- **Evidence:** https://developer.android.com/about/versions/14/changes/fgs-types-required

---

**Next steps:** fix every P0 before resubmitting, then run `auto_audit.py` again and work through `checklist.md`.
