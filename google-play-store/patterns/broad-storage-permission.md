# Pattern 11 — Broad storage permission (MANAGE_EXTERNAL_STORAGE / WRITE_EXTERNAL_STORAGE)

**Severity:** P0 (MANAGE_EXTERNAL_STORAGE) / P1 (WRITE_EXTERNAL_STORAGE)
**Policy:** All Files Access policy
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/10467955
- https://developer.android.com/training/data-storage/shared/media (Scoped Storage)
- https://www.reddit.com/r/androiddev/comments/pchi28/manage_external_storage_rejection/

## Story

Since Android 11 / API 30, apps are expected to use Scoped Storage (MediaStore / SAF). `MANAGE_EXTERNAL_STORAGE` ("All Files Access") is restricted to file managers, backup apps, anti-virus, document management. Everyone else gets rejected without a filed All-Files-Access declaration.

`WRITE_EXTERNAL_STORAGE` is silently ignored on API 30+ so it's harmless but still a red flag to reviewers and an indicator the app hasn't been audited for Scoped Storage.

## Bad

```xml
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

## Good

Use MediaStore:

```kotlin
val imageUri = context.contentResolver.insert(
    MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
    ContentValues().apply {
        put(MediaStore.Images.Media.DISPLAY_NAME, "photo.jpg")
        put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
    }
)
```

Or Storage Access Framework (`ACTION_OPEN_DOCUMENT`). Remove both legacy permissions.

If you genuinely need MANAGE_EXTERNAL_STORAGE (file manager / anti-virus / backup), file the declaration in Play Console → App content → All Files Access.

## Detection rule

Manifest declares `MANAGE_EXTERNAL_STORAGE` → P0. `WRITE_EXTERNAL_STORAGE` alone → P1.

## False positives

- Apps declaring `WRITE_EXTERNAL_STORAGE` with `android:maxSdkVersion="28"` (back-compat for old devices). Often safe. Suppress via `.qaignore`.
