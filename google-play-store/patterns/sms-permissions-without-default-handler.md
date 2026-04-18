# Pattern 2 — SMS permissions without default-handler

**Severity:** P0
**Policy:** SMS and Call Log Permissions Policy
**Real evidence:**
- https://support.google.com/googleplay/android-developer/answer/10208820
- https://www.reddit.com/r/androiddev/comments/16gv4a2/our_app_got_rejected_because_we_need_sms/
- https://orufy.com/blog/webtonative/google-play-app-rejection-reasons

## Story

One of the top-3 Play rejection causes since the 2019 policy tightening. The scenario:

Dev ships a "transaction tracker" that reads OTPs and transaction SMS. Ships with `READ_SMS`. Reviewer rejects because only the user's **default SMS handler** or apps with a Permissions Declaration can read SMS.

## Bad

```xml
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.SEND_SMS" />
```

…and the app has no `SMS_DELIVER` intent-filter (so it cannot be the default SMS app).

## Good

Either (a) remove the permissions, (b) become the default SMS handler:

```xml
<activity android:name=".SmsComposeActivity">
  <intent-filter>
    <action android:name="android.intent.action.SEND" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:mimeType="text/plain" />
  </intent-filter>
</activity>

<service
    android:name=".MySmsService"
    android:exported="true"
    android:permission="android.permission.SEND_RESPOND_VIA_MESSAGE">
    <intent-filter>
        <action android:name="android.intent.action.RESPOND_VIA_MESSAGE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="sms" />
    </intent-filter>
</service>

<receiver
    android:name=".SmsReceiver"
    android:permission="android.permission.BROADCAST_SMS">
    <intent-filter>
        <action android:name="android.provider.Telephony.SMS_DELIVER" />
    </intent-filter>
</receiver>
```

Or (c) submit a Permissions Declaration in Play Console.

## Detection rule

If the manifest declares any of `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS`, `RECEIVE_WAP_PUSH` AND the manifest does NOT contain `android.provider.Telephony.SMS_DELIVER`, flag P0.

## False positives

- Apps with a pre-approved Permissions Declaration — the declaration lives in Play Console; scanner can't see it. Add `.qaignore` if needed.
