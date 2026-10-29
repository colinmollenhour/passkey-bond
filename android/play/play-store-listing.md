# Google Play — manual submission pack (Passkey.bond)

**Status:** not yet published. The first upload creates the listing.

Everything needed to create the Play Console listing for `bond.passkey.app`
by hand. Copy fields straight into the console; asset paths are relative to the
repo root.

---

## 1. App bundle (.aab)

Play needs a **signed** `.aab`. The bundle is built from `android/build-aab.sh`;
the signing step needs the upload-key password, so run it yourself:

```bash
env ANDROID_KEYSTORE_PASSWORD='<your keystore password>' \
    VERSION_CODE=1 \
    ./android/build-aab.sh
# -> android/dist/passkey-bond-<versionName>.aab
```

- `versionName` is read from `package.json`.
- `versionCode` defaults to **1** for the first upload and must strictly
  increase on every upload after that.
- Signing key: `android/signing/passkey-bond.jks`, alias `passkey-bond`.
  Passkey.bond's release/upload key has not been created yet; `build-android.sh`
  / `build-aab.sh` create the keystore on the first build if it is missing.
  Create the real key deliberately and back it up before the first upload. On
  that upload, enroll it as your **upload key** under Play App Signing (Google
  then holds the app-signing key). The GitHub-Releases APK is self-signed with
  the same file, so its signature differs from Play's — a device can hold one
  or the other, not upgrade between them.

---

## 2. Store listing — text

### App name (max 30 chars)
```
Passkey.bond: Passkeys & 2FA
```
(28 chars. The full "Passkey.bond | Passkey and MFA Manager" is 38 chars and
won't fit Play's 30-char title limit.)

### Short description (max 80 chars)
```
Passkeys and 2FA codes, on your device. Encrypted sync, no cloud account.
```

### Full description (max 4000 chars)
```
Passkey.bond keeps your passkeys and two-factor codes in one place, on your device. Sign in without passwords, get your 2FA codes where your passkeys already live, and sync across your devices with no cloud account.

Sync is end-to-end encrypted, so your keys move between your devices without anyone else seeing them — not even us. Nothing leaves your device unless you choose to back it up or sync it.

Highlights:

- A system passkey provider: create and use passkeys in the apps and browsers that support them
- A built-in authenticator: time-based 2FA codes with a live countdown and one-tap copy
- Add a code by pasting its link or scanning a QR — read on your device
- End-to-end encrypted sync across your devices, with no account to create
- Unlock with your fingerprint, face, or screen lock; optional auto-lock
- Encrypted backups you export and restore yourself
- Everything lives on your device — nothing is uploaded unless you back up or sync

Passkey.bond is built for people who want their passkeys and 2FA codes to stay private and portable. Because everything lives on your device, keep an offline backup: there is no recovery if you lose every device and every backup.
```

---

## 3. Categorization & contact

| Field | Value |
|---|---|
| App category | Tools |
| Tags | passkey, authenticator, 2FA, password manager, security |
| Email | support@passkey.bond |
| Website | https://passkey.bond |
| Privacy policy | https://passkey.bond/privacy |

### Pricing

Paid app, one-time purchase. Price not yet set. Keep "free" out of the store
copy.

---

## 4. Graphics

The Fenko-era phone screenshots showed the old branding and have been removed.
Capture new ones before the first upload.

| Asset | Spec | File |
|---|---|---|
| App icon | 512×512 PNG | `android/play/icon-512.png` |
| Feature graphic | 1024×500 PNG | `android/play/feature-graphic.png` |
| Phone screenshots | 1080×2400 PNG | to be captured into `android/play/screenshots/` |

Play requires 2–8 phone screenshots. Cover the vault, adding a 2FA code, sync,
and the Tools/security screens.

---

## 5. Data safety form

- **Does your app collect or share any user data?** No.
- Data stays on the device. Optional sync sends only end-to-end encrypted bundles
  through public Nostr relays the user can change; Passkey.bond runs no server
  and no relay.
- No analytics, no advertising, no tracking, no third-party data sharing.
- **Data encrypted in transit:** Yes (sync is E2E encrypted).
- **Users can request data deletion:** Not applicable — there is no account and no
  server-side data; the user controls all data on-device.

## 6. Content rating questionnaire

- Category: Utility / Productivity / Communication → **Tools**.
- No violence, sexual content, profanity, gambling, or user-generated content.
- No data shared with third parties.
- Expected rating: **Everyone / PEGI 3**.

## 7. App access

- All functionality is available without an account or login. The vault unlocks
  with the device biometric/screen lock. Note this under "All functionality is
  available without special access" (no test credentials needed).

---

## 8. "What's new" (release notes for this version)

```
First Play Store release of Passkey.bond for Android: a passkey provider and 2FA
authenticator that keeps everything on your device, with optional end-to-end
encrypted sync and encrypted backups.
```
