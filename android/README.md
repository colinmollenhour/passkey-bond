# Passkey.bond — Android

Android build of Passkey.bond. A small native shell (WebView + credential provider service) around the same TypeScript crypto code the extension uses.

Package `bond.passkey.app`. The app is not yet published on Google Play. A self-signed APK ships with each [GitHub release](https://github.com/colinmollenhour/passkey-bond/releases); once the Play listing exists, its builds will carry Play's app-signing key, so devices won't be able to upgrade between the two.

## Build

```bash
./android/build-android.sh
```

The signed APK is written to:

```text
android/dist/passkey-bond-android-signed.apk
```

The build is Gradle-free. It uses the Android SDK tools on this machine directly: `aapt2`, `javac`, `d8`, `zipalign`, and `apksigner`.

Signing uses `android/signing/passkey-bond.jks` (gitignored), alias `passkey-bond`, with the password from `ANDROID_KEYSTORE_PASSWORD`. If the keystore is missing, `build-android.sh` creates it on the first build (password `android` when the variable is unset) — fine for hacking, but an APK signed with a throwaway key won't upgrade-install over release-signed builds.

Passkey.bond's release/upload key has not been created yet. Once it exists, keep it in the GitHub Actions secrets `ANDROID_KEYSTORE_BASE64` / `ANDROID_KEYSTORE_PASSWORD` with an offline backup; Google Play App Signing will hold the app-signing key. CI (`.github/workflows/android.yml`) builds and signs the APK on pushes to main that touch `android/`.

Supported Android versions:

- App vault: Android 10 / API 29 and newer.
- Android Credential Manager passkey provider: Android 14 / API 34 and newer.

## Install

```bash
./android/install-android.sh
```

## Features

- Vault screen for passkeys and 2FA codes, with bottom search bar and bottom tab navigation.
- TOTP/HOTP (RFC 6238/4226) with the same `totp_entries` JSON shape as the extension. Add by otpauth URI, manual entry, or camera QR scan (bundled jsQR).
- Android Credential Manager provider (API 34+): passkey create and get flows through the OS picker, with entries encoded in the androidx.credentials slice format.
- Native WebAuthn signing for provider flows. Uses the caller-supplied `clientDataHash` when present (browser flows) and the same Passkey.bond AAGUID as the extension.
- Native/WebView vault snapshot bridge so provider-created passkeys appear in the app vault and vice versa.
- Vault lock via the device lock mechanism only (BiometricPrompt: face, fingerprint, or screen-lock credential). No app-specific PIN. Auto-lock timer (default 5 minutes, configurable in Tools).
- Delete protection: long-press an item, confirm, and it moves to a recycle bin in Tools for 7 days before permanent removal.
- Pull-to-refresh on the vault triggers a sync.
- Nostr sync matching the extension protocol. Default relays are `wss://relay.passkey.bond` (ours, sync events only), `wss://relay.damus.io` and `wss://nos.lol` (`DEFAULT_RELAYS` in `src/sync/protocol.ts`).
- Encrypted backup export/import in the same format as the extension (`src/crypto/backup-crypto.ts`: AES-256-GCM, key from scrypt with its parameters in the file; older PBKDF2 backups still import); raw JSON backup retained.
- Passkey.bond branding: Jost and Bodoni Moda fonts (bundled, SIL OFL), dark theme, adaptive launcher icon that follows the system light/dark theme.
- About panel in Tools: open-source/no-warranty statement, privacy summary, and links to passkey.bond, its terms and privacy policy, and the support and security addresses.

## Verified On Device

Upstream Fenko Vault, before the fork, on a Samsung SM-A566B (Galaxy A56), Android 16 / API 36, 2026-06-11:

- Full passkey registration and authentication on webauthn.io through Chrome and the OS picker, served by Passkey.bond as the selected credential provider.
- TOTP added by camera QR scan generates codes matching `oathtool` for the same window.
- Biometric unlock, auto-lock timer, recycle bin restore, encrypted backup, and sync relay connection all exercised manually.
- `./android/provider-selftest.sh` (runs the provider Java code on-device via `app_process`) passes.

Earlier verification on Samsung SM-G988B (S20 Ultra, API 33) covered the in-app vault; that device cannot exercise the API 34+ provider surface.

## Provider Notes (hard-won)

Three things broke the Credential Manager integration before it worked. If entries stop appearing in the OS picker, check these first:

1. `res/xml/credential_provider.xml` capabilities must use a bare `name` attribute (no `android:` namespace): `<capability name="androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL" />`.
2. Entry slices must match the androidx.credentials encoding exactly (spec names `CreateEntry` / option type / `Action`, revision IDs, and the `androidx.credentials.provider.*` hint strings). The framework binds the service and silently drops entries it cannot parse.
3. For browser callers, the assertion must be signed over `authenticatorData || clientDataHash` using the hash from `androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH` — not a locally built clientDataJSON. Registration appears to work either way (attestation `none` has no signature), so test authentication, not just registration.
