# Play Store screenshots

Captures the Google Play phone screenshots on a headless Android emulator, so they can be retaken with one command after a UI change.

```bash
./android/screenshots/capture.sh             # build the APK, then capture
./android/screenshots/capture.sh --no-build  # reuse android/dist/passkey-bond-android-signed.apk
```

A run takes about 2.5 minutes once the image exists. Output goes to `android/play/screenshots/` as 1080×2400 PNGs:

| File | Screen |
|---|---|
| `01-vault.png` | Vault with 2FA codes and passkeys |
| `02-add.png` | Add tab, a 2FA code typed into "Add 2FA manually" |
| `03-sync.png` | Sync tab after creating a chain |
| `04-tools.png` | Tools: auto-lock and backup |
| `05-locked.png` | Vault locked |
| `06-passkey-signin.png` | Android's passkey sign-in sheet in Chrome on webauthn.io, offering the Passkey.bond passkey |
| `07-passkey-create.png` | Android's "Create passkey" sheet in Chrome on webauthn.io, saving to Passkey.bond |

The set is replaced only when a run succeeds. A failed run leaves what it captured, plus `zz-failure.png`, in `android/screenshots/out/` (git-ignored).

06 and 07 need webauthn.io to be reachable. If they fail, the run still succeeds without them, logs `skipped the Chrome passkey shots`, and keeps a screenshot of the moment in `android/screenshots/out/debug/`.

## Requirements

- Docker and `/dev/kvm` (the emulator runs with KVM inside the container).
- About 6 GB of disk for the image. The first run builds it, downloading the emulator and system image, which takes a few minutes.

## How it works

- `Dockerfile` builds `passkey-bond-screenshots:36`: the same SDK as the APK build (build-tools 36.0.0, platforms;android-36) plus the emulator, the `system-images;android-36;google_apis;x86_64` image and Node. `capture.sh` also builds the APK with it, signed with `android/signing/passkey-bond.jks`.
- `run.sh` (inside the container) creates a `pixel_7` AVD (1080×2400, 420 dpi), boots it fresh (`-wipe-data -no-snapshot`), switches to dark mode and gesture navigation, installs the APK with its permissions granted, makes Passkey.bond the Credential Manager provider and launches it.
- `driver.mjs` drives the app's WebView over the Chrome DevTools Protocol and saves each shot with `adb exec-out screencap -p`, with the status bar in demo mode (9:41, full battery and wifi, no notifications). It seeds data the way a user would: a plain JSON backup pasted into Tools > Import (three 2FA codes and four passkeys with P-256 keys generated per run), a fourth code typed into Add, and a sync chain created on the Sync tab. It then opens webauthn.io in Chrome for the passkey sheets, and finally sets a device PIN (`1234`), since the vault lock needs a screen lock.

The release APK doesn't enable WebView debugging. The `google_apis` system image is a userdebug build, where WebView debugging is on for every app, so the driver works without changing the app. Don't switch to a `google_apis_playstore` image: those are user builds, so the driver can't connect and `adb root` fails.

Demo data is fake: well-known public services and `example.com` accounts. Creating the sync chain connects to the app's default Nostr relays and publishes one encrypted bundle for a throwaway chain. The passkey sheets are only shown and then dismissed, so nothing is registered on webauthn.io.

To change the shots, edit `driver.mjs`: the demo data is in `demoBackup()` and `MANUAL_TOTP`, and `main()` lists the shots in order.

## Known quirks

- The unlock prompt can't be captured: with no fingerprint enrolled it is the system PIN screen, which is secure and screenshots as black.
- On this image, Android's one-account sign-in sheet is headed "Google Password Manager" even though the passkey comes from Passkey.bond. The driver opens "Sign-in options" instead, which labels the entry "Passkey • Passkey.bond".
- SystemUI sometimes sizes the status bar before the emulated display cutout applies, which clips the clock. `run.sh` checks for this and restarts SystemUI.
