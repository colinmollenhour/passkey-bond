# Passkey.bond for iOS

iOS port of Passkey.bond, mirroring the Android architecture: a **WKWebView host
app** running the shared web engine (the same `app.ts` the browser extensions and
Android app use — vault UI, TOTP, and cross-device **sync**) plus a native
**AutoFill credential provider extension** (iOS 17+) that serves passkeys
system-wide. Same vault model and WebAuthn wire format across web, Android, iOS.
Not yet published on the App Store; it will be a paid one-time purchase.

> **Status: runs in the simulator; sync transport verified; provider not yet
> device-tested.** Upstream Fenko Vault built it clean on Xcode 26.4 / iOS 26 SDK,
> with the web app loading and the WKWebView connecting to a Nostr relay, so iOS
> runs the identical, proven sync engine. The default relays are
> `wss://relay.passkey.bond`, `wss://relay.damus.io`, and `wss://nos.lol`. The passkey crypto is checked by a
> cross-platform test (named-curve PKCS8 import + sign/verify round-trip). What's
> left: signing config + running the credential provider on a real device (needs
> paid Apple membership). See [Known gaps](#known-gaps).

## Architecture

```
ios/
├── project.yml                  XcodeGen spec — the .xcodeproj is generated, not committed
├── build-web.sh                 esbuild android/web/src/app.ts -> ios/web (the shared engine)
├── web/                         generated bundle (gitignored): app.js, index.html, assets
├── App/
│   ├── PasskeyBondApp.swift      app entry
│   └── WebVaultView.swift       WKWebView host + window.AndroidBridge shim
├── Shared/                      compiled into BOTH targets
│   ├── WebAuthn.swift           COSE key, authData, attestation, ES256, PKCS8 <-> raw P-256
│   ├── VaultStore.swift         App Group store, snapshot in/out, identity registration
│   ├── PasskeyRecord.swift      vault model (matches the browser/Android JSON shape)
│   ├── TOTP.swift               RFC 6238 codes (for the native provider side)
│   └── Base64.swift
└── CredentialProvider/          ASCredentialProviderExtension (iOS 17+ passkey provider)
```

- **UI + sync run in the WebView** — the entire sync stack (Nostr over WebSocket,
  BIP39 key derivation, AES-GCM, secp256k1 Schnorr) is the shared JS, so iOS is
  byte-compatible with every other platform. No native sync reimplementation.
- **JS ↔ native bridge:** `WebVaultView` injects a `window.AndroidBridge` shim
  (the contract `app.ts` expects) over `WKScriptMessageHandler`. It mirrors the
  vault into the App Group so the credential provider can read it; sync data lives
  in the WebView's persistent localStorage.
- **App ↔ extension sharing:** App Group `group.bond.passkey.app`.
- **Passkey crypto (native side):** CryptoKit `P256` (ES256), canonical **PKCS8
  base64** keys via a small PKCS8 ↔ raw-scalar shim in `WebAuthn.swift`. AAGUID
  matches the Android provider.

## Apple-side prerequisites (one-time)

1. **Apple Developer Program** membership ($99/yr).
2. App IDs in the Developer portal:
   - `bond.passkey.app` — capabilities: App Groups, AutoFill Credential Provider.
   - `bond.passkey.app.CredentialProvider` — capability: App Groups.
3. **App Group** `group.bond.passkey.app` enabled on both App IDs.
4. App record in **App Store Connect** (for TestFlight).
5. **App Store Connect API key** (Users and Access → Integrations → App Store
   Connect API). Note the Key ID, Issuer ID, and download the `.p8` once.

## Build locally (on a Mac)

```bash
brew install xcodegen
npm ci                              # from repo root, for esbuild
bash ios/build-web.sh               # bundles the shared web engine into ios/web
cd ios
DEVELOPMENT_TEAM=YOURTEAMID xcodegen generate
open PasskeyBond.xcodeproj
# select your team on both targets if needed
```

Run in the **Simulator** to exercise the app UI and **sync** (no signing needed) —
open the Sync tab, generate or enter a seed phrase, and it joins the chain over the
relays. To test the passkey provider you need a real device (iOS 17+) and a paid
membership: enable it under **Settings → General → AutoFill & Passwords →
Passkey.bond**, then test a passkey sign-in in Safari.

## Ship to TestFlight (CI)

Pushing a tag `ios-v0.1.0` runs `.github/workflows/ios-testflight.yml` on a macOS
runner: XcodeGen → archive → export → upload. Set these repo secrets first:

| Secret | What |
| --- | --- |
| `APPLE_TEAM_ID` | 10-char Developer Team ID |
| `ASC_KEY_ID` | App Store Connect API key ID |
| `ASC_ISSUER_ID` | API key issuer ID |
| `ASC_KEY_P8_BASE64` | `base64 -i AuthKey_XXXX.p8` |

Then: `git tag ios-v0.1.0 && git push origin ios-v0.1.0`. After upload, add
testers in App Store Connect → TestFlight.

## Known gaps

Verified upstream, before the fork: full build of both targets (Xcode 26.4); the
web app loads in the WKWebView; the WebView connects to a sync relay; the
`ASPasskey*` provider API signatures; and the PKCS8 import/sign path
(cross-platform test). Not yet re-verified under the Passkey.bond bundle IDs.
Still to do:

- **Full 4-way sync round-trip** — connectivity + identical engine are proven, but
  run iOS alongside Chrome/Firefox/Android on one seed phrase to confirm end-to-end
  merge. (iOS-only round-trip can be checked with two simulators.)
- **On-device provider test** — enable as AutoFill provider on a real iOS 17+ device
  and complete a passkey register + sign-in. Needs paid Apple membership (App Groups
  + AutoFill entitlements don't sign on a free account); the simulator can't exercise
  system AutoFill.
- **Bridge cosmetics** — the shim is named `AndroidBridge` and sync device labels
  read "Mobile (Android)". Functional, but rename to a neutral bridge + iOS label.
- **`prepareCredentialList` UI** — auto-selects the first matching passkey; a real
  multi-candidate picker is nicer.
- **App icon / launch screen** — placeholder; add real assets with the
  Passkey.bond mark.
