# Passkey.bond for iOS

Native SwiftUI vault for iOS 17 and later. Development preview: it builds and
passes its tests on CI, but it has not been signed or tested on a real iPhone,
and it is not on the App Store yet. It will be a paid one-time purchase
(US$2.95).

The app stores passkeys and authenticator entries in an encrypted vault unlocked
with Face ID, Touch ID, or the device passcode. There is no app PIN, so the
browser extension's passkey unlock does not apply here. It provides encrypted backups,
TOTP and HOTP codes, QR setup, and end-to-end encrypted sync with Passkey.bond on
your other devices (the browser extensions and the Android app). The AutoFill
extension creates and uses passkeys in Safari and supported apps.

The native app began as Fenko Vault's native iOS app
([FenkoHQ/passkey-vault#33](https://github.com/FenkoHQ/passkey-vault/pull/33)),
which is © Fenko and MIT licensed.

## Layout

```
ios/
├── project.yml            XcodeGen spec (the .xcodeproj is generated, not committed)
├── project-devsync.yml    single-target variant for a free Apple account
├── App/                   SwiftUI app: vault, sync, settings, OTP setup, About
├── CredentialProvider/    AutoFill passkey provider extension
├── Shared/                compiled into both targets: vault store and archive,
│                          WebAuthn, OTP, backups, brand colours and fonts
├── Sync/                  VaultSync Swift package: sync protocol v5 over Nostr
├── Migration/web/         local page that reads the previous iOS app's data once
├── Tests/                 swiftc test programs, XCTest UI tests and unit tests
└── store/                 App Store copy and screenshots
```

## Build on a Mac

Install Xcode with the iOS SDK and XcodeGen, then generate the project:

```bash
brew install xcodegen
cd ios
xcodegen generate
open PasskeyBond.xcodeproj
```

Select an iPhone simulator to try the app. For a signed device build, select your
Apple Developer team for the app and credential provider targets
(`DEVELOPMENT_TEAM=XXXXXXXXXX xcodegen generate` sets it for both).

## Apple setup (one time)

1. Apple Developer Program membership.
2. App IDs: `bond.passkey.app` (App Groups, AutoFill Credential Provider,
   Keychain Sharing) and `bond.passkey.app.CredentialProvider` (App Groups,
   AutoFill Credential Provider, Keychain Sharing).
3. App Group `group.bond.passkey.app` on both App IDs.
4. An app record in App Store Connect, priced at US$2.95.
5. An App Store Connect API key for the TestFlight workflow.

## TestFlight

`.github/workflows/ios-testflight.yml` archives, signs and uploads a build when
an `ios-v*` tag is pushed or the workflow is run by hand. It runs in the
`release` environment, so a reviewer has to approve it. It needs these secrets:

| Secret | What |
| --- | --- |
| `APPLE_TEAM_ID` | 10-character Developer Team ID |
| `ASC_KEY_ID` | App Store Connect API key ID |
| `ASC_ISSUER_ID` | API key issuer ID |
| `ASC_KEY_P8_BASE64` | `base64 -i AuthKey_XXXX.p8` |

## Test with a free Apple account

A separate target supports standalone vault testing on an iPhone:

```bash
cd ios
xcodegen generate --spec project-devsync.yml
open PasskeyBondSync.xcodeproj
```

Select your Personal Team and connected iPhone in Xcode, then run the app.
This target has its own vault and does not provide system passkey AutoFill.

## Tests

`.github/workflows/ios-sync.yml` runs on every pull request, on a macOS runner:

- `ios/test-sync.sh`: swiftc programs for vault storage, merging, credentials
  (checked against Node's WebCrypto), OTP, recovery, sessions and backups.
- `ios/Sync/test-relay.sh`: two native clients sync through a local TLS relay
  that applies `relay/write-policy.jq`, the policy relay.passkey.bond runs, so
  CI fails if the app publishes anything our relay would refuse.
  `verify-native.mjs` then checks a native event with the JavaScript protocol.
- The VaultSync package tests, the app's unit tests, and UI tests on an iPhone
  and an iPad simulator.

## Sync

Sync speaks protocol v5, like the extension and Android app: chain keys come
from scrypt (N=2^17) and HKDF over the seed hash (`src/sync/chain-keys.ts`), and
events are kind 30078 with `pksync-v5-` tags. The default relays match
`DEFAULT_RELAYS` in `src/sync/protocol.ts`: `wss://relay.passkey.bond`,
`wss://relay.damus.io` and `wss://nos.lol`. The app uses one relay at a time and
moves to the next when one fails or rejects an event.

## Store screenshots

`ios/store/screenshots/` holds the App Store screenshots for the 6.9-inch iPhone
(1320 x 2868) and the 13-inch iPad (2064 x 2752). They come from
`Tests/NativeUI/StoreScreenshotTests.swift`, which runs the UI test host with a
demo vault (reserved example domains only, seeded by `-demoVault` in
`Tests/UITestHost/TestApp.swift`). To regenerate them, run the "iOS sync tests"
workflow (on a pull request or by hand), download its `store-screenshots`
artifact, check every image, and replace the files here. The listing copy is in
`ios/store/en-US.json`.

## Backups and upgrades

On first unlock, the native app migrates data from the previous iOS app (the
web-view build) into its encrypted vault. That build kept passkey private keys
in plain app-group preferences; the native vault encrypts them with a key held
in the keychain and removes the plaintext copy.

In Settings, use **Export encrypted backup** to save a backup or **Import backup**
to restore one. Backups contain credentials; keep the sync recovery phrase
separately to reconnect devices to the same chain.

## Before release

- A signed build, installed on a real iPhone: upgrade from the previous build,
  passkey creation and sign-in through AutoFill, camera setup, clipboard
  expiry, backup recovery, and sync with the extensions and Android.
- App Store Connect: the app record, price, privacy answers and the screenshots
  above.
