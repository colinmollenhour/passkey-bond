# App Store — submission pack (Passkey.bond for iOS)

**Status:** coming soon. Not submitted; the app needs a signed build and testing
on a real iPhone first (see `ios/README.md`, "Before release").

Everything needed to create the App Store Connect listing for `bond.passkey.app`.
The listing text itself lives in [`en-US.json`](en-US.json) so it can be copied
field by field; this page covers the rest.

## Pricing

Paid app, one-time purchase of US$2.95 (set the other territories from it in App
Store Connect). No in-app purchases or subscriptions. The copy must not call the
app free.

## Listing fields

| Field | Value |
| --- | --- |
| Name (30 max) | `Passkey.bond: Passkeys & 2FA` (28) |
| Subtitle (30 max) | `Passkeys and 2FA codes` |
| Description | `description` in `en-US.json` |
| Keywords (100 max) | `keywords` in `en-US.json` |
| Category | Utilities (secondary: Productivity) |
| Support URL | https://passkey.bond/ (support@passkey.bond) |
| Marketing URL | https://passkey.bond/ |
| Privacy policy | https://passkey.bond/privacy |
| Copyright | 2026 Dragonstone Labs |

## Screenshots

All from `ios/Tests/NativeUI/StoreScreenshotTests.swift` on CI, with a demo
vault of reserved example domains (see `ios/README.md`, "Store screenshots").

| File | Shows |
| --- | --- |
| `screenshots/iphone-6.9-01-unlock.png` | Lock screen with the mark and wordmark |
| `screenshots/iphone-6.9-02-vault.png` | Vault with passkeys and live 2FA codes |
| `screenshots/iphone-6.9-03-add-code.png` | Adding an authenticator entry |
| `screenshots/iphone-6.9-04-sync.png` | Sync setup and what relays can see |
| `screenshots/iphone-6.9-05-settings.png` | Settings: AutoFill, backups, auto-lock |
| `screenshots/iphone-6.9-06-vault-dark.png` | Vault in dark mode |
| `screenshots/ipad-13-*.png` | The same six screens on a 13-inch iPad |

iPhone 6.9-inch screenshots are 1320 x 2868 and iPad 13-inch are 2064 x 2752,
the sizes App Store Connect asks for; it scales them down for smaller devices.

## App privacy

No data collected by the developer. Vault contents never leave the device
unencrypted. Optional sync sends end-to-end encrypted updates through public
Nostr relays (relay.passkey.bond by default), which see the device's IP address,
sync identifiers and update times, as the in-app privacy text says.
`ios/PrivacyInfo.xcprivacy` declares the one required-reason API the app uses
(shared preferences).
