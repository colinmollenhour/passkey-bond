Adds the AAGUID entry for **Passkey.bond**, an offline, end-to-end-encrypted passkey (WebAuthn) and TOTP manager built as a browser extension and native Android/iOS credential provider.

### Vendor
- **Developer:** Colin Mollenhour (individual developer)
- **Website:** https://passkey.bond
- **Contact:** security@passkey.bond
- **Source:** https://github.com/colinmollenhour/passkey-bond

### Authenticator
- **Name:** Passkey.bond
- **AAGUID:** `2391d29c-2806-4960-a51b-7c18e5da7976`
- Reported byte-identically by all three Passkey.bond authenticators (web extension, Android credential provider, iOS AutoFill provider).
- Passkey.bond began as a fork of [Fenko Vault](https://github.com/FenkoHQ/passkey-vault) by Fenko (MIT licensed) and reports its own AAGUID, distinct from Fenko Vault's.

### Ownership / provenance
The AAGUID is defined in the public source repository above. Store listings are not yet published; links will be added here once they are.

### Icons
`icon_light` / `icon_dark` are square, pure-vector SVG data URIs (no embedded raster) of the Passkey.bond mark: two interlocking amber links on a transparent background. `icon_dark` uses `#F5A623`; `icon_light` uses the deeper `#D4920A` for contrast on light backgrounds.

### Checklist
- [x] Entry added to `aaguid.json`, keyed by the AAGUID
- [x] Icons are base64-encoded SVG data URIs, square, vector-only (no raster)
- [x] Valid JSON, existing entries untouched
