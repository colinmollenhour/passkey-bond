# Passkey.bond AAGUID

## Value

```
2391d29c-2806-4960-a51b-7c18e5da7976
```

Byte form (16 bytes, big-endian, as embedded in attested credential data):

```
23 91 d2 9c 28 06 49 60 a5 1b 7c 18 e5 da 79 76
```

This is a randomly generated UUID version 4 (version nibble `4` in the third
group, RFC 4122 variant nibble `a` in the fourth group). It identifies the
**authenticator model** ("Passkey.bond"), not any user or credential — every
Passkey.bond install reports the same value, exactly like 1Password, Bitwarden,
and iCloud Keychain report theirs.

## Where it is defined (single source of truth per platform)

The same 16 bytes are used byte-for-byte on every platform. If this value ever
changes it MUST be changed in all three places together.

| Platform | File | Symbol |
|----------|------|--------|
| Web extension | `src/background/cbor.ts` | `PASSKEY_BOND_AAGUID` |
| Android | `android/app/src/main/java/bond/passkey/app/WebAuthnNative.java` | `AAGUID` |
| iOS | `ios/Shared/WebAuthn.swift` | `aaguid` |

Verify consistency:

```sh
grep -rnE '0x23, (\(byte\) )?0x91, (\(byte\) )?0xd2, (\(byte\) )?0x9c' src android/app ios
```

## Why it is non-zero

The AAGUID is emitted in attested credential data during registration. With
`none` attestation, a strict reading of the WebAuthn privacy model expects the
client to zero the AAGUID so relying parties cannot fingerprint the
authenticator model without asking for attestation.

Passkey.bond intentionally reports a real, stable AAGUID instead, so that
consumer relying parties (Google, GitHub, etc.) display **"Passkey.bond"** and
its icon in their passkey lists. This is the same trade-off every major
passkey manager makes, and it is what the FIDO Metadata Service listing below
exists to support.

Trade-off, stated plainly: a stable AAGUID reveals to a relying party that the
user's authenticator is Passkey.bond. It is a *model* identifier shared by all
users, so it does not deanonymize an individual. If a future deployment needs
to hide the authenticator brand, zero the AAGUID in the three files above (and
withdraw the MDS entry).

## FIDO Metadata Service entry (makes RPs render the brand)

Relying parties and browsers resolve an AAGUID to a display name and icon
through the FIDO Alliance Metadata Service (MDS). Passkey.bond is to be listed
there as a FIDO2 non-CTAP passkey provider: `none` attestation, ES256 only,
software key protection. The statement to submit is
[`mds-statement.json`](./mds-statement.json).

The older community registry (`passkeydeveloper/passkey-authenticator-aaguids`)
stopped accepting submissions on 2026-11-01, empties its lists on 2027-01-06
and is archived on 2027-07-06, so Passkey.bond was never added to it. Fenko
Vault's MDS entry covers Fenko's AAGUID only.

### Submitting or updating the entry

1. Sign in at <https://mymds.fidoalliance.org/metadata-management> with a
   Passkey.bond vendor account (none exists yet).
2. Open the Passkey.bond statement, or **Add New** → **Sample FIDO2 Non-CTAP**
   for a fresh one.
3. Paste [`mds-statement.json`](./mds-statement.json). Only these fields are
   ours to change; leave the rest as the sample sets them:
   `authenticationAlgorithms`, `aaguid`, `friendlyNames`, `description`,
   `providerLogoLight`, `providerLogoDark`. Do not add `cxConfigURL`.
4. **Analyze**, then save and submit for publication.

Field limits from the Metadata Statement spec v3.1.1: `description` is
English ASCII, 200 characters max; each `friendlyNames` entry 63 characters
max.

### Icon

MDS requires the SVG Tiny Portable/Secure profile: the root element declares
`version="1.2"` and `baseProfile="tiny-ps"`, its first child is a `<title>`
holding the English friendly name, the viewBox is square, and the file is pure
vector with no comments, scripts or raster images. SVG Tiny 1.2 path data has
no arc command, so the keyhole's arcs are written as cubic Béziers.
[`vault-icon-tiny-ps.svg`](./vault-icon-tiny-ps.svg) is that form of the
Passkey.bond mark, and the statement embeds it as a base64 data URL in both
`providerLogoLight` and `providerLogoDark`.

It is the 24–64 px drawing
([`docs/brand/passkey-bond-mark-32.svg`](../brand/passkey-bond-mark-32.svg)),
because password managers show these icons at about that size, on a
transparent background. One drawing serves both themes: the gold rim keeps it
visible on dark backgrounds and the navy body on light ones.
[`vault-icon.svg`](./vault-icon.svg) is the full app icon, the same mark on a
tuxedo-black rounded square.

`docs/brand/tools/build.mjs` generates both SVGs and writes the two logo
fields into `mds-statement.json` (see [`docs/brand/README.md`](../brand/README.md)).
After a logo change, rebuild and resubmit the statement.

## Status

- [x] Proper value: valid random UUIDv4, unique to Passkey.bond.
- [x] Verified: byte-identical across web, Android, and iOS.
- [x] Documented: this file, referenced from each platform's source.
- [ ] Listed in FIDO MDS: statement ready in `mds-statement.json`, not yet
      submitted (needs a FIDO vendor account).
