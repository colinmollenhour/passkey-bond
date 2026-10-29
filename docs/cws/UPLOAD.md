# Chrome Web Store — assets to upload

Passkey.bond is not yet published on the Chrome Web Store. The first upload
creates the listing.

All images are dark-theme and already at the dimensions the dashboard expects.

## Screenshots (1280×800)

The screenshots in this folder predate the rebrand and still show the old
name. Recapture them before the first upload (`npm run build:chrome`, then
`npm run capture:cws`).

Upload in this order — the first is the tile shown in search results:

1. `cws-01-vault.png` — Passkeys and 2FA codes in one vault
2. `cws-08-totp.png` — Built-in 2FA codes, generated locally
3. `cws-02-search.png` — Search across everything
4. `cws-03-detail.png` — Full control over every credential
5. `cws-05-sync.png` — Sync across devices, no cloud required

Extras available in this folder if you want to swap any in:
`cws-04-settings.png` (developer tools), `cws-04-import.png` (backup import),
`cws-07-settings-dark.png` (interception controls).

## Promotional tiles

- Small promo tile (440×280, JPEG, no alpha): `promo-small.jpg`
- Marquee promo tile (1400×560, JPEG, no alpha): `promo-marquee.jpg`

Both tiles carry the Passkey.bond mark. The captioned video is `../video/passkey-bond-promo.mp4`; upload it to YouTube and
paste its link into the listing. See [promo assets](promo-assets.md) for the
prompts and capture instructions.

## Listing text

Summary, detailed description, and the per-locale copy live in
`chrome-web-store-descriptions.md`. The first submission has no "What's new"
text; write one for each release after that.
