# Passkey.bond promo assets

- Banner: `promo-small.jpg`, 440 × 280, opaque JPEG.
- Banner master: `source/passkey-bond-banner.png`.
- Marquee: `promo-marquee.jpg`, 1400 × 560, opaque JPEG.
- Marquee master: `source/passkey-bond-marquee.png`.
- Video: `../video/passkey-bond-promo.mp4`, 1280 × 720, H.264, 30 fps.
- Review frames: `../video/review/`.

The video is silent with on-screen captions. It records the built extension
with sample accounts: vault browsing, search, credential details, adding a
2FA setup link, and exporting a password-protected backup. It does not
demonstrate signing in to a website. No real credentials are used.

Upload the MP4 to YouTube, then use its link in the Chrome Web Store video
field. Neither the video nor the banner has been published by this script.
See [Google's listing requirements](https://developer.chrome.com/docs/webstore/cws-dashboard-listing/).

Recreate the video:

```sh
npm run build:chrome
node scripts/capture-assets.js promo-video
```

Requires Playwright, Chromium and FFmpeg. Video files follow the repository's
existing `docs/video/` ignore rule. The capture uses a disposable browser
profile and adds presentation captions around the popup.

The banner uses the built-in image generation tool and
`docs/brand/passkey-bond-logo.png` as its reference. Prompt:

> Create a new finished Chrome Web Store small promotional banner for
> Passkey.bond, aspect ratio 11:7, ideally 1320x840. Reference image is the
> Passkey.bond logo: a gold-rimmed midnight-navy keyhole framing an ivory
> dinner-shirt front and bow tie. Preserve its identity, use it as a modest
> brand mark, do not redesign. Late-1970s British spy elegance. Full bleed
> opaque tuxedo black #111111 background, brushed gold #C9A24A accents, ivory
> #F4EBD9 text. Refined Didone display typography (Bodoni Moda) for the name,
> geometric sans (Jost) for the tagline. Exact
> text only: "Passkey.bond" large, highly legible, and "Passkeys + 2FA. On
> your device." as a smaller readable two-line tagline. Left aligned
> typographic composition with ample breathing room, logo upper left, subtle
> fine gold line-art on right suggesting a keyhole and a bow tie,
> restrained flat design. No browser UI, no fake screenshots, no extra text,
> no gradients or glow, no rounded outer corners. Strong hierarchy and
> legibility at 440x280 pixels. This is a finished brand banner, not a mockup.

The image generator redraws the logo and wordmark inaccurately, so only its
gold line art is used. Generate at 3:2 with the logo as the reference image,
pick the candidate with the cleanest line art, then composite a 1320 × 840
master in a Playwright-rendered page:

- Draw the generated image scaled to 840 px high, right-aligned, and repaint
  everything left of the line art (including the generated logo and text)
  flat `#111111`. Map the remaining pixels to a blend of `#111111` and
  `#C9A24A` by brightness, so the background stays flat and the lines are
  exactly brushed gold.
- Place the real mark (`docs/brand/png/mark/passkey-bond-mark-1024.png`,
  200 px wide) upper left, the real reversed wordmark
  (`docs/brand/png/lockup/passkey-bond-wordmark-reversed@2x.png`, 780 px
  wide) below it, and the tagline in Jost 400, 60 px, ivory, on two lines,
  all on a 96–116 px left margin.

Save the master as `source/passkey-bond-banner.png`. `npm run capture:promo`
scales it to the 440 × 280 small tile.

The marquee uses the built-in image generation tool with the small banner
master as its reference. Prompt:

> Create the matching wide Chrome Web Store marquee promotional banner for
> the supplied Passkey.bond small promo image. Preserve its gold-rimmed
> keyhole mark, Bodoni Moda and Jost typography, tuxedo-black background and
> gold line-art illustration. Recompose for a wide 5:2 aspect ratio, target
> 1400x560 pixels. Do not stretch the reference. Logo in upper left above the
> text, generous margins. Left portion: large ivory exact title
> "Passkey.bond". Below, gold exact tagline on two lines: "Passkeys + 2FA."
> and "On your device." Right portion: fine gold outline keyhole and bow tie,
> with subtle Art Deco circular geometry. Opaque full bleed tuxedo black
> #111111, brushed gold #C9A24A, ivory #F4EBD9. No UI screenshot, extra words,
> gradients, glow, mockup or rounded outer corners.

Generate at 16:9 and composite a 1400 × 560 master the same way as the
banner: the generated image at its native 768 px height, right-aligned and
shifted up 100 px; the real mark 132 px wide; the reversed wordmark 640 px
wide; the tagline in Jost 400, 44 px, brushed gold.

Save the master as `source/passkey-bond-marquee.png`. `npm run capture:promo`
renders it as the 1400 × 560 marquee tile.
