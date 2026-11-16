# passkey.bond website

Static pages: no build step, no dependencies, no third-party requests. Fonts
(Bodoni Moda and Jost, SIL OFL) and images are served from `assets/`, and each
page sets a Content Security Policy that allows only same-origin resources.

| Path | File |
| --- | --- |
| `/` | `index.html` |
| `/security` | `security/index.html` |
| `/download` | `download/index.html`. The apps link to `/download#chrome`, `#firefox` and `#android`; `#ios` also exists. |
| `/privacy` | `privacy/index.html` (placeholder draft) |
| `/terms` | `terms/index.html` (placeholder draft) |
| not found | `404.html` |

Colours, type and voice follow [`docs/brand/README.md`](../docs/brand/README.md).

## Preview

```sh
cd site
python3 -m http.server 8000
```

Then open <http://localhost:8000/>. Like GitHub Pages, Python's server
redirects `/security` to `/security/`. It doesn't serve `404.html` for missing
pages, but static hosts do.

## Deploy

The site runs on Railway (project `passkey.bond`, Dragonstone Labs workspace)
as a Caddy container built from `Dockerfile` and `Caddyfile`, with the
service's root directory set to `site/`. Railway redeploys when a push to
`main` changes `site/**` (`railway.json`). Caddy serves `/security` without
the trailing slash, redirects `/security/` and `www.passkey.bond` to the
canonical URL, returns `404.html` for missing pages and sets the security
headers, including the CSP from the pages' meta tags plus `frame-ancestors`.

To check the container locally:

```sh
docker build -t passkey-bond-site site
docker run --rm -e PORT=8080 -p 8080:8080 passkey-bond-site
```

## Animations

- `assets/guilloche.js` draws the banknote-style background on any
  `<canvas data-guilloche>`. Use `data-anchor="<selector>"` to centre it on an
  element, or `data-cx`, `data-cy` and `data-r` (fractions of the section) to
  place it.
- `assets/relay-viz.js` runs the sync animation in any `[data-relay-viz]`
  block. `data-detail="true"` switches on the protocol captions used on
  `/security`.

Both pause when off screen or in a hidden tab. With `prefers-reduced-motion`,
the background is drawn once and the sync animation starts paused on its last
step. Add `?vizframe=<ms>` (0 to 16199) to a page URL to freeze the sync
animation on one frame for screenshots.

## Editing

The header and footer are repeated in every page. Change them in all six
files. These things will need updating at launch:

- Store links: the "coming soon" labels in `download/index.html`. The home
  page buttons link to `/download#…`, so they don't need changing.
- Mobile price: the site says "one-time purchase" without a figure.
- `privacy/` and `terms/`: replace the drafts after legal review and remove
  the placeholder notices.
- GitHub links assume `github.com/colinmollenhour/passkey-bond`, and the
  download buttons assume the release assets keep the names
  `passkey-bond-chrome.zip` and `passkey-bond-firefox.zip`
  (see `.github/workflows/release.yml`).
