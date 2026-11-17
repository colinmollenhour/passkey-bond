// Regenerates every Passkey.bond logo SVG and PNG export in docs/brand.
//   cd docs/brand/tools && npm ci && npm run build
// Fonts (SIL OFL, from Google Fonts) are downloaded into .fonts/ on first run;
// the wordmark is converted to outlines so the SVGs never depend on them.
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Resvg } from '@resvg/resvg-js';
import opentype from 'opentype.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BRAND = path.resolve(HERE, '..');
const PNG = path.join(BRAND, 'png');
const AAGUID = path.resolve(BRAND, '../aaguid');

export const COLORS = {
  navy: '#14213D', // Midnight navy: the keyhole, the dinner jacket
  black: '#111111', // Tuxedo black
  gold: '#C9A24A', // Brushed gold: the rim, accents on dark
  goldDeep: '#9C7A2E', // Gold for text and thin lines on light backgrounds
  ivory: '#F4EBD9', // Ivory: the shirt front, light surfaces
  oxblood: '#6B1E2A', // Oxblood: sparing accent, warnings
  green: '#0F3D2E', // British racing green: secondary accent
};

// ---------------------------------------------------------------- geometry
// The keyhole: a circle (cx, cy, r) whose sides leave it `theta` degrees
// below its equator and run straight to a flat base at y = by, x = bx..512-bx.
// keyhole(o) is that shape grown outward by o units, as a single path: the
// same outline a stroke of width 2*o with round joins would trace.
function keyhole(g, o = 0) {
  const { cx, cy, r, theta, bx, by } = g;
  const t = (theta * Math.PI) / 180;
  const f = (n) => +n.toFixed(2);
  const sides = [-1, 1].map((s) => {
    const neck = { x: cx + s * r * Math.cos(t), y: cy + r * Math.sin(t) };
    const base = { x: s < 0 ? bx : 512 - bx, y: by };
    const len = Math.hypot(base.x - neck.x, base.y - neck.y);
    const d = { x: (base.x - neck.x) / len, y: (base.y - neck.y) / len };
    // Outward normal: d rotated 90 degrees, whichever way points away from the centre line.
    const c1 = { x: -d.y, y: d.x }, c2 = { x: d.y, y: -d.x };
    const out = c1.x * s > 0 ? c1 : c2;
    const p0 = { x: neck.x + out.x * o, y: neck.y + out.y * o };
    // Where the offset side meets the grown circle (the lower crossing).
    const R = r + o, ox = p0.x - cx, oy = p0.y - cy;
    const b = ox * d.x + oy * d.y, cc = ox * ox + oy * oy - R * R;
    const tt = -b + Math.sqrt(b * b - cc);
    const top = { x: p0.x + d.x * tt, y: p0.y + d.y * tt };
    const foot = { x: base.x + out.x * o, y: base.y + out.y * o };
    return { top, foot, base };
  });
  const [L, Rt] = sides;
  const R = r + o;
  let d = `M${f(L.foot.x)} ${f(L.foot.y)}L${f(L.top.x)} ${f(L.top.y)}`;
  d += `A${f(R)} ${f(R)} 0 1 1 ${f(Rt.top.x)} ${f(Rt.top.y)}`;
  d += `L${f(Rt.foot.x)} ${f(Rt.foot.y)}`;
  if (o > 0) d += `A${f(o)} ${f(o)} 0 0 1 ${f(Rt.base.x)} ${f(Rt.base.y + o)}`;
  d += `L${f(L.base.x)} ${f(L.base.y + o)}`;
  if (o > 0) d += `A${f(o)} ${f(o)} 0 0 1 ${f(L.foot.x)} ${f(L.foot.y)}`;
  return d + 'Z';
}

// The shirt front between the lapels: an inverted triangle.
const shirt = ({ y, half, tip }) => `M${256 - half} ${y}L${256 + half} ${y}L256 ${tip}Z`;

// The bow tie as one closed outline (wings and knot), centred on (256, y).
function bowtie({ y, half, h, knot }) {
  const k = knot / 2, a = h / 2;
  return (
    `M${256 - half} ${y - a}L${256 - k} ${y - a * 0.42}L${256 + k} ${y - a * 0.42}` +
    `L${256 + half} ${y - a}Q${256 + half + 7} ${y} ${256 + half} ${y + a}` +
    `L${256 + k} ${y + a * 0.42}L${256 - k} ${y + a * 0.42}L${256 - half} ${y + a}` +
    `Q${256 - half - 7} ${y} ${256 - half} ${y - a}Z`
  );
}

// One design, three levels of detail. Small sizes get a heavier rim, a wider
// shirt front and (at 16 px) no bow tie, which would only render as a smudge.
const DETAIL = {
  full: {
    key: { cx: 256, cy: 176, r: 118, theta: 50, bx: 92, by: 462 },
    rim: 22,
    shirt: { y: 278, half: 56, tip: 440 },
    bow: { y: 302, half: 34, h: 30, knot: 16 },
  },
  32: {
    key: { cx: 256, cy: 180, r: 124, theta: 48, bx: 80, by: 456 },
    rim: 40,
    shirt: { y: 282, half: 68, tip: 436 },
    bow: { y: 306, half: 42, h: 36, knot: 20 },
  },
  16: {
    key: { cx: 256, cy: 180, r: 128, theta: 46, bx: 72, by: 448 },
    rim: 48,
    shirt: { y: 288, half: 76, tip: 432 },
    bow: null,
  },
};

const svg = (body, vb = '0 0 512 512', extra = '') =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb}"${extra}>${body}</svg>\n`;

// SVG Tiny 1.2 path data has no arc command, so each circular arc (the only
// kind these paths draw: rx = ry, no rotation) becomes cubic Beziers of at
// most 90 degrees, which stay within 0.03% of the radius.
function arcsToCubics(d) {
  const f = (n) => +n.toFixed(2);
  let x = 0, y = 0;
  return d.replace(/([MLQAZ])([^MLQAZ]*)/g, (_, cmd, args) => {
    const n = args.trim() ? args.trim().split(/[\s,]+/).map(Number) : [];
    if (cmd !== 'A') {
      if (n.length) [x, y] = n.slice(-2);
      return cmd + args;
    }
    const [rx, ry, rot, large, sweep, x2, y2] = n;
    if (rx !== ry || rot !== 0) throw new Error(`arcsToCubics: not a circular arc: A${args}`);
    // Endpoint to centre parameterisation (SVG 1.1 appendix F.6.5).
    const hx = (x - x2) / 2, hy = (y - y2) / 2, h2 = hx * hx + hy * hy;
    const r = Math.max(rx, Math.sqrt(h2));
    const coef = (large !== sweep ? 1 : -1) * Math.sqrt(Math.max(0, (r * r - h2) / h2));
    const cx = coef * hy + (x + x2) / 2, cy = -coef * hx + (y + y2) / 2;
    const a0 = Math.atan2(y - cy, x - cx);
    let span = Math.atan2(y2 - cy, x2 - cx) - a0;
    if (sweep && span < 0) span += 2 * Math.PI;
    if (!sweep && span > 0) span -= 2 * Math.PI;
    const parts = Math.ceil(Math.abs(span) / (Math.PI / 2) - 1e-9);
    const step = span / parts, k = (4 / 3) * Math.tan(step / 4) * r;
    let out = '';
    for (let i = 0; i < parts; i++) {
      const a1 = a0 + i * step, a2 = a1 + step;
      const last = i === parts - 1;
      const ex = last ? x2 : cx + r * Math.cos(a2), ey = last ? y2 : cy + r * Math.sin(a2);
      out += `C${f(cx + r * Math.cos(a1) - k * Math.sin(a1))} ${f(cy + r * Math.sin(a1) + k * Math.cos(a1))}`;
      out += ` ${f(cx + r * Math.cos(a2) + k * Math.sin(a2))} ${f(cy + r * Math.sin(a2) - k * Math.cos(a2))}`;
      out += ` ${f(ex)} ${f(ey)}`;
    }
    [x, y] = [x2, y2];
    return out;
  });
}

// Full-colour mark: gold rim, navy keyhole, ivory shirt, navy bow tie.
function markBody(level, c = {}) {
  const D = DETAIL[level];
  const rim = c.rim ?? COLORS.gold, body = c.body ?? COLORS.navy, front = c.front ?? COLORS.ivory;
  let s = `<path fill="${rim}" d="${keyhole(D.key, D.rim)}"/>`;
  s += `<path fill="${body}" d="${keyhole(D.key, 0)}"/>`;
  s += `<path fill="${front}" d="${shirt(D.shirt)}"/>`;
  if (D.bow) s += `<path fill="${body}" d="${bowtie(D.bow)}"/>`;
  return s;
}

// One-colour mark: the silhouette with the shirt front cut out and the bow
// tie left solid, as a single even-odd path (no masks, so every renderer is
// happy).
function monoBody(level, color) {
  const D = DETAIL[level];
  let d = keyhole(D.key, D.rim) + shirt(D.shirt);
  if (D.bow) d += bowtie(D.bow);
  return `<path fill="${color}" fill-rule="evenodd" d="${d}"/>`;
}

// App icon: the mark on a rounded-square tile.
function iconBody(tile, opts) {
  return (
    `<rect width="512" height="512" rx="112" fill="${tile}"/>` +
    `<g transform="translate(76 72) scale(0.703)">${markBody('full', opts)}</g>`
  );
}

// ---------------------------------------------------------------- wordmark
const FONTS = {
  roman: { file: 'BodoniModa-Medium.ttf', css: 'Bodoni+Moda:opsz,wght@96,500' },
  italic: { file: 'BodoniModa-MediumItalic.ttf', css: 'Bodoni+Moda:ital,opsz,wght@1,96,500' },
};

async function loadFont({ file, css }) {
  const dir = path.join(HERE, '.fonts');
  const p = path.join(dir, file);
  if (!fs.existsSync(p)) {
    fs.mkdirSync(dir, { recursive: true });
    // An old user agent makes Google Fonts serve a static TTF instance.
    const sheet = await (await fetch(`https://fonts.googleapis.com/css2?family=${css}`, {
      headers: { 'User-Agent': 'Mozilla/4.0' },
    })).text();
    const url = sheet.match(/https:[^)]+\.ttf/)?.[0];
    if (!url) throw new Error(`No TTF in Google Fonts CSS for ${css}`);
    fs.writeFileSync(p, Buffer.from(await (await fetch(url)).arrayBuffer()));
  }
  const buf = fs.readFileSync(p);
  return opentype.parse(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
}

// "Passkey" in roman, ".bond" in italic, both as outlines. Returns the paths
// plus their bounding box at font size `size` with the baseline at y = 0.
function wordmark(roman, italic, size) {
  const a = roman.getPath('Passkey', 0, 0, size);
  const w = roman.getAdvanceWidth('Passkey', size);
  const b = italic.getPath('.bond', w + size * 0.01, 0, size);
  const ba = a.getBoundingBox(), bb = b.getBoundingBox();
  return {
    first: a.toPathData(1),
    second: b.toPathData(1),
    box: { x1: Math.min(ba.x1, bb.x1), y1: Math.min(ba.y1, bb.y1), x2: Math.max(ba.x2, bb.x2), y2: Math.max(ba.y2, bb.y2) },
  };
}

function lockupSvg(wm, text, accent) {
  // Mark 160 tall on the left; wordmark x-height roughly centred on it.
  const markH = 160, gap = 40, scale = markH / 470;
  const markW = 512 * scale;
  const tx = markW + gap - wm.box.x1, ty = 122;
  const W = Math.ceil(tx + wm.box.x2 + 8), H = markH + 16;
  const body =
    `<g transform="translate(0 4) scale(${scale.toFixed(4)}) translate(0 -22)">${markBody('full')}</g>` +
    `<g transform="translate(${tx.toFixed(1)} ${ty})"><path fill="${text}" d="${wm.first}"/>` +
    `<path fill="${accent}" d="${wm.second}"/></g>`;
  return { svg: svg(body, `0 0 ${W} ${H}`), W, H };
}

function wordmarkSvg(wm, text, accent) {
  const pad = 6, { x1, y1, x2, y2 } = wm.box;
  const W = Math.ceil(x2 - x1 + pad * 2), H = Math.ceil(y2 - y1 + pad * 2);
  const body = `<g transform="translate(${(pad - x1).toFixed(1)} ${(pad - y1).toFixed(1)})">` +
    `<path fill="${text}" d="${wm.first}"/><path fill="${accent}" d="${wm.second}"/></g>`;
  return { svg: svg(body, `0 0 ${W} ${H}`), W, H };
}

// ---------------------------------------------------------------- output
function write(rel, content) {
  const p = path.join(BRAND, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

function png(svgText, width, rel) {
  const out = new Resvg(svgText, { fitTo: { mode: 'width', value: width } }).render().asPng();
  const p = path.join(BRAND, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, out);
}

const roman = await loadFont(FONTS.roman);
const italic = await loadFont(FONTS.italic);

const files = {
  'passkey-bond-mark.svg': svg(markBody('full')),
  'passkey-bond-mark-32.svg': svg(markBody('32')),
  'passkey-bond-mark-16.svg': svg(markBody('16')),
  'passkey-bond-mark-black.svg': svg(monoBody('full', COLORS.black)),
  'passkey-bond-mark-white.svg': svg(monoBody('full', '#FFFFFF')),
  'passkey-bond-mark-gold.svg': svg(monoBody('full', COLORS.gold)),
  'passkey-bond-mark-mono-16.svg': svg(monoBody('16', COLORS.black)),
  'passkey-bond-icon.svg': svg(iconBody(COLORS.black)),
  'passkey-bond-icon-light.svg': svg(iconBody(COLORS.ivory)),
};
const wm = wordmark(roman, italic, 120);
const lockups = {
  'passkey-bond-lockup.svg': lockupSvg(wm, COLORS.navy, COLORS.goldDeep),
  'passkey-bond-lockup-reversed.svg': lockupSvg(wm, COLORS.ivory, COLORS.gold),
  'passkey-bond-wordmark.svg': wordmarkSvg(wm, COLORS.navy, COLORS.goldDeep),
  'passkey-bond-wordmark-reversed.svg': wordmarkSvg(wm, COLORS.ivory, COLORS.gold),
};
for (const [name, text] of Object.entries(files)) write(name, text);
// Colour swatches for the README.
for (const [name, hex] of Object.entries(COLORS)) {
  write(`swatches/${name}.svg`, svg(`<rect width="24" height="24" rx="4" fill="${hex}" stroke="#8888" stroke-width="1"/>`, '0 0 24 24', ' width="24" height="24"'));
}
for (const [name, l] of Object.entries(lockups)) write(name, l.svg);

// The right drawing for each pixel size.
const markFor = (px) => (px <= 20 ? files['passkey-bond-mark-16.svg'] : px <= 64 ? files['passkey-bond-mark-32.svg'] : files['passkey-bond-mark.svg']);
for (const px of [16, 32, 48, 64, 128, 256, 512, 1024]) png(markFor(px), px, `png/mark/passkey-bond-mark-${px}.png`);
for (const px of [48, 128, 180, 192, 512, 1024]) {
  png(files['passkey-bond-icon.svg'], px, `png/icon/passkey-bond-icon-${px}.png`);
  png(files['passkey-bond-icon-light.svg'], px, `png/icon/passkey-bond-icon-light-${px}.png`);
}
for (const [name, l] of Object.entries(lockups)) {
  png(l.svg, l.W, `png/lockup/${name.replace('.svg', '.png')}`);
  png(l.svg, l.W * 2, `png/lockup/${name.replace('.svg', '@2x.png')}`);
}
// Drop-in extension icons (src/icons uses icon16/48/128.png).
for (const px of [16, 32, 48, 128]) png(markFor(px), px, `png/extension/icon${px}.png`);
// Android launcher icons. The adaptive icon's foreground and monochrome
// (themed icon) layers are 108 dp squares the launcher masks, so the mark sits
// inside the central 66 dp safe zone; the tile colour is @color/icon_background
// (ivory, tuxedo black at night). ic_launcher.png is the pre-Android 8 icon.
const ANDROID_RES = path.resolve(BRAND, '../../android/app/src/main/res');
const ANDROID_PLAY = path.resolve(BRAND, '../../android/play');
const layer = (body) => svg(`<g transform="translate(118 112) scale(0.54)">${body}</g>`);
const androidFg = layer(markBody('full'));
const androidMono = layer(monoBody('full', '#FFFFFF'));
for (const [dpi, scale] of Object.entries({ mdpi: 1, hdpi: 1.5, xhdpi: 2, xxhdpi: 3, xxxhdpi: 4 })) {
  const dir = path.relative(BRAND, path.join(ANDROID_RES, `mipmap-${dpi}`));
  png(androidFg, 108 * scale, `${dir}/ic_launcher_foreground.png`);
  png(androidMono, 108 * scale, `${dir}/ic_launcher_monochrome.png`);
  png(files['passkey-bond-icon.svg'], 48 * scale, `${dir}/ic_launcher.png`);
}
// The mark in the Android app's own header, lock screen and About page.
png(files['passkey-bond-mark.svg'], 256, path.relative(BRAND, path.resolve(BRAND, '../../android/web/src/icon.png')));
// Google Play wants a full square; it rounds the corners itself.
png(svg(iconBody(COLORS.black).replace('rx="112" ', '')), 512, path.relative(BRAND, path.join(ANDROID_PLAY, 'icon-512.png')));
// iOS app icon: a full 1024 square (iOS applies the rounded mask) in the same
// proportions as the Play icon, as an opaque RGB PNG since the App Store
// rejects icons with an alpha channel. Ivory by default, tuxedo black for the
// dark appearance.
const IOS_ICONSET = path.resolve(BRAND, '../../ios/App/Assets.xcassets/AppIcon.appiconset');
const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function pngChunk(type, data) {
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  let c = 0xffffffff;
  for (const b of body) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  const len = Buffer.alloc(4), crc = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  crc.writeUInt32BE((c ^ 0xffffffff) >>> 0);
  return Buffer.concat([len, body, crc]);
}
// Renders an SVG whose drawing covers the whole canvas and writes it as an 8-bit RGB PNG.
function pngOpaque(svgText, size, rel) {
  const img = new Resvg(svgText, { fitTo: { mode: 'width', value: size } }).render();
  const rgba = img.pixels;
  if (img.width !== size || img.height !== size) throw new Error(`${rel}: expected ${size}x${size}`);
  const raw = Buffer.alloc(size * (size * 3 + 1));
  for (let y = 0; y < size; y++) {
    const row = y * (size * 3 + 1);
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      if (rgba[i + 3] !== 255) throw new Error(`${rel}: transparent pixel at ${x},${y}`);
      raw[row + 1 + x * 3] = rgba[i];
      raw[row + 2 + x * 3] = rgba[i + 1];
      raw[row + 3 + x * 3] = rgba[i + 2];
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: RGB, no alpha
  const out = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
  const p = path.join(BRAND, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, out);
}
const iosTile = (tile) => svg(iconBody(tile).replace('rx="112" ', ''));
const iosDir = path.relative(BRAND, IOS_ICONSET);
pngOpaque(iosTile(COLORS.ivory), 1024, `${iosDir}/AppIcon.png`);
pngOpaque(iosTile(COLORS.black), 1024, `${iosDir}/AppIcon-dark.png`);
write(
  `${iosDir}/Contents.json`,
  JSON.stringify(
    {
      images: [
        { filename: 'AppIcon.png', idiom: 'universal', platform: 'ios', size: '1024x1024' },
        {
          appearances: [{ appearance: 'luminosity', value: 'dark' }],
          filename: 'AppIcon-dark.png',
          idiom: 'universal',
          platform: 'ios',
          size: '1024x1024',
        },
      ],
      info: { author: 'xcode', version: 1 },
    },
    null,
    2,
  ) + '\n',
);
// The mark on the iOS lock screen, as a vector image set.
const iosMarkDir = path.relative(BRAND, path.resolve(IOS_ICONSET, '../BrandMark.imageset'));
write(`${iosMarkDir}/BrandMark.svg`, files['passkey-bond-mark.svg']);
write(
  `${iosMarkDir}/Contents.json`,
  JSON.stringify(
    {
      images: [{ filename: 'BrandMark.svg', idiom: 'universal' }],
      info: { author: 'xcode', version: 1 },
      properties: { 'preserves-vector-representation': true },
    },
    null,
    2,
  ) + '\n',
);
// Raster logo used by scripts/capture-promo-video.js.
png(files['passkey-bond-mark.svg'], 512, 'passkey-bond-logo.png');

// AAGUID icons. vault-icon.svg is the app icon. The FIDO Metadata Service
// statement embeds the mark as a data URL in its two logo fields: the 24-64 px
// drawing, since password managers show it at about that size, and one
// drawing for both themes, since the gold rim reads on dark lists and the navy
// body on light ones. MDS takes only the SVG Tiny Portable/Secure profile,
// whose path data has no arcs (see arcsToCubics).
write(path.relative(BRAND, path.join(AAGUID, 'vault-icon.svg')), files['passkey-bond-icon.svg']);
const tinyPs =
  '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 512 512">' +
  '<title>Passkey.bond</title>' +
  markBody('32').replace(/ d="([^"]+)"/g, (_, d) => ` d="${arcsToCubics(d)}"`) +
  '</svg>\n';
write(path.relative(BRAND, path.join(AAGUID, 'vault-icon-tiny-ps.svg')), tinyPs);
const mdsPath = path.join(AAGUID, 'mds-statement.json');
const mds = JSON.parse(fs.readFileSync(mdsPath, 'utf8'));
const logo = 'data:image/svg+xml;base64,' + Buffer.from(tinyPs.trim()).toString('base64');
mds.providerLogoLight = logo;
mds.providerLogoDark = logo;
fs.writeFileSync(mdsPath, JSON.stringify(mds, null, 2) + '\n');

console.log('Wrote', Object.keys(files).length + Object.keys(lockups).length, 'SVGs and PNG exports to', BRAND);
