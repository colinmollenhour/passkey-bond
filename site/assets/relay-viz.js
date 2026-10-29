// "Synced without a server": a passkey saved on a laptop is sealed, copies go
// to public Nostr relays that only ever hold ciphertext, and the phone picks
// one up and opens it. The empty "Our servers" slot stays in view the whole
// time. Visitors can switch relays off to see that one working relay is enough.
//
// Every frame is a pure function of (time, online relays, layout), so pause,
// step and ?vizframe=<ms> screenshots all give the same picture.
(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';

  const RELAYS = [
    { name: 'relay.damus.io', short: 'damus.io' },
    { name: 'nos.lol', short: 'nos.lol' },
    { name: 'relay.nostr.band', short: 'nostr.band' },
  ];

  // Named beats on one clock (ms). The loop rests on the last beat.
  const BEATS = [
    { id: 'save', start: 0, end: 1800 },
    { id: 'seal', start: 1800, end: 3600 },
    { id: 'send', start: 3600, end: 5600 },
    { id: 'hold', start: 5600, end: 8000 },
    { id: 'fetch', start: 8000, end: 10000 },
    { id: 'open', start: 10000, end: 11800 },
    { id: 'none', start: 11800, end: 16200 },
  ];
  const PERIOD = BEATS[BEATS.length - 1].end;

  const T = {
    cardIn: [200, 800],
    scramble: [1900, 2600],
    cardOut: [2700, 3100],
    cardBack: [3700, 4200],
    sendStart: 3600,
    sendStagger: 180,
    sendDur: 1500,
    failAt: 0.55,
    fetchStart: 8000,
    fetchStagger: 260,
    fetchDur: 1500,
    ghostLit: [11900, 12400],
  };

  const CAPTIONS = {
    plain: [
      '<b>You save a passkey on your laptop.</b> It lives there, on your device.',
      '<b>Before it leaves, it is sealed</b> with a key that only your own devices share.',
      '<b>Identical sealed copies go to three public relays</b>, run by independent operators, not by us. Any one of them is enough.',
      '<b>A relay sees sealed noise.</b> It can pass the envelope on. It cannot open it.',
      '<b>Your phone collects it</b> from whichever relays are online, and ignores the duplicate copies.',
      '<b>It opens with the same key</b>, and the passkey is ready on your phone too.',
      '<b>No Passkey.bond server stored it, saw it or passed it on.</b> We don\u2019t run one.',
    ],
    detail: [
      '<b>A new ES256 key pair is created on the laptop</b> and stored in the vault.',
      '<b>The sync payload is sealed with AES-256-GCM</b> under the chain key, inside a Nostr event signed with the chain’s secp256k1 key (BIP340 Schnorr).',
      '<b>The event is published to every configured relay.</b> Two devices sync as long as they share one working relay.',
      '<b>Relays see ciphertext, the chain tag and timing.</b> No domains, usernames, device names or counts.',
      '<b>The phone’s subscriptions on each relay deliver the event.</b>',
      '<b>It checks the Schnorr signature and event ID, decrypts, and merges.</b> Copies from other relays are recognised as replays and ignored.',
      '<b>Zero Passkey.bond servers involved.</b> Relays are interchangeable: add or remove them in Settings.',
    ],
    noRelay: {
      2: '<b>Every relay is switched off</b>, so the sealed copies have nowhere to go.',
      3: '<b>Nothing reaches a relay.</b> Your passkey simply stays on your laptop.',
      4: '<b>The phone has nothing to collect</b> until a relay is back online.',
      5: '<b>Sync waits.</b> Nothing is lost: each device keeps its own vault.',
    },
  };

  // ---------- Layout ----------

  function desktopLayout() {
    const relayY = [180, 275, 370];
    return {
      compact: false,
      w: 960,
      h: 550,
      ghost: { x: 390, y: 20, w: 180, h: 80 },
      relaysLabel: { x: 480, y: 140 },
      relays: relayY.map((y) => ({ x: 480, y, labelY: y + 44 })),
      laptop: { screen: { x: 60, y: 210, w: 180, h: 120 }, label: { x: 150, y: 382 }, sub: 'Chrome · Edge · Firefox' },
      phone: { body: { x: 750, y: 185, w: 120, h: 182 }, label: { x: 810, y: 397 }, sub: 'Android · iPhone' },
      readout: { x: 290, y: 448, w: 380, h: 84 },
      outPath(i, from) {
        const r = this.relays[i];
        return [from, { x: 360, y: from.y }, { x: 360, y: r.y }, { x: 452, y: r.y }];
      },
      inPath(i, to) {
        const r = this.relays[i];
        return [{ x: 508, y: r.y }, { x: 620, y: r.y }, { x: 620, y: to.y }, to];
      },
    };
  }

  function compactLayout() {
    const xs = [72, 200, 328];
    return {
      compact: true,
      w: 400,
      h: 820,
      ghost: { x: 110, y: 12, w: 180, h: 76 },
      relaysLabel: null,
      relays: xs.map((x) => ({ x, y: 350, labelY: 398 })),
      laptop: { screen: { x: 110, y: 128, w: 180, h: 120 }, labelAbove: { x: 200, y: 118 } },
      phone: { body: { x: 140, y: 466, w: 120, h: 182 }, label: { x: 200, y: 678 } },
      readout: { x: 30, y: 704, w: 340, h: 96 },
      outPath(i, from) {
        const r = this.relays[i];
        return [from, { x: from.x, y: 300 }, { x: r.x, y: 290 }, { x: r.x, y: 324 }];
      },
      inPath(i, to) {
        const r = this.relays[i];
        return [{ x: r.x, y: 410 }, { x: r.x, y: 440 }, { x: to.x, y: 430 }, to];
      },
    };
  }

  function screenCard(s, inset) {
    return { x: s.x + inset, y: s.y + s.h - 52, w: s.w - inset * 2, h: 40 };
  }

  function phoneScreen(b) {
    return { x: b.x + 8, y: b.y + 16, w: b.w - 16, h: b.h - 32 };
  }

  function centre(r) {
    return { x: r.x + r.w / 2, y: r.y + r.h / 2 };
  }

  // ---------- Maths ----------

  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const span = (t, [a, b]) => clamp((t - a) / (b - a));
  const ease = (p) => (p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2);

  function cubic([p0, p1, p2, p3], s) {
    const u = 1 - s;
    return {
      x: u * u * u * p0.x + 3 * u * u * s * p1.x + 3 * u * s * s * p2.x + s * s * s * p3.x,
      y: u * u * u * p0.y + 3 * u * u * s * p1.y + 3 * u * s * s * p2.y + s * s * s * p3.y,
    };
  }

  function hash(a, b) {
    let h = (a * 374761393 + b * 668265263) | 0;
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
  }

  const HEX = '0123456789abcdef';
  function hex(n, seed, tick) {
    let out = '';
    for (let i = 0; i < n; i++) out += HEX[Math.floor(hash(i + seed * 97, tick) * 16)];
    return out;
  }

  // Replace a growing share of characters with hex noise.
  function scramble(text, amount, tick) {
    let out = '';
    for (let i = 0; i < text.length; i++) {
      out += text[i] !== ' ' && hash(i, 7) < amount ? HEX[Math.floor(hash(i, tick) * 16)] : text[i];
    }
    return out;
  }

  // ---------- Projection ----------

  function beatAt(t) {
    for (let i = 0; i < BEATS.length; i++) if (t < BEATS[i].end) return i;
    return BEATS.length - 1;
  }

  function project(t, online, L) {
    const tick = Math.floor(t / 90);
    const lapCard = screenCard(L.laptop.screen, 12);
    const phCard = screenCard(phoneScreen(L.phone.body), 6);
    const from = centre(lapCard);
    const to = centre(phCard);
    const onlineIdx = RELAYS.map((_, i) => i).filter((i) => online[i]);

    const f = {
      beat: beatAt(t),
      tick,
      lap: { opacity: 0, scramble: 0 },
      sealEnv: { opacity: 0, at: from },
      out: [],
      parked: [],
      pulse: [],
      inn: [],
      phone: { opacity: 0, scramble: 0 },
      phoneEnv: { opacity: 0, at: to },
      ghost: ease(span(t, T.ghostLit)),
      readout: 'empty',
      anyOnline: onlineIdx.length > 0,
    };

    // Laptop card: appears, scrambles, seals, then returns as plaintext.
    if (t < T.cardOut[0]) {
      f.lap.opacity = ease(span(t, T.cardIn));
      f.lap.scramble = span(t, T.scramble);
    } else if (t < T.sendStart) {
      f.lap.opacity = 1 - ease(span(t, T.cardOut));
      f.lap.scramble = 1;
      f.sealEnv.opacity = ease(span(t, T.cardOut));
    } else {
      f.lap.opacity = ease(span(t, T.cardBack));
    }

    // Outgoing copies, one per relay.
    let firstRelayArrival = Infinity;
    RELAYS.forEach((_, i) => {
      const t0 = T.sendStart + i * T.sendStagger;
      const p = (t - t0) / T.sendDur;
      const path = L.outPath(i, from);
      const arrive = t0 + T.sendDur;
      f.parked[i] = false;
      f.pulse[i] = 0;
      if (online[i]) {
        firstRelayArrival = Math.min(firstRelayArrival, arrive);
        if (p >= 0 && p < 1) f.out[i] = { at: cubic(path, ease(p)), opacity: 1 };
        if (p >= 1) {
          f.parked[i] = true;
          f.pulse[i] = t - arrive < 700 ? (t - arrive) / 700 : 0;
        }
      } else if (p >= 0) {
        const s = Math.min(ease(Math.min(p, 1)), T.failAt);
        const stuck = ease(Math.min(p, 1)) >= T.failAt;
        const failTime = t0 + T.sendDur * 0.52;
        const fade = stuck ? 1 - clamp((t - failTime) / 600) : 1;
        if (fade > 0) f.out[i] = { at: cubic(path, s), opacity: fade, failed: stuck };
      }
    });

    if (f.anyOnline && t >= firstRelayArrival) f.readout = 'cipher';
    if (!f.anyOnline && t >= T.sendStart) f.readout = 'nothing';

    // Incoming copies from each online relay; the first one opens.
    let firstArrival = Infinity;
    onlineIdx.forEach((i, j) => {
      const t0 = T.fetchStart + j * T.fetchStagger;
      const p = (t - t0) / T.fetchDur;
      const arrive = t0 + T.fetchDur;
      if (j === 0) firstArrival = arrive;
      if (p >= 0 && p < 1) f.inn[i] = { at: cubic(L.inPath(i, to), ease(p)), opacity: 1 };
      else if (p >= 1 && j > 0 && t - arrive < 350) {
        f.inn[i] = { at: to, opacity: 1 - (t - arrive) / 350, dup: true };
      }
    });

    if (t >= firstArrival) {
      const a = firstArrival;
      f.phoneEnv.opacity = t < a + 700 ? 1 : 1 - ease(span(t, [a + 700, a + 1100]));
      f.phone.opacity = ease(span(t, [a + 700, a + 1100]));
      f.phone.scramble = 1 - span(t, [a + 900, a + 1700]);
    }
    return f;
  }

  // ---------- Rendering ----------

  function el(name, attrs, parent, text) {
    const n = document.createElementNS(NS, name);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (text != null) n.textContent = text;
    if (parent) parent.appendChild(n);
    return n;
  }

  function envelope(parent, cls) {
    const g = el('g', { class: cls || '' }, parent);
    el('rect', { class: 'env', x: -18, y: -12, width: 36, height: 24, rx: 2 }, g);
    el('path', { class: 'env-flap', d: 'M-18 -11 L0 2 L18 -11' }, g);
    el('circle', { class: 'seal', cx: 0, cy: 2, r: 4 }, g);
    return g;
  }

  function vaultScreen(parent, s, inset) {
    el('rect', { class: 'screen', x: s.x, y: s.y, width: s.w, height: s.h, rx: 3 }, parent);
    el('text', { class: 't-mono', x: s.x + inset, y: s.y + 20 }, parent, 'Vault');
    el('rect', { x: s.x + inset, y: s.y + 32, width: s.w - inset * 2, height: 8, rx: 2, fill: 'rgba(244,235,217,0.16)' }, parent);
    el('rect', { x: s.x + inset, y: s.y + 48, width: (s.w - inset * 2) * 0.66, height: 8, rx: 2, fill: 'rgba(244,235,217,0.16)' }, parent);
  }

  function card(parent, r) {
    const g = el('g', {}, parent);
    el('rect', { class: 'card', x: r.x, y: r.y, width: r.w, height: r.h, rx: 2 }, g);
    const title = el('text', { class: 'card-text', x: r.x + 10, y: r.y + 17 }, g, 'github.com');
    el('text', { class: 'card-sub', x: r.x + 10, y: r.y + 32 }, g, 'Passkey');
    return { g, title };
  }

  function build(svg, L, detail) {
    svg.textContent = '';
    svg.setAttribute('viewBox', `0 0 ${L.w} ${L.h}`);
    svg.toggleAttribute('data-compact', L.compact);
    const refs = { out: [], inn: [], parked: [], pulse: [], relayG: [] };

    // Ghost server: the slot where a sync service would usually sit.
    const gh = L.ghost;
    refs.ghostRect = el('rect', { class: 'ghost', x: gh.x, y: gh.y, width: gh.w, height: gh.h, rx: 3 }, svg);
    el('text', { class: 't-label', x: gh.x + gh.w / 2, y: gh.y + 26, 'text-anchor': 'middle' }, svg, 'Our servers');
    refs.ghostText = el('text', { class: 't-big', x: gh.x + gh.w / 2, y: gh.y + 60, 'text-anchor': 'middle', 'font-style': 'italic' }, svg, 'None');

    if (L.relaysLabel) {
      el('text', { class: 't-label', x: L.relaysLabel.x, y: L.relaysLabel.y, 'text-anchor': 'middle' }, svg, 'Public relays');
    }

    const lapCard = screenCard(L.laptop.screen, 12);
    const phScreen = phoneScreen(L.phone.body);
    const phCard = screenCard(phScreen, 6);

    // Routes, drawn first so everything else sits above them.
    refs.routes = RELAYS.map((_, i) => {
      const o = L.outPath(i, centre(lapCard));
      const n = L.inPath(i, centre(phCard));
      const d = (p) => `M${p[0].x} ${p[0].y} C${p[1].x} ${p[1].y} ${p[2].x} ${p[2].y} ${p[3].x} ${p[3].y}`;
      return [el('path', { class: 'line', d: d(o) }, svg), el('path', { class: 'line', d: d(n) }, svg)];
    });

    // Laptop.
    const ls = L.laptop.screen;
    el('rect', { class: 'device', x: ls.x - 10, y: ls.y - 10, width: ls.w + 20, height: ls.h + 20, rx: 6 }, svg);
    vaultScreen(svg, ls, 12);
    el('path', { class: 'device', d: `M${ls.x - 26} ${ls.y + ls.h + 10} H${ls.x + ls.w + 26} L${ls.x + ls.w + 14} ${ls.y + ls.h + 24} H${ls.x - 14} Z` }, svg);
    if (L.laptop.label) {
      el('text', { class: 't-label', x: L.laptop.label.x, y: L.laptop.label.y, 'text-anchor': 'middle' }, svg, 'Your laptop');
      el('text', { class: 't-mono', x: L.laptop.label.x, y: L.laptop.label.y + 20, 'text-anchor': 'middle' }, svg, L.laptop.sub);
    } else {
      el('text', { class: 't-label', x: L.laptop.labelAbove.x, y: L.laptop.labelAbove.y, 'text-anchor': 'middle' }, svg, 'Your laptop');
    }
    refs.lapCard = card(svg, lapCard);

    // Phone.
    const pb = L.phone.body;
    el('rect', { class: 'device', x: pb.x, y: pb.y, width: pb.w, height: pb.h, rx: 16 }, svg);
    vaultScreen(svg, phScreen, 6);
    el('text', { class: 't-label', x: L.phone.label.x, y: L.phone.label.y, 'text-anchor': 'middle' }, svg, 'Your phone');
    if (L.phone.sub) el('text', { class: 't-mono', x: L.phone.label.x, y: L.phone.label.y + 20, 'text-anchor': 'middle' }, svg, L.phone.sub);
    refs.phCard = card(svg, phCard);

    // Relays.
    L.relays.forEach((r, i) => {
      const g = el('g', { class: 'relay-hit', tabindex: '-1', 'data-relay': i }, svg);
      refs.pulse[i] = el('circle', { class: 'pulse', cx: r.x, cy: r.y, r: 26, opacity: 0 }, g);
      el('circle', { class: 'relay-ring', cx: r.x, cy: r.y, r: 26 }, g);
      el('circle', { class: 'relay-dot', cx: r.x, cy: r.y, r: 4 }, g);
      el('text', { class: 't-name', x: r.x, y: r.labelY, 'text-anchor': 'middle' }, g, L.compact ? RELAYS[i].short : RELAYS[i].name);
      const parked = envelope(g);
      parked.setAttribute('transform', `translate(${r.x} ${r.y}) scale(0.62)`);
      refs.parked[i] = parked;
      refs.relayG[i] = g;
    });

    // Readout: what a relay operator can see.
    const ro = L.readout;
    el('rect', { x: ro.x, y: ro.y, width: ro.w, height: ro.h, rx: 3, fill: '#0b1428', stroke: 'rgba(201,162,74,0.4)' }, svg);
    el('text', { class: 't-label', x: ro.x + 16, y: ro.y + 24 }, svg, 'What a relay sees');
    refs.ro = [0, 1, 2].map((k) => el('text', { class: k === 0 && !detail ? 't-cipher' : 't-mono', x: ro.x + 16, y: ro.y + 46 + k * 17 }, svg, ''));

    // Moving envelopes on top.
    RELAYS.forEach((_, i) => {
      refs.out[i] = envelope(svg);
      refs.out[i].fail = el('path', { class: 'fail', d: 'M-7 -7 L7 7 M7 -7 L-7 7', transform: 'translate(0 -22)' }, refs.out[i]);
      refs.inn[i] = envelope(svg);
    });
    refs.sealEnv = envelope(svg);
    refs.phoneEnv = envelope(svg);
    return refs;
  }

  function place(node, at, opacity, scale) {
    if (!at || opacity <= 0) {
      node.setAttribute('opacity', 0);
      return;
    }
    node.setAttribute('opacity', opacity.toFixed(3));
    node.setAttribute('transform', `translate(${at.x.toFixed(1)} ${at.y.toFixed(1)})${scale ? ` scale(${scale})` : ''}`);
  }

  function render(refs, f, online, L, detail) {
    refs.lapCard.g.setAttribute('opacity', f.lap.opacity.toFixed(3));
    refs.lapCard.title.textContent = scramble('github.com', f.lap.scramble, f.tick);
    refs.phCard.g.setAttribute('opacity', f.phone.opacity.toFixed(3));
    refs.phCard.title.textContent = scramble('github.com', f.phone.scramble, f.tick);

    place(refs.sealEnv, f.sealEnv.at, f.sealEnv.opacity);
    place(refs.phoneEnv, f.phoneEnv.at, f.phoneEnv.opacity);

    RELAYS.forEach((_, i) => {
      const o = f.out[i];
      place(refs.out[i], o && o.at, o ? o.opacity : 0);
      refs.out[i].fail.setAttribute('opacity', o && o.failed ? 1 : 0);
      const n = f.inn[i];
      place(refs.inn[i], n && n.at, n ? n.opacity : 0);

      refs.relayG[i].setAttribute('data-state', online[i] ? 'online' : 'offline');
      refs.parked[i].setAttribute('opacity', f.parked[i] && online[i] ? 1 : 0);
      const pr = f.pulse[i];
      refs.pulse[i].setAttribute('opacity', pr > 0 ? (0.8 * (1 - pr)).toFixed(3) : 0);
      refs.pulse[i].setAttribute('r', (26 + pr * 18).toFixed(1));
      refs.routes[i].forEach((p) => p.setAttribute('stroke-dasharray', online[i] ? '' : '2 6'));
    });

    refs.ghostRect.style.stroke = f.ghost > 0 ? `rgba(201,162,74,${(0.4 + 0.6 * f.ghost).toFixed(2)})` : '';
    refs.ghostRect.style.strokeDasharray = f.ghost > 0.5 ? 'none' : '';
    refs.ghostText.style.fill = f.ghost > 0.5 ? 'var(--gold)' : '';

    // Ciphertext keeps shimmering while the relays hold it, then settles.
    const tick = f.beat === 3 ? f.tick : 3;
    const lines = refs.ro;
    const n = L.compact ? 30 : 36;
    if (f.readout === 'empty') {
      lines[0].textContent = '—';
      lines[1].textContent = detail ? '' : 'Nothing has arrived yet.';
      lines[2].textContent = '';
    } else if (f.readout === 'nothing') {
      lines[0].textContent = '—';
      lines[1].textContent = 'No relay online. Nothing sent.';
      lines[2].textContent = '';
    } else if (detail) {
      lines[0].textContent = `kind 30078 · d: pksync-v5-${hex(L.compact ? 10 : 16, 1, 0)}…`;
      lines[1].textContent = `content: ${hex(n - 9, 2, tick)}…`;
      lines[2].textContent = `sig: ${hex(n - 5, 3, 0)}…`;
    } else {
      lines[0].textContent = hex(n, 2, tick).replace(/(.{4})/g, '$1 ').trim();
      lines[1].textContent = 'Unreadable to the relay. And to us.';
      lines[2].textContent = '';
    }
  }

  // ---------- Controller ----------

  function init(root) {
    const detail = root.dataset.detail === 'true';
    const svg = root.querySelector('svg');
    const caption = root.querySelector('.viz__caption');
    const playBtn = root.querySelector('[data-act="play"]');
    const beatsBox = root.querySelector('.viz__beats');
    const toggles = Array.from(root.querySelectorAll('.relay-toggle'));
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    const override = new URLSearchParams(location.search).get('vizframe');

    const online = RELAYS.map(() => true);
    let L = null;
    let refs = null;
    let t = 0;
    let playing = !reduce.matches && override === null;
    let visible = false;
    let raf = 0;
    let last = 0;
    let shownBeat = -1;

    if (override !== null) t = clamp(Number(override) || 0, 0, PERIOD - 1);
    else if (!playing) t = BEATS[BEATS.length - 1].end - 1;

    const dots = BEATS.map((b, i) => {
      const d = document.createElement('button');
      d.type = 'button';
      d.className = 'viz__beat';
      d.setAttribute('aria-label', `Step ${i + 1} of ${BEATS.length}`);
      d.addEventListener('click', () => go(i));
      beatsBox.appendChild(d);
      return d;
    });

    function layout() {
      const next = root.clientWidth < 620 ? compactLayout() : desktopLayout();
      if (!L || L.compact !== next.compact) {
        L = next;
        refs = build(svg, L, detail);
        svg.querySelectorAll('.relay-hit').forEach((g) => {
          g.addEventListener('click', () => toggle(Number(g.dataset.relay)));
        });
        shownBeat = -1;
      }
      draw();
    }

    function captionFor(b) {
      const anyOnline = online.some(Boolean);
      if (!anyOnline && CAPTIONS.noRelay[b]) return CAPTIONS.noRelay[b];
      return (detail ? CAPTIONS.detail : CAPTIONS.plain)[b];
    }

    function draw() {
      const f = project(t, online, L);
      render(refs, f, online, L, detail);
      if (f.beat !== shownBeat) {
        shownBeat = f.beat;
        caption.innerHTML = captionFor(f.beat);
        dots.forEach((d, i) => (i === f.beat ? d.setAttribute('aria-current', 'step') : d.removeAttribute('aria-current')));
      }
    }

    function frame(now) {
      raf = 0;
      if (!playing || !visible || document.hidden) return;
      const dt = last ? Math.min(now - last, 100) : 0;
      last = now;
      t = (t + dt) % PERIOD;
      draw();
      raf = requestAnimationFrame(frame);
    }

    function run() {
      if (playing && visible && !document.hidden && !raf) {
        last = 0;
        raf = requestAnimationFrame(frame);
      }
    }

    function setPlaying(p) {
      playing = p;
      playBtn.setAttribute('aria-label', p ? 'Pause' : 'Play');
      playBtn.innerHTML = p
        ? '<svg viewBox="0 0 14 14" aria-hidden="true"><rect x="2" y="1" width="3.5" height="12" fill="currentColor"/><rect x="8.5" y="1" width="3.5" height="12" fill="currentColor"/></svg>'
        : '<svg viewBox="0 0 14 14" aria-hidden="true"><path d="M3 1 L13 7 L3 13 Z" fill="currentColor"/></svg>';
      // Announce captions only when the viewer is stepping by hand.
      caption.setAttribute('aria-live', p ? 'off' : 'polite');
      run();
    }

    // Paused: show each beat's finished state. Playing: start the beat.
    function go(i) {
      const b = BEATS[(i + BEATS.length) % BEATS.length];
      t = playing ? b.start : b.end - 1;
      shownBeat = -1;
      draw();
    }

    function toggle(i) {
      online[i] = !online[i];
      toggles[i].setAttribute('aria-pressed', String(online[i]));
      shownBeat = -1;
      draw();
    }

    playBtn.addEventListener('click', () => setPlaying(!playing));
    root.querySelector('[data-act="prev"]').addEventListener('click', () => go(beatAt(t) - 1));
    root.querySelector('[data-act="next"]').addEventListener('click', () => go(beatAt(t) + 1));
    toggles.forEach((b, i) => b.addEventListener('click', () => toggle(i)));

    new ResizeObserver(layout).observe(root);
    new IntersectionObserver(
      (entries) => {
        visible = entries[0].isIntersecting;
        run();
      },
      { rootMargin: '120px' }
    ).observe(root);
    document.addEventListener('visibilitychange', run);

    layout();
    setPlaying(playing);
  }

  document.querySelectorAll('[data-relay-viz]').forEach(init);
})();
