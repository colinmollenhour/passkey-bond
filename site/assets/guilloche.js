// Hero background: banknote-style guilloché bands around a slowly turning
// safe dial. Gold hairlines on black; strands drift in phase so the moiré
// shifts slowly. It pauses offscreen and in hidden tabs, and draws one still
// frame for prefers-reduced-motion.
(function () {
  'use strict';

  const GOLD = '201, 162, 74';
  const TAU = Math.PI * 2;
  const FRAME_MS = 1000 / 30;

  function init(canvas) {
    const hero = canvas.parentElement;
    const anchor = canvas.dataset.anchor ? document.querySelector(canvas.dataset.anchor) : null;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    let width = 0;
    let height = 0;
    let cx = 0;
    let cy = 0;
    let rm = 0;
    let compact = false;
    let visible = true;
    let raf = 0;
    let last = 0;
    const start = performance.now();

    function measure() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const box = hero.getBoundingClientRect();
      width = box.width;
      height = box.height;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      compact = width < 860;

      if (anchor && anchor.offsetParent !== null) {
        const a = anchor.getBoundingClientRect();
        cx = a.left - box.left + a.width / 2;
        cy = a.top - box.top + a.height / 2;
        rm = a.width / 2;
      } else {
        cx = width * parseFloat(canvas.dataset.cx || '0.82');
        cy = height * parseFloat(canvas.dataset.cy || '0.5');
        rm = Math.min(width, height) * parseFloat(canvas.dataset.r || '0.22');
      }
      // On phones the medallion is small; let the bands still reach across.
      if (compact) rm = Math.max(rm, 120);
    }

    // One guilloché band: `strands` closed curves, each a radial wave around
    // the centre, offset in phase from its neighbours.
    function band(t, o) {
      const steps = o.steps;
      ctx.beginPath();
      for (let s = 0; s < o.strands; s++) {
        const phase = (s / o.strands) * Math.PI * o.spread + t * o.drift;
        const breathe = 1 + 0.2 * Math.sin(t * 0.18 + s * 0.6 + o.seed);
        for (let i = 0; i <= steps; i++) {
          const th = (i / steps) * TAU + t * o.spin;
          const r =
            o.base * rm +
            o.amp * rm * breathe * Math.sin(o.lobes * th + phase) +
            o.amp2 * rm * Math.sin(o.lobes2 * th - phase * 0.5 + o.seed);
          const x = cx + r * Math.cos(th);
          const y = cy + r * Math.sin(th);
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
      }
      // On phones the bands run behind body text, so they sit back a little.
      ctx.strokeStyle = `rgba(${GOLD}, ${compact ? o.alpha * 0.6 : o.alpha})`;
      ctx.lineWidth = o.width;
      ctx.stroke();
    }

    // The dial: fine ticks, every tenth one longer, turning the other way.
    function dial(t) {
      const rot = -t * (TAU / 120);
      const inner = rm * 1.06;
      ctx.beginPath();
      for (let i = 0; i < 120; i++) {
        const th = (i / 120) * TAU + rot;
        const len = i % 10 === 0 ? rm * 0.075 : i % 5 === 0 ? rm * 0.045 : rm * 0.025;
        const c = Math.cos(th);
        const s = Math.sin(th);
        ctx.moveTo(cx + inner * c, cy + inner * s);
        ctx.lineTo(cx + (inner + len) * c, cy + (inner + len) * s);
      }
      ctx.strokeStyle = `rgba(${GOLD}, 0.6)`;
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx, cy, rm * 1.17, 0, TAU);
      ctx.strokeStyle = `rgba(${GOLD}, 0.3)`;
      ctx.stroke();
    }

    function draw(now) {
      // Start 30 s in, where the bands have already drifted apart.
      const t = 30 + (now - start) / 1000;
      ctx.clearRect(0, 0, width, height);
      const k = compact ? 0.65 : 1;
      dial(t);
      band(t, { base: 1.5, amp: 0.13, amp2: 0.03, lobes: 18, lobes2: 3, strands: Math.round(14 * k), spread: 1, drift: 0.14, spin: 0.01, seed: 0.3, steps: 720, alpha: 0.5, width: 0.7 });
      band(t, { base: 2.15, amp: 0.22, amp2: 0.06, lobes: 12, lobes2: 4, strands: Math.round(18 * k), spread: 2, drift: -0.1, spin: -0.008, seed: 1.7, steps: 720, alpha: 0.34, width: 0.7 });
      band(t, { base: 3.05, amp: 0.34, amp2: 0.1, lobes: 8, lobes2: 3, strands: Math.round(22 * k), spread: 1.5, drift: 0.07, spin: 0.005, seed: 4.1, steps: 640, alpha: 0.17, width: 0.7 });
      band(t, { base: 4.3, amp: 0.5, amp2: 0.12, lobes: 6, lobes2: 2, strands: Math.round(16 * k), spread: 2, drift: -0.05, spin: -0.004, seed: 2.2, steps: 560, alpha: 0.11, width: 0.7 });
    }

    function loop(now) {
      raf = 0;
      if (!visible || document.hidden || reduce.matches) return;
      if (now - last >= FRAME_MS) {
        last = now;
        draw(now);
      }
      raf = requestAnimationFrame(loop);
    }

    function kick() {
      if (reduce.matches) {
        draw(start);
        return;
      }
      if (!raf) raf = requestAnimationFrame(loop);
    }

    measure();
    draw(start);
    kick();

    new ResizeObserver(() => {
      measure();
      draw(performance.now());
    }).observe(hero);
    new IntersectionObserver(
      (entries) => {
        visible = entries[0].isIntersecting;
        if (visible) kick();
      },
      { rootMargin: '80px' }
    ).observe(hero);
    document.addEventListener('visibilitychange', kick);
    reduce.addEventListener('change', kick);
  }

  document.querySelectorAll('canvas[data-guilloche]').forEach(init);
})();
