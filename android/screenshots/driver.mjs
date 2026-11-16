#!/usr/bin/env node
// Drives the Passkey.bond WebView over the Chrome DevTools Protocol and saves
// Play Store screenshots with `adb exec-out screencap`. Run by run.sh inside
// the screenshot container, after the emulator has booted and the APK is
// installed and launched. Needs Node >= 22 (built-in WebSocket), no npm deps.
//
// Everything is seeded the way a user would do it: a plain JSON backup pasted
// into Tools > Import, a 2FA code typed into Add > Add 2FA manually, a sync
// chain created on the Sync tab. Demo data is fake; services are well-known
// public sites and accounts use example.com.

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { webcrypto as crypto } from 'node:crypto';

const PKG = 'bond.passkey.app';
const OUT = process.env.OUT_DIR || 'android/play/screenshots';
const APP_CDP_PORT = 9222;
const CHROME_CDP_PORT = 9223;
const PIN = process.env.DEVICE_PIN || '1234';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const log = (...args) => console.log('[driver]', ...args);

function adb(...args) {
  return execFileSync('adb', args, { encoding: 'utf8' }).trim();
}

function adbShell(cmd) {
  return adb('shell', cmd);
}

// ---------------------------------------------------------------------------
// CDP plumbing

async function findDevToolsSocket(match, what, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const name = match();
    if (name) return name;
    await sleep(500);
  }
  throw new Error(`No DevTools socket for ${what}`);
}

const unixSockets = () => adbShell('cat /proc/net/unix');

/** The app's WebView. Its DevTools socket is named after the app's pid. */
function appSocket() {
  const pid = adbShell(`pidof ${PKG} || true`).split(/\s+/)[0];
  const name = `webview_devtools_remote_${pid}`;
  return pid && unixSockets().includes(`@${name}`) ? name : null;
}

function chromeSocket() {
  return unixSockets().includes('@chrome_devtools_remote') ? 'chrome_devtools_remote' : null;
}

/** Open a CDP session on the first page of `socket` whose URL contains `urlPart`. */
async function connectPage(socket, port, urlPart) {
  adb('forward', `tcp:${port}`, `localabstract:${socket}`);
  const deadline = Date.now() + 30_000;
  let page;
  while (!page && Date.now() < deadline) {
    try {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      page = targets.find((t) => t.type === 'page' && t.url.includes(urlPart));
    } catch {
      // forward not ready yet
    }
    if (!page) await sleep(500);
  }
  if (!page) throw new Error(`No DevTools page with URL containing ${urlPart}`);
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error('CDP WebSocket failed to open'));
  });
  let nextId = 1;
  const pending = new Map();
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(`${msg.error.message} (${msg.error.code})`));
      else resolve(msg.result);
    }
  };
  // A backgrounded page stops answering, so every call has a deadline.
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`CDP ${method} timed out`));
      }, 20_000);
      pending.set(id, {
        resolve: (value) => (clearTimeout(timer), resolve(value)),
        reject: (error) => (clearTimeout(timer), reject(error)),
      });
      ws.send(JSON.stringify({ id, method, params }));
    });
  return { send, close: () => ws.close() };
}

let cdp;

async function evaluate(expression, session = cdp) {
  const result = await session.send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  });
  if (result.exceptionDetails) {
    const detail = result.exceptionDetails.exception?.description || result.exceptionDetails.text;
    throw new Error(`evaluate failed: ${detail}\n  in: ${expression.slice(0, 200)}`);
  }
  return result.result.value;
}

async function waitFor(expression, what, timeoutMs = 20_000, session = cdp) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await evaluate(`Boolean(${expression})`, session)) return;
    await sleep(250);
  }
  throw new Error(`Timed out waiting for ${what}`);
}

// ---------------------------------------------------------------------------
// UI helpers. These go through the same DOM events a tap or typing fires, so
// the app's own handlers do the work.

const js = (value) => JSON.stringify(value);

async function tab(name) {
  await evaluate(`document.querySelector('[data-tab=${js(name)}]').click()`);
  await waitFor(`document.querySelector('[data-tab=${js(name)}].active')`, `${name} tab`);
}

async function type(selector, value) {
  await evaluate(`(() => {
    const el = document.querySelector(${js(selector)});
    if (!el) throw new Error('missing ' + ${js(selector)});
    el.focus();
    el.value = ${js(value)};
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.blur();
  })()`);
}

async function click(selector) {
  await evaluate(`(() => {
    const el = document.querySelector(${js(selector)});
    if (!el) throw new Error('missing ' + ${js(selector)});
    el.click();
  })()`);
}

async function scrollTo(selector, block = 'start') {
  await evaluate(`(() => {
    const el = ${selector ? `document.querySelector(${js(selector)})` : 'null'};
    if (el) el.scrollIntoView({ block: ${js(block)} });
    else window.scrollTo(0, 0);
  })()`);
}

const statusPanel = `document.querySelector('.shell > .panel.status, .shell > .panel.bad, .shell > .panel.warn, .lock > .panel')`;

async function statusText() {
  return evaluate(`${statusPanel}?.textContent?.trim() || ''`);
}

/** Wait for the in-app status banner (3 s) and its native toast (2 s) to clear. */
async function settle() {
  await waitFor(`!${statusPanel}`, 'status banner to clear', 15_000);
  await waitForNoToast();
  await sleep(400);
}

async function waitForNoToast(timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const windows = adbShell('dumpsys window windows | grep -c "Toast" || true');
    if (windows === '0') return;
    await sleep(300);
  }
}

/** Keep TOTP countdown bars mostly full: wait for the start of a 30 s window. */
async function waitForFreshTotpWindow() {
  const seconds = Number(await evaluate('Math.floor(Date.now() / 1000) % 30'));
  if (seconds > 4) await sleep((30 - seconds + 1) * 1000);
}

/**
 * Status bar demo mode: 9:41, full battery and wifi, no notifications.
 * Sent before every shot, because SystemUI ignores demo commands that arrive
 * too soon after boot, and resending them is harmless.
 */
function statusBarDemo() {
  const demo = (...args) =>
    adb('shell', 'am', 'broadcast', '-a', 'com.android.systemui.demo', '-e', 'command', ...args);
  demo('enter');
  demo('clock', '-e', 'hhmm', '0941');
  demo('battery', '-e', 'level', '100', '-e', 'plugged', 'false', '-e', 'powersave', 'false');
  // No mobile icon: the emulator has no cell data, so it would show "!".
  // Hide it before showing wifi; the other order hides wifi too.
  demo('network', '-e', 'mobile', 'hide');
  demo('network', '-e', 'wifi', 'show', '-e', 'level', '4', '-e', 'fully', 'true');
  demo('notifications', '-e', 'visible', 'false');
  const hide = ['bluetooth', 'location', 'alarm', 'sync', 'mute', 'volume', 'speakerphone', 'tty', 'eri', 'cast', 'hotspot'];
  demo('status', ...hide.flatMap((icon) => ['-e', icon, 'hide']));
}

async function screenshot(name, dir = OUT) {
  statusBarDemo();
  await sleep(500);
  mkdirSync(dir, { recursive: true });
  const png = execFileSync('adb', ['exec-out', 'screencap', '-p'], {
    maxBuffer: 64 * 1024 * 1024,
  });
  const file = join(dir, `${name}.png`);
  writeFileSync(file, png);
  log(`saved ${file} (${png.length} bytes)`);
}

// ---------------------------------------------------------------------------
// Demo data

const DAY = 24 * 60 * 60 * 1000;

const base64 = (bytes) => Buffer.from(bytes).toString('base64');
const base64Url = (bytes) => Buffer.from(bytes).toString('base64url');

async function demoPasskey(rpId, name, displayName, ageDays, counter) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const credentialId = base64Url(crypto.getRandomValues(new Uint8Array(16)));
  const createdAt = Date.now() - ageDays * DAY;
  return {
    id: credentialId,
    credentialId,
    type: 'public-key',
    rpId,
    origin: `https://${rpId}`,
    user: { id: base64Url(crypto.getRandomValues(new Uint8Array(16))), name, displayName },
    privateKey: base64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))),
    publicKey: base64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))),
    createdAt,
    updatedAt: createdAt,
    counter,
  };
}

function demoTotp(issuer, account, secret, ageDays) {
  return {
    id: crypto.randomUUID(),
    type: 'totp',
    issuer,
    account,
    // Base32 setup keys made up for the screenshots (not tied to any account).
    secretB64: Buffer.from(base32Decode(secret)).toString('base64'),
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    counter: 0,
    createdAt: Date.now() - ageDays * DAY,
  };
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of input.replace(/=+$/, '').toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

async function demoBackup() {
  return {
    version: 'passkey-bond-android-0.1.0',
    exportType: 'full',
    exportedAt: Date.now(),
    passkeys: [
      await demoPasskey('github.com', 'alexmorgan', 'Alex Morgan', 41, 37),
      await demoPasskey('google.com', 'alex@example.com', 'Alex Morgan', 63, 112),
      await demoPasskey('login.microsoft.com', 'alex@example.com', 'Alex Morgan', 12, 9),
      // For the Chrome sign-in sheet (06): webauthn.io is the public WebAuthn demo site.
      await demoPasskey('webauthn.io', 'alex@example.com', 'alex@example.com', 3, 2),
    ],
    totpEntries: [
      demoTotp('AWS', 'admin@example.com', 'MZXW6YTBOI5GQ3DFNRXSA4LVNF2GKZDB', 90),
      demoTotp('GitHub', 'alexmorgan', 'NB2W45DFOIQGC3TEEBYGK4TTN5XGC3DM', 75),
      demoTotp('Google', 'alex@example.com', 'KRUGKIDROVUWG2ZAMJZG653OEBTG66BA', 60),
    ],
  };
}

// Typed into Add 2FA manually on camera, then added.
const MANUAL_TOTP = {
  issuer: 'Dropbox',
  account: 'alex@example.com',
  secret: 'JV4WIZLNN5SGK3DPN5VXGIDSMVQWY4TU',
};

// ---------------------------------------------------------------------------
// Shots

/** Tap the on-screen element whose text is `text` (from a uiautomator dump). */
function findText(text) {
  adbShell('uiautomator dump /sdcard/ui.xml > /dev/null');
  const xml = adbShell('cat /sdcard/ui.xml');
  const escaped = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = xml.match(new RegExp(`text="${escaped}"[^>]*bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"`));
  if (!match) return null;
  const [x1, y1, x2, y2] = match.slice(1).map(Number);
  return { x: Math.round((x1 + x2) / 2), y: Math.round((y1 + y2) / 2) };
}

function tapText(text) {
  const at = findText(text);
  if (!at) return false;
  adb('shell', 'input', 'tap', String(at.x), String(at.y));
  return true;
}

async function waitForText(text, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (findText(text)) return;
    await sleep(500);
  }
  throw new Error(`Timed out waiting for "${text}" on screen`);
}

const focusedWindow = () => adbShell('dumpsys window | grep mCurrentFocus || true');

/** Press Back until the focused window matches `pattern` (dismisses the system sheets). */
async function backUntil(pattern, what) {
  for (let i = 0; i < 4; i++) {
    if (pattern.test(focusedWindow())) return;
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK');
    await sleep(1000);
  }
  if (!pattern.test(focusedWindow())) throw new Error(`could not get back to ${what}`);
}

const CHROME_PAGE = /com\.android\.chrome\/.*ChromeTabbedActivity/;

async function chromeShots() {
  adb('shell', 'am', 'start', '-W', '-a', 'android.intent.action.VIEW', '-d', 'https://webauthn.io/', 'com.android.chrome');
  const socket = await findDevToolsSocket(chromeSocket, 'Chrome', 30_000);
  const chrome = await connectPage(socket, CHROME_CDP_PORT, 'webauthn.io');
  try {
    await waitFor(`document.querySelector('#login-button')`, 'webauthn.io', 30_000, chrome).catch(() => {
      throw new Error('webauthn.io did not load');
    });
    // Chrome promos (notifications etc.) can cover the page on first launch.
    for (const label of ['No thanks', 'Not now', 'Got it']) tapText(label);
    await sleep(500);
    const page = (expression) => evaluate(expression, chrome);

    // 06: sign in with a saved passkey (discoverable: no username).
    await page(`document.querySelector('#input-email').value = ''; document.querySelector('#login-button').click()`);
    // The one-account sheet is headed "Google Password Manager" on this
    // image even though the entry is Passkey.bond's, so open "Sign-in options",
    // which names the provider on the entry ("Passkey • Passkey.bond").
    await waitForText('Sign-in options');
    await sleep(500);
    tapText('Sign-in options');
    await waitForText('For alex@example.com');
    await sleep(1000);
    await screenshot('06-passkey-signin');
    await backUntil(CHROME_PAGE, 'Chrome');
    await sleep(1000);

    // 07: create a new passkey, saved in Passkey.bond.
    await page(`(() => {
      const input = document.querySelector('#input-email');
      input.value = 'alex@example.com';
      input.dispatchEvent(new Event('input', { bubbles: true }));
      document.querySelector('#register-button').click();
    })()`);
    await waitForText('Save another way');
    await sleep(1000);
    await screenshot('07-passkey-create');
    await backUntil(CHROME_PAGE, 'Chrome');
  } finally {
    chrome.close();
  }
}

async function main() {
  const socket = await findDevToolsSocket(
    appSocket,
    'the app WebView (the system image must be a userdebug google_apis image, where WebView debugging is on for every app)'
  );
  cdp = await connectPage(socket, APP_CDP_PORT, 'passkey-bond.local');
  log('connected to WebView');
  await waitFor(`document.querySelector('[data-tab=vault]')`, 'app to boot', 60_000);

  // Seed: Tools > Import backup, with a plain JSON backup.
  await tab('tools');
  const backup = await demoBackup();
  await type('#import-json', JSON.stringify(backup, null, 2));
  await click('#import-vault');
  await waitFor(`/Imported \\d+ passkeys/.test(${statusPanel}?.textContent || '')`, 'import');
  log(await statusText());
  await settle();

  // 02-add: the manual form filled in, before Add code.
  await tab('add');
  await type('#totp-manual-form [name=issuer]', MANUAL_TOTP.issuer);
  await type('#totp-manual-form [name=account]', MANUAL_TOTP.account);
  await type('#totp-manual-form [name=secret]', MANUAL_TOTP.secret);
  await sleep(500);
  await screenshot('02-add');
  await evaluate(`document.getElementById('totp-manual-form').requestSubmit()`);
  await waitFor(`document.querySelector('[data-tab=vault].active')`, 'return to vault after add');
  await waitFor(`/2FA code added/.test(${statusPanel}?.textContent || '')`, 'add confirmation');
  await settle();

  // 01-vault
  await scrollTo(null);
  await waitForFreshTotpWindow();
  await sleep(1200); // the vault re-renders its codes every second
  await screenshot('01-vault');

  // 03-sync: create a chain, dismiss the recovery phrase.
  await tab('sync');
  await type('#create-sync-form [name=deviceName]', 'Pixel 7');
  await evaluate(`document.getElementById('create-sync-form').requestSubmit()`);
  await waitFor(`document.getElementById('ack-phrase')`, 'recovery phrase', 60_000);
  await click('#ack-phrase');
  await settle();
  // Give the relay connection a moment so the panel can say "connected".
  const connected = await evaluate(`new Promise((resolve) => {
    const deadline = Date.now() + 20000;
    const tick = () => {
      document.querySelector('[data-tab=sync]').click();
      const text = document.querySelector('#tab-content .panel .muted')?.textContent || '';
      if (/connected/.test(text)) resolve(true);
      else if (Date.now() > deadline) resolve(false);
      else setTimeout(tick, 500);
    };
    tick();
  })`);
  log(connected ? 'sync connected to a relay' : 'sync did not connect to a relay (shot says "Enabled")');
  await settle();
  await scrollTo(null);
  await sleep(300);
  await screenshot('03-sync');

  // 04-tools: auto-lock and backup.
  await tab('tools');
  await scrollTo(null);
  await sleep(300);
  await screenshot('04-tools');

  // 06/07: the Android passkey sheets over Chrome, with Passkey.bond as the
  // provider. Best effort: they depend on Chrome and on webauthn.io being
  // reachable, so a failure here skips them instead of failing the run.
  try {
    await chromeShots();
  } catch (error) {
    log(`skipped the Chrome passkey shots: ${error.message}`);
    await screenshot('chrome-skipped', join(OUT, 'debug'));
  }
  adb('shell', 'am', 'start', '-W', '-n', `${PKG}/.MainActivity`);
  await sleep(1000);

  // 05-locked: the vault lock. It needs a device screen lock, so set a PIN
  // only now (auto-lock would otherwise start counting).
  adb('shell', 'locksettings', 'set-pin', PIN);
  await tab('vault');
  await waitFor(`!document.getElementById('lock-btn').disabled`, 'lock button to enable');
  await click('#lock-btn');
  await waitFor(`document.getElementById('biometric-unlock-btn')`, 'lock screen');
  await sleep(500);
  await screenshot('05-locked');
  // The unlock prompt itself can't be captured: with no fingerprint enrolled
  // it is the system PIN screen, which is FLAG_SECURE and comes out black.

  cdp.close();
}

main().catch(async (error) => {
  console.error('[driver] FAILED:', error.stack || error);
  await screenshot('zz-failure').catch(() => {});
  process.exit(1);
});
