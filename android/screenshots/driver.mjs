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

import { join } from 'node:path';
import { webcrypto as crypto } from 'node:crypto';
import * as device from './device.mjs';
import {
  PKG,
  sleep,
  adb,
  adbShell,
  findDevToolsSocket,
  appSocket,
  chromeSocket,
  connectPage,
  tapText,
  waitForText,
  backUntil,
  CHROME_PAGE,
} from './device.mjs';

const OUT = process.env.OUT_DIR || 'android/play/screenshots';
const APP_CDP_PORT = 9222;
const CHROME_CDP_PORT = 9223;
const PIN = process.env.DEVICE_PIN || '1234';

const log = (...args) => console.log('[driver]', ...args);

let cdp;
const evaluate = (expression, session = cdp) => device.evaluate(expression, session);
const waitFor = (expression, what, timeoutMs = 20_000, session = cdp) =>
  device.waitFor(expression, what, timeoutMs, session);
const screenshot = (name, dir = OUT) => device.screenshot(name, dir);

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
