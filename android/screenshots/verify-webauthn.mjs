#!/usr/bin/env node
// End-to-end passkey check: registers a new passkey on webauthn.io in Chrome
// with Passkey.bond as the Credential Manager provider, then signs in with it
// (discoverable, no username). Run by run.sh with MODE=verify-webauthn, after
// the provider self-test. Exit codes: 0 pass, 1 fail, 3 inconclusive
// (webauthn.io unreachable). Evidence goes to OUT_DIR: a screenshot per step
// and the relevant logcat lines.

import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  sleep,
  adb,
  adbShell,
  findDevToolsSocket,
  chromeSocket,
  connectPage,
  evaluate,
  waitFor,
  findText,
  tapText,
  waitForText,
  focusedWindow,
  screenshot,
  CHROME_PAGE,
} from './device.mjs';

const OUT = process.env.OUT_DIR || 'android/screenshots/out/verify';
const PIN = process.env.DEVICE_PIN || '1234';
const CHROME_CDP_PORT = 9223;
const log = (...args) => console.log('[verify]', ...args);

class Inconclusive extends Error {}

let chrome;
const page = (expression) => evaluate(expression, chrome);

/** webauthn.io's result banner, e.g. "Success! Now try to authenticate...". */
const bannerText = () =>
  page(`[...document.querySelectorAll('.alert')].map((e) => e.innerText.trim()).filter(Boolean).join(' | ')`);

/**
 * Tap Continue on the system passkey sheet, then answer the device PIN prompt
 * (user verification) until Chrome is back in front. The PIN screen is
 * secure, so it screenshots black, but adb input still reaches it.
 */
async function confirmSheet(sheetText, step) {
  await waitForText(sheetText, 30_000);
  await screenshot(`${step}-sheet`, OUT);
  if (!tapText('Continue')) throw new Error(`no Continue button on the ${step} sheet`);
  const deadline = Date.now() + 45_000;
  let pinEntered = false;
  while (Date.now() < deadline) {
    const focus = focusedWindow();
    if (CHROME_PAGE.test(focus)) return;
    if (/BiometricPrompt|Keyguard|ConfirmDeviceCredential/.test(focus) && !pinEntered) {
      await sleep(800);
      adb('shell', 'input', 'text', PIN);
      adb('shell', 'input', 'keyevent', 'KEYCODE_ENTER');
      pinEntered = true;
      log(`${step}: entered the device PIN for user verification`);
    }
    await sleep(500);
  }
  throw new Error(`${step}: Chrome did not come back after Continue (focus: ${focusedWindow()})`);
}

function chromeRejections() {
  const lines = adbShell('logcat -d -v time')
    .split('\n')
    .filter((line) =>
      /[A-Z]\/(CredentialManager|CredentialSelector)\(|E\/AndroidRuntime\(|MojoClassFromJSON|fido2credentialrequest/.test(line)
    );
  writeFileSync(join(OUT, 'logcat.txt'), lines.join('\n') + '\n');
  return lines.filter((line) => /MojoClassFromJSON|fido2credentialrequest.*ERROR/.test(line));
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  // A screen lock, as on a real phone, so the provider asks for user verification.
  adb('shell', 'locksettings', 'set-pin', PIN);
  adb('logcat', '-c');

  adb('shell', 'am', 'start', '-W', '-a', 'android.intent.action.VIEW', '-d', 'https://webauthn.io/', 'com.android.chrome');
  const socket = await findDevToolsSocket(chromeSocket, 'Chrome', 30_000);
  chrome = await connectPage(socket, CHROME_CDP_PORT, 'webauthn.io').catch((error) => {
    throw new Inconclusive(`webauthn.io did not open: ${error.message}`);
  });
  await waitFor(`document.querySelector('#register-button')`, 'webauthn.io', 45_000, chrome).catch(() => {
    throw new Inconclusive('webauthn.io did not load');
  });
  for (const label of ['No thanks', 'Not now', 'Got it']) tapText(label);

  // 1. Register a new passkey.
  const username = `passkeybond-verify-${Date.now()}`;
  await page(`(() => {
    const input = document.querySelector('#input-email');
    input.value = ${JSON.stringify(username)};
    input.dispatchEvent(new Event('input', { bubbles: true }));
    document.querySelector('#register-button').click();
  })()`);
  await confirmSheet('Save another way', '1-register');
  await waitFor(`document.querySelector('.alert')?.innerText.trim()`, 'registration result', 30_000, chrome);
  const registration = await bannerText();
  await screenshot('1-register-result', OUT);
  log(`registration: "${registration}"`);
  if (!/^Success/i.test(registration)) throw new Error(`registration failed: ${registration}`);

  // 2. Sign in with it, discoverable (no username), as passkey sign-in usually is.
  await page(`(() => {
    const input = document.querySelector('#input-email');
    input.value = '';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    document.querySelector('#login-button').click();
  })()`);
  if (!findText(username)) await waitForText(username, 30_000);
  await confirmSheet(username, '2-signin');
  await waitFor(
    `location.pathname === '/profile' || document.querySelector('.alert')?.innerText.trim()`,
    'sign-in result',
    30_000,
    chrome
  );
  const signedIn = await page(`location.pathname === '/profile' && document.body.innerText.includes("You're logged in")`);
  const signin = signedIn ? "You're logged in! (webauthn.io/profile)" : await bannerText();
  await screenshot('2-signin-result', OUT);
  log(`sign-in: "${signin}"`);
  if (!signedIn) throw new Error(`sign-in failed: ${signin}`);

  const rejections = chromeRejections();
  if (rejections.length) throw new Error(`Chrome rejected a response:\n${rejections.join('\n')}`);
  log('logcat: no MojoClassFromJSON or FIDO request errors');
  log('PASS');
}

main()
  .then(() => process.exit(0))
  .catch(async (error) => {
    try {
      const rejections = chromeRejections();
      if (rejections.length) console.error(rejections.join('\n'));
      await screenshot('zz-failure', OUT);
    } catch {
      // best effort
    }
    if (error instanceof Inconclusive) {
      log(`INCONCLUSIVE: ${error.message}`);
      process.exit(3);
    }
    console.error('[verify] FAIL:', error.message);
    process.exit(1);
  });
