// Shared emulator helpers for driver.mjs and verify-webauthn.mjs: adb,
// Chrome DevTools Protocol sessions on the app WebView and Chrome, uiautomator
// text lookup, and screenshots with the status bar in demo mode.

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const PKG = 'bond.passkey.app';

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function adb(...args) {
  return execFileSync('adb', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }).trim();
}

export function adbShell(cmd) {
  return adb('shell', cmd);
}

// ---------------------------------------------------------------------------
// CDP plumbing

export async function findDevToolsSocket(match, what, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const name = match();
    if (name) return name;
    await sleep(500);
  }
  throw new Error(`No DevTools socket for ${what}`);
}

export const unixSockets = () => adbShell('cat /proc/net/unix');

/** The app's WebView. Its DevTools socket is named after the app's pid. */
export function appSocket() {
  const pid = adbShell(`pidof ${PKG} || true`).split(/\s+/)[0];
  const name = `webview_devtools_remote_${pid}`;
  return pid && unixSockets().includes(`@${name}`) ? name : null;
}

export function chromeSocket() {
  return unixSockets().includes('@chrome_devtools_remote') ? 'chrome_devtools_remote' : null;
}

/** Open a CDP session on the first page of `socket` whose URL contains `urlPart`. */
export async function connectPage(socket, port, urlPart) {
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

export async function evaluate(expression, session) {
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

export async function waitFor(expression, what, timeoutMs = 20_000, session) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await evaluate(`Boolean(${expression})`, session)) return;
    await sleep(250);
  }
  throw new Error(`Timed out waiting for ${what}`);
}

/**
 * Status bar demo mode: 9:41, full battery and wifi, no notifications.
 * Sent before every shot, because SystemUI ignores demo commands that arrive
 * too soon after boot, and resending them is harmless.
 */
export function statusBarDemo() {
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

export async function screenshot(name, dir) {
  statusBarDemo();
  await sleep(500);
  mkdirSync(dir, { recursive: true });
  const png = execFileSync('adb', ['exec-out', 'screencap', '-p'], {
    maxBuffer: 64 * 1024 * 1024,
  });
  const file = join(dir, `${name}.png`);
  writeFileSync(file, png);
  console.log(`[device] saved ${file} (${png.length} bytes)`);
}

/** Centre of the on-screen element whose text is `text` (from a uiautomator dump). */
export function findText(text) {
  adbShell('uiautomator dump /sdcard/ui.xml > /dev/null');
  const xml = adbShell('cat /sdcard/ui.xml');
  const escaped = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = xml.match(new RegExp(`text="${escaped}"[^>]*bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"`));
  if (!match) return null;
  const [x1, y1, x2, y2] = match.slice(1).map(Number);
  return { x: Math.round((x1 + x2) / 2), y: Math.round((y1 + y2) / 2) };
}

export function tapText(text) {
  const at = findText(text);
  if (!at) return false;
  adb('shell', 'input', 'tap', String(at.x), String(at.y));
  return true;
}

export async function waitForText(text, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (findText(text)) return;
    await sleep(500);
  }
  throw new Error(`Timed out waiting for "${text}" on screen`);
}

export const focusedWindow = () => adbShell('dumpsys window | grep mCurrentFocus || true');

/** Press Back until the focused window matches `pattern` (dismisses the system sheets). */
export async function backUntil(pattern, what) {
  for (let i = 0; i < 4; i++) {
    if (pattern.test(focusedWindow())) return;
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK');
    await sleep(1000);
  }
  if (!pattern.test(focusedWindow())) throw new Error(`could not get back to ${what}`);
}

export const CHROME_PAGE = /com\.android\.chrome\/.*ChromeTabbedActivity/;

