// End-to-end: unlocking the vault with a passkey, in the built extension with
// the production KDF and Chromium's own WebAuthn client. A PIN'd vault from
// before the wrapped data key is unlocked through the popup, which moves it to
// the new storage format; a passkey on a CDP virtual authenticator with PRF is
// added on the extension's unlock page and opens the vault after a lock and
// after a service worker restart; a second passkey on a second authenticator
// does the same; the PIN keeps working; and Options renames and removes
// passkeys and turns the lock off.
//
// Every ceremony runs in one tab, the one the popup's offer opens: a virtual
// authenticator and its credentials belong to the tab they were attached to.
// They survive that tab changing its URL hash, which is how the page switches
// between unlocking and adding a passkey.
//
//   npm run build:chrome && node tests/e2e/passkey-unlock.test.cjs
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const DIST = path.resolve(__dirname, '../../dist');
const PIN = '482916';
const SENTINEL = { kdf: 'wrapped-data-key', version: 1 };

const PASSKEY = {
  id: 'cred-legacy',
  credentialId: 'cred-legacy',
  type: 'public-key',
  rpId: 'legacy.example',
  origin: 'https://legacy.example',
  user: { name: 'old@legacy.example', displayName: 'Old' },
  publicKey: 'BASE64-PUBLIC-KEY',
  privateKey: 'BASE64-PRIVATE-KEY',
  createdAt: 1700000000000,
  counter: 1,
  backupEligible: true,
  backupState: true,
  backupSource: 'created',
};

// The unlock page shows one of these per URL hash.
const VIEWS = {
  '#unlock': '#unlock-view',
  '#enroll': '#enroll-view',
  '#reset-secret': '#reset-view',
};

let context;
let extensionId;
/** The long-lived unlock.html tab, and the CDP session its authenticators hang off. */
let ceremony;
let webauthn;
/** Virtual authenticators: `laptop` is a platform one, `key` a USB one. */
const authenticators = {};
/** The unlock record as it was right after the move to the new format. */
let migrated;
const consoleErrors = [];

before(async () => {
  assert.ok(fs.existsSync(path.join(DIST, 'unlock.html')), 'run npm run build:chrome first');
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'passkey-bond-e2e-unlock-'));
  context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });
  context.setDefaultTimeout(20000);
  // Every tab, including the ones the popup and Options open themselves.
  context.on('page', (page) => {
    const name = () => path.basename(new URL(page.url()).pathname) || page.url();
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(`${name()}: ${msg.text()}`);
    });
    page.on('pageerror', (error) => consoleErrors.push(`${name()}: ${error}`));
  });
  const worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
  extensionId = new URL(worker.url()).host;

  // A PIN'd vault as builds before KDF records left it: PBKDF2-SHA256 (100k)
  // over the PIN and passext_encryption_salt, values sealed with AES-256-GCM.
  await worker.evaluate(
    async ([pin, passkey]) => {
      const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const material = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(pin),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      const seal = async (text) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          new TextEncoder().encode(text)
        );
        return { data: b64(data), iv: b64(iv), salt: '', version: '2.0' };
      };
      await chrome.storage.local.set({
        passext_encryption_salt: b64(salt),
        passext_master_key_check: await seal('passkey-bond-check'),
        passext_encrypted_passkeys: await seal(JSON.stringify([passkey])),
      });
    },
    [PIN, PASSKEY]
  );
});

after(async () => {
  await context?.close();
});

async function openPage(name) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/${name}`);
  return page;
}

// Storage and messages go through an extension page, not the service worker
// handle: the worker is stopped and replaced part-way through.
const stored = (keys, page = ceremony) => page.evaluate((k) => chrome.storage.local.get(k), keys);
const send = (type, payload, page = ceremony) =>
  page.evaluate((message) => chrome.runtime.sendMessage(message), { type, payload });
const unlockRecord = async (page = ceremony) =>
  (await stored(['passext_vault_unlock'], page)).passext_vault_unlock;
const vaultState = (page = ceremony) => send('IS_SECURE_STORAGE_UNLOCKED', undefined, page);

async function lockVault() {
  await send('LOCK_SECURE_STORAGE');
  assert.equal((await vaultState()).isUnlocked, false);
}

async function waitUntilUnlocked() {
  await ceremony.waitForFunction(
    async () =>
      (await chrome.runtime.sendMessage({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked ===
      true,
    null,
    { polling: 200 }
  );
}

/** The popup, in a tab, once it shows the seeded record: proof the vault decrypts. */
async function popupListsTheRecord() {
  const popup = await openPage('popup.html');
  await popup.locator('.passkey-item', { hasText: 'legacy.example' }).waitFor();
  return popup;
}

/** A tab an extension page opens for itself when `action` runs. */
async function tabOpenedBy(action) {
  const [tab] = await Promise.all([context.waitForEvent('page'), action()]);
  await tab.waitForURL(/unlock\.html/);
  return tab;
}

/**
 * Switch the long-lived tab to a mode by URL hash. Asking for the mode it is
 * already in goes through another one first, so the view starts afresh.
 */
async function showMode(hash) {
  const current = await ceremony.evaluate(() => location.hash);
  if (current === hash) {
    const other = hash === '#unlock' ? '#enroll' : '#unlock';
    await ceremony.evaluate((h) => {
      location.hash = h;
    }, other);
    await ceremony.locator(VIEWS[hash]).waitFor({ state: 'hidden' });
  }
  await ceremony.evaluate((h) => {
    location.hash = h;
  }, hash);
  await ceremony.locator(VIEWS[hash]).waitFor({ state: 'visible' });
}

async function addAuthenticator(options) {
  const { authenticatorId } = await webauthn.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
      ...options,
    },
  });
  return authenticatorId;
}

/**
 * Leave one authenticator answering. With its presence simulation off, an
 * authenticator stays attached and keeps its credentials but never responds,
 * like a security key nobody touches.
 */
async function onlyAnswers(name) {
  for (const [key, authenticatorId] of Object.entries(authenticators)) {
    await webauthn.send('WebAuthn.setAutomaticPresenceSimulation', {
      authenticatorId,
      enabled: key === name,
    });
  }
}

/** The credentials an authenticator holds: `{ id (as the unlock record spells it), signCount }`. */
async function credentialsOn(name) {
  const { credentials } = await webauthn.send('WebAuthn.getCredentials', {
    authenticatorId: authenticators[name],
  });
  return credentials.map((credential) => ({
    id: credential.credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    signCount: credential.signCount,
  }));
}

async function startEnrollment(name) {
  await showMode('#enroll');
  await ceremony.fill('#enroll-secret', PIN);
  await ceremony.fill('#enroll-name', name);
  await ceremony.click('#enroll-create-btn');
}

/** Both clicks of adding a passkey: create it, then prove it opens the vault. */
async function enroll(name) {
  await startEnrollment(name);
  await ceremony.locator('#enroll-confirm-btn').waitFor({ state: 'visible' });
  await ceremony.click('#enroll-confirm-btn');
  await ceremony.locator('#enroll-done').waitFor({ state: 'visible' });
}

async function unlockWithPasskey() {
  await showMode('#unlock');
  await ceremony.click('#passkey-unlock-btn');
  await waitUntilUnlocked();
}

const bytesOf = (base64) => Buffer.from(base64, 'base64').length;

test('a PIN unlock in the popup moves an older vault to the wrapped data key', async () => {
  const popup = await openPage('popup.html');
  await popup.locator('#lock-screen').waitFor({ state: 'visible' });
  // No passkey unlocks this vault yet, so the lock screen is the PIN field alone.
  assert.equal(await popup.locator('#unlock-passkey-btn').isVisible(), false);
  await popup.fill('#unlock-password', PIN);
  await popup.click('#unlock-btn');
  await popup.locator('#main-container').waitFor({ state: 'visible' });
  await popup.locator('.passkey-item', { hasText: 'legacy.example' }).waitFor();

  const after = await stored(
    ['passext_vault_kdf', 'passext_vault_unlock', 'passext_encryption_salt'],
    popup
  );
  assert.deepEqual(after.passext_vault_kdf, SENTINEL);
  assert.equal(after.passext_encryption_salt, undefined);
  migrated = after.passext_vault_unlock;
  assert.equal(migrated.version, 1);
  assert.equal(bytesOf(migrated.vaultId), 16);
  assert.equal(migrated.pin.kdf.kdf, 'scrypt');
  assert.deepEqual(migrated.pin.kdf.params, { N: 131072, r: 8, p: 1 });
  assert.deepEqual(migrated.passkeys, []);
  await popup.close();
});

test('the popup offers passkey unlock and opens the page that adds one', async () => {
  const popup = await popupListsTheRecord();
  await popup.locator('#passkey-offer').waitFor({ state: 'visible' });
  ceremony = await tabOpenedBy(() => popup.click('#passkey-offer-setup-btn'));
  assert.equal(ceremony.url(), `chrome-extension://${extensionId}/unlock.html#enroll`);
  if (!popup.isClosed()) await popup.close();

  await ceremony.locator('#enroll-view').waitFor({ state: 'visible' });
  webauthn = await context.newCDPSession(ceremony);
  await webauthn.send('WebAuthn.enable', { enableUI: false });

  const methods = await send('GET_UNLOCK_METHODS');
  assert.equal(methods.success, true);
  assert.equal(methods.supported, true);
  assert.equal(methods.format, 'v1');
  assert.equal(methods.isUnlocked, true);
  assert.equal(methods.vaultId, migrated.vaultId);
  assert.deepEqual(methods.passkeys, []);
  assert.equal(methods.max, 8);
});

test('a passkey provider without PRF is refused and nothing is saved', async () => {
  const withoutPrf = await addAuthenticator({ hasPrf: false });
  await startEnrollment('No PRF');
  await ceremony.locator('#enroll-error').waitFor({ state: 'visible' });
  assert.match(
    await ceremony.locator('#enroll-error').textContent(),
    /does not support the PRF extension/
  );
  assert.equal(await ceremony.locator('#enroll-done').isVisible(), false);
  assert.deepEqual(await unlockRecord(), migrated);
  await webauthn.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: withoutPrf });
});

test('adds a passkey in two steps and stores only its public record', async () => {
  authenticators.laptop = await addAuthenticator({ transport: 'internal' });
  await startEnrollment('Laptop');
  // The PIN is six digits: the page says a passkey does not make it safer.
  await ceremony.locator('#enroll-short-pin-warning').waitFor({ state: 'visible' });
  await ceremony.locator('#enroll-confirm-btn').waitFor({ state: 'visible' });
  // Nothing is saved until the passkey has opened the vault's key once.
  assert.deepEqual((await unlockRecord()).passkeys, []);
  await ceremony.click('#enroll-confirm-btn');
  await ceremony.locator('#enroll-done').waitFor({ state: 'visible' });

  const record = await unlockRecord();
  assert.deepEqual(Object.keys(record).sort(), ['passkeys', 'pin', 'vaultId', 'version']);
  assert.equal(record.vaultId, migrated.vaultId);
  assert.deepEqual(record.pin, migrated.pin);
  assert.equal(record.passkeys.length, 1);
  const [passkey] = record.passkeys;
  assert.deepEqual(Object.keys(passkey).sort(), [
    'createdAt',
    'credentialId',
    'name',
    'prfSalt',
    'transports',
    'wrapped',
  ]);
  assert.equal(passkey.name, 'Laptop');
  assert.deepEqual(passkey.transports, ['internal']);
  assert.equal(bytesOf(passkey.prfSalt), 32);
  assert.deepEqual(Object.keys(passkey.wrapped).sort(), ['data', 'iv']);
  assert.equal(bytesOf(passkey.wrapped.iv), 12);
  assert.equal(bytesOf(passkey.wrapped.data), 48);
  assert.ok(Math.abs(Date.now() - passkey.createdAt) < 60000);
  // It is the credential the authenticator made, used once to create and once to confirm.
  const [held] = await credentialsOn('laptop');
  assert.equal(passkey.credentialId, held.id);

  const everything = await stored(null);
  assert.deepEqual(
    Object.keys(everything)
      .filter((key) => key.startsWith('passext_'))
      .sort(),
    [
      'passext_encrypted_passkeys',
      'passext_master_key_check',
      'passext_vault_kdf',
      'passext_vault_unlock',
    ]
  );
  assert.deepEqual((await vaultState()).passkeyUnlock, { supported: true, count: 1 });
});

test('the locked popup leads with the passkey, and the passkey opens the vault', async () => {
  await lockVault();
  const popup = await openPage('popup.html');
  await popup.locator('#lock-screen').waitFor({ state: 'visible' });
  await popup.locator('#unlock-passkey-btn').waitFor({ state: 'visible' });
  assert.equal(await popup.locator('#unlock-secret-form').isVisible(), false);
  // The popup cannot hold a passkey prompt (it closes when it loses focus), so it opens a tab.
  const tab = await tabOpenedBy(() => popup.click('#unlock-passkey-btn'));
  assert.equal(tab.url(), `chrome-extension://${extensionId}/unlock.html#unlock`);
  await tab.close();
  if (!popup.isClosed()) await popup.close();

  const [{ signCount: before }] = await credentialsOn('laptop');
  await unlockWithPasskey();
  const [{ signCount: after }] = await credentialsOn('laptop');
  assert.ok(after > before, 'the authenticator signed for this unlock');
  // The tab was not opened to unlock, so it stays open for the ceremonies that follow.
  assert.equal(ceremony.isClosed(), false);
  await (await popupListsTheRecord()).close();
});

test('a vault unlocked with a passkey stays unlocked when the service worker restarts', async () => {
  const session = await context.browser().newBrowserCDPSession();
  const workerTarget = async () =>
    (await session.send('Target.getTargets')).targetInfos.find(
      (target) =>
        target.type === 'service_worker' &&
        target.url.startsWith(`chrome-extension://${extensionId}/`)
    );
  const old = await workerTarget();
  assert.ok(old, 'the service worker is running');
  await session.send('Target.closeTarget', { targetId: old.targetId });

  // The next message starts a new worker, which has only the session copy of the key.
  const state = await vaultState();
  assert.equal(state.isSetup, true);
  assert.equal(state.isUnlocked, true);
  const fresh = await workerTarget();
  assert.ok(fresh, 'a new service worker answered');
  assert.notEqual(fresh.targetId, old.targetId);
  await session.detach();
  await (await popupListsTheRecord()).close();
});

test('a second passkey on another authenticator unlocks too, and each works alone', async () => {
  // The first authenticator stays attached but stops answering, so the new
  // passkey lands on the second one.
  authenticators.key = await addAuthenticator({ transport: 'usb' });
  await onlyAnswers('key');
  await enroll('Security key');

  const record = await unlockRecord();
  assert.deepEqual(
    record.passkeys.map((passkey) => passkey.name),
    ['Laptop', 'Security key']
  );
  const [onLaptop] = await credentialsOn('laptop');
  const [onKey] = await credentialsOn('key');
  assert.equal(record.passkeys[0].credentialId, onLaptop.id);
  assert.equal(record.passkeys[1].credentialId, onKey.id);
  assert.notEqual(record.passkeys[0].prfSalt, record.passkeys[1].prfSalt);
  assert.deepEqual(record.passkeys[1].transports, ['usb']);

  for (const name of ['key', 'laptop']) {
    const other = name === 'key' ? 'laptop' : 'key';
    await lockVault();
    await onlyAnswers(name);
    const [{ signCount: before }] = await credentialsOn(name);
    const [{ signCount: idle }] = await credentialsOn(other);
    await unlockWithPasskey();
    assert.ok((await credentialsOn(name))[0].signCount > before, `${name} signed`);
    assert.equal((await credentialsOn(other))[0].signCount, idle, `${other} did not`);
    await (await popupListsTheRecord()).close();
  }
});

test('a provider that already holds a passkey for this vault is not given another', async () => {
  await onlyAnswers('laptop');
  const before = await unlockRecord();
  await startEnrollment('Laptop again');
  await ceremony.locator('#enroll-error').waitFor({ state: 'visible' });
  assert.match(await ceremony.locator('#enroll-error').textContent(), /already holds a passkey/);
  assert.deepEqual(await unlockRecord(), before);
  assert.equal((await credentialsOn('laptop')).length, 1);
});

// Last of the ceremonies: once a virtual authenticator has failed user
// verification, Chromium refuses every later WebAuthn request in this tab,
// whatever the authenticators are set to afterwards.
test('a failed user verification unlocks nothing, and the PIN still works on the same page', async () => {
  await lockVault();
  await onlyAnswers('laptop');
  await webauthn.send('WebAuthn.setUserVerified', {
    authenticatorId: authenticators.laptop,
    isUserVerified: false,
  });
  await showMode('#unlock');
  await ceremony.click('#passkey-unlock-btn');
  await ceremony.locator('#unlock-error').waitFor({ state: 'visible' });
  assert.match(
    await ceremony.locator('#unlock-error').textContent(),
    /cancelled, timed out, or no matching passkey was available/
  );
  assert.equal((await vaultState()).isUnlocked, false);

  if (!(await ceremony.locator('#fallback-secret').isVisible())) {
    await ceremony.click('#fallback-toggle');
  }
  await ceremony.fill('#fallback-secret', PIN);
  await ceremony.click('#fallback-unlock-btn');
  await waitUntilUnlocked();
  assert.equal(ceremony.isClosed(), false);
});

test("the popup's second action unlocks with the PIN", async () => {
  await lockVault();
  const popup = await openPage('popup.html');
  await popup.locator('#lock-screen').waitFor({ state: 'visible' });
  await popup.locator('#unlock-passkey-btn').waitFor({ state: 'visible' });
  await popup.click('#unlock-use-secret-btn');
  await popup.locator('#unlock-secret-form').waitFor({ state: 'visible' });

  await popup.fill('#unlock-password', '000000');
  await popup.click('#unlock-btn');
  await popup.locator('#unlock-error').waitFor({ state: 'visible' });
  assert.match(await popup.locator('#unlock-error').textContent(), /Wrong PIN or passphrase/);

  await popup.fill('#unlock-password', PIN);
  await popup.click('#unlock-btn');
  await popup.locator('#main-container').waitFor({ state: 'visible' });
  await popup.locator('.passkey-item', { hasText: 'legacy.example' }).waitFor();
  // A passkey is set up, so the offer to add one is gone.
  assert.equal(await popup.locator('#passkey-offer').isVisible(), false);
  await popup.close();
});

test('Options lists the passkeys, renames one and removes one with the PIN', async () => {
  const options = await openPage('options.html');
  await options.click('.nav-item[data-section="security"]');
  await options.locator('#passkey-unlock-card').waitFor({ state: 'visible' });
  const rows = options.locator('#passkey-unlock-list .unlock-passkey-row');
  const rowCount = (count) =>
    options.waitForFunction(
      (n) => document.querySelectorAll('#passkey-unlock-list .unlock-passkey-row').length === n,
      count
    );
  await rowCount(2);
  const names = async () =>
    (await rows.locator('.unlock-passkey-name').allTextContents()).map((name) => name.trim());
  assert.deepEqual(await names(), ['Laptop', 'Security key']);

  // With a passkey set up, changing the PIN keeps the vault's key, and the form says so.
  await options.locator('#change-pw-keeps-key-note').waitFor({ state: 'visible' });
  assert.match(
    await options.locator('#change-pw-keeps-key-note').textContent(),
    /does not re-encrypt the vault/
  );

  // Renaming needs only an unlocked vault.
  const before = await unlockRecord(options);
  options.once('dialog', (dialog) => dialog.accept('Desk laptop'));
  await rows.filter({ hasText: 'Laptop' }).locator('.unlock-passkey-rename-btn').click();
  await rows.filter({ hasText: 'Desk laptop' }).waitFor();
  const renamed = await unlockRecord(options);
  assert.deepEqual(
    renamed.passkeys.map((passkey) => passkey.name),
    ['Desk laptop', 'Security key']
  );
  assert.deepEqual(
    renamed.passkeys.map(({ name, ...rest }) => rest),
    before.passkeys.map(({ name, ...rest }) => rest)
  );

  // Removing asks for the PIN, and a wrong one removes nothing.
  const securityKey = rows.filter({ hasText: 'Security key' });
  const removedId = await securityKey.getAttribute('data-credential-id');
  assert.equal(removedId, before.passkeys[1].credentialId);
  await securityKey.locator('.unlock-passkey-remove-btn').click();
  await options.locator('#passkey-unlock-remove-form').waitFor({ state: 'visible' });
  await options.fill('#passkey-unlock-remove-secret', '000000');
  await options.click('#passkey-unlock-remove-confirm-btn');
  await options.locator('#passkey-unlock-error').waitFor({ state: 'visible' });
  assert.match(
    await options.locator('#passkey-unlock-error').textContent(),
    /Wrong PIN or passphrase/
  );
  assert.deepEqual(await unlockRecord(options), renamed);

  if (!(await options.locator('#passkey-unlock-remove-form').isVisible())) {
    await securityKey.locator('.unlock-passkey-remove-btn').click();
  }
  await options.fill('#passkey-unlock-remove-secret', PIN);
  await options.click('#passkey-unlock-remove-confirm-btn');
  await rowCount(1);
  assert.deepEqual(await names(), ['Desk laptop']);
  const left = await unlockRecord(options);
  assert.deepEqual(left.passkeys, [renamed.passkeys[0]]);
  assert.deepEqual(left.pin, renamed.pin);
  // Only the vault forgot it: the passkey is still at its provider.
  assert.equal((await credentialsOn('key'))[0].id, removedId);
  await options.close();
});

test('turning off the vault lock says how many passkeys stop working and removes them all', async () => {
  const options = await openPage('options.html');
  await options.click('.nav-item[data-section="security"]');
  await options.locator('#master-pw-change').waitFor({ state: 'visible' });
  await options.locator('#passkey-unlock-list .unlock-passkey-row').first().waitFor();

  let confirmation = '';
  options.once('dialog', (dialog) => {
    confirmation = dialog.message();
    return dialog.accept();
  });
  await options.fill('#change-pw-current', PIN);
  await options.click('#remove-pw-btn');
  await options.locator('#master-pw-set').waitFor({ state: 'visible' });
  assert.match(confirmation, /Turn off the vault lock\?/);
  assert.match(confirmation, /stored unencrypted/);
  assert.match(confirmation, /\b1 passkey\b/);
  assert.match(confirmation, /stop working/);
  assert.match(confirmation, /stay at your passkey provider/);

  const left = await stored(null, options);
  assert.deepEqual(
    Object.keys(left).filter((key) => key.startsWith('passext_')),
    []
  );
  assert.equal(left.passkeys[0].privateKey, PASSKEY.privateKey);
  const state = await vaultState(options);
  assert.equal(state.isSetup, false);
  assert.equal(state.passkeyUnlock.count, 0);
  const methods = await send('GET_UNLOCK_METHODS', undefined, options);
  assert.equal(methods.format, 'none');
  assert.deepEqual(methods.passkeys, []);
  await options.close();
});

test('runs without console errors', () => {
  assert.deepEqual(consoleErrors, []);
});
