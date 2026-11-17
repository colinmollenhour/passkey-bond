// End-to-end: unlocking the vault with a passkey, in the built extension with
// the production KDF and Chromium's own WebAuthn client. A PIN'd vault from
// before the wrapped data key is unlocked through the popup, which moves it to
// the new storage format; a passkey on a CDP virtual authenticator with PRF is
// added on the extension's unlock page and opens the vault after a lock and
// after a service worker restart; a second passkey on a second authenticator
// does the same; a passkey sets a new PIN on the page for a forgotten one;
// the PIN keeps working; and Options renames and removes passkeys and turns
// the lock off.
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
/** Set with a passkey part-way through; the tests after that use it. */
const NEW_PIN = '975310';
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

/** Poll from here until `check` holds: waitForFunction does not await an async predicate. */
async function eventually(check, what) {
  const deadline = Date.now() + 20000;
  while (!(await check())) {
    assert.ok(Date.now() < deadline, `timed out waiting until ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

const waitUntilUnlocked = () =>
  eventually(async () => (await vaultState()).isUnlocked === true, 'the vault is unlocked');

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

/** Set the long-lived tab's URL hash and wait until the page has drawn that mode. */
async function enterMode(hash) {
  await ceremony.evaluate((h) => {
    location.hash = h;
  }, hash);
  await ceremony.locator(`body[data-mode="${hash.slice(1)}"]`).waitFor();
}

/**
 * Switch the long-lived tab to a mode by URL hash. Asking for the mode it is
 * already in goes through another one first, so the view starts afresh.
 */
async function showMode(hash) {
  const current = await ceremony.evaluate(() => location.hash);
  if (current === hash) await enterMode(hash === '#unlock' ? '#enroll' : '#unlock');
  await enterMode(hash);
  await ceremony.locator(VIEWS[hash]).waitFor({ state: 'visible' });
}

/** As showMode, for a mode that needs the vault unlocked while it is locked: the lock screen shows. */
async function showModeLocked(hash) {
  const current = await ceremony.evaluate(() => location.hash);
  if (current === hash) await enterMode('#unlock');
  await enterMode(hash);
  await ceremony.locator('#unlock-view').waitFor({ state: 'visible' });
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

async function credentialsOnAuthenticator(authenticatorId) {
  return (await webauthn.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
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
  // One banner at a time: the offer waits until the backup warning is closed.
  await popup.locator('#vault-warning').waitFor({ state: 'visible' });
  assert.equal(await popup.locator('#passkey-offer').isVisible(), false);
  await popup.click('#vault-warning-dismiss');
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

test('an upgraded vault that owes its backup says so before any passkey is created', async () => {
  const spare = await addAuthenticator({ transport: 'internal' });
  await ceremony.evaluate(() => chrome.storage.local.set({ upgrade_backup_required_0_9_5: true }));
  assert.equal((await send('GET_UNLOCK_METHODS')).backupRequired, true);

  // The page explains instead of showing the form whose result would be refused.
  await ceremony.evaluate(() => {
    location.hash = '#unlock';
  });
  await ceremony.locator('#unlock-view').waitFor({ state: 'visible' });
  await ceremony.evaluate(() => {
    location.hash = '#enroll';
  });
  await ceremony.locator('#unavailable-view').waitFor({ state: 'visible' });
  assert.match(
    await ceremony.locator('#unavailable-text').textContent(),
    /export an encrypted backup/
  );
  assert.equal(await ceremony.locator('#enroll-view').isVisible(), false);
  assert.deepEqual(await credentialsOnAuthenticator(spare), []);

  // Neither the popup nor Options offers what would be refused.
  const popup = await popupListsTheRecord();
  await popup.locator('#upgrade-backup-required').waitFor({ state: 'visible' });
  assert.equal(await popup.locator('#passkey-offer').isVisible(), false);
  await popup.close();
  const options = await openPage('options.html');
  await options.click('.nav-item[data-section="security"]');
  await options.locator('#passkey-unlock-card').waitFor({ state: 'visible' });
  assert.match(
    await options.locator('#passkey-unlock-hint').textContent(),
    /export an encrypted backup/
  );
  assert.equal(await options.locator('#passkey-unlock-add-btn').isVisible(), false);
  await options.close();

  // The background refuses it as well, with the code the pages have words for.
  const refused = await send('ENROLL_UNLOCK_PASSKEY', {});
  assert.equal(refused.success, false);
  assert.equal(refused.code, 'UPGRADE_BACKUP_REQUIRED');
  assert.deepEqual(await unlockRecord(), migrated);

  // Exporting the backup clears it; here the message the export ends with does.
  assert.equal((await send('COMPLETE_UPGRADE_BACKUP')).success, true);
  await showMode('#enroll');
  assert.equal(await ceremony.locator('#enroll-create-btn').isVisible(), true);
  await webauthn.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: spare });
});

test('a passkey the vault refuses to store is dropped, not offered for confirming again', async () => {
  const spare = await addAuthenticator({ transport: 'internal' });
  await startEnrollment('Dropped');
  await ceremony.locator('#enroll-confirm-btn').waitFor({ state: 'visible' });
  // The vault locks between the two steps, so the commit comes back refused.
  await lockVault();
  await ceremony.click('#enroll-confirm-btn');
  await ceremony.locator('#enroll-error').waitFor({ state: 'visible' });
  assert.match(
    await ceremony.locator('#enroll-error').textContent(),
    /locked while the passkey prompt was open/
  );
  // Only a dismissed prompt can be answered again. This enrollment is over.
  assert.equal(await ceremony.locator('#enroll-confirm-btn').isVisible(), false);
  assert.equal(await ceremony.locator('#enroll-done').isVisible(), false);
  assert.deepEqual(await unlockRecord(), migrated);

  assert.equal((await send('UNLOCK_SECURE_STORAGE', { password: PIN })).success, true);
  await webauthn.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: spare });
});

test('adds a passkey in two steps and stores only its public record', async () => {
  authenticators.laptop = await addAuthenticator({ transport: 'internal' });
  await showMode('#enroll');
  // A refused PIN is not the vault's, so it gets no advice about its length.
  await ceremony.fill('#enroll-secret', '000000');
  await ceremony.locator('#enroll-short-pin-warning').waitFor({ state: 'visible' });
  await ceremony.click('#enroll-create-btn');
  await ceremony.locator('#enroll-error').waitFor({ state: 'visible' });
  assert.match(await ceremony.locator('#enroll-error').textContent(), /Wrong PIN or passphrase/);
  assert.equal(await ceremony.locator('#enroll-short-pin-warning').isVisible(), false);
  // Retyping clears the refusal.
  await ceremony.fill('#enroll-secret', PIN);
  assert.equal(await ceremony.locator('#enroll-error').isVisible(), false);
  // The PIN is six digits: the page warns about it, in place of its general note.
  await ceremony.locator('#enroll-short-pin-warning').waitFor({ state: 'visible' });
  assert.equal(await ceremony.locator('#enroll-disclosure').isVisible(), false);
  await ceremony.fill('#enroll-name', 'Laptop');
  await ceremony.click('#enroll-create-btn');
  await ceremony.locator('#enroll-confirm-btn').waitFor({ state: 'visible' });
  // The PIN is checked and its field gone, and the warning with it.
  assert.equal(await ceremony.locator('#enroll-secret').isVisible(), false);
  assert.equal(await ceremony.locator('#enroll-short-pin-warning').isVisible(), false);
  assert.equal(await ceremony.locator('#enroll-disclosure').isVisible(), false);
  // Nothing is saved until the passkey has opened the vault's key once.
  assert.deepEqual((await unlockRecord()).passkeys, []);
  await ceremony.click('#enroll-confirm-btn');
  await ceremony.locator('#enroll-done').waitFor({ state: 'visible' });
  // Done: a heading for the result, without the instructions that led to it.
  assert.match(await ceremony.locator('#enroll-title').textContent(), /Passkey added/);
  assert.equal(await ceremony.locator('#enroll-help').isVisible(), false);
  assert.equal(await ceremony.locator('#enroll-close-btn').isVisible(), true);

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
  const workerTargets = async () =>
    (await session.send('Target.getTargets')).targetInfos.filter(
      (target) =>
        target.type === 'service_worker' &&
        target.url.startsWith(`chrome-extension://${extensionId}/`)
    );
  const [running] = await workerTargets();
  assert.ok(running, 'the service worker is running');
  await session.send('Target.closeTarget', { targetId: running.targetId });
  // Chromium gives the next worker the same target ID, so the restart shows as
  // the target going away and, once a message needs it, coming back.
  await eventually(async () => (await workerTargets()).length === 0, 'the worker has stopped');

  // The new worker has nothing in memory: only the session copy of the key.
  const state = await vaultState();
  assert.equal(state.isSetup, true);
  assert.equal(state.isUnlocked, true);
  assert.equal((await workerTargets()).length, 1, 'a new service worker answered');
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

test('a passkey sets a new PIN on the page, and the old PIN stops working', async () => {
  await onlyAnswers('laptop');
  const before = await unlockRecord();
  const [{ signCount }] = await credentialsOn('laptop');
  await showMode('#reset-secret');

  // The two entries must agree before any prompt opens.
  await ceremony.fill('#reset-secret-new', NEW_PIN);
  await ceremony.fill('#reset-secret-confirm', PIN);
  await ceremony.click('#reset-confirm-btn');
  await ceremony.locator('#reset-error').waitFor({ state: 'visible' });
  assert.match(await ceremony.locator('#reset-error').textContent(), /don't match/);
  assert.equal((await credentialsOn('laptop'))[0].signCount, signCount);
  assert.deepEqual(await unlockRecord(), before);

  await ceremony.fill('#reset-secret-confirm', NEW_PIN);
  await ceremony.click('#reset-confirm-btn');
  // Done: the heading says so, and the way on is to close the tab.
  await ceremony.locator('#reset-done').waitFor({ state: 'visible' });
  assert.match(
    await ceremony.locator('#reset-title').textContent(),
    /new PIN or passphrase is set/
  );
  assert.equal(await ceremony.locator('#reset-close-btn').isVisible(), true);
  assert.equal(await ceremony.locator('#reset-error').isVisible(), false);
  // Done: the form is gone and its fields hold nothing.
  assert.equal(await ceremony.locator('#reset-form').isVisible(), false);
  assert.equal(await ceremony.inputValue('#reset-secret-new'), '');
  assert.ok((await credentialsOn('laptop'))[0].signCount > signCount, 'the passkey authorized it');

  // Only the PIN wrapper changed: the passkeys still wrap the same data key.
  const record = await unlockRecord();
  assert.equal(record.vaultId, before.vaultId);
  assert.deepEqual(record.passkeys, before.passkeys);
  assert.notDeepEqual(record.pin, before.pin);

  await lockVault();
  assert.equal((await send('UNLOCK_SECURE_STORAGE', { password: PIN })).success, false);
  assert.equal((await vaultState()).isUnlocked, false);
  assert.equal((await send('UNLOCK_SECURE_STORAGE', { password: NEW_PIN })).success, true);
  await (await popupListsTheRecord()).close();
  await lockVault();
  await unlockWithPasskey();
  await (await popupListsTheRecord()).close();
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
  // A wrong PIN is reported under the PIN field, not up by the passkey button.
  await ceremony.fill('#fallback-secret', '000000');
  await ceremony.click('#fallback-unlock-btn');
  await ceremony.waitForFunction(() =>
    /Wrong PIN or passphrase/.test(document.getElementById('unlock-error').textContent)
  );
  assert.equal(
    await ceremony.evaluate(
      () => document.getElementById('unlock-error').previousElementSibling.id
    ),
    'fallback-secret'
  );

  await ceremony.fill('#fallback-secret', NEW_PIN);
  await ceremony.click('#fallback-unlock-btn');
  await waitUntilUnlocked();
  assert.equal(ceremony.isClosed(), false);
  // Unlocked, in a tab that was not opened to unlock: it says so and offers to close.
  await ceremony.locator('#unlock-close-btn').waitFor({ state: 'visible' });
  assert.match(await ceremony.locator('#unlock-title').textContent(), /The vault is unlocked/);
});

test('a page opened to add a passkey unlocks a locked vault first, then carries on', async () => {
  await lockVault();
  await showModeLocked('#enroll');
  assert.match(await ceremony.locator('#unlock-help').textContent(), /Unlock it to add a passkey/);
  assert.equal(await ceremony.locator('#enroll-view').isVisible(), false);

  if (!(await ceremony.locator('#fallback-secret').isVisible())) {
    await ceremony.click('#fallback-toggle');
  }
  await ceremony.fill('#fallback-secret', NEW_PIN);
  await ceremony.click('#fallback-unlock-btn');
  // Back to what the page was asked for, in the same tab.
  await ceremony.locator('#enroll-view').waitFor({ state: 'visible' });
  await ceremony.locator('#enroll-secret').waitFor({ state: 'visible' });
  assert.equal((await vaultState()).isUnlocked, true);
  assert.equal(ceremony.isClosed(), false);

  // Someone setting a new PIN has forgotten the old one: only the passkey is
  // offered there, with closing the tab as the way out.
  await lockVault();
  await showModeLocked('#reset-secret');
  assert.match(
    await ceremony.locator('#unlock-help').textContent(),
    /Unlock it with a passkey to set a new PIN or passphrase/
  );
  assert.equal(await ceremony.locator('#passkey-unlock-btn').isVisible(), true);
  assert.equal(await ceremony.locator('#fallback-toggle').isVisible(), false);
  assert.equal(await ceremony.locator('#fallback-secret').isVisible(), false);
  assert.equal(await ceremony.locator('#unlock-close-btn').isVisible(), true);
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

  await popup.fill('#unlock-password', NEW_PIN);
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
  await options.fill('#passkey-unlock-remove-secret', NEW_PIN);
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
  await options.fill('#change-pw-current', NEW_PIN);
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
