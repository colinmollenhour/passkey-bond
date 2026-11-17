/**
 * Unlocking the vault with a passkey held outside it: the background's
 * message protocol and the storage behind it, with the real background and
 * secure storage against an in-memory chrome.storage.local.
 *
 * The WebAuthn prompt itself runs in the unlock page and is tested there
 * (tests/unlock-passkey-client.test.ts, tests/e2e/passkey-unlock.test.cjs).
 * What reaches the background is a credential ID and the 32-byte PRF output
 * the passkey gave for its stored salt, so here a passkey is just those
 * bytes: random, as an authenticator's HMAC output is.
 */

import { createDecipheriv, hkdfSync, randomBytes, scryptSync } from 'crypto';
import {
  loadBackground,
  unlocksWith,
  useFakeStorage,
  type Respond,
  type StorageData,
} from './helpers/pin-background';
import { legacyVault } from './helpers/legacy-vault';

jest.mock('../src/sync/sync-service', () => ({
  syncService: {
    initialize: jest.fn(async () => {}),
    disconnect: jest.fn(async () => {}),
    requestSync: jest.fn(async () => {}),
    broadcastPasskeyUpdate: jest.fn(async () => {}),
    getStatus: jest.fn(() => ({ connected: false })),
    getDebugLogs: jest.fn(() => []),
    clearDebugLogs: jest.fn(),
  },
}));

const PIN = '482916';
const NEW_PIN = '975310';

const passkey = {
  id: 'pk-1',
  credentialId: 'cred-1',
  type: 'public-key',
  rpId: 'example.com',
  origin: 'https://example.com',
  user: { id: 'u', name: 'user', displayName: 'User' },
  privateKey: 'private-key',
  publicKey: 'public-key',
  createdAt: 1,
  counter: 0,
  backupEligible: true,
  backupState: true,
  backupSource: 'created',
};
const totp = {
  id: 'totp-1',
  type: 'totp',
  issuer: 'Example',
  account: 'user',
  secretB64: 'AAAAAAAAAAAAAAAAAAAA',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  counter: 0,
};
const chain = {
  enabled: true,
  chainId: 'a'.repeat(32),
  deviceId: 'device-a',
  deviceName: 'Laptop',
  seedHash: 'a'.repeat(64),
};

interface Sealed {
  data: string;
  iv: string;
}
interface StoredPasskey {
  credentialId: string;
  prfSalt: string;
  wrapped: Sealed;
  name: string;
  createdAt: number;
  transports?: string[];
}
interface StoredRecord {
  version: number;
  vaultId: string;
  pin: { kdf: { params: { N: number; r: number; p: number }; salt: string }; wrapped: Sealed };
  passkeys: StoredPasskey[];
}

/** An unlock passkey as the background sees one: its ID, salt and PRF output. */
interface UnlockPasskey {
  credentialId: string;
  prfSalt: string;
  prfOutput: string;
}

const newPasskey = (): UnlockPasskey => ({
  credentialId: randomBytes(32).toString('base64url'),
  prfSalt: randomBytes(32).toString('base64'),
  prfOutput: randomBytes(32).toString('base64'),
});

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const local = () => chrome.storage.local as unknown as Record<string, jest.Mock>;
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const vaultState = () =>
  clone(Object.fromEntries(Object.entries(storage).filter(([key]) => key.startsWith('passext_'))));
const record = () => storage.passext_vault_unlock as StoredRecord;
const isUnlocked = async (send: Respond) =>
  (await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked;

function open(sealed: Sealed, key: Uint8Array, aad?: string): Buffer {
  const bytes = Buffer.from(sealed.data, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(bytes.subarray(bytes.length - 16));
  return Buffer.concat([decipher.update(bytes.subarray(0, bytes.length - 16)), decipher.final()]);
}

/** The key the PIN derives, from the stored record alone. */
function pinKey(pin: string): Buffer {
  const { kdf } = record().pin;
  return scryptSync(pin.normalize('NFC'), Buffer.from(kdf.salt, 'base64'), 32, { ...kdf.params });
}

/** The vault data key, opened from the PIN wrapper with Node's crypto. */
function dataKey(pin = PIN): Buffer {
  const { vaultId, pin: part } = record();
  return open(part.wrapped, pinKey(pin), `passkey.bond/vault-unlock/wrap/v1\n${vaultId}\npin\n`);
}

/** The key that wraps the data key for an unlock passkey. */
function wrappingKey(unlockPasskey: UnlockPasskey): Buffer {
  return Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(unlockPasskey.prfOutput, 'base64'),
      Buffer.from(record().vaultId, 'base64'),
      'passkey.bond/vault-unlock/prf-wrap-key/v1',
      32
    )
  );
}

async function enroll(
  send: Respond,
  unlockPasskey: UnlockPasskey,
  overrides: Record<string, unknown> = {}
) {
  const { vaultId } = await send({ type: 'GET_UNLOCK_METHODS' });
  return send({
    type: 'ENROLL_UNLOCK_PASSKEY',
    payload: {
      password: PIN,
      vaultId,
      ...unlockPasskey,
      name: 'Laptop',
      transports: ['internal'],
      ...overrides,
    },
  });
}

const unlockWith = (send: Respond, { credentialId, prfOutput }: UnlockPasskey) =>
  send({ type: 'UNLOCK_WITH_PASSKEY', payload: { credentialId, prfOutput } });

const lock = (send: Respond) => send({ type: 'LOCK_SECURE_STORAGE' });

/** A PIN'd vault holding a passkey, a TOTP entry and a sync chain's seed. */
async function fullVault() {
  storage.passkeys = [passkey];
  storage.totp_entries = [totp];
  storage.sync_config = { ...chain };
  const background = await loadBackground();
  expect(
    (await background.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
  ).toBe(true);
  return background;
}

/** A full vault with one unlock passkey enrolled, unlocked. */
async function enrolledVault() {
  const background = await fullVault();
  const unlockPasskey = newPasskey();
  expect((await enroll(background.send, unlockPasskey)).success).toBe(true);
  return { ...background, unlockPasskey };
}

let storage: StorageData;

beforeEach(() => {
  storage = useFakeStorage();
});

describe('enrolling an unlock passkey', () => {
  it('stores a wrapper that the passkey opens, and nothing else about it', async () => {
    const { send } = await fullVault();
    const unlockPasskey = newPasskey();
    const before = vaultState();

    const enrolled = await enroll(send, unlockPasskey, { name: '  Work laptop ' });

    expect(enrolled).toEqual({
      success: true,
      passkey: {
        credentialId: unlockPasskey.credentialId,
        name: 'Work laptop',
        createdAt: expect.any(Number),
        prfSalt: unlockPasskey.prfSalt,
        transports: ['internal'],
      },
    });
    expect(record().passkeys).toEqual([
      {
        credentialId: unlockPasskey.credentialId,
        prfSalt: unlockPasskey.prfSalt,
        wrapped: { iv: expect.any(String), data: expect.any(String) },
        name: 'Work laptop',
        createdAt: enrolled.passkey && (enrolled.passkey as { createdAt: number }).createdAt,
        transports: ['internal'],
      },
    ]);
    // Only the record changed: the PIN wrapper and every encrypted value stay.
    expect({ ...vaultState(), passext_vault_unlock: undefined }).toEqual({
      ...before,
      passext_vault_unlock: undefined,
    });
    expect(record().pin).toEqual((before.passext_vault_unlock as StoredRecord).pin);

    const { vaultId, passkeys } = record();
    const opened = open(
      passkeys[0].wrapped,
      wrappingKey(unlockPasskey),
      `passkey.bond/vault-unlock/wrap/v1\n${vaultId}\npasskey-prf\n${unlockPasskey.credentialId}`
    );
    expect(opened).toEqual(dataKey());
  });

  it('is listed with its public fields, also while locked', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    await lock(send);

    const methods = await send({ type: 'GET_UNLOCK_METHODS' });

    expect(methods).toEqual({
      success: true,
      isSetup: true,
      isUnlocked: false,
      supported: true,
      format: 'v1',
      vaultId: record().vaultId,
      passkeys: [
        {
          credentialId: unlockPasskey.credentialId,
          name: 'Laptop',
          createdAt: expect.any(Number),
          prfSalt: unlockPasskey.prfSalt,
          transports: ['internal'],
        },
      ],
      damagedPasskeys: 0,
      max: 8,
    });
    expect(JSON.stringify(methods)).not.toContain('wrapped');
    expect(await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).toMatchObject({
      isSetup: true,
      isUnlocked: false,
      passkeyUnlock: { supported: true, count: 1 },
    });
  });

  it('is refused while the vault is locked', async () => {
    const { send } = await fullVault();
    const { vaultId } = await send({ type: 'GET_UNLOCK_METHODS' });
    await lock(send);
    const before = vaultState();

    const enrolled = await enroll(send, newPasskey(), { vaultId });

    expect(enrolled).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
    expect(vaultState()).toEqual(before);
  });

  it('is refused on a vault without a lock', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();

    const enrolled = await enroll(send, newPasskey(), {
      vaultId: randomBytes(16).toString('base64'),
    });

    expect(enrolled.success).toBe(false);
    expect(Object.keys(storage).filter((key) => key.startsWith('passext_'))).toEqual([]);
  });

  it('stores nothing for a wrong PIN', async () => {
    const { send } = await fullVault();
    const before = vaultState();

    const enrolled = await enroll(send, newPasskey(), { password: '482917' });

    expect(enrolled).toMatchObject({ success: false, code: 'WRONG_SECRET' });
    expect(vaultState()).toEqual(before);
    expect(await isUnlocked(send)).toBe(true);
  });

  it('is refused when the prompt ran for another vault ID', async () => {
    const { send } = await fullVault();
    const before = vaultState();

    const enrolled = await enroll(send, newPasskey(), {
      vaultId: randomBytes(16).toString('base64'),
    });

    expect(enrolled).toMatchObject({ success: false, code: 'VAULT_CHANGED' });
    expect(vaultState()).toEqual(before);
  });

  it('is refused for a credential that is already enrolled', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = vaultState();

    const again = await enroll(send, { ...newPasskey(), credentialId: unlockPasskey.credentialId });

    expect(again).toMatchObject({ success: false, code: 'UNLOCK_PASSKEY_DUPLICATE' });
    expect(vaultState()).toEqual(before);
  });

  it('stops at eight passkeys', async () => {
    const { send } = await fullVault();
    for (let i = 0; i < 8; i++) {
      expect((await enroll(send, newPasskey(), { name: `Key ${i + 1}` })).success).toBe(true);
    }
    const before = vaultState();

    const ninth = await enroll(send, newPasskey());

    expect(ninth).toMatchObject({ success: false, code: 'UNLOCK_PASSKEY_LIMIT' });
    expect(vaultState()).toEqual(before);
    expect((await send({ type: 'GET_UNLOCK_METHODS' })).passkeys).toHaveLength(8);
  });

  it.each([
    ['a PRF output that is not 32 bytes', { prfOutput: randomBytes(31).toString('base64') }],
    ['a PRF output that is not base64', { prfOutput: 'not base64 at all!' }],
    ['a missing PRF output', { prfOutput: undefined }],
    ['a salt that is not 32 bytes', { prfSalt: randomBytes(16).toString('base64') }],
    [
      'a credential ID in standard base64',
      { credentialId: `${randomBytes(16).toString('base64')}` },
    ],
    ['an empty credential ID', { credentialId: '' }],
    ['an empty name', { name: '   ' }],
    ['a name with a line break', { name: 'Lap\ntop' }],
    ['a name that is not a string', { name: { toString: () => 'Laptop' } }],
    ['transports that are not a list', { transports: 'usb' }],
    ['a missing PIN', { password: undefined }],
  ])('refuses %s without a code, storing nothing', async (_name, overrides) => {
    const { send } = await fullVault();
    const before = vaultState();

    const enrolled = await enroll(send, newPasskey(), overrides);

    expect(enrolled.success).toBe(false);
    expect(enrolled.code).toBeUndefined();
    expect(vaultState()).toEqual(before);
  });

  it('never echoes what it was sent in an error', async () => {
    const { send } = await fullVault();
    const unlockPasskey = newPasskey();

    const responses = [
      await enroll(send, unlockPasskey, { password: 'guess-482917' }),
      await enroll(send, unlockPasskey, { vaultId: randomBytes(16).toString('base64') }),
      await unlockWith(send, unlockPasskey),
      await send({
        type: 'REMOVE_UNLOCK_PASSKEY',
        payload: { password: 'guess-482917', credentialId: unlockPasskey.credentialId },
      }),
    ];

    for (const response of responses) {
      expect(response.success).toBe(false);
      const text = JSON.stringify(response);
      expect(text).not.toContain(unlockPasskey.prfOutput);
      expect(text).not.toContain(unlockPasskey.credentialId);
      expect(text).not.toContain('guess-482917');
    }
  });
});

describe('unlocking with a passkey', () => {
  it('opens the vault: its records list and decrypt', async () => {
    const { send, secure, unlockPasskey } = await enrolledVault();
    await lock(send);
    expect(await isUnlocked(send)).toBe(false);

    expect(await unlockWith(send, unlockPasskey)).toEqual({ success: true });

    expect(await isUnlocked(send)).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    expect(await secure.getTotpEntries()).toEqual([totp]);
    expect((await secure.getSyncConfig())?.seedHash).toBe(chain.seedHash);
  });

  it('opens it in a worker that has never seen the PIN', async () => {
    const { unlockPasskey } = await enrolledVault();
    const restarted = await loadBackground();

    expect((await unlockWith(restarted.send, unlockPasskey)).success).toBe(true);

    expect((await restarted.send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    // What it saves now opens with the PIN too: one data key behind both.
    await restarted.send({ type: 'ADD_TOTP_ENTRY', payload: { entry: { ...totp, id: 'totp-2' } } });
    const again = await loadBackground();
    expect(await unlocksWith(again.send, PIN)).toBe(true);
    expect((await again.secure.getTotpEntries()).map((entry) => entry.id)).toEqual([
      'totp-1',
      'totp-2',
    ]);
  });

  it('starts sync, folds in records left in cleartext and strips the cleartext seed', async () => {
    const { send, sync, secure, unlockPasskey } = await enrolledVault();
    await lock(send);
    sync.initialize.mockClear();
    // What an interrupted removal of the lock, or an older build, leaves behind.
    const leftover = { ...passkey, id: 'pk-2', credentialId: 'cred-2' };
    storage.passkeys = [leftover];
    storage.sync_devices = {
      id: chain.chainId,
      createdAt: 1,
      devices: [],
      seedHash: chain.seedHash,
    };

    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);

    expect(sync.initialize).toHaveBeenLastCalledWith(
      chain.chainId,
      chain.deviceId,
      chain.seedHash,
      chain.deviceName,
      expect.anything()
    );
    const listed = (await send({ type: 'LIST_PASSKEYS' })).passkeys as Array<{ id: string }>;
    expect(listed.map((entry) => entry.id).sort()).toEqual(['pk-1', 'pk-2']);
    expect(storage.passkeys).toBeUndefined();
    expect((storage.sync_devices as { seedHash?: string }).seedHash).toBeUndefined();
    expect((storage.sync_config as { seedHash?: string }).seedHash).toBeUndefined();
    expect((await secure.getSyncConfig())?.seedHash).toBe(chain.seedHash);
  });

  it('refuses a PRF output that does not open the wrapper, and keeps the wrapper', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    await lock(send);
    const before = vaultState();

    const wrong = await unlockWith(send, {
      ...unlockPasskey,
      prfOutput: randomBytes(32).toString('base64'),
    });

    expect(wrong).toMatchObject({ success: false, code: 'UNLOCK_PASSKEY_MISMATCH' });
    expect(await isUnlocked(send)).toBe(false);
    expect(vaultState()).toEqual(before);
    // The right output still opens it.
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
  });

  it('refuses a credential the vault does not list', async () => {
    const { send } = await enrolledVault();
    await lock(send);
    const before = vaultState();

    const unknown = await unlockWith(send, newPasskey());

    expect(unknown).toMatchObject({ success: false, code: 'UNLOCK_PASSKEY_UNKNOWN' });
    expect(await isUnlocked(send)).toBe(false);
    expect(vaultState()).toEqual(before);
  });

  it('refuses a passkey on a vault without a lock, and on one without passkeys', async () => {
    const unprotected = await loadBackground();
    expect(await unlockWith(unprotected.send, newPasskey())).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_UNKNOWN',
    });
    expect(Object.keys(storage).filter((key) => key.startsWith('passext_'))).toEqual([]);

    const { send } = await fullVault();
    await lock(send);
    expect(await unlockWith(send, newPasskey())).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_UNKNOWN',
    });
  });

  it('refuses a malformed request without a code', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    await lock(send);

    for (const payload of [
      {},
      { credentialId: unlockPasskey.credentialId },
      { credentialId: unlockPasskey.credentialId, prfOutput: randomBytes(33).toString('base64') },
      { credentialId: 42, prfOutput: unlockPasskey.prfOutput },
      { credentialId: unlockPasskey.credentialId, prfOutput: [1, 2, 3] },
    ]) {
      const response = await send({ type: 'UNLOCK_WITH_PASSKEY', payload });
      expect(response.success).toBe(false);
      expect(response.code).toBeUndefined();
    }
    expect(await isUnlocked(send)).toBe(false);
  });

  it('leaves an unlocked vault unlocked, whatever the passkey', async () => {
    const { send, unlockPasskey } = await enrolledVault();

    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
    expect(await isUnlocked(send)).toBe(true);
    const wrong = await unlockWith(send, {
      ...unlockPasskey,
      prfOutput: randomBytes(32).toString('base64'),
    });
    expect(wrong).toMatchObject({ success: false, code: 'UNLOCK_PASSKEY_MISMATCH' });
    expect(await isUnlocked(send)).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('reports damage when the wrapper opens but the vault does not', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    await lock(send);
    const check = storage.passext_master_key_check as { data: string };
    const bytes = Buffer.from(check.data, 'base64');
    bytes[0] ^= 0xff;
    check.data = bytes.toString('base64');

    expect(await unlockWith(send, unlockPasskey)).toMatchObject({
      success: false,
      code: 'VAULT_DAMAGED',
    });
    expect(await isUnlocked(send)).toBe(false);
  });

  it('skips a malformed entry, counts it, and still opens with the others', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    await lock(send);
    record().passkeys.unshift({ ...record().passkeys[0], credentialId: 'not/base64url', name: '' });

    const methods = await send({ type: 'GET_UNLOCK_METHODS' });
    expect(methods.passkeys).toHaveLength(1);
    expect(methods.damagedPasskeys).toBe(1);
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
    expect(await unlocksWith(send, PIN)).toBe(true);
  });
});

describe('several unlock passkeys', () => {
  it('each unlock the vault on their own', async () => {
    const { send, unlockPasskey: first } = await enrolledVault();
    const second = newPasskey();
    expect(
      (await enroll(send, second, { name: 'Security key', transports: ['usb'] })).success
    ).toBe(true);
    expect(record().passkeys.map((entry) => entry.name)).toEqual(['Laptop', 'Security key']);

    for (const unlockPasskey of [first, second]) {
      await lock(send);
      expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
      expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    }
    // One passkey's output does not open the other's wrapper.
    await lock(send);
    expect(await unlockWith(send, { ...first, prfOutput: second.prfOutput })).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_MISMATCH',
    });
  });

  it('keeps the others when one is removed', async () => {
    const { send, unlockPasskey: first } = await enrolledVault();
    const second = newPasskey();
    await enroll(send, second, { name: 'Security key' });
    const kept = clone(record().passkeys[1]);
    const pin = clone(record().pin);

    const removed = await send({
      type: 'REMOVE_UNLOCK_PASSKEY',
      payload: { password: PIN, credentialId: first.credentialId },
    });

    expect(removed).toEqual({ success: true });
    expect(record().passkeys).toEqual([kept]);
    expect(record().pin).toEqual(pin);
    await lock(send);
    expect(await unlockWith(send, first)).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_UNKNOWN',
    });
    expect((await unlockWith(send, second)).success).toBe(true);
    expect(await unlocksWith(send, PIN)).toBe(true);
  });

  it('needs the PIN to remove one', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = vaultState();

    const wrong = await send({
      type: 'REMOVE_UNLOCK_PASSKEY',
      payload: { password: '482917', credentialId: unlockPasskey.credentialId },
    });
    const unknown = await send({
      type: 'REMOVE_UNLOCK_PASSKEY',
      payload: { password: PIN, credentialId: newPasskey().credentialId },
    });

    expect(wrong).toMatchObject({ success: false, code: 'WRONG_SECRET' });
    expect(unknown).toMatchObject({ success: false, code: 'UNLOCK_PASSKEY_UNKNOWN' });
    expect(vaultState()).toEqual(before);

    await lock(send);
    const locked = await send({
      type: 'REMOVE_UNLOCK_PASSKEY',
      payload: { password: PIN, credentialId: unlockPasskey.credentialId },
    });
    expect(locked).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
    expect(vaultState()).toEqual(before);
  });

  it('renames one without the PIN, changing only its name', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = clone(record());

    const renamed = await send({
      type: 'RENAME_UNLOCK_PASSKEY',
      payload: { credentialId: unlockPasskey.credentialId, name: ' Desk ' },
    });

    expect(renamed).toEqual({ success: true });
    expect(record()).toEqual({
      ...before,
      passkeys: [{ ...before.passkeys[0], name: 'Desk' }],
    });
    // The name is not part of what the wrapper is bound to.
    await lock(send);
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
  });

  it('refuses a rename it cannot make', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = vaultState();
    const rename = (payload: Record<string, unknown>) =>
      send({ type: 'RENAME_UNLOCK_PASSKEY', payload });

    expect(await rename({ credentialId: newPasskey().credentialId, name: 'Desk' })).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_UNKNOWN',
    });
    const blank = await rename({ credentialId: unlockPasskey.credentialId, name: '  ' });
    expect(blank.success).toBe(false);
    expect(blank.code).toBeUndefined();
    const long = await rename({ credentialId: unlockPasskey.credentialId, name: 'x'.repeat(65) });
    expect(long.success).toBe(false);
    expect(vaultState()).toEqual(before);

    await lock(send);
    expect(await rename({ credentialId: unlockPasskey.credentialId, name: 'Desk' })).toMatchObject({
      success: false,
      code: 'VAULT_LOCKED',
    });
    expect(vaultState()).toEqual(before);
  });
});

describe('checking the PIN before a prompt', () => {
  it('says whether it is right without changing the lock state', async () => {
    const { send } = await fullVault();
    const before = vaultState();
    const verify = (password: unknown) =>
      send({ type: 'VERIFY_MASTER_PASSWORD', payload: { password } });

    expect(await verify(PIN)).toEqual({ success: true, valid: true });
    expect(await verify('482917')).toEqual({ success: true, valid: false });
    expect((await verify(undefined)).success).toBe(false);
    expect(await isUnlocked(send)).toBe(true);
    expect(vaultState()).toEqual(before);

    await lock(send);
    expect(await verify(PIN)).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
    expect(await isUnlocked(send)).toBe(false);
  });

  it('works for a vault still in the legacy format', async () => {
    Object.assign(storage, legacyVault(PIN, { totpEntries: [totp] }));
    const { send } = await loadBackground();
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation(async (items: StorageData) => {
      if ('passext_vault_unlock' in items) throw new Error('QUOTA_BYTES quota exceeded');
      return write(items);
    });
    await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    local().set.mockImplementation(write);

    expect(await send({ type: 'VERIFY_MASTER_PASSWORD', payload: { password: PIN } })).toEqual({
      success: true,
      valid: true,
    });
    expect(await send({ type: 'VERIFY_MASTER_PASSWORD', payload: { password: '000000' } })).toEqual(
      { success: true, valid: false }
    );
  });
});

describe('changing the PIN', () => {
  const change = (send: Respond, currentPassword = PIN, newPassword = NEW_PIN) =>
    send({ type: 'CHANGE_MASTER_PASSWORD', payload: { currentPassword, newPassword } });

  it('replaces the data key and re-encrypts everything when no passkey is enrolled', async () => {
    const { send } = await fullVault();
    const before = vaultState();
    const oldKey = dataKey();

    expect((await change(send)).success).toBe(true);

    const newKey = dataKey(NEW_PIN);
    expect(newKey).not.toEqual(oldKey);
    expect(record().vaultId).toBe((before.passext_vault_unlock as StoredRecord).vaultId);
    for (const name of [
      'passext_master_key_check',
      'passext_encrypted_passkeys',
      'passext_encrypted_totp_entries',
      'passext_encrypted_sync_config',
    ]) {
      expect(storage[name]).not.toEqual(before[name]);
      // A copy of the old storage and the old PIN reads nothing stored since.
      expect(() => open(storage[name] as Sealed, oldKey)).toThrow();
      expect(() => open(storage[name] as Sealed, newKey)).not.toThrow();
    }
    expect(await isUnlocked(send)).toBe(true);
    expect(await unlocksWith(send, PIN)).toBe(false);
    expect(await unlocksWith(send, NEW_PIN)).toBe(true);
  });

  it('keeps the data key, the passkey and every encrypted value when one is enrolled', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = vaultState();
    const oldKey = dataKey();
    local().set.mockClear();

    expect((await change(send)).success).toBe(true);

    // One write, of the record alone.
    const writes = local().set.mock.calls.filter(([items]) =>
      Object.keys(items).some((key) => key.startsWith('passext_'))
    );
    expect(writes.map(([items]) => Object.keys(items))).toEqual([['passext_vault_unlock']]);
    expect(dataKey(NEW_PIN)).toEqual(oldKey);
    expect({ ...vaultState(), passext_vault_unlock: undefined }).toEqual({
      ...before,
      passext_vault_unlock: undefined,
    });
    expect(record().passkeys).toEqual((before.passext_vault_unlock as StoredRecord).passkeys);
    expect(record().pin).not.toEqual((before.passext_vault_unlock as StoredRecord).pin);
    expect(record().vaultId).toBe((before.passext_vault_unlock as StoredRecord).vaultId);

    expect(await isUnlocked(send)).toBe(true);
    expect(await unlocksWith(send, PIN)).toBe(false);
    expect(await unlocksWith(send, NEW_PIN)).toBe(true);
    await lock(send);
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('re-encrypts again once the passkeys are removed', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const oldKey = dataKey();
    await send({
      type: 'REMOVE_UNLOCK_PASSKEY',
      payload: { password: PIN, credentialId: unlockPasskey.credentialId },
    });

    expect((await change(send)).success).toBe(true);

    expect(dataKey(NEW_PIN)).not.toEqual(oldKey);
    // The removed passkey's old wrapper, were it kept, would open nothing now.
    expect(() => open(storage.passext_master_key_check as Sealed, oldKey)).toThrow();
  });

  it('refuses a wrong current PIN whether or not a passkey is enrolled', async () => {
    const { send } = await enrolledVault();
    const before = vaultState();

    expect((await change(send, '482917')).success).toBe(false);

    expect(vaultState()).toEqual(before);
    expect(await isUnlocked(send)).toBe(true);
  });

  it('keeps a passkey whose enrollment lands just before the change commits', async () => {
    const { send, secure } = await fullVault();
    const unlockPasskey = newPasskey();
    const oldKey = dataKey();

    // The change derives its keys outside the queue; the enrollment gets in first.
    const changing = secure.changeMasterPassword(PIN, NEW_PIN);
    const enrolling = secure.addUnlockPasskey({
      vaultId: record().vaultId,
      credentialId: unlockPasskey.credentialId,
      prfSalt: unlockPasskey.prfSalt,
      prfOutput: new Uint8Array(Buffer.from(unlockPasskey.prfOutput, 'base64')),
      name: 'Laptop',
    });

    await enrolling;
    expect(await changing).toBe(true);
    // The change saw the passkey and kept the key it wraps.
    expect(record().passkeys).toHaveLength(1);
    expect(dataKey(NEW_PIN)).toEqual(oldKey);
    await lock(send);
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    expect(await unlocksWith(send, NEW_PIN)).toBe(true);
  });

  it('keeps a passkey whose enrollment lands just after the change commits', async () => {
    const { send, secure } = await fullVault();
    const unlockPasskey = newPasskey();
    const oldKey = dataKey();
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation(async (items: StorageData) => {
      if ('passext_vault_kdf' in items) await held;
      return write(items);
    });
    local().set.mockClear();

    const changing = secure.changeMasterPassword(PIN, NEW_PIN);
    while (!local().set.mock.calls.some(([items]) => 'passext_vault_kdf' in items)) await flush();
    // The rotated vault is on its way to storage; the enrollment queues behind it.
    const enrolling = secure.addUnlockPasskey({
      vaultId: record().vaultId,
      credentialId: unlockPasskey.credentialId,
      prfSalt: unlockPasskey.prfSalt,
      prfOutput: new Uint8Array(Buffer.from(unlockPasskey.prfOutput, 'base64')),
      name: 'Laptop',
    });
    for (let i = 0; i < 5; i++) await flush();
    release();
    expect(await changing).toBe(true);
    await enrolling;
    local().set.mockImplementation(write);

    // The key was rotated, and the passkey wraps the new one.
    expect(dataKey(NEW_PIN)).not.toEqual(oldKey);
    expect(record().passkeys).toHaveLength(1);
    await lock(send);
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    expect(await unlocksWith(send, NEW_PIN)).toBe(true);
  });
});

describe('setting a new PIN with a passkey', () => {
  const reset = (send: Respond, unlockPasskey: UnlockPasskey, newPassword: unknown = NEW_PIN) =>
    send({
      type: 'CHANGE_MASTER_PASSWORD_WITH_PASSKEY',
      payload: {
        credentialId: unlockPasskey.credentialId,
        prfOutput: unlockPasskey.prfOutput,
        newPassword,
      },
    });

  it('replaces only the PIN wrapper', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = vaultState();
    const oldKey = dataKey();

    expect(await reset(send, unlockPasskey)).toEqual({ success: true });

    expect(dataKey(NEW_PIN)).toEqual(oldKey);
    expect({ ...vaultState(), passext_vault_unlock: undefined }).toEqual({
      ...before,
      passext_vault_unlock: undefined,
    });
    expect(record().passkeys).toEqual((before.passext_vault_unlock as StoredRecord).passkeys);
    expect(await unlocksWith(send, PIN)).toBe(false);
    expect(await unlocksWith(send, NEW_PIN)).toBe(true);
    await lock(send);
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
  });

  it.each([
    ['unreadable', (wrapped: Sealed) => (wrapped.data = 'AAAA')],
    [
      'well-formed but not opening',
      (wrapped: Sealed) => {
        const bytes = Buffer.from(wrapped.data, 'base64');
        bytes[0] ^= 0xff;
        wrapped.data = bytes.toString('base64');
      },
    ],
  ])('repairs a PIN wrapper that is %s', async (_name, damage) => {
    const { send, unlockPasskey } = await enrolledVault();
    await lock(send);
    damage(record().pin.wrapped);
    expect(await unlocksWith(send, PIN)).toBe(false);

    // The passkey still opens the vault, and can set a secret that works.
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
    expect((await reset(send, unlockPasskey)).success).toBe(true);

    expect(await unlocksWith(send, NEW_PIN)).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    expect((await send({ type: 'GET_UNLOCK_METHODS' })).format).toBe('v1');
  });

  it('is refused for a passkey that does not open this vault', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = vaultState();

    expect(
      await reset(send, { ...unlockPasskey, prfOutput: randomBytes(32).toString('base64') })
    ).toMatchObject({ success: false, code: 'UNLOCK_PASSKEY_MISMATCH' });
    expect(await reset(send, newPasskey())).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_UNKNOWN',
    });

    expect(vaultState()).toEqual(before);
    expect(await unlocksWith(send, PIN)).toBe(true);
  });

  it('is refused while locked, and for a secret that is too short', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = vaultState();

    const short = await reset(send, unlockPasskey, '12');
    expect(short.success).toBe(false);
    expect(short.code).toBeUndefined();
    expect(short.error).toEqual(expect.stringContaining('at least 4 digits'));
    expect((await reset(send, unlockPasskey, null)).success).toBe(false);

    await lock(send);
    expect(await reset(send, unlockPasskey)).toMatchObject({
      success: false,
      code: 'VAULT_LOCKED',
    });
    expect(vaultState()).toEqual(before);
  });
});

describe('turning off the lock with passkeys enrolled', () => {
  it('needs the PIN, and removes every wrapper along with the lock', async () => {
    const { send, unlockPasskey: first } = await enrolledVault();
    const second = newPasskey();
    await enroll(send, second, { name: 'Security key' });
    const before = vaultState();

    const wrong = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: '482917' },
    });
    expect(wrong.success).toBe(false);
    expect(vaultState()).toEqual(before);

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PIN },
    });

    expect(removed.success).toBe(true);
    expect(Object.keys(storage).filter((key) => key.startsWith('passext_'))).toEqual([]);
    expect(storage.passkeys).toEqual([passkey]);
    expect(storage.totp_entries).toEqual([totp]);
    expect(await send({ type: 'GET_UNLOCK_METHODS' })).toMatchObject({
      isSetup: false,
      format: 'none',
      vaultId: null,
      passkeys: [],
    });
    for (const unlockPasskey of [first, second]) {
      expect(await unlockWith(send, unlockPasskey)).toMatchObject({
        success: false,
        code: 'UNLOCK_PASSKEY_UNKNOWN',
      });
    }
  });

  it('removes the wrappers in the same removal as the check value', async () => {
    const { send } = await enrolledVault();
    local().remove.mockClear();

    await send({ type: 'REMOVE_MASTER_PASSWORD', payload: { currentPassword: PIN } });

    const removals = local()
      .remove.mock.calls.map(([keys]) => [keys].flat() as string[])
      .filter((keys) => keys.some((key) => key.startsWith('passext_')));
    expect(removals).toHaveLength(1);
    expect(removals[0]).toEqual(
      expect.arrayContaining([
        'passext_master_key_check',
        'passext_vault_unlock',
        'passext_vault_kdf',
      ])
    );
  });

  it('gives a later lock a new vault ID that the old passkeys cannot open', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const old = clone(record());
    await send({ type: 'REMOVE_MASTER_PASSWORD', payload: { currentPassword: PIN } });

    // The same PIN again: nothing about the old lock comes back with it.
    expect(
      (await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
    ).toBe(true);

    expect(record().vaultId).not.toBe(old.vaultId);
    expect(record().passkeys).toEqual([]);
    expect(dataKey()).not.toEqual(
      open(
        old.pin.wrapped,
        scryptSync(PIN, Buffer.from(old.pin.kdf.salt, 'base64'), 32, {
          ...old.pin.kdf.params,
        }),
        `passkey.bond/vault-unlock/wrap/v1\n${old.vaultId}\npin\n`
      )
    );
    await lock(send);
    expect(await unlockWith(send, unlockPasskey)).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_UNKNOWN',
    });

    // The old wrapper, copied into the new record by hand, does not open either.
    record().passkeys.push(old.passkeys[0]);
    expect((await send({ type: 'GET_UNLOCK_METHODS' })).passkeys).toHaveLength(1);
    expect(await unlockWith(send, unlockPasskey)).toMatchObject({
      success: false,
      code: 'UNLOCK_PASSKEY_MISMATCH',
    });
    expect(await isUnlocked(send)).toBe(false);
    expect(await unlocksWith(send, PIN)).toBe(true);
  });
});

describe('what is stored and exported', () => {
  const encodings = (bytes: Buffer) => [
    bytes.toString('base64'),
    bytes.toString('base64url'),
    bytes.toString('hex'),
  ];

  it('never holds a PRF output, a wrapping key, the PIN key or the data key', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const second = newPasskey();
    await enroll(send, second, { name: 'Security key' });
    await lock(send);
    await unlockWith(send, unlockPasskey);
    await send({
      type: 'CHANGE_MASTER_PASSWORD_WITH_PASSKEY',
      payload: { ...second, newPassword: NEW_PIN },
    });
    await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: NEW_PIN, newPassword: PIN },
    });
    await send({
      type: 'RENAME_UNLOCK_PASSKEY',
      payload: { credentialId: second.credentialId, name: 'Key' },
    });
    await lock(send);

    const secrets = [
      Buffer.from(unlockPasskey.prfOutput, 'base64'),
      Buffer.from(second.prfOutput, 'base64'),
      wrappingKey(unlockPasskey),
      wrappingKey(second),
      pinKey(PIN),
      dataKey(),
    ];
    const stored = JSON.stringify(storage);
    for (const secret of secrets) {
      for (const text of encodings(secret)) expect(stored).not.toContain(text);
    }
  });

  it('holds only the fields of the format in the unlock record', async () => {
    await enrolledVault();

    expect(Object.keys(record()).sort()).toEqual(['passkeys', 'pin', 'vaultId', 'version']);
    expect(Object.keys(record().pin).sort()).toEqual(['kdf', 'wrapped']);
    expect(Object.keys(record().pin.wrapped).sort()).toEqual(['data', 'iv']);
    expect(Object.keys(record().passkeys[0]).sort()).toEqual([
      'createdAt',
      'credentialId',
      'name',
      'prfSalt',
      'transports',
      'wrapped',
    ]);
    expect(Buffer.from(record().passkeys[0].wrapped.iv, 'base64')).toHaveLength(12);
    expect(Buffer.from(record().passkeys[0].wrapped.data, 'base64')).toHaveLength(48);
  });

  it('leaves the unlock record out of an export', async () => {
    const { send, unlockPasskey } = await enrolledVault();

    const exported = await send({ type: 'EXPORT_VAULT' });

    expect(exported.success).toBe(true);
    const text = JSON.stringify(exported);
    for (const absent of [
      'passext_vault_unlock',
      'vaultId',
      'prfSalt',
      'wrapped',
      record().vaultId,
      unlockPasskey.credentialId,
      unlockPasskey.prfSalt,
      record().pin.wrapped.data,
      record().passkeys[0].wrapped.data,
    ]) {
      expect(text).not.toContain(absent);
    }
  });

  it('keeps the unlock passkeys when the vault is cleared', async () => {
    const { send, unlockPasskey } = await enrolledVault();
    const before = clone(record());

    expect((await send({ type: 'CLEAR_VAULT' })).success).toBe(true);

    expect(record()).toEqual(before);
    await lock(send);
    expect((await unlockWith(send, unlockPasskey)).success).toBe(true);
  });
});

describe('in a browser that cannot use the extension as a relying party', () => {
  const getURL = () => chrome.runtime.getURL as unknown as jest.Mock;
  let original: ((path: string) => string) | undefined;

  afterEach(() => {
    if (original) getURL().mockImplementation(original);
    original = undefined;
  });

  function useFirefox() {
    original = getURL().getMockImplementation();
    getURL().mockImplementation(
      (path: string) => `moz-extension://0b0c4e7c-7b0d-4e0e-9a43-3a1e6f0d7e11/${path}`
    );
  }

  it('reports passkey unlock as unsupported, and refuses to enroll', async () => {
    useFirefox();
    const { send } = await fullVault();
    const before = vaultState();

    expect(await send({ type: 'GET_UNLOCK_METHODS' })).toMatchObject({
      success: true,
      supported: false,
      format: 'v1',
      passkeys: [],
    });
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).passkeyUnlock).toEqual({
      supported: false,
      count: 0,
    });
    expect(await enroll(send, newPasskey())).toMatchObject({
      success: false,
      code: 'PASSKEY_UNLOCK_UNSUPPORTED',
    });
    expect(vaultState()).toEqual(before);
  });

  it('refuses a passkey unlock even for a record that lists one', async () => {
    // A profile with an enrolled passkey, opened where the origin differs.
    const { send, unlockPasskey } = await enrolledVault();
    await lock(send);
    useFirefox();
    const firefox = await loadBackground();

    expect(await unlockWith(firefox.send, unlockPasskey)).toMatchObject({
      success: false,
      code: 'PASSKEY_UNLOCK_UNSUPPORTED',
    });
    expect(await isUnlocked(firefox.send)).toBe(false);
    // The PIN still opens it.
    expect(await unlocksWith(firefox.send, PIN)).toBe(true);
  });
});
