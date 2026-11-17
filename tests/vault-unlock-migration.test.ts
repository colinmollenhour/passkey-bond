/**
 * Moving a vault from before unlock records to the current format on its
 * next PIN unlock: a random data key, wrapped under the PIN's key, with every
 * value re-encrypted under it in one storage write. The write is proven to
 * open before it is sent and read back afterwards, and a stopped worker or a
 * failed write at any point leaves a vault that the same PIN still opens.
 *
 * The legacy vaults are built with Node's crypto (tests/helpers/legacy-vault.ts)
 * and the migrated ones are opened with it too, so neither side of the
 * comparison is the code under test. The whole suite runs twice: Firefox
 * vaults migrate as well, although passkey unlock is not offered there.
 */

import { createDecipheriv, pbkdf2Sync, randomBytes, scryptSync } from 'crypto';
import {
  loadBackground,
  unlocksWith,
  useFakeStorage,
  type StorageData,
} from './helpers/pin-background';
import { ENCRYPTED_VAULT_VALUES, legacyVault, scryptVault } from './helpers/legacy-vault';

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

/** Set to make an encryption come out as bytes that do not decrypt. */
const mockCipher: { corrupt: ((plaintext: Uint8Array) => boolean) | null } = { corrupt: null };
jest.mock('@noble/ciphers/aes', () => {
  const actual = jest.requireActual('@noble/ciphers/aes');
  return {
    ...actual,
    gcm: (key: Uint8Array, iv: Uint8Array, aad?: Uint8Array) => {
      const cipher = actual.gcm(key, iv, aad);
      return {
        decrypt: (data: Uint8Array) => cipher.decrypt(data),
        encrypt: (plaintext: Uint8Array) => {
          const sealed = cipher.encrypt(plaintext);
          if (mockCipher.corrupt?.(plaintext)) sealed[0] ^= 0xff;
          return sealed;
        },
      };
    },
  };
});

const PIN = '482916';
const SENTINEL = { kdf: 'wrapped-data-key', version: 1 };
const VAULT_WRITE = ['passext_vault_kdf', 'passext_vault_unlock', ...ENCRYPTED_VAULT_VALUES].sort();
const BLOBS = ENCRYPTED_VAULT_VALUES.filter((key) => key !== 'passext_master_key_check');

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
interface StoredRecord {
  version: number;
  vaultId: string;
  pin: {
    kdf: { kdf: string; params: { N: number; r: number; p: number }; salt: string };
    wrapped: Sealed;
  };
  passkeys: unknown[];
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const local = () => chrome.storage.local as unknown as Record<string, jest.Mock>;
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const vaultState = () =>
  clone(Object.fromEntries(Object.entries(storage).filter(([key]) => key.startsWith('passext_'))));
const isVaultWrite = (items: StorageData) => 'passext_vault_unlock' in items;
const vaultWrites = () => local().set.mock.calls.filter(([items]) => isVaultWrite(items));
const record = () => storage.passext_vault_unlock as StoredRecord;

/** AES-256-GCM as Node does it; throws when `key` does not open `sealed`. */
function open(sealed: Sealed, key: Uint8Array, aad?: string): Buffer {
  const bytes = Buffer.from(sealed.data, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(bytes.subarray(bytes.length - 16));
  return Buffer.concat([decipher.update(bytes.subarray(0, bytes.length - 16)), decipher.final()]);
}

function opens(sealed: Sealed, key: Uint8Array): boolean {
  try {
    open(sealed, key);
    return true;
  } catch {
    return false;
  }
}

const legacyKey = (salt: string) =>
  pbkdf2Sync(PIN, Buffer.from(salt, 'base64'), 100000, 32, 'sha256');

/** The data key of the stored vault, from the PIN and the stored record alone. */
function dataKey(pin = PIN): Buffer {
  const { vaultId, pin: part } = record();
  const pinKey = scryptSync(pin.normalize('NFC'), Buffer.from(part.kdf.salt, 'base64'), 32, {
    ...part.kdf.params,
  });
  return open(part.wrapped, pinKey, `passkey.bond/vault-unlock/wrap/v1\n${vaultId}\npin\n`);
}

/** Unlock in a fresh worker and read everything back. */
async function contentsWith(pin: string) {
  const { send, secure } = await loadBackground();
  const unlocked = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: pin } });
  if (!unlocked.success) return null;
  return {
    passkeys: ((await send({ type: 'LIST_PASSKEYS' })).passkeys as Array<{ id: string }>).map(
      (p) => p.id
    ),
    totp: await secure.getTotpEntries(),
    seedHash: (await secure.getSyncConfig())?.seedHash,
  };
}

const EVERYTHING = { passkeys: [passkey.id], totp: [totp], seedHash: chain.seedHash };

let storage: StorageData;

describe.each([
  ['Chrome', 'chrome-extension://test/'],
  ['Firefox', 'moz-extension://0b0c4e7c-7b0d-4e0e-9a43-3a1e6f0d7e11/'],
])('in %s', (_browser, extensionUrl) => {
  const getURL = () => chrome.runtime.getURL as unknown as jest.Mock;
  let originalGetURL: ((path: string) => string) | undefined;

  beforeAll(() => {
    originalGetURL = getURL().getMockImplementation();
    getURL().mockImplementation((path: string) => `${extensionUrl}${path}`);
  });
  afterAll(() => {
    getURL().mockImplementation(originalGetURL);
  });

  beforeEach(() => {
    mockCipher.corrupt = null;
    storage = useFakeStorage();
    // As a PIN'd vault leaves it: the seed only in the encrypted config.
    Object.assign(
      storage,
      legacyVault(PIN, { passkeys: [passkey], totpEntries: [totp], syncConfig: chain }),
      { sync_config: { ...chain, seedHash: undefined } }
    );
  });

  describe('unlocking a legacy vault', () => {
    it('moves a PBKDF2 vault to the new format in exactly one vault write', async () => {
      const legacy = vaultState();
      const { send } = await loadBackground();
      local().set.mockClear();

      expect(
        (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } })).success
      ).toBe(true);

      expect(vaultWrites()).toHaveLength(1);
      expect(Object.keys(vaultWrites()[0][0]).sort()).toEqual(VAULT_WRITE);
      // No other write touched the vault's keys.
      const others = local().set.mock.calls.filter(([items]) => !isVaultWrite(items));
      for (const [items] of others) {
        expect(Object.keys(items).filter((key) => VAULT_WRITE.includes(key))).toEqual([]);
      }
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
      expect(record()).toEqual({
        version: 1,
        vaultId: expect.any(String),
        pin: {
          kdf: { kdf: 'scrypt', params: { N: 1024, r: 8, p: 1 }, salt: expect.any(String) },
          wrapped: { iv: expect.any(String), data: expect.any(String) },
        },
        passkeys: [],
      });
      expect(Buffer.from(record().vaultId, 'base64')).toHaveLength(16);
      expect(storage.passext_encryption_salt).toBeUndefined();
      for (const key of ENCRYPTED_VAULT_VALUES) expect(storage[key]).not.toEqual(legacy[key]);
      // The PIN's old key opens nothing any more.
      const oldKey = legacyKey(legacy.passext_encryption_salt as string);
      for (const key of ENCRYPTED_VAULT_VALUES)
        expect(opens(storage[key] as Sealed, oldKey)).toBe(false);
    });

    it('keeps the KDF record of a 0.13.0 vault as the PIN wrapper, in one vault write', async () => {
      for (const key of Object.keys(storage)) delete storage[key];
      Object.assign(
        storage,
        scryptVault(PIN, { N: 1024, r: 8, p: 1 }, { passkeys: [passkey], totpEntries: [totp] })
      );
      const before = vaultState();
      const { send } = await loadBackground();
      local().set.mockClear();

      expect(
        (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } })).success
      ).toBe(true);

      expect(vaultWrites()).toHaveLength(1);
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
      // The PIN derives the same key as before; it now wraps the data key.
      expect(record().pin.kdf).toEqual(before.passext_vault_kdf);
      const pinKey = scryptSync(PIN, Buffer.from(record().pin.kdf.salt, 'base64'), 32, {
        N: 1024,
        r: 8,
        p: 1,
      });
      expect(opens(before.passext_master_key_check as Sealed, pinKey)).toBe(true);
      expect(opens(storage.passext_master_key_check as Sealed, pinKey)).toBe(false);
      expect(opens(storage.passext_master_key_check as Sealed, dataKey())).toBe(true);
    });

    it('folds the upgrade of a weak scrypt record into the same write', async () => {
      for (const key of Object.keys(storage)) delete storage[key];
      Object.assign(storage, scryptVault(PIN, { N: 512, r: 8, p: 1 }, { totpEntries: [totp] }));
      const { send } = await loadBackground();
      local().set.mockClear();

      expect(
        (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } })).success
      ).toBe(true);

      expect(vaultWrites()).toHaveLength(1);
      expect(record().pin.kdf).toMatchObject({ kdf: 'scrypt', params: { N: 1024 } });
      const migrated = vaultState();

      // Nothing is left to upgrade: the next unlock writes no lock data.
      expect((await contentsWith(PIN))?.totp).toEqual([totp]);
      expect(vaultWrites()).toHaveLength(1);
      expect(vaultState()).toEqual(migrated);
    });

    it('carries every record over unchanged, byte for byte', async () => {
      const legacy = vaultState();
      const oldKey = legacyKey(legacy.passext_encryption_salt as string);
      const before = Object.fromEntries(
        BLOBS.map((key) => [key, open(legacy[key] as Sealed, oldKey).toString('utf8')])
      );
      const { send, secure } = await loadBackground();
      local().set.mockClear();

      await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

      // What is stored is what the write intended.
      const [intended] = vaultWrites()[0];
      expect(storage.passext_vault_unlock).toEqual(intended.passext_vault_unlock);
      for (const key of VAULT_WRITE) expect(storage[key]).toEqual(intended[key]);

      const key = dataKey();
      expect(open(storage.passext_master_key_check as Sealed, key).toString('utf8')).toBe(
        'passkey-bond-check'
      );
      for (const name of BLOBS) {
        expect(open(storage[name] as Sealed, key).toString('utf8')).toBe(before[name]);
      }
      expect(JSON.parse(before.passext_encrypted_passkeys)).toEqual([passkey]);
      expect(JSON.parse(before.passext_encrypted_totp_entries)).toEqual([totp]);
      expect(JSON.parse(before.passext_encrypted_sync_config)).toEqual(chain);

      // And the vault reads them back through its own code.
      expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
      expect(await secure.getTotpEntries()).toEqual([totp]);
      expect(await secure.getSyncConfig()).toEqual(chain);
      expect(await contentsWith(PIN)).toEqual(EVERYTHING);
    });

    it('starts sync with the seed from the migrated config', async () => {
      const { send, sync } = await loadBackground();

      await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

      expect(sync.initialize).toHaveBeenLastCalledWith(
        chain.chainId,
        chain.deviceId,
        chain.seedHash,
        chain.deviceName,
        expect.anything()
      );
    });

    it('rejects a wrong PIN and leaves storage byte-identical', async () => {
      const before = JSON.stringify(vaultState());
      const { send } = await loadBackground();
      local().set.mockClear();

      expect(
        (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: '482917' } })).success
      ).toBe(false);

      expect(JSON.stringify(vaultState())).toBe(before);
      expect(vaultWrites()).toEqual([]);
    });

    it('rejects a wrong PIN afterwards and does not migrate again', async () => {
      const { send } = await loadBackground();
      await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      const migrated = vaultState();

      expect(await unlocksWith(send, '000000')).toBe(false);
      expect(await unlocksWith(send, PIN)).toBe(true);
      expect(vaultState()).toEqual(migrated);
    });

    it('survives a worker restart on the data key', async () => {
      const { send } = await loadBackground();
      await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

      expect(await contentsWith(PIN)).toEqual(EVERYTHING);
      expect((await send({ type: 'GET_UNLOCK_METHODS' })).format).toBe('v1');
    });
  });

  describe('an interrupted migration', () => {
    it('leaves the old vault when the worker dies before the write lands', async () => {
      const legacy = vaultState();
      const { send } = await loadBackground();
      const write = local().set.getMockImplementation()!;
      local().set.mockImplementation((items: StorageData) =>
        isVaultWrite(items) ? new Promise(() => {}) : write(items)
      );

      void send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      while (!local().set.mock.calls.some(([items]) => isVaultWrite(items))) await flush();
      local().set.mockImplementation(write);

      // The next worker finds the old vault, opens it and migrates it.
      expect(vaultState()).toEqual(legacy);
      expect(await contentsWith(PIN)).toEqual(EVERYTHING);
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
      expect(storage.passext_encryption_salt).toBeUndefined();
    });

    it('unlocks with the old key when the write fails, and retries next unlock', async () => {
      const legacy = vaultState();
      const { send, secure } = await loadBackground();
      const write = local().set.getMockImplementation()!;
      local().set.mockImplementation(async (items: StorageData) => {
        if (isVaultWrite(items)) throw new Error('QUOTA_BYTES quota exceeded');
        return write(items);
      });

      const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      local().set.mockImplementation(write);

      expect(unlock.success).toBe(true);
      expect(vaultState()).toEqual(legacy);
      expect((await send({ type: 'GET_UNLOCK_METHODS' })).format).toBe('legacy');
      expect(await secure.getTotpEntries()).toEqual([totp]);
      // Saved while on the old key, and carried over by the retried migration.
      await secure.storeTotpEntries([totp, { ...totp, id: 'totp-2' }]);
      const oldKey = legacyKey(legacy.passext_encryption_salt as string);
      expect(opens(storage.passext_master_key_check as Sealed, oldKey)).toBe(true);

      expect(await contentsWith(PIN)).toEqual({
        ...EVERYTHING,
        totp: [totp, { ...totp, id: 'totp-2' }],
      });
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
      expect(storage.passext_encryption_salt).toBeUndefined();
    });

    it('uses the data key when a write that reported failure landed anyway', async () => {
      const { send, secure } = await loadBackground();
      const write = local().set.getMockImplementation()!;
      local().set.mockImplementation(async (items: StorageData) => {
        await write(items);
        if (isVaultWrite(items)) throw new Error('reported late');
      });

      const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      local().set.mockImplementation(write);
      await secure.storeTotpEntries([{ ...totp, id: 'totp-3' }]);

      expect(unlock.success).toBe(true);
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
      expect(storage.passext_encryption_salt).toBeUndefined();
      // The entry saved after the unlock is under the key of the stored vault.
      expect(
        JSON.parse(
          open(storage.passext_encrypted_totp_entries as Sealed, dataKey()).toString('utf8')
        )
      ).toEqual([{ ...totp, id: 'totp-3' }]);
      expect((await contentsWith(PIN))?.totp).toEqual([{ ...totp, id: 'totp-3' }]);
    });

    it('writes nothing when a value under the old key does not decrypt', async () => {
      const damaged = storage.passext_encrypted_totp_entries as { data: string };
      const bytes = Buffer.from(damaged.data, 'base64');
      bytes[0] ^= 0xff;
      damaged.data = bytes.toString('base64');
      const legacy = vaultState();
      const { send } = await loadBackground();
      local().set.mockClear();

      const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

      // Unreadable data is not rewritten or dropped; the rest stays usable.
      expect(unlock.success).toBe(true);
      expect(vaultWrites()).toEqual([]);
      expect(vaultState()).toEqual(legacy);
      expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toHaveLength(1);
    });

    it('writes nothing when the new vault fails verification, and unlocks with the old key', async () => {
      const legacy = vaultState();
      const { send, secure } = await loadBackground();
      local().set.mockClear();
      // The re-encrypted TOTP entries come out as bytes that do not decrypt.
      mockCipher.corrupt = (plaintext) => Buffer.from(plaintext).includes(totp.id);

      const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      mockCipher.corrupt = null;

      expect(unlock.success).toBe(true);
      expect(vaultWrites()).toEqual([]);
      expect(vaultState()).toEqual(legacy);
      expect(await secure.getTotpEntries()).toEqual([totp]);
      // The next unlock migrates it.
      expect(await contentsWith(PIN)).toEqual(EVERYTHING);
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
    });

    it('writes nothing when the PIN wrapper would not open again', async () => {
      const legacy = vaultState();
      const { send } = await loadBackground();
      local().set.mockClear();
      // A wrapped key is the only 32-byte plaintext the migration encrypts.
      mockCipher.corrupt = (plaintext) => plaintext.length === 32;

      const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      mockCipher.corrupt = null;

      expect(unlock.success).toBe(true);
      expect(vaultWrites()).toEqual([]);
      expect(vaultState()).toEqual(legacy);
      expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toHaveLength(1);
    });

    it('stays locked, keeping the legacy salt, when the write does not read back', async () => {
      const { send } = await loadBackground();
      const write = local().set.getMockImplementation()!;
      // Reports success, but one value never reaches storage.
      local().set.mockImplementation(async (items: StorageData) => {
        if (!isVaultWrite(items)) return write(items);
        const { passext_encrypted_totp_entries: _lost, ...rest } = items;
        return write(rest);
      });

      const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      local().set.mockImplementation(write);

      expect(unlock.success).toBe(false);
      expect(unlock.error).toEqual(expect.stringContaining('could not be read back'));
      expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(false);
      expect(storage.passext_encryption_salt).toBeDefined();
      const removedSalt = local().remove.mock.calls.some(([keys]) =>
        [keys].flat().includes('passext_encryption_salt')
      );
      expect(removedSalt).toBe(false);
    });

    it('removes the legacy salt only after the write has been read back', async () => {
      const { send } = await loadBackground();
      local().set.mockClear();
      local().get.mockClear();
      local().remove.mockClear();

      await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

      const order = (mock: jest.Mock, matches: (argument: unknown) => boolean) =>
        mock.mock.calls
          .map(([argument], index) =>
            matches(argument) ? mock.mock.invocationCallOrder[index] : 0
          )
          .filter(Boolean);
      const [written] = order(local().set, (items) => isVaultWrite(items as StorageData));
      const readBack = order(
        local().get,
        (keys) => Array.isArray(keys) && [...keys].sort().join() === VAULT_WRITE.join()
      ).filter((at) => at > written);
      const [removed] = order(local().remove, (keys) =>
        [keys].flat().includes('passext_encryption_salt')
      );

      expect(readBack).toHaveLength(1);
      expect(written).toBeLessThan(readBack[0]);
      expect(readBack[0]).toBeLessThan(removed);
    });

    it('finishes when the worker died between the write and removing the old salt', async () => {
      const { send } = await loadBackground();
      const drop = local().remove.getMockImplementation()!;
      local().remove.mockImplementation((keys: string | string[]) =>
        [keys].flat().includes('passext_encryption_salt') ? new Promise(() => {}) : drop(keys)
      );

      void send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      const removesSalt = (call: unknown[]) =>
        [call[0] as string | string[]].flat().includes('passext_encryption_salt');
      while (!local().remove.mock.calls.some(removesSalt)) await flush();
      local().remove.mockImplementation(drop);
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
      expect(storage.passext_encryption_salt).toBeDefined();

      // The record wins over the stale salt, and the next unlock removes it.
      expect(await contentsWith(PIN)).toEqual(EVERYTHING);
      expect(storage.passext_encryption_salt).toBeUndefined();
    });

    it('lands a write made during the migration under the data key, not lost or under the old one', async () => {
      const { send, secure } = await loadBackground();
      const write = local().set.getMockImplementation()!;
      // A failed first migration leaves the vault unlocked on the old key...
      local().set.mockImplementation(async (items: StorageData) => {
        if (isVaultWrite(items)) throw new Error('QUOTA_BYTES quota exceeded');
        return write(items);
      });
      await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      // ...and the PIN typed again retries it while a sync merge saves.
      let release!: () => void;
      const held = new Promise<void>((resolve) => (release = resolve));
      local().set.mockImplementation(async (items: StorageData) => {
        if (isVaultWrite(items)) await held;
        return write(items);
      });
      local().set.mockClear();
      const racing = [{ ...totp, id: 'racing' }];

      const unlock = send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      while (!local().set.mock.calls.some(([items]) => isVaultWrite(items))) await flush();
      const save = secure.storeTotpEntries(racing);
      for (let i = 0; i < 5; i++) await flush();
      release();
      expect((await unlock).success).toBe(true);
      await save;
      local().set.mockImplementation(write);

      expect(
        JSON.parse(
          open(storage.passext_encrypted_totp_entries as Sealed, dataKey()).toString('utf8')
        )
      ).toEqual(racing);
      // Removing the PIN decrypts every value strictly, so it fails on any
      // value left under another key.
      const restarted = await loadBackground();
      await restarted.send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      const removed = await restarted.send({
        type: 'REMOVE_MASTER_PASSWORD',
        payload: { currentPassword: PIN },
      });
      expect(removed.success).toBe(true);
      expect(storage.totp_entries).toEqual(racing);
    });
  });

  describe('a vault unlocked before its migration could be written', () => {
    async function unlockedUnmigrated() {
      const background = await loadBackground();
      const write = local().set.getMockImplementation()!;
      local().set.mockImplementation(async (items: StorageData) => {
        if (isVaultWrite(items)) throw new Error('QUOTA_BYTES quota exceeded');
        return write(items);
      });
      await background.send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
      local().set.mockImplementation(write);
      return background;
    }

    it('refuses to enroll an unlock passkey', async () => {
      const { send } = await unlockedUnmigrated();
      const before = vaultState();

      const enrolled = await send({
        type: 'ENROLL_UNLOCK_PASSKEY',
        payload: {
          password: PIN,
          vaultId: randomBytes(16).toString('base64'),
          credentialId: randomBytes(32).toString('base64url'),
          prfSalt: randomBytes(32).toString('base64'),
          prfOutput: randomBytes(32).toString('base64'),
          name: 'Laptop',
          transports: ['internal'],
        },
      });

      expect(enrolled.success).toBe(false);
      expect(enrolled.code).toBe(
        extensionUrl.startsWith('chrome-extension://')
          ? 'VAULT_FORMAT_PENDING'
          : 'PASSKEY_UNLOCK_UNSUPPORTED'
      );
      expect(vaultState()).toEqual(before);
    });

    it('migrates in the same write as a change of PIN', async () => {
      const { send } = await unlockedUnmigrated();
      local().set.mockClear();

      const change = await send({
        type: 'CHANGE_MASTER_PASSWORD',
        payload: { currentPassword: PIN, newPassword: '975310' },
      });

      expect(change.success).toBe(true);
      expect(vaultWrites()).toHaveLength(1);
      expect(storage.passext_vault_kdf).toEqual(SENTINEL);
      expect(storage.passext_encryption_salt).toBeUndefined();
      expect(await contentsWith(PIN)).toBeNull();
      expect(await contentsWith('975310')).toEqual(EVERYTHING);
    });

    it('can still turn the lock off', async () => {
      const { send } = await unlockedUnmigrated();

      const removed = await send({
        type: 'REMOVE_MASTER_PASSWORD',
        payload: { currentPassword: PIN },
      });

      expect(removed.success).toBe(true);
      expect(Object.keys(storage).filter((key) => key.startsWith('passext_'))).toEqual([]);
      expect(storage.totp_entries).toEqual([totp]);
    });
  });
});
