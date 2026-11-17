/**
 * What an older build does with a vault in the current format, and what this
 * build does with a newer one. Version 0.13.0 must say "needs a newer
 * version" and leave the vault alone: it must neither report a wrong PIN nor
 * offer to set up a new lock over it. That is pinned by running the frozen
 * 0.13.0 code (tests/fixtures/v0.13.0) against storage written by the current
 * build. The current build must treat a later format the same way, and must
 * tell damaged lock data apart from both.
 */

import {
  loadBackground,
  useFakeStorage,
  type Respond,
  type StorageData,
} from './helpers/pin-background';
import { legacyVault } from './helpers/legacy-vault';
import { SecureStorage as SecureStorage0130 } from './fixtures/v0.13.0/secure-storage';
import { UnsupportedKdfError as UnsupportedKdfError0130 } from './fixtures/v0.13.0/kdf';

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

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const vaultState = () =>
  clone(Object.fromEntries(Object.entries(storage).filter(([key]) => key.startsWith('passext_'))));
const unlock = (send: Respond, password = PIN) =>
  send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password } });

let storage: StorageData;

beforeEach(() => {
  storage = useFakeStorage();
});

/** A vault from 0.13.0 or earlier, unlocked once by the current build. */
async function migratedVault() {
  Object.assign(storage, legacyVault(PIN, { totpEntries: [totp] }));
  const { send } = await loadBackground();
  expect((await unlock(send)).success).toBe(true);
  await send({ type: 'LOCK_SECURE_STORAGE' });
}

/** A lock set up by the current build. */
async function freshVault() {
  storage.totp_entries = [totp];
  const { send } = await loadBackground();
  expect((await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success).toBe(
    true
  );
  await send({ type: 'LOCK_SECURE_STORAGE' });
}

describe.each([
  ['a migrated vault', migratedVault],
  ['a vault set up in the current format', freshVault],
])('version 0.13.0 opening %s', (_name, prepare) => {
  it('says it needs a newer version, and changes nothing', async () => {
    await prepare();
    expect(storage.passext_vault_kdf).toEqual({ kdf: 'wrapped-data-key', version: 1 });
    const before = JSON.stringify(vaultState());
    const old = new SecureStorage0130();

    await expect(old.initialize(PIN)).rejects.toBeInstanceOf(UnsupportedKdfError0130);
    await expect(old.initialize(PIN)).rejects.toMatchObject({ code: 'UNSUPPORTED_KDF' });

    expect(old.isStorageUnlocked()).toBe(false);
    expect(JSON.stringify(vaultState())).toBe(before);
  });

  it('still sees a lock, so it does not offer to set up a new one', async () => {
    await prepare();

    expect(await new SecureStorage0130().isSetup()).toBe(true);
  });

  it('opens again in the current build afterwards', async () => {
    await prepare();
    await new SecureStorage0130().initialize(PIN).catch(() => undefined);

    const { send, secure } = await loadBackground();
    expect((await unlock(send)).success).toBe(true);
    expect(await secure.getTotpEntries()).toEqual([totp]);
  });
});

describe('the current build opening a vault from a newer version', () => {
  it.each([
    [
      'a newer format marker',
      () => {
        storage.passext_vault_kdf = { kdf: 'wrapped-data-key', version: 2 };
      },
    ],
    [
      'a newer unlock record',
      () => {
        (storage.passext_vault_unlock as { version: number }).version = 2;
      },
    ],
    [
      'a newer marker and record',
      () => {
        storage.passext_vault_kdf = { kdf: 'wrapped-data-key', version: 3 };
        (storage.passext_vault_unlock as { version: number }).version = 3;
      },
    ],
    [
      'a PIN key derivation it does not know',
      () => {
        const record = storage.passext_vault_unlock as { pin: { kdf: Record<string, unknown> } };
        record.pin.kdf = {
          kdf: 'argon2id',
          params: { m: 65536, t: 3, p: 1 },
          salt: record.pin.kdf.salt,
        };
      },
    ],
  ])('says %s needs a newer version, and changes nothing', async (_name, tamper) => {
    await freshVault();
    tamper();
    const before = JSON.stringify(vaultState());
    const { send } = await loadBackground();

    expect(await unlock(send)).toMatchObject({ success: false, code: 'UNSUPPORTED_KDF' });
    expect(await unlock(send, '000000')).toMatchObject({ success: false, code: 'UNSUPPORTED_KDF' });

    expect((await send({ type: 'GET_UNLOCK_METHODS' })).format).toBe('unsupported');
    expect(await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).toMatchObject({
      isSetup: true,
      isUnlocked: false,
      passkeyUnlock: { count: 0 },
    });
    const setup = await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    expect(setup.success).toBe(false);
    expect(JSON.stringify(vaultState())).toBe(before);
  });
});

describe('the current build opening a vault whose lock data is damaged', () => {
  it.each([
    [
      'a format marker without its unlock record',
      () => {
        delete storage.passext_vault_unlock;
      },
    ],
    [
      'an unlock record without its format marker',
      () => {
        delete storage.passext_vault_kdf;
      },
    ],
    [
      'an unlock record beside a legacy KDF record',
      () => {
        storage.passext_vault_kdf = (
          storage.passext_vault_unlock as { pin: { kdf: unknown } }
        ).pin.kdf;
      },
    ],
    [
      'a malformed vault ID',
      () => {
        (storage.passext_vault_unlock as { vaultId: string }).vaultId = 'AAAA';
      },
    ],
    [
      'a malformed PIN wrapper',
      () => {
        (storage.passext_vault_unlock as { pin: { wrapped: { data: string } } }).pin.wrapped.data =
          'AAAA';
      },
    ],
    [
      'an unlock record without its check value',
      () => {
        delete storage.passext_master_key_check;
      },
    ],
    [
      'a check value the data key does not open',
      () => {
        const check = storage.passext_master_key_check as { data: string };
        const bytes = Buffer.from(check.data, 'base64');
        bytes[0] ^= 0xff;
        check.data = bytes.toString('base64');
      },
    ],
  ])('reports %s as damage, not as a wrong PIN, and changes nothing', async (_name, tamper) => {
    await freshVault();
    tamper();
    const before = JSON.stringify(vaultState());
    const { send } = await loadBackground();

    expect(await unlock(send)).toMatchObject({ success: false, code: 'VAULT_DAMAGED' });

    // Still a locked vault: setting up over it would lose it for good.
    expect(await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).toMatchObject({
      isSetup: true,
      isUnlocked: false,
    });
    const setup = await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    expect(setup.success).toBe(false);
    expect(JSON.stringify(vaultState())).toBe(before);
  });

  it('never deletes a PIN wrapper for failing to open', async () => {
    await freshVault();
    const before = JSON.stringify(vaultState());
    const { send } = await loadBackground();

    for (const guess of ['000000', '111111', '482917']) {
      expect((await unlock(send, guess)).success).toBe(false);
    }

    expect(JSON.stringify(vaultState())).toBe(before);
    expect((await unlock(send)).success).toBe(true);
  });
});
