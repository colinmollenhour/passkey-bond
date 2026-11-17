/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: the MV3 service worker dies.
 *
 * Chrome stops an idle extension worker after about 30 seconds and starts a
 * new one for the next message, and it can kill one mid-message. A ceremony
 * spans several messages with a human in between, so the worker that lists
 * the passkeys is often not the one that signs.
 *
 * Steady state: every page request settles (resolves or rejects, never
 * hangs), a credential the page receives verifies, and the vault never
 * holds half a passkey.
 */

import { setupVault, vaultReady, type PasskeyOption } from '../helpers/harness';
import { legacyVault } from '../helpers/legacy-vault';
import { authenticate, outcome, register } from '../helpers/ceremony';
import {
  authenticationJSON,
  creationOptionsFromJSON,
  registrationJSON,
  requestOptionsFromJSON,
} from '../helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

const PIN = '123456';

/** An unlock passkey as the background sees one: its ID, salt and PRF output. */
const unlockPasskey = {
  credentialId: Buffer.alloc(32, 7).toString('base64url'),
  prfSalt: Buffer.alloc(32, 1).toString('base64'),
  prfOutput: Buffer.alloc(32, 2).toString('base64'),
};

/** Set a PIN and enroll the unlock passkey; returns the vault ID the prompt ran for. */
async function enrollUnlockPasskey(): Promise<string> {
  expect(
    (await vault.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
  ).toBe(true);
  const { vaultId } = await vault.send({ type: 'GET_UNLOCK_METHODS' });
  const enrolled = await vault.send({
    type: 'ENROLL_UNLOCK_PASSKEY',
    payload: { password: PIN, vaultId, ...unlockPasskey, name: 'Laptop', transports: [] },
  });
  expect(enrolled.success).toBe(true);
  return vaultId;
}

describe('a worker restart between the picker and the signature', () => {
  it('still signs: the picker ran on one worker, the signature on the next', async () => {
    const registration = await register();
    vault.user.choosePasskey.mockImplementation(async (options: PasskeyOption[]) => {
      await vault.restartWorker();
      return { action: 'use', id: options[0].id };
    });

    await authenticate(registration);
  });

  it('keeps a PIN-protected vault unlocked across the restart', async () => {
    const registration = await register();
    expect(
      (await vault.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
    ).toBe(true);
    vault.user.choosePasskey.mockImplementation(async (options: PasskeyOption[]) => {
      await vault.restartWorker();
      return { action: 'use', id: options[0].id };
    });

    await authenticate(registration);
    expect((await vault.send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(true);
  });

  it('keeps a vault whose key was upgraded on unlock unlocked across the restart', async () => {
    await vault.reset(legacyVault(PIN));
    expect(
      (await vault.send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } })).success
    ).toBe(true);
    expect(vault.storage.passext_vault_kdf).toEqual({ kdf: 'wrapped-data-key', version: 1 });
    expect((vault.storage.passext_vault_unlock as { pin: { kdf: unknown } }).pin.kdf).toMatchObject(
      { kdf: 'scrypt' }
    );
    const registration = await register();

    // The session saved for the next worker holds the new key, not the old.
    await vault.restartWorker();
    expect((await vault.send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(true);
    await authenticate(registration);
  });

  it('keeps a vault unlocked with a passkey unlocked across the restart', async () => {
    const registration = await register();
    await enrollUnlockPasskey();
    await vault.send({ type: 'LOCK_SECURE_STORAGE' });
    await vault.restartWorker();
    expect((await vault.send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(false);

    const { credentialId, prfOutput } = unlockPasskey;
    expect(
      (await vault.send({ type: 'UNLOCK_WITH_PASSKEY', payload: { credentialId, prfOutput } }))
        .success
    ).toBe(true);

    // The session saved for the next worker holds the data key, however it was opened.
    await vault.restartWorker();
    expect(await vault.send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).toMatchObject({
      isUnlocked: true,
      passkeyUnlock: { supported: true, count: 1 },
    });
    await authenticate(registration);
  });

  it('keeps a session from before a PIN change that kept the data key', async () => {
    const registration = await register();
    await enrollUnlockPasskey();

    // With a passkey enrolled only the PIN wrapper is replaced.
    const changed = await vault.send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: '654321' },
    });
    expect(changed.success).toBe(true);

    await vault.restartWorker();
    expect((await vault.send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(true);
    await authenticate(registration);
  });

  it('registers on a worker that started after the user confirmed', async () => {
    vault.user.confirmCreate.mockImplementation(async () => {
      await vault.restartWorker();
      return true;
    });

    const registration = await register();
    expect((await vault.passkeys()).map((p) => p.credentialId)).toEqual([registration.record.id]);
  });
});

describe('a worker killed in the middle of a message', () => {
  it('fails the registration cleanly when the worker dies before saving', async () => {
    // The save never completes: the worker is gone before storage answers.
    vault.chrome.faults.push({
      op: 'set',
      match: (keys) => keys.includes('passkeys'),
      hang: true,
      times: 1,
    });
    vault.user.confirmCreate.mockImplementation(() => {
      setTimeout(() => vault.killWorker(), 5);
      return true;
    });

    const { error } = await outcome(
      navigator.credentials.create({
        publicKey: creationOptionsFromJSON(
          registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
        ),
      })
    );
    await vault.restartWorker();

    expect(error?.name).toBe('NotAllowedError');
    expect(await vault.passkeys()).toEqual([]);
  });

  it('answers a sign-in whose worker died, without stranding the page', async () => {
    await register();
    vault.chrome.faults.push({
      op: 'set',
      match: (keys) => keys.includes('passkeys'),
      hang: true,
      times: 1,
    });
    vault.user.choosePasskey.mockImplementation((options: PasskeyOption[]) => {
      setTimeout(() => vault.killWorker(), 5);
      return { action: 'use', id: options[0].id };
    });

    const { error } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
      })
    );

    expect(error?.name).toBe('NotAllowedError');
    expect(vault.native.get).not.toHaveBeenCalled();
  });
});

describe('no worker at all', () => {
  it('hands sign-in to the browser when the vault cannot be reached', async () => {
    vault.killWorker();
    vault.native.get.mockResolvedValue({ id: 'native' });

    const result: any = await navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
    });

    expect(result.id).toBe('native');
  });

  it('rejects registration rather than hanging when the vault cannot be reached', async () => {
    vault.killWorker();

    const { error } = await outcome(
      navigator.credentials.create({
        publicKey: creationOptionsFromJSON(
          registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
        ),
      })
    );

    expect(error).toBeDefined();
  });
});

describe('repeated restarts', () => {
  // Twenty ceremonies and a worker start per message.
  it('survives a restart before every message of twenty ceremonies', async () => {
    const original = vault.chrome.deliver.bind(vault.chrome);
    let restarts = 0;
    jest.spyOn(vault.chrome, 'deliver').mockImplementation(async (message, sender) => {
      if (sender.tab) {
        restarts++;
        vault.chrome.killWorker();
        await vault.restartWorker();
      }
      return original(message, sender);
    });
    try {
      const registration = await register();
      for (let i = 0; i < 19; i++) await authenticate(registration);
    } finally {
      jest.restoreAllMocks();
    }

    expect(restarts).toBeGreaterThanOrEqual(20);
    const [stored] = await vault.passkeys();
    expect(stored.counter).toBe(19);
  }, 60000);
});

describe('the vault locks while an unlock passkey prompt is open', () => {
  const lockData = () =>
    JSON.stringify(
      Object.fromEntries(
        Object.entries(vault.storage).filter(([key]) => key.startsWith('passext_'))
      )
    );

  it('refuses the enrollment that arrives after the lock, storing nothing', async () => {
    const vaultId = await enrollUnlockPasskey();
    const before = lockData();
    // The auto-lock alarm fires while the browser's prompt is showing.
    await vault.send({ type: 'LOCK_SECURE_STORAGE' });

    const enrolled = await vault.send({
      type: 'ENROLL_UNLOCK_PASSKEY',
      payload: {
        password: PIN,
        vaultId,
        credentialId: Buffer.alloc(32, 9).toString('base64url'),
        prfSalt: unlockPasskey.prfSalt,
        prfOutput: Buffer.alloc(32, 3).toString('base64'),
        name: 'Phone',
        transports: ['hybrid'],
      },
    });

    expect(enrolled).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
    expect(lockData()).toBe(before);
  });

  it('refuses a new PIN, a removal and a rename that arrive after the lock', async () => {
    await enrollUnlockPasskey();
    const before = lockData();
    await vault.send({ type: 'LOCK_SECURE_STORAGE' });
    const { credentialId, prfOutput } = unlockPasskey;

    for (const message of [
      {
        type: 'CHANGE_MASTER_PASSWORD_WITH_PASSKEY',
        payload: { credentialId, prfOutput, newPassword: '654321' },
      },
      { type: 'REMOVE_UNLOCK_PASSKEY', payload: { password: PIN, credentialId } },
      { type: 'RENAME_UNLOCK_PASSKEY', payload: { credentialId, name: 'Renamed' } },
    ]) {
      expect(await vault.send(message)).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
    }

    expect(lockData()).toBe(before);
  });

  it('refuses an enrollment whose prompt outlived the worker and the lock', async () => {
    const vaultId = await enrollUnlockPasskey();
    const before = lockData();
    await vault.send({ type: 'LOCK_SECURE_STORAGE' });
    await vault.restartWorker();

    const enrolled = await vault.send({
      type: 'ENROLL_UNLOCK_PASSKEY',
      payload: {
        password: PIN,
        vaultId,
        credentialId: Buffer.alloc(32, 9).toString('base64url'),
        prfSalt: unlockPasskey.prfSalt,
        prfOutput: Buffer.alloc(32, 3).toString('base64'),
        name: 'Phone',
        transports: [],
      },
    });

    expect(enrolled).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
    expect(lockData()).toBe(before);
  });
});

describe('the vault locks mid-ceremony', () => {
  it('refuses the signature, without the browser prompt, when the vault locked while the picker was open', async () => {
    await register();
    expect(
      (await vault.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
    ).toBe(true);
    vault.user.choosePasskey.mockImplementation(async (options: PasskeyOption[]) => {
      // The auto-lock alarm fires while the user is choosing.
      await vault.send({ type: 'LOCK_SECURE_STORAGE' });
      return { action: 'use', id: options[0].id };
    });

    const { error } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
      })
    );

    expect(error?.name).toBe('NotAllowedError');
    expect(vault.native.get).not.toHaveBeenCalled();
    expect(vault.user.errorToast).toHaveBeenCalled();
  });
});
