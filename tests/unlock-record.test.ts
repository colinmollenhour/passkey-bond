/**
 * The unlock record's primitives (src/crypto/unlock-record.ts): wrapping the
 * vault data key for an unlock method, deriving a passkey's wrapping key from
 * its PRF output, and reading a stored record. The context strings and the
 * layout are part of the storage format, so they are pinned here against
 * Node's own crypto rather than against the code under test.
 */

import { createDecipheriv, hkdfSync, randomBytes } from 'crypto';
import { parseKdfSpec, UnsupportedKdfError } from '../src/crypto/kdf';
import {
  cleanPasskeyName,
  isPasskeyUnlockOrigin,
  isUnlockSentinel,
  MAX_UNLOCK_PASSKEYS,
  newVaultId,
  parseUnlockRecord,
  PRF_WRAP_INFO,
  prfWrappingKey,
  UNLOCK_RECORD_KEY,
  UNLOCK_RECORD_VERSION,
  UNLOCK_SENTINEL_KDF,
  unlockSentinel,
  unwrapDataKey,
  VaultDamagedError,
  WRAP_AAD_CONTEXT,
  wrapDataKey,
} from '../src/crypto/unlock-record';

const bytes = (length: number) => new Uint8Array(randomBytes(length));
const b64 = (length: number) => randomBytes(length).toString('base64');
const b64url = (length: number) => randomBytes(length).toString('base64url');

const KDF = { kdf: 'scrypt', params: { N: 1024, r: 8, p: 1 }, salt: b64(32) };

function passkeyEntry(overrides: Record<string, unknown> = {}) {
  return {
    credentialId: b64url(32),
    prfSalt: b64(32),
    wrapped: { iv: b64(12), data: b64(48) },
    name: 'Laptop',
    createdAt: 1700000000000,
    transports: ['internal'],
    ...overrides,
  };
}

function record(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    vaultId: newVaultId(),
    pin: { kdf: KDF, wrapped: { iv: b64(12), data: b64(48) } },
    passkeys: [],
    ...overrides,
  };
}

describe('the pinned format', () => {
  it('uses these names and context strings', () => {
    expect(UNLOCK_RECORD_KEY).toBe('passext_vault_unlock');
    expect(UNLOCK_SENTINEL_KDF).toBe('wrapped-data-key');
    expect(UNLOCK_RECORD_VERSION).toBe(1);
    expect(MAX_UNLOCK_PASSKEYS).toBe(8);
    expect(WRAP_AAD_CONTEXT).toBe('passkey.bond/vault-unlock/wrap/v1');
    expect(PRF_WRAP_INFO).toBe('passkey.bond/vault-unlock/prf-wrap-key/v1');
    expect(unlockSentinel()).toEqual({ kdf: 'wrapped-data-key', version: 1 });
  });

  it('has a sentinel that the KDF parser rejects as unknown, as 0.13.0 does', () => {
    expect(isUnlockSentinel(unlockSentinel())).toBe(true);
    expect(isUnlockSentinel({ kdf: 'wrapped-data-key', version: 2 })).toBe(true);
    expect(isUnlockSentinel(KDF)).toBe(false);
    expect(isUnlockSentinel(undefined)).toBe(false);
    expect(() => parseKdfSpec(unlockSentinel())).toThrow(UnsupportedKdfError);
  });

  it('makes a vault ID of 16 random bytes', () => {
    const first = newVaultId();
    expect(Buffer.from(first, 'base64')).toHaveLength(16);
    expect(newVaultId()).not.toBe(first);
  });

  it('knows which extension origin can be a relying party', () => {
    expect(isPasskeyUnlockOrigin('chrome-extension://abcdefghijklmnop/')).toBe(true);
    expect(isPasskeyUnlockOrigin('moz-extension://0b0c4e7c-7b0d-4e0e-9a43-3a1e6f0d7e11/')).toBe(
      false
    );
    expect(isPasskeyUnlockOrigin('https://example.com/')).toBe(false);
  });
});

describe('wrapping the data key', () => {
  const dataKey = bytes(32);
  const wrappingKey = bytes(32);
  const vaultId = newVaultId();
  const credentialId = b64url(20);

  it('round-trips for the PIN and for a passkey', () => {
    const pin = wrapDataKey(dataKey, wrappingKey, vaultId, 'pin');
    const passkey = wrapDataKey(dataKey, wrappingKey, vaultId, 'passkey-prf', credentialId);

    expect(Buffer.from(pin.iv, 'base64')).toHaveLength(12);
    expect(Buffer.from(pin.data, 'base64')).toHaveLength(48);
    expect(unwrapDataKey(pin, wrappingKey, vaultId, 'pin')).toEqual(dataKey);
    expect(unwrapDataKey(passkey, wrappingKey, vaultId, 'passkey-prf', credentialId)).toEqual(
      dataKey
    );
  });

  it('uses a fresh IV for every wrap', () => {
    const first = wrapDataKey(dataKey, wrappingKey, vaultId, 'pin');
    const second = wrapDataKey(dataKey, wrappingKey, vaultId, 'pin');
    expect(second.iv).not.toBe(first.iv);
    expect(second.data).not.toBe(first.data);
  });

  it('is AES-256-GCM with the vault ID, method and credential ID as associated data', () => {
    const wrapped = wrapDataKey(dataKey, wrappingKey, vaultId, 'passkey-prf', credentialId);
    const sealed = Buffer.from(wrapped.data, 'base64');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      wrappingKey,
      Buffer.from(wrapped.iv, 'base64')
    );
    decipher.setAAD(
      Buffer.from(`passkey.bond/vault-unlock/wrap/v1\n${vaultId}\npasskey-prf\n${credentialId}`)
    );
    decipher.setAuthTag(sealed.subarray(32));
    const opened = Buffer.concat([decipher.update(sealed.subarray(0, 32)), decipher.final()]);

    expect(new Uint8Array(opened)).toEqual(dataKey);
  });

  it('does not open under another wrapping key', () => {
    const wrapped = wrapDataKey(dataKey, wrappingKey, vaultId, 'pin');
    expect(() => unwrapDataKey(wrapped, bytes(32), vaultId, 'pin')).toThrow();
  });

  it('does not open for another vault ID, method or credential ID', () => {
    const pin = wrapDataKey(dataKey, wrappingKey, vaultId, 'pin');
    const passkey = wrapDataKey(dataKey, wrappingKey, vaultId, 'passkey-prf', credentialId);

    expect(() => unwrapDataKey(pin, wrappingKey, newVaultId(), 'pin')).toThrow();
    expect(() => unwrapDataKey(pin, wrappingKey, vaultId, 'passkey-prf', credentialId)).toThrow();
    expect(() => unwrapDataKey(passkey, wrappingKey, vaultId, 'pin')).toThrow();
    expect(() => unwrapDataKey(passkey, wrappingKey, vaultId, 'passkey-prf', b64url(20))).toThrow();
    expect(() =>
      unwrapDataKey(passkey, wrappingKey, newVaultId(), 'passkey-prf', credentialId)
    ).toThrow();
  });

  it('refuses keys and wrappers of the wrong size', () => {
    const wrapped = wrapDataKey(dataKey, wrappingKey, vaultId, 'pin');

    expect(() => wrapDataKey(bytes(31), wrappingKey, vaultId, 'pin')).toThrow();
    expect(() => wrapDataKey(dataKey, bytes(16), vaultId, 'pin')).toThrow();
    expect(() => wrapDataKey(dataKey, wrappingKey, 'not-a-vault-id', 'pin')).toThrow();
    expect(() => wrapDataKey(dataKey, wrappingKey, vaultId, 'passkey-prf')).toThrow();
    expect(() => wrapDataKey(dataKey, wrappingKey, vaultId, 'pin', credentialId)).toThrow();
    expect(() =>
      unwrapDataKey({ iv: wrapped.iv, data: b64(47) }, wrappingKey, vaultId, 'pin')
    ).toThrow();
    expect(() =>
      unwrapDataKey({ iv: b64(16), data: wrapped.data }, wrappingKey, vaultId, 'pin')
    ).toThrow();
  });
});

describe('the wrapping key of an unlock passkey', () => {
  it('is HKDF-SHA256 of the PRF output, salted with the vault ID', () => {
    const prfOutput = bytes(32);
    const vaultId = newVaultId();

    const expected = hkdfSync(
      'sha256',
      prfOutput,
      Buffer.from(vaultId, 'base64'),
      'passkey.bond/vault-unlock/prf-wrap-key/v1',
      32
    );

    expect(prfWrappingKey(prfOutput, vaultId)).toEqual(new Uint8Array(expected));
  });

  it('differs between vaults for the same PRF output', () => {
    const prfOutput = bytes(32);
    expect(prfWrappingKey(prfOutput, newVaultId())).not.toEqual(
      prfWrappingKey(prfOutput, newVaultId())
    );
  });

  it('refuses a PRF output that is not 32 bytes, and a malformed vault ID', () => {
    expect(() => prfWrappingKey(bytes(31), newVaultId())).toThrow();
    expect(() => prfWrappingKey(bytes(64), newVaultId())).toThrow();
    expect(() => prfWrappingKey(bytes(32), b64(15))).toThrow();
  });
});

describe('reading a stored record', () => {
  it('returns a clean copy without unknown fields', () => {
    const entry = passkeyEntry();
    const stored = record({
      passkeys: [{ ...entry, extra: 'dropped' }],
      note: 'dropped',
    });

    const parsed = parseUnlockRecord(stored);

    expect(parsed).toEqual({
      version: 1,
      vaultId: stored.vaultId,
      pin: stored.pin,
      passkeys: [entry],
      damagedPasskeys: 0,
    });
  });

  it('reports a newer version as unsupported and other versions as damage', () => {
    expect(() => parseUnlockRecord(record({ version: 2 }))).toThrow(UnsupportedKdfError);
    expect(() => parseUnlockRecord(record({ version: 0 }))).toThrow(VaultDamagedError);
    expect(() => parseUnlockRecord(record({ version: '1' }))).toThrow(VaultDamagedError);
    expect(() => parseUnlockRecord(record({ version: 1.5 }))).toThrow(VaultDamagedError);
    expect(() => parseUnlockRecord(undefined)).toThrow(VaultDamagedError);
    expect(() => parseUnlockRecord([])).toThrow(VaultDamagedError);
  });

  it('is strict about the vault ID', () => {
    expect(() => parseUnlockRecord(record({ vaultId: b64(15) }))).toThrow(VaultDamagedError);
    expect(() => parseUnlockRecord(record({ vaultId: 42 }))).toThrow(VaultDamagedError);
    // 16 bytes, but not the canonical encoding: the padding is missing.
    const unpadded = newVaultId().replace(/=+$/, '');
    expect(() => parseUnlockRecord(record({ vaultId: unpadded }))).toThrow(VaultDamagedError);
  });

  it('gives a null PIN part for a malformed PIN wrapper, keeping the passkeys', () => {
    const entry = passkeyEntry();
    for (const pin of [
      undefined,
      'pin',
      { kdf: KDF },
      { kdf: KDF, wrapped: { iv: b64(12), data: b64(40) } },
      { kdf: KDF, wrapped: { iv: 'not base64!', data: b64(48) } },
      { wrapped: { iv: b64(12), data: b64(48) } },
    ]) {
      const parsed = parseUnlockRecord(record({ pin, passkeys: [entry] }));
      expect(parsed.pin).toBeNull();
      expect(parsed.passkeys).toEqual([entry]);
    }
  });

  it('reports a PIN KDF it cannot use as unsupported, not as a wrong PIN', () => {
    const pin = {
      kdf: { kdf: 'argon2id', params: { m: 65536, t: 3, p: 1 }, salt: KDF.salt },
      wrapped: { iv: b64(12), data: b64(48) },
    };
    expect(() => parseUnlockRecord(record({ pin }))).toThrow(UnsupportedKdfError);
  });

  it('skips and counts a malformed passkey entry without failing', () => {
    const good = passkeyEntry();
    const malformed = [
      null,
      'passkey',
      passkeyEntry({ credentialId: '' }),
      passkeyEntry({ credentialId: `${b64url(16)}=` }),
      passkeyEntry({ credentialId: randomBytes(16).toString('base64').replace(/=+$/, '') + '+' }),
      passkeyEntry({ credentialId: b64url(1024) }),
      passkeyEntry({ prfSalt: b64(31) }),
      passkeyEntry({ wrapped: { iv: b64(12), data: b64(32) } }),
      passkeyEntry({ wrapped: undefined }),
      passkeyEntry({ name: '' }),
      passkeyEntry({ name: ' padded ' }),
      passkeyEntry({ name: 'x'.repeat(65) }),
      passkeyEntry({ name: 'line\nbreak' }),
      passkeyEntry({ createdAt: '1700000000000' }),
      passkeyEntry({ createdAt: -1 }),
      passkeyEntry({ transports: 'usb' }),
    ];

    const parsed = parseUnlockRecord(record({ passkeys: [...malformed, good] }));

    expect(parsed.passkeys).toEqual([good]);
    expect(parsed.damagedPasskeys).toBe(malformed.length);
    // The list as stored goes along, for a rewrite that must not clear it.
    expect(parsed.storedPasskeys).toEqual([...malformed, good]);
    expect(parseUnlockRecord(record({ passkeys: [good] })).storedPasskeys).toBeUndefined();
    expect(parsed.pin).not.toBeNull();
  });

  it('rejects base64 that is not canonical', () => {
    // The same 32 bytes, but with unused trailing bits set in the last character.
    const salt = Buffer.alloc(32, 1).toString('base64');
    const loose = salt.slice(0, -2) + 'F=';
    expect(Buffer.from(loose, 'base64')).toEqual(Buffer.from(salt, 'base64'));

    const parsed = parseUnlockRecord(
      record({ passkeys: [passkeyEntry({ prfSalt: loose }), passkeyEntry({ prfSalt: salt })] })
    );

    expect(parsed.passkeys).toHaveLength(1);
    expect(parsed.damagedPasskeys).toBe(1);
  });

  it('accepts credential IDs from 1 to 1023 bytes', () => {
    const parsed = parseUnlockRecord(
      record({
        passkeys: [
          passkeyEntry({ credentialId: b64url(1) }),
          passkeyEntry({ credentialId: b64url(1023) }),
        ],
      })
    );
    expect(parsed.passkeys).toHaveLength(2);
  });

  it('uses each credential once, and at most eight passkeys', () => {
    const entry = passkeyEntry();
    const repeated = parseUnlockRecord(record({ passkeys: [entry, { ...entry, name: 'Again' }] }));
    expect(repeated.passkeys).toEqual([entry]);
    expect(repeated.damagedPasskeys).toBe(1);

    const many = Array.from({ length: 10 }, () => passkeyEntry());
    const capped = parseUnlockRecord(record({ passkeys: many }));
    expect(capped.passkeys).toEqual(many.slice(0, 8));
    expect(capped.damagedPasskeys).toBe(2);
  });

  it('keeps only the transports it knows, and tolerates a missing list', () => {
    const withUnknown = passkeyEntry({ transports: ['hybrid', 'teleport', 'usb', 7] });
    const { transports: _dropped, ...without } = passkeyEntry();

    const parsed = parseUnlockRecord(record({ passkeys: [withUnknown, without] }));

    expect(parsed.passkeys[0].transports).toEqual(['usb', 'hybrid']);
    expect(parsed.passkeys[1]).toEqual(without);
  });
});

describe('a passkey name', () => {
  it('is trimmed and kept between 1 and 64 code points', () => {
    expect(cleanPasskeyName('  Work laptop  ')).toBe('Work laptop');
    expect(cleanPasskeyName('🔑'.repeat(64))).toBe('🔑'.repeat(64));
    expect(cleanPasskeyName('🔑'.repeat(65))).toBeNull();
    expect(cleanPasskeyName('   ')).toBeNull();
    expect(cleanPasskeyName('')).toBeNull();
  });

  it('cannot hold control characters or be anything but a string', () => {
    // NUL, tab, NEL (a C1 control) and the line separator.
    for (const code of [0x00, 0x09, 0x85, 0x2028]) {
      expect(cleanPasskeyName(`a${String.fromCharCode(code)}b`)).toBeNull();
    }
    expect(cleanPasskeyName(42)).toBeNull();
    expect(cleanPasskeyName(null)).toBeNull();
  });
});
