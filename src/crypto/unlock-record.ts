/**
 * The vault's unlock record: how the vault data key is wrapped for each way
 * of unlocking. Pure functions, no `chrome` APIs; storage and the unlock
 * state live in secure-storage.ts.
 *
 * A protected vault is encrypted under a random 32-byte data key. That key is
 * never stored as is. Each unlock method holds its own wrapped copy in the
 * record stored at `passext_vault_unlock`:
 *
 *   record   = { version: 1, vaultId, pin: { kdf, wrapped }, passkeys: [...] }
 *   wrapped  = AES-256-GCM(wrappingKey, random 12-byte IV, aad).encrypt(dataKey)
 *   aad      = utf8(WRAP_AAD_CONTEXT + '\n' + vaultId + '\n' + method + '\n' + credentialId)
 *              method is 'pin' or 'passkey-prf'; credentialId is '' for 'pin'
 *
 *   PIN or passphrase:  wrappingKey = deriveKey(secret, pin.kdf)          (kdf.ts)
 *   Unlock passkey:     wrappingKey = HKDF-SHA256(ikm = PRF output (32 bytes),
 *                                                 salt = vaultId bytes (16),
 *                                                 info = PRF_WRAP_INFO, 32)
 *
 * An unlock passkey is a WebAuthn credential held outside this vault (an OS
 * passkey manager, a phone, a security key). Its PRF output for the stored
 * per-credential `prfSalt` is the input above; the browser applies the
 * WebAuthn PRF prefix hashing to the salt itself. This is unrelated to
 * src/background/prf.ts, which answers PRF for web sites from stored passkeys.
 *
 * `vaultId` is new at every setup and migration and fixed until the lock is
 * removed. It is in both the AAD and the HKDF salt, so a wrapper copied from
 * one vault configuration into another never opens. The editable `name`,
 * `createdAt` and `transports` are not bound.
 *
 * While a record exists, `passext_vault_kdf` holds a sentinel,
 * `{ kdf: 'wrapped-data-key', version: 1 }`, which builds from before the
 * record reject as an unknown KDF ("needs a newer version") instead of
 * misreading the vault.
 *
 * Everything in the record is public or ciphertext: IDs, salts, KDF
 * parameters, wrapped keys. PRF outputs, wrapping keys and the data key are
 * never stored. Byte arrays holding them are wiped after use; the base64
 * strings that carry a PRF output in a runtime message cannot be, which is
 * also how the PIN travels.
 *
 * The context strings and the layout are part of the storage format and are
 * pinned by tests/unlock-record.test.ts.
 */

import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import {
  arrayBufferToBase64URL,
  base64URLToArrayBuffer,
  base64ToUint8Array,
  uint8ArrayToBase64,
} from '../utils/base64';
import { KEY_LENGTH, parseKdfSpec, UnsupportedKdfError, type KdfSpec } from './kdf';
import { cleanPasskeyName } from './passkey-name';

export { cleanPasskeyName };

export const UNLOCK_RECORD_KEY = 'passext_vault_unlock';
export const UNLOCK_SENTINEL_KDF = 'wrapped-data-key';
export const UNLOCK_RECORD_VERSION = 1;
export const MAX_UNLOCK_PASSKEYS = 8;
export const WRAP_AAD_CONTEXT = 'passkey.bond/vault-unlock/wrap/v1';
export const PRF_WRAP_INFO = 'passkey.bond/vault-unlock/prf-wrap-key/v1';

/** Bytes of a PRF output and of a per-credential PRF salt. */
export const PRF_LENGTH = 32;
const VAULT_ID_LENGTH = 16;
const WRAP_IV_LENGTH = 12;
const WRAPPED_LENGTH = KEY_LENGTH + 16; // data key + GCM tag
const MAX_CREDENTIAL_ID_LENGTH = 1023;
const TRANSPORTS = ['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal'];

export type UnlockMethod = 'pin' | 'passkey-prf';

/** Base64: a 12-byte IV and 48 bytes of ciphertext (32-byte key + GCM tag). */
export interface WrappedKey {
  iv: string;
  data: string;
}

export interface UnlockPasskey {
  /** Base64url without padding, 1..1023 bytes, canonical. */
  credentialId: string;
  /** Base64 of 32 random bytes: the PRF input for this credential. */
  prfSalt: string;
  wrapped: WrappedKey;
  /** 1..64 code points, trimmed, no control characters. */
  name: string;
  /** Milliseconds since the epoch. */
  createdAt: number;
  /** Subset of usb, nfc, ble, smart-card, hybrid, internal. */
  transports?: string[];
}

export interface UnlockRecord {
  version: 1;
  /** Base64 of 16 random bytes. */
  vaultId: string;
  pin: { kdf: KdfSpec; wrapped: WrappedKey };
  /** 0..8 entries, unique credentialId. */
  passkeys: UnlockPasskey[];
}

export interface ParsedUnlockRecord {
  version: 1;
  vaultId: string;
  /** Null when the stored PIN part is malformed. */
  pin: UnlockRecord['pin'] | null;
  passkeys: UnlockPasskey[];
  /** Stored passkey entries that were skipped as malformed. */
  damagedPasskeys: number;
  /**
   * The `passkeys` value exactly as stored, set only when entries were
   * skipped: a rewrite that is not about the passkeys puts it back, so the
   * skipped entries stay until the passkey list itself is edited.
   */
  storedPasskeys?: unknown;
}

/** The public fields of an unlock passkey, as sent to extension pages. */
export interface UnlockPasskeyInfo {
  credentialId: string;
  name: string;
  createdAt: number;
  prfSalt: string;
  transports: string[];
}

/**
 * The stored lock data cannot be used: a sentinel without a readable record,
 * a record without its sentinel, a malformed PIN wrapper, or a wrapper that
 * opens to a key that does not open the vault.
 */
export class VaultDamagedError extends Error {
  readonly code = 'VAULT_DAMAGED';

  constructor(detail: string) {
    super(`Vault lock data is damaged: ${detail}`);
    this.name = 'VaultDamagedError';
  }
}

/** A refused unlock-method operation, with a code the pages localize. */
export class UnlockError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'UnlockError';
    this.code = code;
  }
}

export function unlockSentinel(): { kdf: 'wrapped-data-key'; version: 1 } {
  return { kdf: UNLOCK_SENTINEL_KDF, version: UNLOCK_RECORD_VERSION };
}

/**
 * Whether a stored `passext_vault_kdf` value is the sentinel of an unlock
 * record, of any version. The version is checked by the reader.
 */
export function isUnlockSentinel(value: unknown): boolean {
  return (
    !!value && typeof value === 'object' && (value as { kdf?: unknown }).kdf === UNLOCK_SENTINEL_KDF
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/** Decode canonical standard base64 of exactly `length` bytes, or null. */
function decodeBase64(value: unknown, length: number): Uint8Array | null {
  if (typeof value !== 'string') return null;
  try {
    const bytes = base64ToUint8Array(value);
    if (bytes.length !== length || uint8ArrayToBase64(bytes) !== value) return null;
    return bytes;
  } catch {
    return null;
  }
}

/** Whether `value` is canonical base64 of exactly `length` bytes. */
export function isCanonicalBase64(value: unknown, length: number): value is string {
  return decodeBase64(value, length) !== null;
}

/** Whether `value` is a canonical base64url credential ID of 1..1023 bytes. */
export function isCredentialId(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const buffer = base64URLToArrayBuffer(value);
    return (
      buffer.byteLength >= 1 &&
      buffer.byteLength <= MAX_CREDENTIAL_ID_LENGTH &&
      arrayBufferToBase64URL(buffer) === value
    );
  } catch {
    return false;
  }
}

function parseWrappedKey(value: unknown): WrappedKey | null {
  if (!isObject(value)) return null;
  const { iv, data } = value;
  if (!isCanonicalBase64(iv, WRAP_IV_LENGTH) || !isCanonicalBase64(data, WRAPPED_LENGTH)) {
    return null;
  }
  return { iv, data };
}

/** The known transports in `value`, in order and without repeats. */
export function cleanTransports(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return TRANSPORTS.filter((transport) => value.includes(transport));
}

function parsePasskey(value: unknown): UnlockPasskey | null {
  if (!isObject(value)) return null;
  const { credentialId, prfSalt, name, createdAt, transports } = value;
  const wrapped = parseWrappedKey(value.wrapped);
  if (
    !isCredentialId(credentialId) ||
    !isCanonicalBase64(prfSalt, PRF_LENGTH) ||
    !wrapped ||
    typeof name !== 'string' ||
    cleanPasskeyName(name) !== name ||
    typeof createdAt !== 'number' ||
    !Number.isSafeInteger(createdAt) ||
    createdAt < 0 ||
    (transports !== undefined && !Array.isArray(transports))
  ) {
    return null;
  }
  const passkey: UnlockPasskey = { credentialId, prfSalt, wrapped, name, createdAt };
  if (transports !== undefined) passkey.transports = cleanTransports(transports);
  return passkey;
}

/**
 * Validate a stored unlock record, returning a clean copy without unknown
 * fields. `version` and `vaultId` are strict. A malformed PIN part gives
 * `pin: null` so an unlock passkey can still open the vault and set a new
 * secret. A malformed, repeated or surplus passkey entry is skipped and
 * counted, never fatal; the list is then also returned as stored.
 *
 * Throws UnsupportedKdfError for a newer version or a PIN KDF this build
 * cannot use, VaultDamagedError for anything else it cannot read.
 */
export function parseUnlockRecord(value: unknown): ParsedUnlockRecord {
  if (!isObject(value)) throw new VaultDamagedError('no unlock record');
  const { version, vaultId, pin, passkeys } = value;
  if (version !== UNLOCK_RECORD_VERSION) {
    if (typeof version === 'number' && Number.isInteger(version) && version > 1) {
      throw new UnsupportedKdfError(`unlock record version ${version}`);
    }
    throw new VaultDamagedError('unlock record version');
  }
  if (!isCanonicalBase64(vaultId, VAULT_ID_LENGTH)) throw new VaultDamagedError('vault ID');

  let parsedPin: UnlockRecord['pin'] | null = null;
  if (isObject(pin)) {
    const wrapped = parseWrappedKey(pin.wrapped);
    // A KDF record that is present but unusable is a newer build's, as it is
    // for a vault without an unlock record; only a missing one is damage.
    if (wrapped && isObject(pin.kdf)) parsedPin = { kdf: parseKdfSpec(pin.kdf), wrapped };
  }

  const parsedPasskeys: UnlockPasskey[] = [];
  let damagedPasskeys = 0;
  if (Array.isArray(passkeys)) {
    const seen = new Set<string>();
    for (const entry of passkeys) {
      const passkey = parsePasskey(entry);
      if (
        !passkey ||
        seen.has(passkey.credentialId) ||
        parsedPasskeys.length >= MAX_UNLOCK_PASSKEYS
      ) {
        damagedPasskeys++;
        continue;
      }
      seen.add(passkey.credentialId);
      parsedPasskeys.push(passkey);
    }
  } else if (passkeys !== undefined) {
    damagedPasskeys = 1;
  }

  const parsed: ParsedUnlockRecord = {
    version: UNLOCK_RECORD_VERSION,
    vaultId,
    pin: parsedPin,
    passkeys: parsedPasskeys,
    damagedPasskeys,
  };
  if (damagedPasskeys > 0) parsed.storedPasskeys = passkeys;
  return parsed;
}

/** The public fields of a stored unlock passkey. */
export function unlockPasskeyInfo(passkey: UnlockPasskey): UnlockPasskeyInfo {
  return {
    credentialId: passkey.credentialId,
    name: passkey.name,
    createdAt: passkey.createdAt,
    prfSalt: passkey.prfSalt,
    transports: [...(passkey.transports ?? [])],
  };
}

export function newVaultId(): string {
  return uint8ArrayToBase64(randomBytes(VAULT_ID_LENGTH));
}

function wrapAad(vaultId: string, method: UnlockMethod, credentialId: string): Uint8Array {
  if (!isCanonicalBase64(vaultId, VAULT_ID_LENGTH)) throw new Error('Invalid vault ID');
  if (method === 'pin' ? credentialId !== '' : !isCredentialId(credentialId)) {
    throw new Error('Invalid credential ID for this unlock method');
  }
  return new TextEncoder().encode(`${WRAP_AAD_CONTEXT}\n${vaultId}\n${method}\n${credentialId}`);
}

function requireKey(key: Uint8Array, what: string): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LENGTH) {
    throw new Error(`${what} must be ${KEY_LENGTH} bytes`);
  }
}

/** Wrap the vault data key for one unlock method, under a fresh random IV. */
export function wrapDataKey(
  dataKey: Uint8Array,
  wrappingKey: Uint8Array,
  vaultId: string,
  method: UnlockMethod,
  credentialId = ''
): WrappedKey {
  requireKey(dataKey, 'Data key');
  requireKey(wrappingKey, 'Wrapping key');
  const iv = randomBytes(WRAP_IV_LENGTH);
  const data = gcm(wrappingKey, iv, wrapAad(vaultId, method, credentialId)).encrypt(dataKey);
  return { iv: uint8ArrayToBase64(iv), data: uint8ArrayToBase64(data) };
}

/**
 * Open a wrapper, returning the 32-byte data key for the caller to wipe.
 * Throws when it does not open: a wrong wrapping key, or a wrapper made for
 * another vault ID, method or credential.
 */
export function unwrapDataKey(
  wrapped: WrappedKey,
  wrappingKey: Uint8Array,
  vaultId: string,
  method: UnlockMethod,
  credentialId = ''
): Uint8Array {
  requireKey(wrappingKey, 'Wrapping key');
  const iv = decodeBase64(wrapped?.iv, WRAP_IV_LENGTH);
  const data = decodeBase64(wrapped?.data, WRAPPED_LENGTH);
  if (!iv || !data) throw new Error('Malformed wrapped key');
  const dataKey = gcm(wrappingKey, iv, wrapAad(vaultId, method, credentialId)).decrypt(data);
  requireKey(dataKey, 'Unwrapped key');
  return dataKey;
}

/** The wrapping key for an unlock passkey, from its 32-byte PRF output. */
export function prfWrappingKey(prfOutput: Uint8Array, vaultId: string): Uint8Array {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length !== PRF_LENGTH) {
    throw new Error(`PRF output must be ${PRF_LENGTH} bytes`);
  }
  const salt = decodeBase64(vaultId, VAULT_ID_LENGTH);
  if (!salt) throw new Error('Invalid vault ID');
  return hkdf(sha256, prfOutput, salt, PRF_WRAP_INFO, KEY_LENGTH);
}

/**
 * Whether passkey unlock can work for an extension at this URL. The relying
 * party is the extension's own origin, which only Chromium accepts.
 */
export function isPasskeyUnlockOrigin(extensionUrl: string): boolean {
  return typeof extensionUrl === 'string' && extensionUrl.startsWith('chrome-extension://');
}
