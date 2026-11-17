import { cleanSyncConfig } from '../sync/config';
/**
 * Secure Storage Module for Passkey.bond
 * Provides encrypted storage for sensitive data like seed hashes and passkeys
 */

import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';
import { uint8ArrayToBase64, base64ToUint8Array } from '../utils/base64';
import {
  deriveKey,
  isWeakerThanDefault,
  legacyKdfSpec,
  newKdfSpec,
  parseKdfSpec,
  sameKdfSpec,
  UnsupportedKdfError,
  type KdfSpec,
} from './kdf';
import {
  cleanPasskeyName,
  cleanTransports,
  isCanonicalBase64,
  isCredentialId,
  isUnlockSentinel,
  MAX_UNLOCK_PASSKEYS,
  newVaultId,
  parseUnlockRecord,
  PRF_LENGTH,
  prfWrappingKey,
  UnlockError,
  UNLOCK_RECORD_KEY,
  UNLOCK_RECORD_VERSION,
  unlockPasskeyInfo,
  unlockSentinel,
  unwrapDataKey,
  VaultDamagedError,
  wrapDataKey,
  type ParsedUnlockRecord,
  type UnlockPasskey,
  type UnlockPasskeyInfo,
  type UnlockRecord,
  type WrappedKey,
} from './unlock-record';

const ENCRYPTION_CONFIG = {
  algorithm: 'AES-256-GCM',
  keyLength: 32, // 256 bits
  ivLength: 12, // 96 bits for GCM
  saltLength: 32, // 256 bits
} as const;

const STORAGE_KEYS = {
  MASTER_KEY_CHECK: 'passext_master_key_check',
  ENCRYPTED_SYNC_CONFIG: 'passext_encrypted_sync_config',
  ENCRYPTED_PASSKEYS: 'passext_encrypted_passkeys',
  ENCRYPTED_TOTP_ENTRIES: 'passext_encrypted_totp_entries',
  /**
   * The format marker of a vault with an unlock record (unlockSentinel()).
   * Legacy: how the vault key is derived straight from the PIN, a KdfSpec,
   * `{ kdf, params, salt }`.
   */
  VAULT_KDF: 'passext_vault_kdf',
  /** The unlock record: the vault data key wrapped for each unlock method. */
  VAULT_UNLOCK: UNLOCK_RECORD_KEY,
  /**
   * Legacy: the PBKDF2 salt of a vault from before VAULT_KDF existed. Read
   * only while VAULT_KDF is absent, and removed once the vault is re-keyed.
   */
  ENCRYPTION_SALT: 'passext_encryption_salt',
} as const;

/**
 * Every value encrypted under the vault data key apart from the check value.
 * A re-key (format upgrade, PIN change without unlock passkeys) rewrites all
 * of them in the same storage write as the unlock record and check value.
 */
const ENCRYPTED_BLOB_KEYS = [
  STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
  STORAGE_KEYS.ENCRYPTED_PASSKEYS,
  STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES,
] as const;

/** Everything that makes up the encrypted vault, for removal. */
const VAULT_STORAGE_KEYS = [
  STORAGE_KEYS.MASTER_KEY_CHECK,
  ...ENCRYPTED_BLOB_KEYS,
  STORAGE_KEYS.VAULT_KDF,
  STORAGE_KEYS.VAULT_UNLOCK,
  STORAGE_KEYS.ENCRYPTION_SALT,
];

const CHECK_VALUE = 'passkey-bond-check';

/** chrome.storage.local key holding the auto-lock timeout in minutes; 0 means never. */
export const AUTO_LOCK_SETTING_KEY = 'auto_lock_timeout';
export const AUTO_LOCK_ALARM = 'passext-auto-lock';
const UNLOCKED_SESSION_KEY = 'passext_unlocked_session';
export enum StorageActivity {
  Record = 'record',
  Maintenance = 'maintenance',
}
// Activity extends the deadline in memory at once but reaches session storage
// at most this often, so a restarted worker may lock up to this much early.
const SESSION_WRITE_INTERVAL_MS = 15 * 1000;

/**
 * The unlock kept in session storage: the vault data key (or, for a legacy
 * vault whose upgrade could not be written, its PIN-derived key). Sessions
 * written by earlier builds also carry a `salt`, which is ignored.
 */
interface UnlockedSession {
  key: string;
  activeAt: number;
}

/** What is stored about the vault's lock: see SecureStorage.readVaultFormat(). */
type VaultState =
  | { format: 'none' }
  | { format: 'legacy'; spec: KdfSpec | null; check: EncryptedData | undefined }
  | { format: 'v1'; record: ParsedUnlockRecord; check: EncryptedData | undefined };

/** The vault's lock as extension pages may see it, without any key. */
export interface UnlockMethods {
  format: 'none' | 'legacy' | 'v1' | 'unsupported' | 'damaged';
  vaultId: string | null;
  passkeys: UnlockPasskeyInfo[];
  /** Stored passkey entries that are malformed and were skipped. */
  damagedPasskeys: number;
}

/**
 * A vault write reported success but storage does not hold what was written.
 * The new key must not be used, and the old one may no longer open the vault.
 */
export class VaultWriteUnverifiedError extends Error {
  readonly code = 'VAULT_WRITE_UNVERIFIED';

  constructor() {
    super('The vault was written but could not be read back; it stays locked');
    this.name = 'VaultWriteUnverifiedError';
  }
}

/**
 * Memory-only storage that outlives the service worker until the browser
 * quits. Content scripts cannot read it at its default access level. Absent
 * before Firefox 115, where an unlock lasts only as long as the worker.
 */
function sessionArea(): chrome.storage.StorageArea | null {
  return typeof chrome !== 'undefined' && chrome.storage?.session ? chrome.storage.session : null;
}

function alarms(): typeof chrome.alarms | null {
  return typeof chrome !== 'undefined' && chrome.alarms ? chrome.alarms : null;
}

export interface SecureStorageConfig {
  seedHash: string;
  chainId: string;
  deviceId: string;
  deviceName: string;
  enabled: boolean;
}

/** The decrypted vault handed over when the master password is removed. */
export interface DecryptedVault {
  passkeys: Record<string, unknown>[];
  totpEntries: Record<string, unknown>[];
  syncConfig: SecureStorageConfig | null;
}

export interface EncryptedData {
  data: string;
  iv: string;
  salt: string;
  version: string;
}

export { UnsupportedKdfError, UnlockError, VaultDamagedError };

function unknownPasskey(): UnlockError {
  return new UnlockError('UNLOCK_PASSKEY_UNKNOWN', 'That passkey is not set up for this vault');
}

function vaultLocked(): UnlockError {
  return new UnlockError('VAULT_LOCKED', 'The vault is locked');
}

/** JSON with object keys sorted, so equal stored values compare equal. */
function canonical(value: unknown): string {
  return (
    JSON.stringify(value, (_key, entry) =>
      entry && typeof entry === 'object' && !Array.isArray(entry)
        ? Object.fromEntries(Object.entries(entry).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
        : entry
    ) ?? ''
  );
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

/** Whether both records hold the same wrapper and salt for `credentialId`. */
function samePasskey(a: ParsedUnlockRecord, b: ParsedUnlockRecord, credentialId: string): boolean {
  const pick = (record: ParsedUnlockRecord) => {
    const entry = record.passkeys.find((passkey) => passkey.credentialId === credentialId);
    return entry ? canonical({ prfSalt: entry.prfSalt, wrapped: entry.wrapped }) : null;
  };
  const first = pick(a);
  return first !== null && first === pick(b);
}

function encryptData(data: string, key: Uint8Array): EncryptedData {
  const iv = randomBytes(ENCRYPTION_CONFIG.ivLength);
  const cipher = gcm(key, iv);
  const encrypted = cipher.encrypt(new TextEncoder().encode(data));

  return {
    data: uint8ArrayToBase64(encrypted),
    iv: uint8ArrayToBase64(iv),
    salt: '',
    version: '2.0',
  };
}

function opensVault(check: EncryptedData, key: Uint8Array): boolean {
  try {
    return decryptData(check, key) === CHECK_VALUE;
  } catch {
    return false;
  }
}

function decryptData(encryptedData: EncryptedData, key: Uint8Array): string {
  const iv = base64ToUint8Array(encryptedData.iv);
  const encrypted = base64ToUint8Array(encryptedData.data);

  const cipher = gcm(key, iv);
  const decrypted = cipher.decrypt(encrypted);

  return new TextDecoder().decode(decrypted);
}

function secureWipe(arr: Uint8Array | null): void {
  if (!arr) return;
  crypto.getRandomValues(arr);
  arr.fill(0);
}

/**
 * SecureStorage class for managing encrypted sensitive data
 */
export class SecureStorage {
  private encryptionKey: Uint8Array | null = null;
  private isUnlocked = false;
  private lockTimeout: ReturnType<typeof setTimeout> | null = null;
  private autoLockMs = 30 * 60 * 1000; // 30 minutes default; 0 never locks
  private activeAt = 0;
  private sessionSavedAt = 0;
  /** Tail of the queue that serialises encrypted reads, writes and key swaps. */
  private storageJobs: Promise<unknown> = Promise.resolve();
  /** Tail of the queue that keeps session saves and clears in call order. */
  private sessionWrites: Promise<void> = Promise.resolve();
  /** Called when the vault locks itself after the timeout. */
  onAutoLock: (() => void) | null = null;

  /**
   * Run `job` once every earlier job has finished. Everything that reads or
   * writes an encrypted value, or swaps the key, runs through here, so no
   * write under the old key can land after a re-key has committed, and no
   * read can decrypt with a key that changed between its fetch and its
   * decrypt. The slow key derivations stay outside. A job must not call a
   * public method of this class, which would wait on itself.
   */
  private exclusive<T>(job: () => Promise<T>): Promise<T> {
    const result = this.storageJobs.then(job, job);
    this.storageJobs = result.catch(() => {});
    return result;
  }

  /**
   * Pick up an unlock made by an earlier instance of the service worker.
   * Chrome stops an idle MV3 service worker after about 30 seconds, and the
   * key used to go with it, locking the vault long before the timeout.
   * Drops the session instead when it has expired or no longer opens the
   * vault (the PIN changed). Returns whether the vault is unlocked.
   */
  async restoreSession(): Promise<boolean> {
    const setting = (await chrome.storage.local.get(AUTO_LOCK_SETTING_KEY))[AUTO_LOCK_SETTING_KEY];
    if (typeof setting === 'number') this.autoLockMs = setting * 60 * 1000;

    const area = sessionArea();
    if (this.isStorageUnlocked() || !area) return this.isStorageUnlocked();
    return this.exclusive(async () => {
      // An unlock may have finished while this waited its turn; keep its key.
      if (this.isStorageUnlocked()) return true;
      const session = (await area.get(UNLOCKED_SESSION_KEY))[UNLOCKED_SESSION_KEY] as
        | UnlockedSession
        | undefined;
      if (!session) return false;

      const key = base64ToUint8Array(session.key);
      const check = await this.readCheck();
      if (this.isIdle(session.activeAt) || !check || !opensVault(check, key)) {
        secureWipe(key);
        await this.clearSession();
        return false;
      }

      this.encryptionKey = key;
      this.isUnlocked = true;
      this.activeAt = session.activeAt;
      this.sessionSavedAt = session.activeAt;
      this.scheduleAutoLock();
      return true;
    });
  }

  /**
   * Lock when the timeout has passed. The alarm calls this, since neither the
   * in-memory timer nor the key survives a stopped service worker.
   */
  async lockIfIdle(): Promise<void> {
    if (!this.isStorageUnlocked()) {
      return;
    }
    if (this.isIdle(this.activeAt)) await this.autoLock();
  }

  /** The stored check value, encrypted under the vault key; absent without a PIN. */
  private async readCheck(): Promise<EncryptedData | undefined> {
    return (await chrome.storage.local.get(STORAGE_KEYS.MASTER_KEY_CHECK))[
      STORAGE_KEYS.MASTER_KEY_CHECK
    ];
  }

  /**
   * What is stored about the vault's lock, read in one get():
   *
   *   none    no check value and no unlock record: no lock is set
   *   legacy  a vault from before unlock records, keyed straight from the PIN
   *           through its KDF record or, older still, the legacy PBKDF2 salt
   *   v1      the format marker and an unlock record (unlock-record.ts)
   *
   * Throws UnsupportedKdfError for a format, record or KDF from a newer
   * build, and VaultDamagedError for a marker without a readable record or a
   * record without its marker. The marker is recognised before the KDF
   * parser sees it, which would reject it as an unknown KDF.
   */
  private async readVaultFormat(): Promise<VaultState> {
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.MASTER_KEY_CHECK,
      STORAGE_KEYS.VAULT_KDF,
      STORAGE_KEYS.ENCRYPTION_SALT,
      STORAGE_KEYS.VAULT_UNLOCK,
    ]);
    const check = stored[STORAGE_KEYS.MASTER_KEY_CHECK] as EncryptedData | undefined;
    const kdf = stored[STORAGE_KEYS.VAULT_KDF];
    const record = stored[STORAGE_KEYS.VAULT_UNLOCK];
    if (!check && record === undefined) return { format: 'none' };

    if (isUnlockSentinel(kdf)) {
      const version = (kdf as { version?: unknown }).version;
      if (version !== UNLOCK_RECORD_VERSION) {
        if (typeof version === 'number' && Number.isInteger(version) && version > 1) {
          throw new UnsupportedKdfError(`vault format version ${version}`);
        }
        throw new VaultDamagedError('vault format marker');
      }
      return { format: 'v1', record: parseUnlockRecord(record), check };
    }
    if (record !== undefined) {
      // A newer build's KDF record or unlock record says so first.
      if (kdf !== undefined) parseKdfSpec(kdf);
      parseUnlockRecord(record);
      throw new VaultDamagedError('unlock record without its format marker');
    }
    if (kdf !== undefined) return { format: 'legacy', spec: parseKdfSpec(kdf), check };
    const legacySalt = stored[STORAGE_KEYS.ENCRYPTION_SALT];
    // A check value without its salt cannot be opened by any PIN.
    return { format: 'legacy', spec: legacySalt ? legacyKdfSpec(legacySalt) : null, check };
  }

  /**
   * Whether the stored vault is still the one `snapshot` described when a
   * slow key derivation started outside the queue: the same legacy KDF record
   * with a check value `key` opens, or the same vault ID and PIN wrapper.
   * Returns the vault as it is now (its passkey list may have changed), or
   * null. Run inside exclusive().
   */
  private async sameVault<S extends VaultState>(snapshot: S, key?: Uint8Array): Promise<S | null> {
    const current = await this.readVaultFormat();
    if (current.format !== snapshot.format) return null;
    if (current.format === 'legacy' && snapshot.format === 'legacy') {
      const same =
        !!current.spec &&
        !!snapshot.spec &&
        !!current.check &&
        !!key &&
        sameKdfSpec(current.spec, snapshot.spec) &&
        opensVault(current.check, key);
      return same ? (current as S) : null;
    }
    if (current.format === 'v1' && snapshot.format === 'v1') {
      const same =
        current.record.vaultId === snapshot.record.vaultId &&
        canonical(current.record.pin) === canonical(snapshot.record.pin);
      return same ? (current as S) : null;
    }
    return current as S;
  }

  /**
   * Derive what `secret` gives for the stored vault, without touching the
   * unlock state: the key the PIN derives (`pinKey`) and the key the vault is
   * encrypted under (`vaultKey`), which are the same array for a legacy
   * vault. Null for a wrong secret. The caller wipes both. Throws
   * VaultDamagedError when the PIN wrapper is unreadable, or opens to a key
   * that does not open the vault.
   */
  private async openWithSecret(
    secret: string,
    state: Exclude<VaultState, { format: 'none' }>
  ): Promise<{ pinKey: Uint8Array; vaultKey: Uint8Array } | null> {
    if (state.format === 'legacy') {
      if (!state.spec || !state.check) return null;
      const key = await deriveKey(secret, state.spec);
      if (opensVault(state.check, key)) return { pinKey: key, vaultKey: key };
      secureWipe(key);
      return null;
    }
    const { pin, vaultId } = state.record;
    if (!pin) throw new VaultDamagedError('PIN wrapper');
    const pinKey = await deriveKey(secret, pin.kdf);
    let vaultKey: Uint8Array;
    try {
      vaultKey = unwrapDataKey(pin.wrapped, pinKey, vaultId, 'pin');
    } catch {
      secureWipe(pinKey);
      return null;
    }
    if (!state.check || !opensVault(state.check, vaultKey)) {
      secureWipe(pinKey);
      secureWipe(vaultKey);
      throw new VaultDamagedError('the PIN wrapper opens, the vault does not');
    }
    return { pinKey, vaultKey };
  }

  /**
   * The data key that an enrolled unlock passkey's PRF output opens, for the
   * caller to wipe. Throws UnlockError UNLOCK_PASSKEY_UNKNOWN for a credential
   * this vault does not list and UNLOCK_PASSKEY_MISMATCH for a wrapper that
   * does not open, which is kept: a wrapper is never deleted for failing.
   */
  private openWithPasskey(
    state: Extract<VaultState, { format: 'v1' }>,
    credentialId: string,
    prfOutput: Uint8Array
  ): Uint8Array {
    const { vaultId, passkeys } = state.record;
    const passkey = passkeys.find((entry) => entry.credentialId === credentialId);
    if (!passkey) throw unknownPasskey();
    const wrappingKey = prfWrappingKey(prfOutput, vaultId);
    let dataKey: Uint8Array;
    try {
      dataKey = unwrapDataKey(passkey.wrapped, wrappingKey, vaultId, 'passkey-prf', credentialId);
    } catch {
      throw new UnlockError('UNLOCK_PASSKEY_MISMATCH', 'That passkey did not open the vault');
    } finally {
      secureWipe(wrappingKey);
    }
    if (!state.check || !opensVault(state.check, dataKey)) {
      secureWipe(dataKey);
      throw new VaultDamagedError('the passkey wrapper opens, the vault does not');
    }
    return dataKey;
  }

  /** A PIN wrapper for `dataKey`, checked to open again before it is stored. */
  private pinPart(
    dataKey: Uint8Array,
    pinKey: Uint8Array,
    kdf: KdfSpec,
    vaultId: string
  ): UnlockRecord['pin'] {
    const wrapped = wrapDataKey(dataKey, pinKey, vaultId, 'pin');
    const reopened = unwrapDataKey(wrapped, pinKey, vaultId, 'pin');
    const same = sameBytes(reopened, dataKey);
    secureWipe(reopened);
    if (!same) throw new Error('The new PIN wrapper does not open');
    return { kdf, wrapped };
  }

  /**
   * `record` with its PIN wrapper replaced and its passkeys untouched. Where
   * the parser skipped entries, the list goes back exactly as stored: the
   * Options page says they are cleared by adding, renaming or removing a
   * passkey, so a change of PIN or a KDF upgrade at unlock must not clear
   * them first, before that notice was ever seen.
   */
  private withPin(record: ParsedUnlockRecord, pin: UnlockRecord['pin']): UnlockRecord {
    const passkeys =
      record.damagedPasskeys > 0 ? (record.storedPasskeys as UnlockPasskey[]) : record.passkeys;
    return { version: UNLOCK_RECORD_VERSION, vaultId: record.vaultId, pin, passkeys };
  }

  /**
   * Re-encrypt the whole vault from `oldKey` to the data key `newDataKey` and
   * store `record`, whose PIN wrapper `pinKey` opens, in one storage write.
   * This is the migration of a legacy vault and the key rotation of a PIN
   * change alike. chrome.storage.local applies a multi-key set() as a single
   * transaction (a LevelDB write batch in Chrome, an IndexedDB transaction in
   * Firefox), so a crash or a stopped worker leaves either the old vault or
   * the new one, never blobs under two keys.
   *
   * 1. Every blob is decrypted strictly with the old key: one that does not
   *    open aborts, rather than being dropped or left behind. The plaintext
   *    is carried over as stored, without parsing it.
   * 2. The batch is built: format marker, record, check value and blobs
   *    under the new data key.
   * 3. Before anything is written, a JSON round trip of the batch is proven
   *    to open: the PIN wrapper gives the data key, the check value opens,
   *    and each blob decrypts to exactly the plaintext of step 1. The old
   *    vault is therefore only ever replaced by one known to open.
   * 4. One set(): the commit point.
   * 5. The batch is read back and must equal what was sent. This settles a
   *    set() that reported a failure but landed (committed) or did not (the
   *    failure is rethrown and the caller keeps the old key). A read-back
   *    that differs after a reported success throws
   *    VaultWriteUnverifiedError: the caller must not install the new key.
   * 6. Only then is a stale legacy salt removed.
   *
   * Writing the new values under other keys first and deleting the old ones
   * afterwards would give up the single-write atomicity, and leave a window
   * an older build misreads. Run inside exclusive().
   */
  private async writeVault(
    oldKey: Uint8Array,
    newDataKey: Uint8Array,
    pinKey: Uint8Array,
    record: UnlockRecord
  ): Promise<void> {
    const stored = await chrome.storage.local.get([...ENCRYPTED_BLOB_KEYS]);
    const plaintexts = new Map<string, string>();
    for (const name of ENCRYPTED_BLOB_KEYS) {
      if (stored[name] === undefined) continue;
      plaintexts.set(name, decryptData(stored[name], oldKey));
    }

    const batch: Record<string, unknown> = {
      [STORAGE_KEYS.VAULT_KDF]: unlockSentinel(),
      [STORAGE_KEYS.VAULT_UNLOCK]: record,
      [STORAGE_KEYS.MASTER_KEY_CHECK]: encryptData(CHECK_VALUE, newDataKey),
    };
    for (const [name, plaintext] of plaintexts) {
      batch[name] = encryptData(plaintext, newDataKey);
    }

    const expected = JSON.parse(JSON.stringify(batch)) as Record<string, unknown>;
    this.verifyBatch(expected, newDataKey, pinKey, plaintexts);

    let failure: { error: unknown } | null = null;
    try {
      await chrome.storage.local.set(batch);
    } catch (error) {
      failure = { error };
    }
    let landed = false;
    try {
      const readBack = await chrome.storage.local.get(Object.keys(expected));
      landed = canonical(readBack) === canonical(expected);
    } catch (error) {
      if (failure) throw failure.error;
      throw new VaultWriteUnverifiedError();
    }
    if (!landed) {
      if (failure) throw failure.error;
      throw new VaultWriteUnverifiedError();
    }
    await this.dropStaleLegacySalt();
  }

  /** Step 3 of writeVault(): throws unless `batch` opens under the new keys. */
  private verifyBatch(
    batch: Record<string, unknown>,
    dataKey: Uint8Array,
    pinKey: Uint8Array,
    plaintexts: Map<string, string>
  ): void {
    const fail = (what: string) => new Error(`The new vault failed verification: ${what}`);
    if (!isUnlockSentinel(batch[STORAGE_KEYS.VAULT_KDF])) throw fail('format marker');
    const parsed = parseUnlockRecord(batch[STORAGE_KEYS.VAULT_UNLOCK]);
    if (!parsed.pin || parsed.damagedPasskeys > 0) throw fail('unlock record');
    let unwrapped: Uint8Array | null = null;
    try {
      unwrapped = unwrapDataKey(parsed.pin.wrapped, pinKey, parsed.vaultId, 'pin');
      if (!sameBytes(unwrapped, dataKey)) throw fail('PIN wrapper');
    } catch {
      throw fail('PIN wrapper');
    } finally {
      secureWipe(unwrapped);
    }
    if (!opensVault(batch[STORAGE_KEYS.MASTER_KEY_CHECK] as EncryptedData, dataKey)) {
      throw fail('check value');
    }
    for (const [name, plaintext] of plaintexts) {
      let reopened: string;
      try {
        reopened = decryptData(batch[name] as EncryptedData, dataKey);
      } catch {
        throw fail(name);
      }
      if (reopened !== plaintext) throw fail(name);
    }
  }

  /**
   * Store a changed unlock record for a vault whose data key stays: one
   * single-key set(). A set() that reports a failure is checked against
   * storage, since one that landed anyway has changed the vault. Run inside
   * exclusive().
   */
  private async writeRecord(record: UnlockRecord): Promise<void> {
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.VAULT_UNLOCK]: record });
    } catch (error) {
      const stored = await chrome.storage.local.get(STORAGE_KEYS.VAULT_UNLOCK).catch(() => ({}));
      const landed =
        canonical((stored as Record<string, unknown>)[STORAGE_KEYS.VAULT_UNLOCK]) ===
        canonical(JSON.parse(JSON.stringify(record)));
      if (!landed) throw error;
    }
  }

  /**
   * Remove a legacy PBKDF2 salt that outlived its vault's re-key (a worker
   * stopped between the two writes). VAULT_KDF takes precedence over it, so
   * until then it is only dead weight; a failure is retried next unlock.
   */
  private async dropStaleLegacySalt(): Promise<void> {
    try {
      const stored = await chrome.storage.local.get([
        STORAGE_KEYS.VAULT_KDF,
        STORAGE_KEYS.ENCRYPTION_SALT,
      ]);
      if (
        stored[STORAGE_KEYS.VAULT_KDF] !== undefined &&
        stored[STORAGE_KEYS.ENCRYPTION_SALT] !== undefined
      ) {
        await chrome.storage.local.remove(STORAGE_KEYS.ENCRYPTION_SALT);
      }
    } catch (error) {
      console.error('Failed to remove the legacy vault salt:', error);
    }
  }

  /** Make `key` the live vault key and save the unlock for a restarted worker. */
  private install(key: Uint8Array): void {
    if (this.encryptionKey && this.encryptionKey !== key) {
      secureWipe(this.encryptionKey);
    }
    this.encryptionKey = key;
    this.isUnlocked = true;
    this.resetAutoLock(true);
  }

  /** Wipe candidate keys, sparing whichever one became the live key. */
  private discard(...keys: Array<Uint8Array | null | undefined>): void {
    for (const key of keys) {
      if (key && key !== this.encryptionKey) secureWipe(key);
    }
  }

  /**
   * Unlock with the master PIN or passphrase, or set it up when the vault has
   * none yet. A vault from before unlock records is moved to the current
   * format on the way (unlockLegacy), and a PIN wrapper under a weaker KDF
   * than the current default is replaced.
   *
   * Returns false for a wrong PIN. Throws UnsupportedKdfError when the vault
   * was set up by a newer build, VaultDamagedError when its lock data cannot
   * be read, and VaultWriteUnverifiedError when the format upgrade was
   * written but could not be confirmed.
   */
  async initialize(masterPassword: string): Promise<boolean> {
    try {
      const state = await this.readVaultFormat();
      if (state.format === 'none') return await this.setUp(masterPassword);
      if (state.format === 'legacy') return await this.unlockLegacy(masterPassword, state);
      return await this.unlockWrapped(masterPassword, state);
    } catch (error) {
      if (
        error instanceof UnsupportedKdfError ||
        error instanceof VaultDamagedError ||
        error instanceof VaultWriteUnverifiedError
      ) {
        throw error;
      }
      console.error('SecureStorage initialization failed:', error);
      return false;
    }
  }

  /**
   * First-time setup: a fresh data key and vault ID, with the format marker,
   * the unlock record and the check value in one write.
   */
  private async setUp(secret: string): Promise<boolean> {
    // Candidate keys stay local until the write has landed, so concurrent
    // readers never decrypt with a key that is not the vault's.
    let pinKey: Uint8Array | null = null;
    const dataKey = randomBytes(ENCRYPTION_CONFIG.keyLength);
    try {
      const spec = newKdfSpec();
      pinKey = await deriveKey(secret, spec);
      const vaultId = newVaultId();
      const record: UnlockRecord = {
        version: UNLOCK_RECORD_VERSION,
        vaultId,
        pin: this.pinPart(dataKey, pinKey, spec, vaultId),
        passkeys: [],
      };
      return await this.exclusive(async () => {
        if ((await this.readVaultFormat()).format !== 'none') return false; // set up meanwhile
        await chrome.storage.local.set({
          [STORAGE_KEYS.VAULT_KDF]: unlockSentinel(),
          [STORAGE_KEYS.VAULT_UNLOCK]: record,
          [STORAGE_KEYS.MASTER_KEY_CHECK]: encryptData(CHECK_VALUE, dataKey),
        });
        this.install(dataKey);
        // A legacy salt left by an interrupted setup in an older build.
        await this.dropStaleLegacySalt();
        return true;
      });
    } finally {
      this.discard(pinKey, dataKey);
    }
  }

  /**
   * Unlock a vault from before unlock records and move it to the current
   * format: a random data key, wrapped under the PIN's key, with everything
   * re-encrypted in one write (writeVault). A PIN key from a weaker KDF than
   * the default is replaced in that same write, so there is never a second
   * migration. Nothing is written before the commit, so there is nothing to
   * roll back: if the upgrade cannot be written, the vault unlocks with its
   * old key and the upgrade is tried again on the next unlock.
   */
  private async unlockLegacy(
    secret: string,
    state: Extract<VaultState, { format: 'legacy' }>
  ): Promise<boolean> {
    const { spec, check } = state;
    if (!spec || !check) return false;
    let legacyKey: Uint8Array | null = null;
    let pinKey: Uint8Array | null = null;
    const dataKey = randomBytes(ENCRYPTION_CONFIG.keyLength);
    try {
      legacyKey = await deriveKey(secret, spec);
      if (!opensVault(check, legacyKey)) return false;

      const weak = isWeakerThanDefault(spec);
      const pinSpec = weak ? newKdfSpec() : spec;
      pinKey = weak ? await deriveKey(secret, pinSpec) : legacyKey;

      const oldKey = legacyKey;
      const wrappingKey = pinKey;
      return await this.exclusive(async () => {
        // The PIN may have changed while this was deriving.
        if (!(await this.sameVault(state, oldKey))) return false;
        try {
          const vaultId = newVaultId();
          await this.writeVault(oldKey, dataKey, wrappingKey, {
            version: UNLOCK_RECORD_VERSION,
            vaultId,
            pin: this.pinPart(dataKey, wrappingKey, pinSpec, vaultId),
            passkeys: [],
          });
          this.install(dataKey);
          return true;
        } catch (error) {
          if (error instanceof VaultWriteUnverifiedError) {
            // Storage no longer matches either vault for certain: hold no key.
            if (this.isStorageUnlocked()) await this.autoLock();
            throw error;
          }
          console.error('Vault format upgrade failed; it will be retried next unlock:', error);
          // Unlock with the old key, unless the vault moved on regardless. A
          // repeated unlock may already hold that old key from an earlier
          // failed upgrade: once it no longer opens what is stored (or that
          // cannot be told), holding it would read the vault as empty and
          // overwrite it, so the vault locks.
          if (!(await this.sameVault(state, oldKey).catch(() => null))) {
            if (this.isStorageUnlocked()) await this.autoLock();
            return false;
          }
        }
        this.install(oldKey);
        await this.dropStaleLegacySalt();
        return true;
      });
    } finally {
      this.discard(legacyKey, pinKey, dataKey);
    }
  }

  /** Unlock a vault in the current format with its PIN or passphrase. */
  private async unlockWrapped(
    secret: string,
    state: Extract<VaultState, { format: 'v1' }>
  ): Promise<boolean> {
    let opened: { pinKey: Uint8Array; vaultKey: Uint8Array } | null = null;
    let upgraded: Uint8Array | null = null;
    try {
      opened = await this.openWithSecret(secret, state);
      if (!opened) return false;

      const upgradeSpec =
        state.record.pin && isWeakerThanDefault(state.record.pin.kdf) ? newKdfSpec() : null;
      if (upgradeSpec) upgraded = await deriveKey(secret, upgradeSpec);

      const dataKey = opened.vaultKey;
      const stronger = upgraded;
      return await this.exclusive(async () => {
        // The PIN may have changed while this was deriving.
        const now = await this.sameVault(state);
        if (!now) return false;
        if (upgradeSpec && stronger) {
          try {
            const { vaultId } = now.record;
            await this.writeRecord(
              this.withPin(now.record, this.pinPart(dataKey, stronger, upgradeSpec, vaultId))
            );
          } catch (error) {
            console.error('Key derivation upgrade failed; it will be retried next unlock:', error);
          }
        }
        this.install(dataKey);
        // Left behind when a worker stopped right after a format upgrade.
        await this.dropStaleLegacySalt();
        return true;
      });
    } finally {
      this.discard(opened?.pinKey, opened?.vaultKey, upgraded);
    }
  }

  /**
   * Unlock with an enrolled unlock passkey's 32-byte PRF output. The output
   * derives the key that unwraps this passkey's copy of the data key; that
   * the wrapper opens, and the check value under its key, is the whole proof.
   * The caller wipes `prfOutput`.
   *
   * Throws UnlockError (UNLOCK_PASSKEY_UNKNOWN, UNLOCK_PASSKEY_MISMATCH),
   * VaultDamagedError or UnsupportedKdfError. Succeeds without changing
   * anything when the vault is already unlocked.
   */
  async unlockWithPasskey(credentialId: string, prfOutput: Uint8Array): Promise<void> {
    const state = await this.readVaultFormat();
    if (state.format !== 'v1') throw unknownPasskey();
    const candidate = this.openWithPasskey(state, credentialId, prfOutput);
    try {
      await this.exclusive(async () => {
        // The passkey may have been removed, or the lock replaced, meanwhile.
        const now = await this.readVaultFormat();
        if (
          now.format !== 'v1' ||
          now.record.vaultId !== state.record.vaultId ||
          !samePasskey(now.record, state.record, credentialId)
        ) {
          throw unknownPasskey();
        }
        if (this.isStorageUnlocked()) return;
        this.install(candidate);
      });
    } finally {
      this.discard(candidate);
    }
  }

  /**
   * Check a PIN or passphrase against the stored vault without touching the
   * unlock state: the candidate keys are derived locally and wiped
   * afterwards. False when no lock is set up.
   */
  async verifyMasterPassword(password: string): Promise<boolean> {
    const state = await this.readVaultFormat();
    if (state.format === 'none') return false;
    const opened = await this.openWithSecret(password, state);
    if (!opened) return false;
    secureWipe(opened.pinKey);
    secureWipe(opened.vaultKey);
    return true;
  }

  /**
   * The vault's format and its unlock passkeys' public fields. Needs no key
   * and does not throw for storage this build cannot read, which it reports
   * as the format `unsupported` or `damaged`.
   */
  async getUnlockMethods(): Promise<UnlockMethods> {
    const empty = { vaultId: null, passkeys: [], damagedPasskeys: 0 };
    try {
      const state = await this.readVaultFormat();
      if (state.format !== 'v1') return { format: state.format, ...empty };
      return {
        format: 'v1',
        vaultId: state.record.vaultId,
        passkeys: state.record.passkeys.map(unlockPasskeyInfo),
        damagedPasskeys: state.record.damagedPasskeys,
      };
    } catch (error) {
      if (error instanceof UnsupportedKdfError) return { format: 'unsupported', ...empty };
      if (error instanceof VaultDamagedError) return { format: 'damaged', ...empty };
      throw error;
    }
  }

  /**
   * Check if secure storage is unlocked
   */
  isStorageUnlocked(): boolean {
    return this.isUnlocked && this.encryptionKey !== null;
  }

  /**
   * Check if a master password has been set up
   */
  async isSetup(): Promise<boolean> {
    // The record counts too, so that a vault whose check value is lost reads
    // as damaged rather than as free to set up over.
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.MASTER_KEY_CHECK,
      STORAGE_KEYS.VAULT_UNLOCK,
    ]);
    return (
      !!stored[STORAGE_KEYS.MASTER_KEY_CHECK] || stored[STORAGE_KEYS.VAULT_UNLOCK] !== undefined
    );
  }

  /**
   * Lock the secure storage, wiping encryption key from memory
   */
  lock(): Promise<void> {
    if (this.encryptionKey) {
      secureWipe(this.encryptionKey);
      this.encryptionKey = null;
    }
    this.isUnlocked = false;
    if (this.lockTimeout) {
      clearTimeout(this.lockTimeout);
      this.lockTimeout = null;
    }
    return this.clearSession();
  }

  private autoLock(): Promise<void> {
    const cleared = this.lock();
    this.onAutoLock?.();
    return cleared;
  }

  private isIdle(activeAt: number): boolean {
    return this.autoLockMs > 0 && Date.now() >= activeAt + this.autoLockMs;
  }

  /**
   * Record activity: push the deadline back and, at most every
   * SESSION_WRITE_INTERVAL_MS unless forced, save it with the key.
   */
  private resetAutoLock(forceSave = false): void {
    this.activeAt = Date.now();
    this.scheduleAutoLock();
    if (forceSave || this.activeAt - this.sessionSavedAt >= SESSION_WRITE_INTERVAL_MS) {
      void this.saveSession();
    }
  }

  private scheduleAutoLock(): void {
    if (this.lockTimeout) {
      clearTimeout(this.lockTimeout);
      this.lockTimeout = null;
    }
    if (this.autoLockMs <= 0) return;
    const delay = Math.max(0, this.activeAt + this.autoLockMs - Date.now());
    this.lockTimeout = setTimeout(() => void this.autoLock(), delay);
  }

  private saveSession(): Promise<void> {
    const area = sessionArea();
    if (!area || !this.encryptionKey) return Promise.resolve();
    this.sessionSavedAt = this.activeAt;
    const session = {
      [UNLOCKED_SESSION_KEY]: {
        key: uint8ArrayToBase64(this.encryptionKey),
        activeAt: this.activeAt,
      } satisfies UnlockedSession,
    };
    return this.writeSession(async () => {
      await area.set(session);
      await this.scheduleAlarm();
    });
  }

  private async scheduleAlarm(): Promise<void> {
    const api = alarms();
    if (!api) return;
    if (this.autoLockMs > 0) {
      await api.create(AUTO_LOCK_ALARM, { when: this.activeAt + this.autoLockMs });
    } else {
      await api.clear(AUTO_LOCK_ALARM);
    }
  }

  private clearSession(): Promise<void> {
    this.sessionSavedAt = 0;
    return this.writeSession(async () => {
      await sessionArea()?.remove(UNLOCKED_SESSION_KEY);
      await alarms()?.clear(AUTO_LOCK_ALARM);
    });
  }

  private writeSession(write: () => Promise<void>): Promise<void> {
    const next = this.sessionWrites.catch(() => undefined).then(write);
    this.sessionWrites = next;
    return next;
  }

  /**
   * Set auto-lock timeout in milliseconds; 0 never locks. Counts from the
   * last activity rather than restarting the clock.
   */
  setAutoLockTimeout(ms: number): void {
    this.autoLockMs = ms;
    if (this.isStorageUnlocked()) {
      this.scheduleAutoLock();
      void this.scheduleAlarm();
    }
  }

  /** Encrypt `plaintext` under the live key and store it, with `alongside` in the same write. */
  private async writeBlob(
    storageKey: string,
    plaintext: string,
    alongside: Record<string, unknown> = {},
    activity = StorageActivity.Record
  ): Promise<void> {
    this.ensureUnlocked();
    const encrypted = encryptData(plaintext, this.encryptionKey!);
    await chrome.storage.local.set({ ...alongside, [storageKey]: encrypted });
    this.recordActivity(activity);
  }

  /** Push the auto-lock back for a user's activity, but not for maintenance. */
  private recordActivity(activity: StorageActivity): void {
    if (activity === StorageActivity.Record) this.resetAutoLock();
  }

  /**
   * Decrypt a stored value under the live key: undefined when absent, throws
   * when it does not decrypt.
   */
  private async readBlob(storageKey: string): Promise<string | undefined> {
    this.ensureUnlocked();
    const stored = (await chrome.storage.local.get(storageKey))[storageKey];
    if (!stored) return undefined;
    return decryptData(stored, this.encryptionKey!);
  }

  /**
   * Store sync configuration securely. `alongside` holds other keys to write
   * in the same storage operation, so the two land together or not at all.
   */
  async storeSyncConfig(
    config: SecureStorageConfig,
    alongside: Record<string, unknown> = {},
    activity = StorageActivity.Record
  ): Promise<void> {
    this.ensureUnlocked();
    return this.exclusive(() =>
      this.writeBlob(
        STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
        JSON.stringify(cleanSyncConfig(config)),
        alongside,
        activity
      )
    );
  }

  /**
   * Retrieve sync configuration
   */
  async getSyncConfig(activity = StorageActivity.Record): Promise<SecureStorageConfig | null> {
    this.ensureUnlocked();
    return this.exclusive(async () => {
      try {
        const decrypted = await this.readBlob(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG);
        if (decrypted === undefined) return null;
        this.recordActivity(activity);
        const stored = JSON.parse(decrypted);
        const config = cleanSyncConfig(stored);
        if (JSON.stringify(stored) !== JSON.stringify(config)) {
          await this.writeBlob(
            STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
            JSON.stringify(config),
            {},
            activity
          );
        }
        return config;
      } catch (error) {
        console.error('Failed to decrypt sync config:', error);
        return null;
      }
    });
  }

  /**
   * Delete sync configuration
   */
  deleteSyncConfig(): Promise<void> {
    return this.exclusive(() => chrome.storage.local.remove(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG));
  }

  async storePasskeys(
    passkeys: Record<string, unknown>[],
    activity = StorageActivity.Record
  ): Promise<void> {
    this.ensureUnlocked();
    return this.exclusive(() =>
      this.writeBlob(STORAGE_KEYS.ENCRYPTED_PASSKEYS, JSON.stringify(passkeys), {}, activity)
    );
  }

  async getPasskeys(activity = StorageActivity.Record): Promise<Record<string, unknown>[]> {
    this.ensureUnlocked();
    return this.exclusive(() =>
      this.readList(STORAGE_KEYS.ENCRYPTED_PASSKEYS, 'passkeys', activity)
    );
  }

  /**
   * A stored list, or [] when it is absent or does not decrypt. The callers
   * refuse at once while locked; a lock while the read waited its turn reads
   * as [], as it did before reads were queued.
   */
  private async readList(
    storageKey: string,
    label: string,
    activity: StorageActivity
  ): Promise<Record<string, unknown>[]> {
    try {
      const decrypted = await this.readBlob(storageKey);
      if (decrypted === undefined) return [];
      this.recordActivity(activity);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error(`Failed to decrypt ${label}:`, error);
      return [];
    }
  }

  async upsertPasskey(passkey: Record<string, unknown>): Promise<void> {
    const passkeys = await this.getPasskeys();
    const index = passkeys.findIndex((p) => p.id === passkey.id);

    if (index >= 0) {
      passkeys[index] = passkey;
    } else {
      passkeys.push(passkey);
    }

    await this.storePasskeys(passkeys);
  }

  async deletePasskey(passkeyId: string): Promise<boolean> {
    const passkeys = await this.getPasskeys();
    const filtered = passkeys.filter((p) => p.id !== passkeyId && p.credentialId !== passkeyId);

    if (filtered.length < passkeys.length) {
      await this.storePasskeys(filtered);
      return true;
    }
    return false;
  }

  async getPasskeysForRp(rpId: string): Promise<Record<string, unknown>[]> {
    const passkeys = await this.getPasskeys();
    return passkeys.filter((p) => p.rpId === rpId);
  }

  async storeTotpEntries(
    entries: Record<string, unknown>[],
    activity = StorageActivity.Record
  ): Promise<void> {
    this.ensureUnlocked();
    return this.exclusive(() =>
      this.writeBlob(STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES, JSON.stringify(entries), {}, activity)
    );
  }

  async getTotpEntries(activity = StorageActivity.Record): Promise<Record<string, unknown>[]> {
    this.ensureUnlocked();
    return this.exclusive(() =>
      this.readList(STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES, 'TOTP entries', activity)
    );
  }

  async upsertTotpEntry(entry: Record<string, unknown>): Promise<void> {
    const entries = await this.getTotpEntries();
    const index = entries.findIndex((e) => e.id === entry.id);

    if (index >= 0) {
      entries[index] = entry;
    } else {
      entries.push(entry);
    }

    await this.storeTotpEntries(entries);
  }

  async deleteTotpEntry(id: string): Promise<boolean> {
    const entries = await this.getTotpEntries();
    const filtered = entries.filter((e) => e.id !== id);

    if (filtered.length < entries.length) {
      await this.storeTotpEntries(filtered);
      return true;
    }
    return false;
  }

  /**
   * Change the master PIN or passphrase. The new PIN key comes from the
   * current default KDF with a fresh salt.
   *
   * What else changes depends on the vault, read inside the same queued job
   * as the write so that an unlock passkey enrolled meanwhile is never lost:
   *
   * - No unlock passkey: the data key is replaced and everything is
   *   re-encrypted in one write (writeVault), so a copy of the old storage
   *   and the old PIN cannot read anything stored afterwards. A legacy vault
   *   moves to the current format in that same write.
   * - One or more unlock passkeys: only the PIN wrapper is replaced. The
   *   passkeys wrap the data key, and no passkey is at hand to wrap a new
   *   one, so the data key stays and the vault is not re-encrypted.
   *   Stored passkey entries this build skipped as damaged are kept as they
   *   are (withPin).
   *
   * Returns false for a wrong current PIN. Throws UnsupportedKdfError,
   * VaultDamagedError (an unreadable PIN wrapper, which an unlock passkey can
   * replace) and VaultWriteUnverifiedError, as initialize() does.
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<boolean> {
    let opened: { pinKey: Uint8Array; vaultKey: Uint8Array } | null = null;
    let newPinKey: Uint8Array | null = null;
    const dataKey = randomBytes(ENCRYPTION_CONFIG.keyLength);
    try {
      // Always check the current PIN. The background only routes this message
      // while unlocked, so a check that ran only when locked never ran at all.
      const state = await this.readVaultFormat();
      if (state.format === 'none') return false;
      opened = await this.openWithSecret(currentPassword, state);
      if (!opened) return false;

      const nextSpec = newKdfSpec();
      newPinKey = await deriveKey(newPassword, nextSpec);

      // Only after the commit does the in-memory key change.
      const oldKey = opened.vaultKey;
      const pinKey = newPinKey;
      return await this.exclusive(async () => {
        const now = await this.sameVault(state, oldKey);
        if (!now) return false;
        try {
          // A skipped entry counts as a passkey here: it is only cleared by
          // an edit of the passkey list, where the user is told.
          if (
            now.format === 'v1' &&
            (now.record.passkeys.length > 0 || now.record.damagedPasskeys > 0)
          ) {
            const { vaultId } = now.record;
            await this.writeRecord(
              this.withPin(now.record, this.pinPart(oldKey, pinKey, nextSpec, vaultId))
            );
            return true;
          }
          const vaultId = now.format === 'v1' ? now.record.vaultId : newVaultId();
          await this.writeVault(oldKey, dataKey, pinKey, {
            version: UNLOCK_RECORD_VERSION,
            vaultId,
            pin: this.pinPart(dataKey, pinKey, nextSpec, vaultId),
            passkeys: [],
          });
        } catch (error) {
          // Keep the old key only while it still opens the stored vault.
          if (!(await this.sameVault(state, oldKey).catch(() => null))) await this.autoLock();
          throw error;
        }
        this.install(dataKey);
        return true;
      });
    } catch (error) {
      // Not a wrong PIN: the caller says which, as initialize() does.
      if (
        error instanceof UnsupportedKdfError ||
        error instanceof VaultDamagedError ||
        error instanceof VaultWriteUnverifiedError
      ) {
        throw error;
      }
      console.error('Failed to change master password:', error);
      return false;
    } finally {
      this.discard(opened?.pinKey, opened?.vaultKey, newPinKey, dataKey);
    }
  }

  /**
   * Set a new PIN or passphrase on an unlocked vault, authorized by an
   * enrolled unlock passkey instead of the current secret. Only the PIN
   * wrapper is replaced, which also repairs a damaged one. The caller wipes
   * `prfOutput`. Throws UnlockError (VAULT_LOCKED, UNLOCK_PASSKEY_UNKNOWN,
   * UNLOCK_PASSKEY_MISMATCH) or VaultDamagedError.
   */
  async changeMasterPasswordWithPasskey(
    credentialId: string,
    prfOutput: Uint8Array,
    newPassword: string
  ): Promise<void> {
    let candidate: Uint8Array | null = null;
    let newPinKey: Uint8Array | null = null;
    try {
      if (!this.isStorageUnlocked()) throw vaultLocked();
      const state = await this.readVaultFormat();
      if (state.format !== 'v1') throw unknownPasskey();
      candidate = this.openWithPasskey(state, credentialId, prfOutput);

      const nextSpec = newKdfSpec();
      newPinKey = await deriveKey(newPassword, nextSpec);

      const proven = candidate;
      const pinKey = newPinKey;
      await this.exclusive(async () => {
        if (!this.isStorageUnlocked()) throw vaultLocked();
        const now = await this.readVaultFormat();
        if (
          now.format !== 'v1' ||
          now.record.vaultId !== state.record.vaultId ||
          !samePasskey(now.record, state.record, credentialId)
        ) {
          throw unknownPasskey();
        }
        if (!sameBytes(proven, this.encryptionKey!)) {
          throw new UnlockError('UNLOCK_PASSKEY_MISMATCH', 'That passkey did not open the vault');
        }
        const { vaultId } = now.record;
        await this.writeRecord(
          this.withPin(now.record, this.pinPart(proven, pinKey, nextSpec, vaultId))
        );
        this.resetAutoLock();
      });
    } finally {
      this.discard(candidate, newPinKey);
    }
  }

  /**
   * Enroll an unlock passkey: wrap the live data key under the key its PRF
   * output derives and add the wrapper to the record. `vaultId` is the vault
   * the page ran the prompt for. Everything is checked inside the queue, so a
   * result from a prompt that outlived a lock, a lock change or another
   * enrollment is refused with nothing written. The caller wipes `prfOutput`.
   *
   * Throws UnlockError: VAULT_LOCKED, VAULT_FORMAT_PENDING (a legacy vault
   * whose upgrade has not been written yet), VAULT_CHANGED,
   * UNLOCK_PASSKEY_DUPLICATE, UNLOCK_PASSKEY_LIMIT.
   */
  addUnlockPasskey(input: {
    vaultId: string;
    credentialId: string;
    prfSalt: string;
    prfOutput: Uint8Array;
    name: string;
    transports?: string[];
  }): Promise<UnlockPasskeyInfo> {
    return this.exclusive(async () => {
      const record = await this.editableRecord();
      if (record.vaultId !== input.vaultId) {
        throw new UnlockError('VAULT_CHANGED', 'The vault lock changed during the passkey prompt');
      }
      const name = cleanPasskeyName(input.name);
      if (
        !name ||
        !isCredentialId(input.credentialId) ||
        !isCanonicalBase64(input.prfSalt, PRF_LENGTH)
      ) {
        throw new Error('Invalid unlock passkey');
      }
      if (record.passkeys.some((entry) => entry.credentialId === input.credentialId)) {
        throw new UnlockError('UNLOCK_PASSKEY_DUPLICATE', 'This passkey is already set up');
      }
      if (record.passkeys.length >= MAX_UNLOCK_PASSKEYS) {
        throw new UnlockError(
          'UNLOCK_PASSKEY_LIMIT',
          `This vault already has the maximum of ${MAX_UNLOCK_PASSKEYS} passkeys`
        );
      }

      const liveKey = this.encryptionKey!;
      const wrappingKey = prfWrappingKey(input.prfOutput, record.vaultId);
      let wrapped: WrappedKey;
      try {
        const method = 'passkey-prf';
        wrapped = wrapDataKey(liveKey, wrappingKey, record.vaultId, method, input.credentialId);
        // Nothing is stored unless the new wrapper opens to the live key.
        const reopened = unwrapDataKey(
          wrapped,
          wrappingKey,
          record.vaultId,
          method,
          input.credentialId
        );
        const same = sameBytes(reopened, liveKey);
        secureWipe(reopened);
        if (!same) throw new Error('The new passkey wrapper does not open');
      } finally {
        secureWipe(wrappingKey);
      }

      const passkey: UnlockPasskey = {
        credentialId: input.credentialId,
        prfSalt: input.prfSalt,
        wrapped,
        name,
        createdAt: Date.now(),
        transports: cleanTransports(input.transports),
      };
      await this.writeRecord({ ...record, passkeys: [...record.passkeys, passkey] });
      this.resetAutoLock();
      return unlockPasskeyInfo(passkey);
    });
  }

  /** Rename an unlock passkey. Throws UnlockError VAULT_LOCKED or UNLOCK_PASSKEY_UNKNOWN. */
  renameUnlockPasskey(credentialId: string, name: string): Promise<void> {
    return this.exclusive(async () => {
      const record = await this.editableRecord();
      const cleaned = cleanPasskeyName(name);
      if (!cleaned) throw new Error('Invalid passkey name');
      if (!record.passkeys.some((entry) => entry.credentialId === credentialId)) {
        throw unknownPasskey();
      }
      await this.writeRecord({
        ...record,
        passkeys: record.passkeys.map((entry) =>
          entry.credentialId === credentialId ? { ...entry, name: cleaned } : entry
        ),
      });
      this.resetAutoLock();
    });
  }

  /**
   * Remove one unlock passkey's wrapper; the others and the PIN wrapper stay.
   * The credential itself stays at its provider, and still opens any earlier
   * copy of this storage. Throws UnlockError VAULT_LOCKED or
   * UNLOCK_PASSKEY_UNKNOWN.
   */
  removeUnlockPasskey(credentialId: string): Promise<void> {
    return this.exclusive(async () => {
      const record = await this.editableRecord();
      if (!record.passkeys.some((entry) => entry.credentialId === credentialId)) {
        throw unknownPasskey();
      }
      await this.writeRecord({
        ...record,
        passkeys: record.passkeys.filter((entry) => entry.credentialId !== credentialId),
      });
      this.resetAutoLock();
    });
  }

  /**
   * The unlock record of an unlocked vault in the current format, for a
   * change to its passkeys. Run inside exclusive().
   */
  private async editableRecord(): Promise<UnlockRecord> {
    if (!this.isStorageUnlocked()) throw vaultLocked();
    const state = await this.readVaultFormat();
    if (state.format !== 'v1') {
      throw new UnlockError(
        'VAULT_FORMAT_PENDING',
        'Lock the vault and unlock it once with your PIN or passphrase, then try again'
      );
    }
    const { vaultId, pin, passkeys } = state.record;
    // Entries the parser skipped are left out on purpose: an edit of the
    // passkey list clears them, as the Options page says it will.
    // Rewriting the record would drop a PIN wrapper this build cannot read.
    if (!pin) throw new VaultDamagedError('PIN wrapper');
    return { version: UNLOCK_RECORD_VERSION, vaultId, pin, passkeys };
  }

  /**
   * Remove the master password: verify the current one, hand the decrypted
   * vault to `persistPlaintext` to write the cleartext copy, and only once that
   * write has succeeded drop the encrypted layer (check value, KDF record,
   * blobs, and the unlock record with every unlock passkey's wrapper, in the
   * same removal). A failure or a stopped worker before then leaves the PIN'd vault
   * intact. If only the final removal fails, the vault stays PIN'd and locked,
   * and the next unlock folds the cleartext copy back in and deletes it.
   * `persistPlaintext` runs while this holds the storage queue, so it must not
   * call SecureStorage.
   */
  async removeMasterPassword(
    currentPassword: string,
    persistPlaintext: (vault: DecryptedVault) => Promise<void>
  ): Promise<boolean> {
    // A side-effect-free check: initialize() here used to lock the vault on a
    // mistyped PIN without disconnecting sync.
    if (!(await this.verifyMasterPassword(currentPassword))) {
      return false;
    }
    return this.exclusive(async () => {
      // Strict reads: a blob that fails to decrypt aborts the removal rather
      // than being replaced by an empty cleartext list and then deleted.
      const syncConfig = await this.readEncrypted<SecureStorageConfig>(
        STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG
      );
      await persistPlaintext({
        passkeys: (await this.readEncrypted(STORAGE_KEYS.ENCRYPTED_PASSKEYS)) || [],
        totpEntries: (await this.readEncrypted(STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES)) || [],
        syncConfig: syncConfig ? cleanSyncConfig(syncConfig) : null,
      });
      await this.lock();
      await chrome.storage.local.remove(VAULT_STORAGE_KEYS);
      return true;
    });
  }

  /** Decrypt a stored blob; null when absent, throws when it does not decrypt. */
  private async readEncrypted<T = Record<string, unknown>[]>(
    storageKey: string
  ): Promise<T | null> {
    const decrypted = await this.readBlob(storageKey);
    return decrypted === undefined ? null : (JSON.parse(decrypted) as T);
  }

  /**
   * Wipe all secure data (emergency reset)
   */
  emergencyWipe(): Promise<void> {
    return this.exclusive(async () => {
      await this.lock();
      await chrome.storage.local.remove(VAULT_STORAGE_KEYS);
    });
  }

  /**
   * Ensure storage is unlocked before operations
   */
  private ensureUnlocked(): void {
    if (!this.isUnlocked || !this.encryptionKey) {
      throw new Error('Secure storage is locked. Please unlock with master password.');
    }
  }

  /**
   * Generate a random salt for sync PBKDF2 operations
   */
  generateSyncSalt(): string {
    const salt = randomBytes(ENCRYPTION_CONFIG.saltLength);
    return uint8ArrayToBase64(salt);
  }
}

// Export singleton instance
export const secureStorage = new SecureStorage();
