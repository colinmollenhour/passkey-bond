/**
 * The WebAuthn side of passkey unlock: asking a passkey held outside the
 * vault (the operating system's passkey manager, a phone, a security key)
 * for the PRF output that opens this vault's wrapped data key.
 *
 * This runs in the unlock page, never in the popup, the worker or the vault
 * dialog. It takes the CredentialsContainer as a parameter: the page passes
 * navigator.credentials, tests pass a fake. Content scripts match only web
 * pages, so on an extension page that is the browser's own WebAuthn, not
 * this extension's shim.
 *
 * The relying party is the extension's own origin, which is what leaving
 * out rp.id and rpId selects. Chromium accepts that; Firefox does not, so
 * Firefox has no entry point to this module.
 *
 * Nothing here checks a signature or a challenge. The proof is whether the
 * PRF output unwraps the data key, and the background decides that
 * (src/crypto/unlock-record.ts). The website authenticator in
 * src/background/prf.ts is the vault answering PRF for web sites and has
 * nothing to do with this.
 */

import {
  arrayBufferToBase64,
  arrayBufferToBase64URL,
  base64ToUint8Array,
  base64URLToArrayBuffer,
} from '../utils/base64';

export type CeremonyFailure =
  | 'cancelled'
  | 'no-prf'
  | 'prf-unstable'
  | 'excluded'
  | 'unsupported'
  | 'failed';

export class UnlockCeremonyError extends Error {
  readonly reason: CeremonyFailure;

  constructor(reason: CeremonyFailure) {
    super(`Passkey unlock ceremony: ${reason}`);
    this.name = 'UnlockCeremonyError';
    this.reason = reason;
  }
}

/** What the vault stores about an enrolled passkey that a prompt needs. */
export interface EnrolledRef {
  credentialId: string; // base64url, no padding
  prfSalt: string; // base64 of 32 bytes
  transports?: string[];
}

export interface CreatedUnlockPasskey {
  credentialId: string;
  prfSalt: string;
  transports: string[];
  /** The PRF output the provider returned at creation, when it returned one. */
  createOutput: Uint8Array | null;
}

export const UNLOCK_RP_NAME = 'Passkey.bond';
export const UNLOCK_USER_NAME = 'Passkey.bond vault unlock';
const PRF_BYTES = 32;
const TRANSPORTS = ['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal'];

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** A private copy of a BufferSource, whichever realm made it; null otherwise. */
function copyBytes(value: unknown): Uint8Array | null {
  if (value == null || typeof value !== 'object') return null;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  }
  if (typeof (value as ArrayBuffer).byteLength === 'number') {
    try {
      return new Uint8Array(value as ArrayBuffer).slice();
    } catch {
      return null;
    }
  }
  return null;
}

function credentialIdBytes(credentialId: string): Uint8Array {
  return new Uint8Array(base64URLToArrayBuffer(credentialId));
}

function knownTransports(transports: unknown): string[] {
  if (!Array.isArray(transports)) return [];
  return TRANSPORTS.filter((transport) => transports.includes(transport));
}

/** The first PRF result when it is exactly 32 bytes, else null. */
function prfResult(credential: unknown): Uint8Array | null {
  const first = extensionResults(credential)?.results?.first;
  const bytes = copyBytes(first);
  if (!bytes) return null;
  if (bytes.length !== PRF_BYTES) {
    bytes.fill(0);
    return null;
  }
  return bytes;
}

function extensionResults(
  credential: unknown
): { enabled?: boolean; results?: { first?: unknown } } | undefined {
  try {
    const results = (credential as PublicKeyCredential).getClientExtensionResults?.();
    return (results as { prf?: { enabled?: boolean; results?: { first?: unknown } } })?.prf;
  } catch {
    return undefined;
  }
}

/**
 * Cancel, timeout, failed verification and "no such passkey here" all arrive
 * as NotAllowedError, so they share one reason and the message for it does
 * not claim to know which it was.
 */
function ceremonyError(error: unknown, creating: boolean): UnlockCeremonyError {
  if (error instanceof UnlockCeremonyError) return error;
  const name = (error as { name?: unknown } | null)?.name;
  if (name === 'NotAllowedError' || name === 'AbortError') {
    return new UnlockCeremonyError('cancelled');
  }
  if (name === 'InvalidStateError' && creating) return new UnlockCeremonyError('excluded');
  if (name === 'SecurityError' || name === 'NotSupportedError') {
    return new UnlockCeremonyError('unsupported');
  }
  return new UnlockCeremonyError('failed');
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

/**
 * Create a passkey at whichever provider the user picks, asking for PRF.
 * Throws 'no-prf' when the provider neither enables PRF nor returns a result,
 * in which case the caller stops before any second prompt. The passkey then
 * stays at the provider, unreferenced by the vault.
 */
export async function createUnlockPasskey(
  credentials: CredentialsContainer,
  input: { name: string; excludeCredentialIds: string[] }
): Promise<CreatedUnlockPasskey> {
  if (typeof credentials?.create !== 'function') throw new UnlockCeremonyError('unsupported');

  const salt = randomBytes(PRF_BYTES);
  const publicKey = {
    // No rp.id: the relying party is this extension's origin.
    rp: { name: UNLOCK_RP_NAME },
    // A fresh user.id each time, so a second passkey at the same provider is
    // a second credential and does not replace the first.
    user: { id: randomBytes(16), name: UNLOCK_USER_NAME, displayName: input.name },
    // Nothing verifies the response, so the challenge only has to be there.
    challenge: randomBytes(32),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    // Unlock always sends an allow list, so the passkey need not be discoverable.
    authenticatorSelection: { userVerification: 'required', residentKey: 'discouraged' },
    attestation: 'none',
    excludeCredentials: input.excludeCredentialIds.map((id) => ({
      type: 'public-key',
      id: credentialIdBytes(id),
    })),
    extensions: { prf: { eval: { first: salt } } },
  };

  let credential: Credential | null;
  try {
    credential = await credentials.create({
      publicKey: publicKey as unknown as PublicKeyCredentialCreationOptions,
    });
  } catch (error) {
    throw ceremonyError(error, true);
  }

  const rawId = copyBytes((credential as PublicKeyCredential | null)?.rawId);
  if (!rawId || rawId.length === 0) throw new UnlockCeremonyError('failed');

  const createOutput = prfResult(credential);
  if (!createOutput && extensionResults(credential)?.enabled !== true) {
    throw new UnlockCeremonyError('no-prf');
  }

  let transports: string[] = [];
  try {
    const response = (credential as PublicKeyCredential)
      .response as AuthenticatorAttestationResponse;
    transports = knownTransports(response?.getTransports?.());
  } catch {
    transports = [];
  }

  return {
    credentialId: arrayBufferToBase64URL(rawId.buffer as ArrayBuffer),
    prfSalt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
    transports,
    createOutput,
  };
}

/**
 * Ask one of the enrolled passkeys for its PRF output. Each passkey has its
 * own salt, so the salts go in evalByCredential and the answer is matched to
 * its wrapper by the credential ID that comes back.
 */
export async function readUnlockPrf(
  credentials: CredentialsContainer,
  enrolled: EnrolledRef[]
): Promise<{ credentialId: string; prfOutput: Uint8Array }> {
  if (typeof credentials?.get !== 'function') throw new UnlockCeremonyError('unsupported');
  // Without an allow list the browser would offer any passkey for this origin.
  if (enrolled.length === 0) throw new UnlockCeremonyError('failed');

  const evalByCredential: Record<string, { first: Uint8Array }> = {};
  for (const passkey of enrolled) {
    evalByCredential[passkey.credentialId] = { first: base64ToUint8Array(passkey.prfSalt) };
  }
  const publicKey = {
    // No rpId: the relying party is this extension's origin.
    challenge: randomBytes(32),
    allowCredentials: enrolled.map((passkey) => {
      const transports = knownTransports(passkey.transports);
      return {
        type: 'public-key',
        id: credentialIdBytes(passkey.credentialId),
        ...(transports.length > 0 ? { transports } : {}),
      };
    }),
    userVerification: 'required',
    extensions: { prf: { evalByCredential } },
  };

  let credential: Credential | null;
  try {
    credential = await credentials.get({
      publicKey: publicKey as unknown as PublicKeyCredentialRequestOptions,
    });
  } catch (error) {
    throw ceremonyError(error, false);
  }

  const rawId = copyBytes((credential as PublicKeyCredential | null)?.rawId);
  if (!rawId || rawId.length === 0) throw new UnlockCeremonyError('failed');
  const credentialId = arrayBufferToBase64URL(rawId.buffer as ArrayBuffer);
  if (!enrolled.some((passkey) => passkey.credentialId === credentialId)) {
    throw new UnlockCeremonyError('failed');
  }

  const prfOutput = prfResult(credential);
  if (!prfOutput) throw new UnlockCeremonyError('no-prf');
  return { credentialId, prfOutput };
}

/**
 * The second prompt of enrollment: read the new passkey's PRF output the way
 * every later unlock will. Some providers return no output at creation, and
 * one that answers differently the second time could never unlock anything,
 * so nothing is stored until this has succeeded.
 */
export async function confirmUnlockPasskey(
  credentials: CredentialsContainer,
  created: CreatedUnlockPasskey
): Promise<Uint8Array> {
  const { prfOutput } = await readUnlockPrf(credentials, [
    {
      credentialId: created.credentialId,
      prfSalt: created.prfSalt,
      transports: created.transports,
    },
  ]);
  if (created.createOutput && !sameBytes(created.createOutput, prfOutput)) {
    prfOutput.fill(0);
    throw new UnlockCeremonyError('prf-unstable');
  }
  return prfOutput;
}
