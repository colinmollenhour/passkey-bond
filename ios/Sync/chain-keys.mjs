// Protocol v5 chain keys for the native fixture scripts: the derivation in
// src/sync/chain-keys.ts, with the same @noble/hashes primitives, for plain
// Node (that module is TypeScript and imports without file extensions).
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const require = createRequire(resolve('package.json'));
const { scrypt } = require('@noble/hashes/scrypt');
const { hkdf } = require('@noble/hashes/hkdf');
const { sha256 } = require('@noble/hashes/sha256');

export const SYNC_KEY_PREFIX = 'pkvault-sync-v5';
export const SYNC_EVENT_PREFIX = 'pksync-v5';

export function deriveChainKeys(seedHash) {
  const encoder = new TextEncoder();
  const root = scrypt(encoder.encode(seedHash), encoder.encode(`${SYNC_KEY_PREFIX}/root`), {
    N: 2 ** 17,
    r: 8,
    p: 1,
    dkLen: 32,
  });
  const expand = (label, length) => hkdf(sha256, root, undefined, `${SYNC_KEY_PREFIX}/${label}`, length);
  return {
    root,
    chainId: Buffer.from(expand('chain-id', 16)).toString('hex'),
    encryptionKey: expand('aes-256-gcm', 32),
    nostrPrivateKey: expand('nostr-secp256k1', 32),
  };
}

export const legacyChainID = (seedHash) => seedHash.slice(0, 32);
