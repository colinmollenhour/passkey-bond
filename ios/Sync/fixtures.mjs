// Regenerates the native sync fixtures from the browser's own libraries:
//   node ios/Sync/fixtures.mjs   (from the repository root)
// The chain keys follow src/sync/chain-keys.ts (protocol v5).
import { createHash, createCipheriv, scryptSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { deriveChainKeys, legacyChainID, SYNC_EVENT_PREFIX } from './chain-keys.mjs';

const require = createRequire(resolve('package.json'));
const { schnorr } = await import(require.resolve('@noble/secp256k1'));
const hex = (bytes) => Buffer.from(bytes).toString('hex');

// node:crypto's scrypt, independent of @noble/hashes, must agree on the root.
const check = 'ab'.repeat(32);
assert.equal(
  hex(scryptSync(check, 'pkvault-sync-v5/root', 32, { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 })),
  hex(deriveChainKeys(check).root)
);
// Pinned by tests/sync/chain-keys.test.ts.
assert.equal(deriveChainKeys(check).chainId, '707571ea9119f5dd95a71a1b0429ae48');

const entropy = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';
const phrase = 'audit vanish execute note pledge rotate bundle stand regular burden reunion tide';
const seedHash = createHash('sha256').update(Buffer.from(entropy, 'hex')).digest('hex');
const keys = deriveChainKeys(seedHash);
const chainID = keys.chainId;
const author = hex(schnorr.getPublicKey(keys.nostrPrivateKey));
const plaintext = JSON.stringify({ type: 'announce', chainId: chainID, deviceName: 'Phone / 🔑', line: '\n' });
const nonce = Buffer.alloc(12, 7);
const cipher = createCipheriv('aes-256-gcm', keys.encryptionKey, nonce);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
const content = JSON.stringify({ n: nonce.toString('base64'), c: ciphertext.toString('base64') });
const created_at = 1_700_000_000;
const tags = [['d', `${SYNC_EVENT_PREFIX}-${chainID}`], ['t', 'unicode / 🔑']];
const id = createHash('sha256').update(JSON.stringify([0, author, created_at, 30078, tags, content])).digest('hex');
const sig = hex(await schnorr.signAsync(Buffer.from(id, 'hex'), keys.nostrPrivateKey, Buffer.alloc(32)));
const fixture = {
  entropy, phrase, seedHash, chainID, legacyChainID: legacyChainID(seedHash), author, plaintext,
  event: { id, pubkey: author, created_at, kind: 30078, tags, content, sig },
};
writeFileSync(new URL('Tests/VaultSyncTests/Fixtures/browser-sync.json', import.meta.url), `${JSON.stringify(fixture, null, 2)}\n`);

// The seeds the native tests use, plus the BIP39 test phrase's seed from tests/sync/chain-keys.test.ts.
const abandon = createHash('sha256').update(Buffer.alloc(16)).digest('hex');
const vectors = [check, 'cd'.repeat(32), abandon, seedHash].map((seed) => {
  const derived = deriveChainKeys(seed);
  return {
    seedHash: seed,
    chainID: derived.chainId,
    encryptionKey: hex(derived.encryptionKey),
    signingKey: hex(derived.nostrPrivateKey),
    author: hex(schnorr.getPublicKey(derived.nostrPrivateKey)),
  };
});
assert.equal(vectors[2].chainID, '8fc61ad8d0c0c37bf0b1c1c53ec3642c');
writeFileSync(new URL('Tests/VaultSyncTests/Fixtures/chain-keys.json', import.meta.url), `${JSON.stringify(vectors, null, 2)}\n`);
