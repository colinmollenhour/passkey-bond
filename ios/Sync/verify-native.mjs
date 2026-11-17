import { createHash, createDecipheriv } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { deriveChainKeys, SYNC_EVENT_PREFIX } from './chain-keys.mjs';

const require = createRequire(resolve('package.json'));
const { schnorr } = await import(require.resolve('@noble/secp256k1'));
const fixture = JSON.parse(readFileSync(new URL('Tests/VaultSyncTests/Fixtures/browser-sync.json', import.meta.url)));
const event = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const id = createHash('sha256').update(JSON.stringify([
  0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
])).digest('hex');
assert.equal(id, event.id);
assert.equal(event.pubkey, fixture.author);
assert(await schnorr.verifyAsync(Buffer.from(event.sig, 'hex'), Buffer.from(id, 'hex'), Buffer.from(event.pubkey, 'hex')));
const keys = deriveChainKeys(fixture.seedHash);
assert.equal(keys.chainId, fixture.chainID);
assert.equal(event.pubkey, Buffer.from(schnorr.getPublicKey(keys.nostrPrivateKey)).toString('hex'));
assert(event.tags.some((tag) => tag[0] === 'd' && tag[1] === `${SYNC_EVENT_PREFIX}-${keys.chainId}`));
const key = keys.encryptionKey;
const box = JSON.parse(event.content);
const data = Buffer.from(box.c, 'base64');
const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(box.n, 'base64'));
decipher.setAuthTag(data.subarray(-16));
const plaintext = Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]).toString('utf8');
assert.equal(plaintext, fixture.plaintext);
console.log('Browser verified native sync ciphertext and Schnorr signature: PASS');
