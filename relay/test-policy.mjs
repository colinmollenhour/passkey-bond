// Checks relay.passkey.bond's write policy against a running relay:
//   node relay/test-policy.mjs ws://localhost:7777
// Signs throwaway events and expects sync events and their deletions to be
// accepted and everything else rejected.
import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const url = process.argv[2] ?? 'ws://localhost:7777';
const key = secp256k1.utils.randomSecretKey();
const pubkey = bytesToHex(secp256k1.schnorr.getPublicKey(key));
const chain = bytesToHex(secp256k1.utils.randomSecretKey()).slice(0, 32);
const now = Math.floor(Date.now() / 1000);

async function sign(kind, tags, content = 'x') {
  const data = [0, pubkey, now, kind, tags, content];
  const id = bytesToHex(sha256(new TextEncoder().encode(JSON.stringify(data))));
  const sig = bytesToHex(await secp256k1.schnorr.signAsync(hexToBytes(id), key));
  return { id, pubkey, created_at: now, kind, tags, content, sig };
}

const cases = [
  ['announcement', true, 30078, [['d', `pksync-v5-${chain}`]]],
  ['snapshot chunk', true, 30078, [['d', `pksync-v5-${chain}-dev1-update-0`], ['h', chain]]],
  ['v4 deletion', true, 5, [['a', `30078:${pubkey}:pksync-v4-${chain}`], ['e', '0'.repeat(64)], ['k', '30078']]],
  ['text note', false, 1, []],
  ['other app data', false, 30078, [['d', 'some-other-app']]],
  ['old protocol event', false, 30078, [['d', `pksync-v4-${chain}`]]],
  ['two d tags', false, 30078, [['d', `pksync-v5-${chain}`], ['d', 'x']]],
  ['deletion of another app', false, 5, [['a', `30078:${pubkey}:other`], ['k', '30078']]],
  ['deletion without k', false, 5, [['a', `30078:${pubkey}:pksync-v5-${chain}`]]],
];

const ws = new WebSocket(url);
await new Promise((resolve, reject) => {
  ws.onopen = resolve;
  ws.onerror = () => reject(new Error(`cannot connect to ${url}`));
});
const pending = new Map();
ws.onmessage = ({ data }) => {
  const [type, id, ok, msg] = JSON.parse(data);
  if (type === 'OK') pending.get(id)?.({ ok, msg });
};

let failures = 0;
for (const [name, expected, kind, tags] of cases) {
  const event = await sign(kind, tags);
  const result = await new Promise((resolve) => {
    pending.set(event.id, resolve);
    ws.send(JSON.stringify(['EVENT', event]));
  });
  const pass = result.ok === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'ok  ' : 'FAIL'} ${name}: ${result.ok ? 'accepted' : `rejected (${result.msg})`}`);
}
ws.close();
process.exit(failures ? 1 : 0);
