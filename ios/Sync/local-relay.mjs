// A local TLS relay for the native sync tests:
//   node ios/Sync/local-relay.mjs cert.pem key.pem ready-file rejected-file
// Every event passes relay.passkey.bond's write policy first, so the tests fail
// on anything that relay would refuse; each refusal is appended to
// rejected-file for test-relay.sh.
import { createServer } from 'node:https';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const require = createRequire(resolve('package.json'));
const { WebSocketServer } = require('ws');
const { schnorr } = await import(require.resolve('@noble/secp256k1'));
const NOT_FOUND = 404;
const EVENT_KIND = 30078;
const MAX_FRAME = 18_432;
const MAX_EVENTS = 1000;
const rejections = process.argv[5];

// The strfry write policy, run as relay/write-policy.sh runs it: one
// long-lived jq reading one request per line and answering one decision per
// line, in order.
const policy = spawn('jq', ['-c', '--unbuffered', '-f', resolve('relay/write-policy.jq')], {
  stdio: ['pipe', 'pipe', 'inherit'],
});
const decisions = [];
policy.on('exit', code => {
  process.stderr.write(`Write policy exited (${code})\n`);
  for (const decide of decisions.splice(0)) decide({ action: 'reject', msg: 'error: write policy stopped' });
});
createInterface({ input: policy.stdout }).on('line', line => decisions.shift()?.(JSON.parse(line)));
const admit = event => new Promise(decide => {
  decisions.push(decide);
  const request = { type: 'new', event, receivedAt: Math.floor(Date.now() / 1000), sourceType: 'IP4', sourceInfo: '127.0.0.1' };
  policy.stdin.write(`${JSON.stringify(request)}\n`);
});

const server = createServer({ cert: readFileSync(process.argv[2]), key: readFileSync(process.argv[3]) }, (_, response) => {
  response.writeHead(NOT_FOUND).end();
});
const sockets = new WebSocketServer({ server, maxPayload: MAX_FRAME });
server.on('tlsClientError', error => process.stderr.write(`Local relay TLS error: ${error.message}\n`));
const subscriptions = new Map();
const stored = new Map();
const matches = (event, filters) => filters.some(filter => {
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.since && event.created_at < filter.since) return false;
  return Object.entries(filter).filter(([key]) => key.startsWith('#')).every(([key, values]) =>
    event.tags.some(tag => tag[0] === key.slice(1) && values.includes(tag[1])));
});
const send = (socket, value) => socket.send(JSON.stringify(value));
sockets.on('connection', socket => {
  process.stdout.write('Local relay connected\n');
  const active = new Map();
  subscriptions.set(socket, active);
  socket.on('close', () => subscriptions.delete(socket));
  socket.on('message', async bytes => {
    try {
      const [type, value, ...rest] = JSON.parse(bytes.toString());
      if (type === 'REQ') {
        active.set(value, rest);
        for (const event of stored.values()) {
          if (matches(event, rest)) send(socket, ['EVENT', value, event]);
        }
        send(socket, ['EOSE', value]);
      } else if (type === 'CLOSE') {
        active.delete(value);
      } else if (type === 'EVENT') {
        const event = value;
        const digest = createHash('sha256').update(JSON.stringify([
          0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
        ])).digest('hex');
        const valid = event.kind === EVENT_KIND && digest === event.id &&
          await schnorr.verifyAsync(Buffer.from(event.sig, 'hex'), Buffer.from(digest, 'hex'), Buffer.from(event.pubkey, 'hex'));
        const decision = valid ? await admit(event) : { id: event.id, action: 'reject', msg: 'invalid: event' };
        const accepted = decision.id === event.id && decision.action === 'accept';
        send(socket, ['OK', event.id, accepted, accepted ? '' : decision.msg ?? 'blocked']);
        if (!accepted) {
          const line = `Rejected kind ${event.kind} ${JSON.stringify(event.tags)}: ${decision.msg}\n`;
          process.stderr.write(line);
          if (rejections) appendFileSync(rejections, line);
          return;
        }
        stored.set(event.id, event);
        if (stored.size > MAX_EVENTS) stored.delete(stored.keys().next().value);
        for (const [peer, requests] of subscriptions) {
          for (const [id, filters] of requests) {
            if (matches(event, filters)) send(peer, ['EVENT', id, event]);
          }
        }
      }
    } catch {
      send(socket, ['NOTICE', 'invalid frame']);
    }
  });
});
server.listen(0, '127.0.0.1', () => {
  writeFileSync(process.argv[4], `wss://localhost:${server.address().port}`);
});
process.on('SIGTERM', () => {
  for (const socket of subscriptions.keys()) socket.terminate();
  server.close();
  policy.stdin.end();
});
