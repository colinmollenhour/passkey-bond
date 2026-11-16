# relay.passkey.bond

The Passkey.bond sync relay: [strfry](https://github.com/hoytech/strfry),
pinned by image digest, with a write policy that admits only Passkey.bond
sync traffic. It holds nothing it can read: sync events are AES-256-GCM
ciphertext under keys that never leave the user's devices.

| File | Purpose |
| --- | --- |
| `Dockerfile` | strfry plus `jq` and `su-exec` |
| `strfry.conf` | The image's default config; every change is marked `Passkey.bond:` |
| `write-policy.jq` | Accepts kind 30078 events whose one `d` tag starts with `pksync-v5-`, and the NIP-09 deletions (kind 5, `k` = 30078) that remove a device's old protocol v4 events. Rejects everything else. |
| `write-policy.sh` | strfry's plugin: one long-running `jq`, one decision per line |
| `start.sh` | Gives the database volume to the `strfry` user, then starts the relay |
| `test-policy.mjs` | Signs throwaway events and checks what the relay accepts |

If the sync protocol's event shape changes (`src/sync/protocol.ts`,
`createNostrEvent` in `src/sync/sync-service.ts`), update `write-policy.jq`
and `test-policy.mjs` with it, or devices on the new version stop syncing
through this relay.

## Hosting

Railway project `passkey.bond` (Dragonstone Labs), service `relay`: built from
this folder, root directory `/relay`, watching `/relay/**`, with a volume at
`/app/strfry-db` and the custom domain `relay.passkey.bond` on port 7777.

## Test locally

```sh
docker build -t passkey-bond-relay relay
docker run --rm -p 7777:7777 passkey-bond-relay
node relay/test-policy.mjs ws://localhost:7777
```

Against production: `node relay/test-policy.mjs wss://relay.passkey.bond`.
The accepted test events stay in the relay's database, so run it there only
when needed.
