# strfry write policy for relay.passkey.bond. strfry sends one JSON request
# per line and reads one decision per line back (strfry docs/plugins.md).
# Only Passkey.bond sync events (src/sync/sync-service.ts createNostrEvent)
# and the NIP-09 deletions that clean up protocol v4 events
# (src/sync/legacy-chain.ts) get in, so the relay can't be used for anything
# else.
def tagvals($name): [.tags[] | select(.[0] == $name) | .[1]];

def sync_event:
  .kind == 30078
  and (tagvals("d") | length == 1 and (.[0] | type == "string" and startswith("pksync-v5-")));

# strfry itself only lets a key delete its own events.
def sync_deletion:
  .pubkey as $pk
  | .kind == 5
  and tagvals("k") == ["30078"]
  and (tagvals("a") + tagvals("e") | length > 0)
  and (tagvals("a") | all(type == "string" and startswith("30078:" + $pk + ":pksync-")));

.event as $e
| try (
    if ($e | sync_event) or ($e | sync_deletion)
    then {id: $e.id, action: "accept"}
    else {id: $e.id, action: "reject", msg: "blocked: this relay only carries Passkey.bond sync events"}
    end
  ) catch {id: $e.id, action: "reject", msg: "blocked: malformed event"}
