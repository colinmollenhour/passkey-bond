import Foundation

func require(_ condition: Bool, _ message: String) { precondition(condition, message) }
func expectFailure(_ operation: () throws -> Void) {
    do { try operation() } catch { return }
    fatalError("Expected storage operation to fail")
}

let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
defer { try? FileManager.default.removeItem(at: directory) }
let archive = VaultArchive(directory: directory)
try archive.unlock(key: Data(repeating: 9, count: 32))
let vault = VaultStore(archive: archive)
let seed = String(repeating: "ab", count: 32)
// Protocol v5 IDs, pinned by tests/sync/chain-keys.test.ts and ios/Sync/fixtures.mjs. VaultSync derives
// them; this storage layer only stores and checks their shape.
let chainID = "707571ea9119f5dd95a71a1b0429ae48"
let legacyChainID = String(seed.prefix(32))
expectFailure { try vault.joinSync(seedHash: seed, chainID: legacyChainID, deviceName: "iPhone") }
expectFailure { try vault.joinSync(seedHash: seed, chainID: "707571EA9119F5DD95A71A1B0429AE48", deviceName: "iPhone") }
expectFailure { try vault.joinSync(seedHash: seed, chainID: chainID, deviceName: " ") }
try vault.joinSync(seedHash: seed, chainID: chainID, deviceName: "iPhone")
let settings = try vault.syncSettings()!
require(settings.seedHash == seed && settings.chainID == chainID && !settings.usesLegacyChainID,
        "Sync identity was not stored")
let registration = try vault.register(rpId: "example.com", userName: "alice", userHandle: Data("alice".utf8), excluded: [])
let record = try vault.findPasskey(credentialId: Base64URL.encode(registration.credentialID))!
try vault.savePasskeys([])
let peer = VaultPeer(id: "browser", name: "Browser", type: "Desktop", lastSeen: 1000)
var payload: [String: Any] = ["passkeys": [record.toJSON()], "totpEntries": [], "deletions": [],
                              "syncConfig": ["seedHash": "untrusted-key"]]
let data = try JSONSerialization.data(withJSONObject: payload)
require(try vault.applySync(data, peer: peer), "First snapshot was not marked changed")
require(try !vault.applySync(data, peer: peer), "Identical snapshot caused a sync echo")
require(try vault.loadPasskeys().count == 1, "Remote credential was lost")
require(try vault.syncSettings()!.seedHash == seed, "Remote data replaced local sync identity")
require(try vault.syncPeers().contains { $0.id == "browser" }, "Peer metadata was not stored")
let outbound = String(decoding: try vault.syncSnapshot(), as: UTF8.self)
require(!outbound.contains(seed) && !outbound.contains(settings.deviceID), "Outbound snapshot exposed local identity")

let before = try archive.read()
payload["passkeys"] = [["id": "invalid", "rpId": "example.com", "privateKey": ""]]
expectFailure { _ = try vault.applySync(JSONSerialization.data(withJSONObject: payload), peer: peer) }
require(try archive.read() == before, "Invalid snapshot partially changed the vault")
payload["passkeys"] = []
payload["deletions"] = [["kind": "passkey", "id": record.id, "deletedAt": record.createdAt + 1]]
require(try vault.applySync(JSONSerialization.data(withJSONObject: payload), peer: peer), "Deletion did not change the vault")
require(try vault.loadPasskeys().isEmpty, "Deleted credential survived")
require(try !vault.applySync(data, peer: peer), "Stale snapshot restored a deleted credential")
try vault.leaveSync()
require(try vault.syncSettings() == nil, "Leaving sync kept the chain active")
require(try !vault.snapshotJSON().contains(seed), "Leaving sync retained the seed hash")
expectFailure { _ = try vault.applySync(data, peer: peer) }
vault.lock()
expectFailure { _ = try vault.syncSnapshot() }

// A config saved before protocol v5 (for example by the previous web app) holds the v4 ID.
// The chain ID in the stored config, then in the stored device list.
func storedChainIDs(_ vault: VaultStore) throws -> [String?] {
    let snapshot = try JSONSerialization.jsonObject(with: Data(vault.snapshotJSON().utf8)) as! [String: Any]
    return [(snapshot["syncConfig"] as? [String: Any])?["chainId"] as? String,
            (snapshot["syncDevices"] as? [String: Any])?["id"] as? String]
}
let legacyArchive = VaultArchive(directory: directory.appendingPathComponent("legacy"))
try legacyArchive.unlock(key: Data(repeating: 9, count: 32))
let legacyVault = VaultStore(archive: legacyArchive)
let legacyConfig: [String: Any] = ["enabled": true, "seedHash": seed, "chainId": legacyChainID,
                                   "deviceId": "web-device", "deviceName": "iPhone"]
let legacyDevices: [String: Any] = ["id": legacyChainID, "createdAt": 1, "devices": [] as [Any]]
try legacyVault.saveSnapshotFromWeb(
    passkeys: nil, totp: nil,
    syncConfig: String(decoding: try JSONSerialization.data(withJSONObject: legacyConfig), as: UTF8.self),
    syncDevices: String(decoding: try JSONSerialization.data(withJSONObject: legacyDevices), as: UTF8.self),
    customRelays: nil)
require(try legacyVault.syncSettings()!.usesLegacyChainID, "A v4 config was not recognised")
// Another seed's v4 ID is not this config's: nothing moves.
try legacyVault.adoptSyncChainID(chainID, replacing: String(repeating: "cd", count: 16))
require(try storedChainIDs(legacyVault) == [legacyChainID, legacyChainID], "Moved a chain the seed does not own")
expectFailure { try legacyVault.adoptSyncChainID("not-a-chain", replacing: legacyChainID) }
try legacyVault.adoptSyncChainID(chainID, replacing: legacyChainID)
let moved = try legacyVault.syncSettings()!
require(moved.chainID == chainID && !moved.usesLegacyChainID && moved.deviceID == "web-device",
        "The v4 config did not move to its v5 chain ID")
require(try storedChainIDs(legacyVault) == [chainID, chainID], "The device list kept the v4 chain ID")
// Retrying after a move changes nothing.
try legacyVault.adoptSyncChainID(chainID, replacing: legacyChainID)
require(try storedChainIDs(legacyVault) == [chainID, chainID], "A retried move changed the stored chain")
try legacyVault.saveSnapshotFromWeb(passkeys: nil, totp: nil, syncConfig: "{\"chainId\":\"short\"}",
                                    syncDevices: nil, customRelays: nil)
expectFailure { _ = try legacyVault.syncSettings() }
print("iOS sync storage transactions: PASS")
