import Foundation

struct VaultSyncSettings {
    // Keep in step with DEFAULT_RELAYS in src/sync/protocol.ts.
    static let defaultRelays = ["wss://relay.passkey.bond", "wss://relay.damus.io", "wss://nos.lol"]
    let seedHash: String
    let chainID: String
    let deviceID: String
    let deviceName: String
    let relays: [URL]
}

struct VaultPeer: Identifiable {
    let id: String
    let name: String
    let type: String
    let lastSeen: Double
}
