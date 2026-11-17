import Foundation

struct VaultSyncSettings {
    // Keep in step with DEFAULT_RELAYS in src/sync/protocol.ts.
    static let defaultRelays = ["wss://relay.passkey.bond", "wss://relay.damus.io", "wss://nos.lol"]
    // Hex characters in a chain ID under protocol v4 and v5 (CHAIN_ID_LENGTH in src/sync/chain-keys.ts).
    static let chainIDLength = 32
    let seedHash: String
    // Protocol v5 derives it from the seed through scrypt (VaultSync's SyncChainKeys); a config saved
    // before v5 still holds the v4 ID until the app moves it (VaultStore.adoptSyncChainID).
    let chainID: String
    let deviceID: String
    let deviceName: String
    let relays: [URL]

    /// The chain ID protocol v4 published: a prefix of the seed hash (legacyChainId in src/sync/chain-keys.ts).
    static func legacyChainID(seedHash: String) -> String {
        String(seedHash.prefix(chainIDLength))
    }

    var usesLegacyChainID: Bool {
        chainID == Self.legacyChainID(seedHash: seedHash)
    }
}

struct VaultPeer: Identifiable {
    let id: String
    let name: String
    let type: String
    let lastSeen: Double
}
