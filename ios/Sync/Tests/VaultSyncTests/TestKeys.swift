import Foundation
import XCTest
@testable import VaultSync

/// The v5 chain keys of a test seed. Seeds in Fixtures/chain-keys.json (written by fixtures.mjs with the
/// browser's libraries) load from it, so only the tests that check derivation pay for scrypt.
struct ChainKeyVector: Decodable {
    let seedHash: String
    let chainID: String
    let encryptionKey: String
    let signingKey: String
    let author: String

    static func all() throws -> [ChainKeyVector] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "chain-keys", withExtension: "json",
                                                  subdirectory: "Fixtures"))
        return try JSONDecoder().decode([ChainKeyVector].self, from: Data(contentsOf: url))
    }

    func keys() throws -> SyncChainKeys {
        try SyncChainKeys(chainID: chainID, encryptionKey: XCTUnwrap(Data(hex: encryptionKey)),
                          signingKey: XCTUnwrap(Data(hex: signingKey)))
    }
}

enum TestKeys {
    static func of(_ seedHash: String) throws -> SyncChainKeys {
        if let vector = try ChainKeyVector.all().first(where: { $0.seedHash == seedHash }) {
            return try vector.keys()
        }
        return try SyncChainKeys.derive(seedHash: seedHash)
    }
}
