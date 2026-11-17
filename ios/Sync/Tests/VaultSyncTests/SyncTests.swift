import CryptoKit
import Foundation
import XCTest
@testable import VaultSync

final class SyncTests: XCTestCase {
    private struct Fixture: Decodable {
        let entropy: String
        let phrase: String
        let seedHash: String
        let chainID: String
        let legacyChainID: String
        let author: String
        let plaintext: String
        let event: RelayEvent
    }

    private func fixture() throws -> Fixture {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "browser-sync", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }

    func testRecoveryCompatibility() throws {
        let fixture = try fixture()
        XCTAssertEqual(try SyncRecovery.decode(fixture.phrase).hex, fixture.entropy)
        XCTAssertEqual(try SyncRecovery.encode(Data(hex: fixture.entropy)!), fixture.phrase)
        XCTAssertEqual(try SyncRecovery.seedHash(fixture.phrase), fixture.seedHash)
        let extended = "school zero lens rule swift jeans afraid hand guilt estate vicious teach " +
            "pizza coffee hat enter foil sport notable regret pizza coffee hat flag"
        XCTAssertEqual(try SyncRecovery.decode(extended).hex,
                       "c0ffee00deadbeef0123456789abcdef5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
        XCTAssertEqual(try SyncRecovery.encode(SyncRecovery.decode(extended)), extended)
        XCTAssertThrowsError(try SyncRecovery.decode("abandon"))
        XCTAssertThrowsError(try SyncRecovery.decode(Array(repeating: "not-a-word", count: 12).joined(separator: " ")))
        XCTAssertThrowsError(try SyncRecovery.encode(Data(repeating: 255, count: 16)))
        for length in [SyncRecovery.Length.standard, .extended] {
            for _ in 0..<100 {
                let phrase = try SyncRecovery.generate(length: length)
                XCTAssertEqual(phrase.split(separator: " ").count, length.rawValue)
                XCTAssertEqual(try SyncRecovery.encode(SyncRecovery.decode(phrase)), phrase)
            }
        }
    }

    // RFC 7914, section 12.
    func testScryptVectors() throws {
        let vectors: [(String, String, UInt64, UInt32, UInt32, String)] = [
            ("", "", 16, 1, 1,
             "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede2144" +
             "2fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
            ("password", "NaCl", 1024, 8, 16,
             "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
             "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
            ("pleaseletmein", "SodiumChloride", 16384, 8, 1,
             "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2" +
             "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
        ]
        for (password, salt, n, r, p, expected) in vectors {
            let output = try Scrypt.derive(password: Array(password.utf8), salt: Array(salt.utf8),
                                           n: n, r: r, p: p, length: 64)
            XCTAssertEqual(Data(output).hex, expected, "scrypt N=\(n) r=\(r) p=\(p)")
        }
        XCTAssertThrowsError(try Scrypt.derive(password: [], salt: [], n: 15, r: 1, p: 1, length: 32))
        XCTAssertThrowsError(try Scrypt.derive(password: [], salt: [], n: 16, r: 0, p: 1, length: 32))
    }

    // The same keys as src/sync/chain-keys.ts, from Fixtures/chain-keys.json (fixtures.mjs).
    func testChainKeysMatchBrowser() throws {
        let vectors = try ChainKeyVector.all()
        XCTAssertEqual(vectors.first(where: { $0.seedHash == String(repeating: "ab", count: 32) })?.chainID,
                       "707571ea9119f5dd95a71a1b0429ae48", "Pinned by tests/sync/chain-keys.test.ts")
        for vector in vectors {
            let keys = try SyncChainKeys.derive(seedHash: vector.seedHash)
            XCTAssertEqual(keys.chainID, vector.chainID)
            XCTAssertEqual(keys.encryptionKey.hex, vector.encryptionKey)
            XCTAssertEqual(keys.signingKey.hex, vector.signingKey)
            XCTAssertEqual(try SyncCipher(keys: keys).author, vector.author)
            XCTAssertNotEqual(keys.chainID, SyncChainKeys.legacyChainID(seedHash: vector.seedHash))
        }
        XCTAssertThrowsError(try SyncChainKeys.derive(seedHash: "not-a-seed"))
    }

    func testDerivationLeavesTheCallingActor() async throws {
        let seed = String(repeating: "ab", count: 32)
        let keys = try await SyncChainKeys.derived(seedHash: seed)
        XCTAssertEqual(keys.chainID, try TestKeys.of(seed).chainID)
    }

    func testBrowserMessageAndSignature() throws {
        let fixture = try fixture()
        let cipher = try SyncCipher(keys: TestKeys.of(fixture.seedHash))
        XCTAssertEqual(cipher.chainID, fixture.chainID)
        XCTAssertEqual(fixture.legacyChainID, SyncChainKeys.legacyChainID(seedHash: fixture.seedHash))
        XCTAssertEqual(fixture.event.tags.first, ["d", "pksync-v5-\(fixture.chainID)"])
        XCTAssertEqual(cipher.author, fixture.author)
        XCTAssertTrue(cipher.verify(fixture.event))
        XCTAssertEqual(try cipher.decryptMessage(fixture.event.content), Data(fixture.plaintext.utf8))
        let signed = try cipher.sign(content: fixture.event.content, tags: fixture.event.tags,
                                     createdAt: fixture.event.createdAt)
        XCTAssertEqual(signed.id, fixture.event.id, "Canonical event JSON differs from the browser")
        XCTAssertTrue(cipher.verify(signed))
        let wrong = try SyncCipher(keys: TestKeys.of(String(repeating: "ab", count: 32)))
        XCTAssertFalse(wrong.verify(signed))
        XCTAssertThrowsError(try wrong.decryptMessage(signed.content))
        let changed = RelayEvent(id: signed.id, pubkey: signed.pubkey, createdAt: signed.createdAt,
                                  kind: signed.kind, tags: signed.tags, content: signed.content + " ", sig: signed.sig)
        XCTAssertFalse(cipher.verify(changed))
        let forged = RelayEvent(id: signed.id, pubkey: signed.pubkey, createdAt: signed.createdAt,
                                 kind: signed.kind, tags: signed.tags, content: signed.content,
                                 sig: String(repeating: "00", count: 64))
        XCTAssertFalse(cipher.verify(forged))
    }

    func testCipherBoundsAndTampering() throws {
        let cipher = try SyncCipher(keys: TestKeys.of(fixture().seedHash))
        let data = Data("native sync".utf8)
        let first = try cipher.encryptMessage(data)
        let second = try cipher.encryptMessage(data)
        XCTAssertNotEqual(first, second, "AES-GCM nonce was reused")
        XCTAssertEqual(try cipher.decryptMessage(first), data)
        let box = try cipher.seal(data)
        var damaged = Data(base64Encoded: box.ciphertext)!
        damaged[0] ^= 1
        XCTAssertThrowsError(try cipher.open(SyncBox(nonce: box.nonce, ciphertext: damaged.base64EncodedString())))
        XCTAssertThrowsError(try cipher.open(SyncBox(nonce: "", ciphertext: box.ciphertext)))
        XCTAssertThrowsError(try cipher.sign(content: String(repeating: "x", count: SyncCipher.maxEventBytes),
                                             tags: [], createdAt: 1))
        XCTAssertThrowsError(try SyncCipher(seedHash: "bad-key"))
    }

    func testRelayCapacityUsesWireJSON() throws {
        let cipher = try SyncCipher(keys: TestKeys.of(fixture().seedHash))
        // JSON.stringify leaves slashes literal; base64 can contain many of them.
        let signed = try cipher.sign(content: String(repeating: "/", count: 12_000), tags: [], createdAt: 1)
        XCTAssertTrue(cipher.verify(signed))
    }

    func testExportForBrowserVerification() throws {
        guard let output = ProcessInfo.processInfo.environment["SYNC_INTEROP_OUT"] else { return }
        let fixture = try fixture()
        let cipher = try SyncCipher(keys: TestKeys.of(fixture.seedHash))
        let content = try cipher.encryptMessage(Data(fixture.plaintext.utf8))
        let event = try cipher.sign(content: content, tags: fixture.event.tags, createdAt: fixture.event.createdAt)
        try JSONEncoder().encode(event).write(to: URL(fileURLWithPath: output), options: .atomic)
    }
}
