import CryptoKit
import CVaultScrypt
import Foundation

/// The keys of a sync chain, derived exactly as src/sync/chain-keys.ts does:
///
///     root          = scrypt(utf8(seedHash), utf8("pkvault-sync-v5/root"), N=2^17, r=8, p=1, dkLen=32)
///     chainID       = hex(HKDF-SHA256(root, no salt, "pkvault-sync-v5/chain-id", 16))
///     encryptionKey = HKDF-SHA256(root, no salt, "pkvault-sync-v5/aes-256-gcm", 32)
///     signingKey    = HKDF-SHA256(root, no salt, "pkvault-sync-v5/nostr-secp256k1", 32)
///
/// The chain ID is public. The scrypt step makes checking a guessed phrase against it cost 128 MiB and
/// a fraction of a second; protocol v4 published a prefix of the seed hash instead (`legacyChainID`).
/// Derivation is slow on purpose: run it off the main thread with `derived(seedHash:)`.
public struct SyncChainKeys: Sendable {
    public static let keyPrefix = "pkvault-sync-v5"
    public static let chainIDLength = 32
    static let scryptN: UInt64 = 1 << 17
    static let scryptR: UInt32 = 8
    static let scryptP: UInt32 = 1

    public let chainID: String
    let encryptionKey: Data
    let signingKey: Data

    init(chainID: String, encryptionKey: Data, signingKey: Data) {
        self.chainID = chainID
        self.encryptionKey = encryptionKey
        self.signingKey = signingKey
    }

    /// Runs scrypt on the calling thread.
    public static func derive(seedHash: String) throws -> SyncChainKeys {
        guard Data(hex: seedHash)?.count == 32 else { throw SyncError.invalidKey }
        let root = try Scrypt.derive(password: Array(seedHash.utf8), salt: Array("\(keyPrefix)/root".utf8),
                                     n: scryptN, r: scryptR, p: scryptP, length: 32)
        let material = SymmetricKey(data: root)
        func expand(_ label: String, _ count: Int) -> Data {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: material, salt: Data(),
                                   info: Data("\(keyPrefix)/\(label)".utf8), outputByteCount: count)
                .withUnsafeBytes { Data($0) }
        }
        return SyncChainKeys(chainID: expand("chain-id", chainIDLength / 2).hex,
                             encryptionKey: expand("aes-256-gcm", 32),
                             signingKey: expand("nostr-secp256k1", 32))
    }

    /// Derives on a background task, never on the caller's actor.
    public static func derived(seedHash: String) async throws -> SyncChainKeys {
        try await Task.detached(priority: .userInitiated) {
            try SyncChainKeys.derive(seedHash: seedHash)
        }.value
    }

    /// The chain ID protocol v4 published for this seed: a prefix of the seed hash.
    public static func legacyChainID(seedHash: String) -> String {
        String(seedHash.prefix(chainIDLength))
    }
}

/// scrypt (RFC 7914) with PBKDF2-HMAC-SHA256 in Swift and ROMix in C.
enum Scrypt {
    private static let hashBytes = 32

    static func derive(password: [UInt8], salt: [UInt8], n: UInt64, r: UInt32, p: UInt32,
                       length: Int) throws -> [UInt8] {
        guard r > 0, p > 0, length > 0, n > 1, n & (n - 1) == 0,
              UInt64(r) * UInt64(p) < 1 << 30 else { throw SyncError.invalidKey }
        let blockBytes = 128 * Int(r)
        var blocks = pbkdf2(password: password, salt: salt, length: Int(p) * blockBytes)
        let status = blocks.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            for index in 0..<Int(p) {
                let result = vault_scrypt_romix(base + index * blockBytes, r, n)
                if result != 0 { return result }
            }
            return 0
        }
        // vault_scrypt_romix returns -2 when malloc fails.
        guard status == 0 else { throw status == -2 ? SyncError.outOfMemory : SyncError.invalidKey }
        return pbkdf2(password: password, salt: blocks, length: length)
    }

    /// PBKDF2-HMAC-SHA256 with one iteration, all scrypt needs.
    static func pbkdf2(password: [UInt8], salt: [UInt8], length: Int) -> [UInt8] {
        let key = SymmetricKey(data: password)
        var output: [UInt8] = []
        output.reserveCapacity(length + hashBytes)
        var counter: UInt32 = 1
        while output.count < length {
            var message = salt
            message.append(contentsOf: [UInt8(truncatingIfNeeded: counter >> 24),
                                        UInt8(truncatingIfNeeded: counter >> 16),
                                        UInt8(truncatingIfNeeded: counter >> 8),
                                        UInt8(truncatingIfNeeded: counter)])
            output.append(contentsOf: HMAC<SHA256>.authenticationCode(for: message, using: key))
            counter += 1
        }
        return Array(output.prefix(length))
    }
}
