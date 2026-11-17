import LocalAuthentication
import SwiftUI

// This executable is a separate test target and is never embedded in the shipping app.
@main
struct VaultUITestApp: App {
    private let access = FixtureVault()

    init() { Brand.applyAppearance() }

    var body: some Scene {
        WindowGroup {
            VaultHomeView(model: NativeVaultModel(vault: access, authenticate: { _ in true }),
                          sync: NativeSyncModel(vault: access.vault))
        }
    }
}

private final class FixtureVault: NativeVaultAccess {
    let vault: VaultStore
    private let archive: VaultArchive
    private let key = Data(repeating: 51, count: 32)

    init() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        archive = VaultArchive(directory: directory)
        vault = VaultStore(archive: archive)
    }

    func unlock(context: LAContext) throws {
        try archive.unlock(key: key)
        if ProcessInfo.processInfo.arguments.contains("-demoVault"), try vault.items(at: Date()).isEmpty {
            try seedDemoVault()
        }
    }

    /// Demo entries for the App Store screenshots. Reserved example domains
    /// and made-up accounts only: the screenshots are public.
    private func seedDemoVault() throws {
        let passkeys = [
            ("bank.example", "alex@example.com"),
            ("mail.example.com", "alex@example.com"),
            ("shop.example.org", "alex"),
            ("travel.example.net", "alex@example.com"),
        ]
        for (index, passkey) in passkeys.enumerated() {
            _ = try vault.register(rpId: passkey.0, userName: passkey.1,
                                   userHandle: Data("demo-user-\(index)".utf8), excluded: [])
        }
        let codes = [
            ("Example Cloud", "alex@example.com", "JBSWY3DPEHPK3PXP"),
            ("Example Forum", "alex", "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TF"),
            ("Example Hosting", "admin@example.net", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        ]
        for code in codes {
            try vault.addOTP(OTPSetup(kind: .totp, issuer: code.0, account: code.1, secret: code.2,
                                      algorithm: .sha1, digits: 6, period: 30, counter: 0))
        }
    }
    func lock() { vault.lock() }
    func items(at date: Date) throws -> [VaultItem] { try vault.items(at: date) }
    func exportBackup(password: String) throws -> Data { try vault.exportBackup(password: password) }
    func importFile(_ url: URL, password: String) throws -> Int { try vault.importFile(url, password: password) }
    func issueHOTP(_ id: String) throws -> String { try vault.issueHOTP(id) }
    func addOTP(_ setup: OTPSetup) throws { try vault.addOTP(setup) }
    func deleteItem(_ id: String, kind: VaultItemKind) throws { try vault.deleteItem(id, kind: kind) }
}
