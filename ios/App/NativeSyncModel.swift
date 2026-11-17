import Foundation
import SwiftUI
import VaultSync

@MainActor
final class NativeSyncModel: ObservableObject, NativeSyncLifecycle {
    @Published private(set) var enabled = false
    @Published private(set) var preparing = false
    @Published private(set) var peers: [VaultPeer] = []
    @Published private(set) var status: SyncStatus = .stopped
    @Published var deviceName = "iPhone"
    @Published var recoveryPhrase: String?
    @Published var message: String?
    private let vault: VaultStore
    private var service: SyncService?
    // The stored seed's chain keys, derived once per unlock: scrypt takes 128 MiB and a good part of a second.
    private var chain: (seedHash: String, keys: SyncChainKeys)?
    private var active = false
    private var generation = 0

    init(vault: VaultStore = .shared) {
        self.vault = vault
    }

    var statusText: String {
        if preparing { return "Preparing sync keys…" }
        switch status {
        case .stopped: return enabled ? "Sync is paused." : "Sync is off."
        case .connecting: return "Connecting to relay…"
        case .connected: return "Connected to relay."
        case .sent: return "Update accepted by relay."
        case .received: return "Update received."
        case .retryNeeded: return "An update needs retrying."
        case .networkError: return "Connection interrupted. Retrying…"
        case .storageError: return "Could not read or save a sync update."
        }
    }

    func resume() {
        active = true
        restart()
    }

    func suspend() {
        active = false
        recoveryPhrase = nil
        peers = []
        message = nil
        chain = nil
        stopCurrent()
    }

    func changed() {
        guard active, let service else { return }
        Task { await service.changed() }
    }

    func create() {
        guard active, !enabled, !preparing else { return }
        do {
            begin(try SyncRecovery.generate(), reveal: true)
        } catch { message = "Could not create a sync chain. Try again." }
    }

    /// Checks the phrase now and joins once its chain keys are derived. Returns whether joining started.
    @discardableResult
    func join(_ phrase: String) -> Bool {
        guard active, !enabled, !preparing else { return false }
        return begin(phrase, reveal: false)
    }

    func leave() {
        guard active else { return }
        stopCurrent()
        do {
            try vault.leaveSync()
            enabled = false
            peers = []
            recoveryPhrase = nil
            chain = nil
        } catch {
            message = "Could not leave the sync chain. Try again."
            restart()
        }
    }

    func retry() {
        guard active, let service else { return }
        Task { await service.retry() }
    }

    @discardableResult
    private func begin(_ phrase: String, reveal: Bool) -> Bool {
        let failure = reveal ? "Could not create a sync chain. Check the device name and try again."
            : "Could not join. Check the recovery phrase and device name."
        guard let hash = try? SyncRecovery.seedHash(phrase), VaultStore.isValidSyncDeviceName(deviceName) else {
            message = failure
            return false
        }
        let name = deviceName
        let token = generation
        preparing = true
        Task { [weak self] in
            let keys = try? await SyncChainKeys.derived(seedHash: hash)
            guard let self, self.active, self.generation == token else { return }
            self.preparing = false
            do {
                guard let keys else { throw VaultError.invalidData }
                try self.vault.joinSync(seedHash: hash, chainID: keys.chainID, deviceName: name)
                self.chain = (seedHash: hash, keys: keys)
            } catch {
                self.message = failure
                return
            }
            if reveal { self.recoveryPhrase = phrase }
            self.restart()
        }
        return true
    }

    private func stopCurrent() {
        generation += 1
        let previous = service
        service = nil
        status = .stopped
        // A derivation still running belongs to the previous generation and is discarded.
        preparing = false
        Task { await previous?.stop() }
    }

    private func restart() {
        stopCurrent()
        guard active else { return }
        let settings: VaultSyncSettings
        do {
            guard let stored = try vault.syncSettings() else {
                enabled = false
                chain = nil
                return
            }
            settings = stored
            enabled = true
            deviceName = settings.deviceName
            peers = try vault.syncPeers()
        } catch {
            loadFailed()
            return
        }
        let token = generation
        if let chain, chain.seedHash == settings.seedHash {
            connect(settings, keys: chain.keys, token: token)
            return
        }
        chain = nil
        preparing = true
        Task { [weak self] in
            let keys = try? await SyncChainKeys.derived(seedHash: settings.seedHash)
            guard let self, self.active, self.generation == token else { return }
            self.preparing = false
            guard let keys else {
                self.loadFailed()
                return
            }
            self.chain = (seedHash: settings.seedHash, keys: keys)
            self.connect(settings, keys: keys, token: token)
        }
    }

    // Mirrors the extension's SyncService.runInitialize: the keys name the chain, and a stored protocol v4
    // ID of the same seed moves to the v5 one before the first relay connection.
    private func connect(_ settings: VaultSyncSettings, keys: SyncChainKeys, token: Int) {
        if keys.chainID != settings.chainID {
            // Anything but this seed's v4 ID means the stored config and seed disagree.
            guard settings.usesLegacyChainID else {
                status = .storageError
                message = "The saved sync chain does not match its recovery phrase. Leave sync and join again."
                return
            }
            // As on the extension, a failed write is retried on the next start; sync uses the v5 ID meanwhile.
            try? vault.adoptSyncChainID(keys.chainID, replacing: settings.chainID)
        }
        do {
            let config = try RelaySyncConfig(keys: keys, deviceID: settings.deviceID,
                                             deviceName: settings.deviceName, relays: settings.relays)
            let next = SyncService(config: config, load: { [weak self] in
                try await MainActor.run {
                    guard let self, self.active, self.generation == token else { throw VaultError.locked }
                    return try self.vault.syncSnapshot()
                }
            }, apply: { [weak self] incoming in
                try await MainActor.run {
                    guard let self, self.active, self.generation == token else { throw VaultError.locked }
                    let peer = VaultPeer(id: incoming.peer.id, name: incoming.peer.name,
                                         type: incoming.peer.type, lastSeen: incoming.peer.lastSeen)
                    let changed = try self.vault.applySync(incoming.snapshot, peer: peer)
                    self.peers = try self.vault.syncPeers()
                    return changed ? .changed : .unchanged
                }
            }, report: { [weak self] status in
                await MainActor.run {
                    guard let self, self.active, self.generation == token else { return }
                    self.status = status
                }
            })
            service = next
            Task {
                guard active, generation == token else { return }
                await next.start()
                if !active || generation != token { await next.stop() }
            }
        } catch {
            loadFailed()
        }
    }

    private func loadFailed() {
        status = .storageError
        message = "Could not load sync settings. Your vault entries are unchanged."
    }
}
