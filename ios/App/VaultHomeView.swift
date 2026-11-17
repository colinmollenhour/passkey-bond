import SwiftUI
import UniformTypeIdentifiers

private enum VaultLinks {
    static let privacy = URL(string: "https://passkey.bond/privacy")!
    static let support = URL(string: "mailto:support@passkey.bond")!
}

private struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    let data: Data

    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else { throw VaultError.invalidData }
        self.data = data
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

private enum HomeTab: Hashable {
    case vault, sync, settings
}

struct VaultHomeView: View {
    @StateObject private var model: NativeVaultModel
    @StateObject private var sync: NativeSyncModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var search = ""
    @State private var password = ""
    @State private var confirmation = ""
    @State private var importing = false
    @State private var exporting = false
    @State private var document: BackupDocument?
    @State private var addingOTP = false
    @State private var deleting: VaultItem?
    @State private var clipboard = VaultClipboard()
    @State private var tab = HomeTab.vault
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    init() {
        let sync = NativeSyncModel()
        _sync = StateObject(wrappedValue: sync)
        _model = StateObject(wrappedValue: NativeVaultModel(sync: sync, migrate: {
            try await LegacyWebMigration().run()
        }))
    }

    init(model: NativeVaultModel, sync: NativeSyncModel) {
        _model = StateObject(wrappedValue: model)
        _sync = StateObject(wrappedValue: sync)
    }

    var body: some View {
        Group {
            if model.session == .unlocked {
                TabView(selection: $tab) {
                    vault.tabItem { Label("Vault", systemImage: "key.fill") }.tag(HomeTab.vault)
                    NativeSyncView(model: sync).tabItem { Label("Sync", systemImage: "arrow.triangle.2.circlepath") }
                        .tag(HomeTab.sync)
                    settings.tabItem { Label("Settings", systemImage: "gearshape") }.tag(HomeTab.settings)
                }
            } else {
                lockScreen
            }
        }
        .brandChrome()
        .simultaneousGesture(TapGesture().onEnded { model.touch() })
        .onReceive(timer) { _ in model.tick() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { model.lock() }
            if phase == .active { model.refresh() }
        }
        .onChange(of: model.session) { _, session in
            if session == .locked {
                password = ""
                confirmation = ""
                search = ""
                document = nil
                exporting = false
                importing = false
                addingOTP = false
                deleting = nil
                // Allow pasting into another app after backgrounding locks the vault.
                if scenePhase == .active { clipboard.clear() }
            }
        }
        .overlay {
            if scenePhase != .active {
                Rectangle().fill(Brand.page).overlay {
                    BrandWordmark(size: 32)
                }.ignoresSafeArea()
            }
        }
        .alert("Passkey.bond", isPresented: Binding(get: { model.message != nil || sync.message != nil },
                                                   set: { if !$0 { model.message = nil; sync.message = nil } })) {
            Button("OK") { model.message = nil; sync.message = nil }
        } message: { Text(model.message ?? sync.message ?? "") }
        .fileExporter(isPresented: $exporting, document: document,
                      contentType: .json, defaultFilename: "passkey-bond-backup") { result in
            document = nil
            if case .failure = result { model.message = "The backup could not be saved. Try again." }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            if case .success(let url) = result { model.restore(url: url, password: password) }
            password = ""
            confirmation = ""
        }
        .sheet(isPresented: $addingOTP) { OTPSetupView(model: model).presentationBackground(Brand.page) }
        .confirmationDialog("Delete this entry?", isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }
        ), titleVisibility: .visible) {
            if let item = deleting {
                Button("Delete \(item.title)", role: .destructive) {
                    model.deleteItem(item)
                    deleting = nil
                }
            }
            Button("Cancel", role: .cancel) { deleting = nil }
        } message: {
            Text("This also deletes the entry from synced devices. Keep another way to sign in to the account.")
        }
    }

    private var lockScreen: some View {
        VStack(spacing: 24) {
            Image("BrandMark")
                .resizable().scaledToFit().frame(width: 112, height: 112)
                .accessibilityHidden(true)
            BrandWordmark(size: 40)
            Text("Your passkeys and 2FA codes, on your device.")
                .foregroundStyle(Brand.muted).multilineTextAlignment(.center)
            Button {
                Task { await model.unlock() }
            } label: {
                if model.session == .unlocking { ProgressView().tint(Brand.onAccent) }
                else { Label("Unlock vault", systemImage: "faceid") }
            }
            .buttonStyle(.brandProminent)
            .disabled(model.session == .unlocking)
            Text("Use Face ID, Touch ID, or your device passcode.")
                .font(.jost(13, relativeTo: .footnote)).foregroundStyle(Brand.muted)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Brand.page)
    }

    private var vault: some View {
        NavigationStack {
            List {
                ForEach(model.items.filter { item in
                    search.isEmpty || (item.title + " " + item.account).localizedCaseInsensitiveContains(search)
                }) { item in
                    HStack(spacing: 14) {
                        Image(systemName: item.kind == .passkey ? "person.badge.key.fill" : "number.square")
                            .font(.title3).foregroundStyle(Brand.gold).frame(width: 30)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.title).font(.jost(18, .medium, relativeTo: .headline))
                            Text(item.account).font(.jost(15, relativeTo: .subheadline)).foregroundStyle(Brand.muted)
                            if let code = item.code ?? model.issuedCodes[item.id] {
                                HStack {
                                    Text(code).font(.jost(26, .medium, relativeTo: .title2).monospacedDigit())
                                        .tracking(1.5)
                                    Button("Copy code", systemImage: "doc.on.doc") {
                                        clipboard.copyCode(code)
                                        model.touch()
                                    }
                                    .labelStyle(.iconOnly)
                                    .buttonStyle(.borderless)
                                }
                            }
                            if item.kind == .hotp {
                                Button(model.issuedCodes[item.id] == nil ? "Generate code" : "Next code") {
                                    model.issueHOTP(item.id)
                                }.buttonStyle(.borderless)
                            }
                        }
                        .padding(.vertical, 6)
                    }
                    .accessibilityElement(children: .combine)
                    .listRowBackground(Brand.surface)
                    .swipeActions {
                        Button("Delete", role: .destructive) { deleting = item }.tint(Brand.dangerFill)
                    }
                }
            }
            .brandList()
            .overlay {
                if model.items.isEmpty {
                    ContentUnavailableView("Your vault is empty", systemImage: "key",
                                           description: Text("Import a backup in Settings, or enable Passkey.bond as a passkey provider."))
                }
            }
            .navigationTitle("Vault")
            .searchable(text: $search, prompt: "Search sites and accounts")
            .onChange(of: search) { _, _ in model.touch() }
            .toolbar {
                Button("Add 2FA code", systemImage: "plus") { addingOTP = true }
                Button("Lock", systemImage: "lock") { model.lock() }
            }
        }
    }

    private var settings: some View {
        NavigationStack {
            Form {
                Section {
                    #if LOCAL_DEVICE_TEST
                    Text("This test app supports vault storage and backups. Passkey AutoFill requires the full Passkey.bond build.")
                    #else
                    Text("Enable Passkey.bond in your device's Password AutoFill settings to create and use passkeys in apps and Safari.")
                    #endif
                } header: { BrandHeader("Passkeys") }
                .listRowBackground(Brand.surface)
                .textCase(nil)
                Section {
                    SecureField("Backup password", text: $password)
                    SecureField("Confirm password for export", text: $confirmation)
                    Button("Export encrypted backup") {
                        do {
                            document = BackupDocument(data: try model.backup(password: password))
                            password = ""
                            confirmation = ""
                            exporting = true
                        } catch { model.message = error.localizedDescription }
                    }
                    .disabled(password.isEmpty || password != confirmation)
                    Button("Import backup") { importing = true }
                    Text("Keep the file and password safe. Nobody can recover them for you.")
                        .font(.jost(13, relativeTo: .footnote)).foregroundStyle(Brand.muted)
                } header: { BrandHeader("Backup and restore") }
                .listRowBackground(Brand.surface)
                .textCase(nil)
                Section {
                    Text("The vault locks when you leave the app or after five minutes without activity.")
                    Text("Copied codes stay on this device and expire after 30 seconds.")
                    Button("Lock vault") { model.lock() }
                } header: { BrandHeader("Security") }
                .listRowBackground(Brand.surface)
                .textCase(nil)
                Section {
                    Text("QR codes are read on this device. Camera images are not uploaded.")
                    Text("Sync encrypts your vault contents. Relays can see your IP address, sync identifiers and update times. Leaving sync does not delete records already held by relays.")
                    Link("Privacy policy", destination: VaultLinks.privacy)
                    Link("Contact support", destination: VaultLinks.support)
                    NavigationLink("About and licenses") { OpenSourceView() }
                } header: { BrandHeader("Privacy and support") }
                .listRowBackground(Brand.surface)
                .textCase(nil)
            }
            .brandList()
            .onChange(of: password) { _, _ in model.touch() }
            .onChange(of: confirmation) { _, _ in model.touch() }
            .navigationTitle("Settings")
        }
    }
}
