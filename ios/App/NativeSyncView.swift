import SwiftUI

struct NativeSyncView: View {
    @ObservedObject var model: NativeSyncModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var phrase = ""
    @State private var leaving = false

    var body: some View {
        NavigationStack {
            Form {
                BrandSection("Status") {
                    Text(model.statusText)
                    Text("Sync runs while the vault is unlocked. Relay acceptance confirms upload; another device must connect to receive it.")
                        .font(.jost(13, relativeTo: .footnote)).foregroundStyle(Brand.muted)
                }
                if model.enabled {
                    BrandSection("Devices") {
                        ForEach(model.peers) { peer in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(peer.name)
                                Text(peer.type).font(.jost(13, relativeTo: .footnote)).foregroundStyle(Brand.muted)
                            }
                        }
                        Button("Retry sync") { model.retry() }
                    }
                    Section {
                        Button("Leave sync chain", role: .destructive) { leaving = true }
                            .foregroundStyle(Brand.danger)
                    } footer: {
                        Text("Leaving keeps this device's vault entries. It does not remove copies on other devices or records held by relays.")
                            .font(.jost(13, relativeTo: .footnote)).foregroundStyle(Brand.muted)
                    }
                    .listRowBackground(Brand.surface)
                } else {
                    BrandSection("Sync privacy") {
                        Text("Your vault contents are encrypted before upload. Relays can see your IP address, sync identifiers and update times. They may retain these records after you leave sync.")
                    }
                    BrandSection("This device") {
                        TextField("Device name", text: $model.deviceName)
                    }
                    BrandSection("Start a chain") {
                        Button("Create sync chain") { model.create() }
                        Text("Save the recovery phrase, then enter it on your other devices.")
                            .font(.jost(13, relativeTo: .footnote)).foregroundStyle(Brand.muted)
                    }
                    BrandSection("Join an existing chain") {
                        SecureField("12- or 24-word recovery phrase", text: $phrase)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button("Join sync chain") {
                            if model.join(phrase) { phrase = "" }
                        }.disabled(phrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
            }
            .brandList()
            .navigationTitle("Sync")
            .confirmationDialog("Leave this sync chain?", isPresented: $leaving, titleVisibility: .visible) {
                Button("Leave chain", role: .destructive) { model.leave() }
            }
            .onDisappear { phrase = "" }
            .sheet(isPresented: Binding(get: { model.recoveryPhrase != nil },
                                         set: { if !$0 { model.recoveryPhrase = nil } })) {
                NavigationStack {
                    VStack(alignment: .leading, spacing: 24) {
                        Text("Save your recovery phrase").font(.jost(24, .semibold, relativeTo: .title2))
                        Text("Anyone with this phrase can join your chain and read its vault entries. Keep it private.")
                        Text(model.recoveryPhrase ?? "")
                            .font(.system(.title3, design: .monospaced)).textSelection(.enabled).privacySensitive()
                        Text("This phrase is shown once. Keep an encrypted backup as well.")
                            .font(.jost(13, relativeTo: .footnote)).foregroundStyle(Brand.muted)
                        Button("I've saved it") { model.recoveryPhrase = nil }
                            .buttonStyle(.brandProminent)
                    }
                    .padding(24)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .background(Brand.page)
                    .overlay {
                        if scenePhase != .active { Rectangle().fill(Brand.page).ignoresSafeArea() }
                    }
                    .brandChrome()
                }
            }
        }
    }
}
