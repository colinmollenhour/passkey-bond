import AuthenticationServices
import LocalAuthentication
import SwiftUI
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let vault = VaultStore.shared
    private let session = ProviderSession()
    private var hosted: UIViewController?

    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        cancel(.userInteractionRequired)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        guard let request = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancel(.failed)
            return
        }
        authenticate(reason: "Sign in to \(identity.relyingPartyIdentifier)") { [self] in
            try sign(credentialID: identity.credentialID, rpId: identity.relyingPartyIdentifier,
                     clientHash: request.clientDataHash)
        }
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        let rpId = requestParameters.relyingPartyIdentifier
        authenticate(reason: "Choose a passkey for \(rpId)") { [self] in
            let choices = try vault.credentials(rpId: rpId, allowed: requestParameters.allowedCredentials)
            show(ProviderPicker(rpId: rpId, choices: choices, choose: { [weak self] id in
                guard let self else { return }
                do {
                    try self.sign(credentialID: id, rpId: rpId, clientHash: requestParameters.clientDataHash)
                } catch { self.cancel(.failed) }
            }, cancel: { [weak self] in self?.cancel(.userCanceled) }))
        }
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
              request.supportedAlgorithms.contains(.ES256), request.clientDataHash.count == 32 else {
            cancel(.failed)
            return
        }
        show(ProviderRegistration(rpId: identity.relyingPartyIdentifier, account: identity.userName,
                                  save: { [weak self] in
            guard let self else { return }
            self.authenticate(reason: "Save a passkey for \(identity.relyingPartyIdentifier)") { [self] in
                var excluded: [Data] = []
                if #available(iOS 18.0, *) {
                    excluded = request.excludedCredentials?.map { $0.credentialID } ?? []
                }
                let result = try self.vault.register(rpId: identity.relyingPartyIdentifier, userName: identity.userName,
                                                userHandle: identity.userHandle, excluded: excluded)
                let credential = ASPasskeyRegistrationCredential(relyingParty: identity.relyingPartyIdentifier,
                                                                  clientDataHash: request.clientDataHash,
                                                                  credentialID: result.credentialID,
                                                                  attestationObject: result.attestation)
                self.session.cancel()
                self.extensionContext.completeRegistrationRequest(using: credential)
            }
        }, cancel: { [weak self] in self?.cancel(.userCanceled) }))
    }

    override func prepareInterfaceForExtensionConfiguration() {
        show(ProviderConfiguration(done: { [weak self] in
            self?.extensionContext.completeExtensionConfigurationRequest()
        }))
    }

    private func sign(credentialID: Data, rpId: String, clientHash: Data) throws {
        let result = try vault.assertion(credentialID: credentialID, rpId: rpId, clientHash: clientHash)
        let credential = ASPasskeyAssertionCredential(userHandle: result.userHandle, relyingParty: rpId,
                                                       signature: result.signature, clientDataHash: clientHash,
                                                       authenticatorData: result.authenticatorData,
                                                       credentialID: credentialID)
        session.cancel()
        extensionContext.completeAssertionRequest(using: credential)
    }

    private func authenticate(reason: String, operation: @escaping () throws -> Void) {
        Task { [weak self] in
            guard let self else { return }
            do {
                try await session.perform(reason: reason, operation: operation)
            } catch ProviderSessionError.stale {
                return
            } catch ProviderSessionError.denied {
                cancel(.userCanceled)
            } catch VaultError.excludedCredential {
                if #available(iOS 18.0, *) { cancel(.matchedExcludedCredential) }
                else { cancel(.failed) }
            } catch { cancel(.failed) }
        }
    }

    private func cancel(_ code: ASExtensionError.Code) {
        session.cancel()
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }

    private func show<Content: View>(_ content: Content) {
        hosted?.willMove(toParent: nil)
        hosted?.view.removeFromSuperview()
        hosted?.removeFromParent()
        Brand.applyAppearance()
        let controller = UIHostingController(rootView: content.brandChrome())
        addChild(controller)
        view.addSubview(controller.view)
        controller.view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            controller.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            controller.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            controller.view.topAnchor.constraint(equalTo: view.topAnchor),
            controller.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        controller.didMove(toParent: self)
        hosted = controller
    }
}

private struct ProviderPicker: View {
    let rpId: String
    let choices: [ProviderCredential]
    let choose: (Data) -> Void
    let cancel: () -> Void

    var body: some View {
        NavigationStack {
            List(choices) { choice in
                Button { choose(choice.id) } label: {
                    Label {
                        Text(choice.account).foregroundStyle(Brand.text)
                    } icon: {
                        Image(systemName: "person.badge.key.fill").foregroundStyle(Brand.gold)
                    }
                    .padding(.vertical, 8)
                }
                .listRowBackground(Brand.surface)
            }
            .brandList()
            .overlay {
                if choices.isEmpty {
                    ContentUnavailableView("No matching passkey", systemImage: "key",
                                           description: Text("Open Passkey.bond to import or sync your passkeys."))
                }
            }
            .navigationTitle(rpId)
            .toolbar { Button("Cancel", action: cancel) }
        }
    }
}

private struct ProviderRegistration: View {
    let rpId: String
    let account: String
    let save: () -> Void
    let cancel: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(systemName: "person.badge.key.fill").font(.largeTitle).foregroundStyle(Brand.gold)
                Text("Save a passkey?").font(.jost(28, .semibold, relativeTo: .title))
                Text(rpId).font(.jost(18, .medium, relativeTo: .headline))
                Text(account).foregroundStyle(Brand.muted)
                Button("Save in Passkey.bond", action: save).buttonStyle(.brandProminent)
            }.padding()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Brand.page)
                .toolbar { Button("Cancel", action: cancel) }
        }
    }
}

private struct ProviderConfiguration: View {
    let done: () -> Void
    var body: some View {
        VStack(spacing: 20) {
            BrandWordmark(size: 34)
            Text("Open Passkey.bond to unlock your vault and import your credentials. You can then save and use passkeys in apps and Safari.")
                .multilineTextAlignment(.center)
            Button("Done", action: done).buttonStyle(.brandProminent)
        }.padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Brand.page)
    }
}
