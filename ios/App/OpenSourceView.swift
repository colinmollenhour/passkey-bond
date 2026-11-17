import SwiftUI

struct OpenSourceView: View {
    private let notices = Bundle.main.url(forResource: "OpenSourceNotices", withExtension: "txt")
        .flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "License notices could not be loaded."
    private let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                BrandWordmark(size: 30)
                Text("Version \(version) · Dragonstone Labs")
                    .font(.jost(15, relativeTo: .subheadline)).foregroundStyle(Brand.muted)
                Text("Passkey.bond is maintained by Dragonstone Labs. It began as a fork of Fenko Vault, which is © Fenko and MIT licensed.")
                Link("Source code on GitHub", destination: URL(string: "https://github.com/colinmollenhour/passkey-bond")!)
                    .font(.jost(17, .medium))
                Divider().overlay(Brand.separator)
                Text("Licenses").font(.jost(20, .semibold, relativeTo: .title3))
                Text(notices)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(Brand.muted)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
        }
        .background(Brand.page)
        .navigationTitle("About")
        .navigationBarTitleDisplayMode(.inline)
    }
}
