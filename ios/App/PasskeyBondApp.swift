import SwiftUI

@main
struct PasskeyBondApp: App {
    init() { Brand.applyAppearance() }

    var body: some Scene {
        WindowGroup {
            VaultHomeView()
        }
    }
}
