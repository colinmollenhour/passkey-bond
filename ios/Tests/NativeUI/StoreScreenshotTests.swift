import XCTest

/// Captures the App Store screenshots from a vault seeded with demo entries
/// (see FixtureVault in Tests/UITestHost). CI exports the attachments from
/// the result bundle; ios/store/export-screenshots.mjs names them.
final class StoreScreenshotTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    override func tearDown() {
        XCUIDevice.shared.appearance = .light
    }

    func testStoreScreenshots() {
        XCUIDevice.shared.appearance = .light
        let app = XCUIApplication()
        app.launchArguments += ["-demoVault"]
        app.launch()

        XCTAssertTrue(app.buttons["Unlock vault"].waitForExistence(timeout: 10))
        capture(app, "01-unlock")

        app.buttons["Unlock vault"].tap()
        let bank = app.cells.containing(.staticText, identifier: "bank.example").firstMatch
        XCTAssertTrue(bank.waitForExistence(timeout: 10))
        capture(app, "02-vault")

        app.buttons["Add 2FA code"].tap()
        // Fill in the visible fields only: iOS leaves secure fields blank in
        // screenshots, so the setup key keeps its placeholder.
        let issuer = app.textFields["Issuer or service"]
        XCTAssertTrue(issuer.waitForExistence(timeout: 5))
        issuer.tap()
        issuer.typeText("Example Mail")
        let account = app.textFields["Account"]
        account.tap()
        account.typeText("alex@example.com\n")
        dismissKeyboard(app)
        capture(app, "03-add-code")
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.navigationBars["Add 2FA code"].waitForNonExistence(timeout: 5))

        select(app, "Sync")
        XCTAssertTrue(app.buttons["Create sync chain"].waitForExistence(timeout: 5))
        capture(app, "04-sync")

        select(app, "Settings")
        XCTAssertTrue(app.buttons["Export encrypted backup"].waitForExistence(timeout: 5))
        capture(app, "05-settings")

        select(app, "Vault")
        XCTAssertTrue(bank.waitForExistence(timeout: 5))
        XCUIDevice.shared.appearance = .dark
        // Let the trait change redraw before capturing.
        Thread.sleep(forTimeInterval: 1)
        capture(app, "06-vault-dark")
    }

    /// Tab bar items are tab bar buttons on iPhone, and plain buttons in the
    /// iPad's floating tab bar.
    private func tab(_ app: XCUIApplication, _ name: String) -> XCUIElement {
        let item = app.tabBars.buttons[name]
        return item.exists ? item : app.buttons[name].firstMatch
    }

    /// Selects a tab, tapping again if the first tap was swallowed (it can be
    /// right after a sheet closes).
    private func select(_ app: XCUIApplication, _ name: String) {
        for _ in 0..<3 {
            let item = tab(app, name)
            XCTAssertTrue(item.waitForExistence(timeout: 5))
            item.tap()
            if item.wait(for: \.isSelected, toEqual: true, timeout: 2) { return }
        }
        XCTFail("Could not select the \(name) tab")
    }

    private func dismissKeyboard(_ app: XCUIApplication) {
        guard app.keyboards.count > 0 else { return }
        let title = app.navigationBars["Add 2FA code"]
        if title.exists { title.tap() }
    }

    private func capture(_ app: XCUIApplication, _ name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
