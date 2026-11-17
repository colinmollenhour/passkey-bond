import XCTest

/// Captures the App Store screenshots from a vault seeded with demo entries
/// (see FixtureVault in Tests/UITestHost). CI exports the attachments from
/// the result bundle; ios/store/export-screenshots.mjs names them.
final class StoreScreenshotTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    func testStoreScreenshots() {
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
        capture(app, "03-add-code")
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.navigationBars["Add 2FA code"].waitForNonExistence(timeout: 5))

        select(app, "Sync", until: app.buttons["Create sync chain"])
        capture(app, "04-sync")

        select(app, "Settings", until: app.buttons["Export encrypted backup"])
        capture(app, "05-settings")
        app.terminate()
    }

    /// The vault in dark mode. The host app takes the colour scheme from a
    /// launch argument, since the simulator appearance can't be switched
    /// reliably from inside a test.
    func testStoreScreenshotDark() {
        let app = XCUIApplication()
        app.launchArguments += ["-demoVault", "-darkMode"]
        app.launch()
        XCTAssertTrue(app.buttons["Unlock vault"].waitForExistence(timeout: 10))
        app.buttons["Unlock vault"].tap()
        let bank = app.cells.containing(.staticText, identifier: "bank.example").firstMatch
        XCTAssertTrue(bank.waitForExistence(timeout: 10))
        capture(app, "06-vault-dark")
        app.terminate()
    }

    /// Tab bar items are tab bar buttons on iPhone, and plain buttons in the
    /// iPad's floating tab bar.
    private func tab(_ app: XCUIApplication, _ name: String) -> XCUIElement {
        let item = app.tabBars.buttons[name]
        return item.exists ? item : app.buttons[name].firstMatch
    }

    /// Selects a tab until `landmark` (an element on that tab) appears,
    /// tapping again if a tap was swallowed. iPad tab items don't report
    /// isSelected, so the landmark is the check.
    private func select(_ app: XCUIApplication, _ name: String, until landmark: XCUIElement) {
        for _ in 0..<3 {
            let item = tab(app, name)
            XCTAssertTrue(item.waitForExistence(timeout: 5))
            item.tap()
            if landmark.waitForExistence(timeout: 3) { return }
        }
        XCTFail("Could not select the \(name) tab")
    }

    private func capture(_ app: XCUIApplication, _ name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
