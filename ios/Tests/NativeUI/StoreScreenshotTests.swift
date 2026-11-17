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
        let link = app.secureTextFields["otpauth:// link"]
        XCTAssertTrue(link.waitForExistence(timeout: 5))
        link.tap()
        link.typeText("otpauth://totp/Example%20Mail:alex%40example.com?secret=MFRGGZDFMZTWQ2LK&issuer=Example%20Mail")
        app.buttons["Read setup link"].tap()
        XCTAssertEqual(app.textFields["Issuer or service"].value as? String, "Example Mail")
        dismissKeyboard(app)
        capture(app, "03-add-code")
        app.buttons["Cancel"].tap()
        XCTAssertTrue(bank.waitForExistence(timeout: 5))

        tab(app, "Sync").tap()
        XCTAssertTrue(app.buttons["Create sync chain"].waitForExistence(timeout: 5))
        capture(app, "04-sync")

        tab(app, "Settings").tap()
        XCTAssertTrue(app.buttons["Export encrypted backup"].waitForExistence(timeout: 5))
        capture(app, "05-settings")

        tab(app, "Vault").tap()
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
