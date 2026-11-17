import UIKit
import XCTest

final class TypographyTests: XCTestCase {
    func testBundledFontsAreAvailable() {
        let registered = UIFont.familyNames.filter { $0.contains("Jost") || $0.contains("Bodoni Moda") }
            .flatMap { UIFont.fontNames(forFamilyName: $0) }
        for name in ["Jost-Regular", "Jost-Medium", "Jost-SemiBold", "BodoniModa-Medium", "BodoniModa-MediumItalic"] {
            XCTAssertNotNil(UIFont(name: name, size: 17),
                            "\(name) is unavailable. Registered brand faces: \(registered)")
        }
    }
}
