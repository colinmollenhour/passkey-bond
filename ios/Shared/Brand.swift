#if canImport(UIKit)
import SwiftUI
import UIKit

/// Passkey.bond's "Black Tie Keyhole" palette and type (docs/brand/README.md),
/// mirroring the CSS custom properties in src/ui/options.css and
/// android/web/src/styles.css: ivory and navy in light mode, tuxedo black and
/// gold in dark mode.
enum Brand {
    static let navy = 0x14213D
    static let tuxedo = 0x111111
    static let goldHex = 0xC9A24A
    static let deepGold = 0x9C7A2E
    static let ivory = 0xF4EBD9
    static let oxblood = 0x6B1E2A
    static let racingGreen = 0x0F3D2E

    /// Page behind grouped lists (--bg-elev light, --bg dark).
    static let page = dynamic(light: ivory, dark: tuxedo)
    /// Rows and cards (--bg light, --bg-elev dark).
    static let surface = dynamic(light: 0xFBF7EF, dark: navy)
    static let text = dynamic(light: navy, dark: ivory)
    static let muted = dynamic(light: 0x3B4660, dark: 0xB9B1A3)
    /// Buttons and controls: navy on light, gold on dark (--accent).
    static let accent = dynamic(light: navy, dark: goldHex)
    static let onAccent = dynamic(light: 0xFBF7EF, dark: tuxedo)
    /// Icons and the wordmark's ".bond" (--wordmark-accent).
    static let gold = dynamic(light: deepGold, dark: goldHex)
    static let danger = dynamic(light: oxblood, dark: 0xE07A86)
    /// Filled destructive controls (swipe actions) carry a light label, so
    /// they stay oxblood in dark mode too.
    static let dangerFill = dynamic(light: oxblood, dark: oxblood)
    static let success = dynamic(light: racingGreen, dark: 0x6FB592)
    static let separator = dynamic(light: 0xD8CCB4, dark: 0x30363D)

    static func uiColor(_ hex: Int) -> UIColor {
        UIColor(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }

    static func dynamicUIColor(light: Int, dark: Int) -> UIColor {
        UIColor { $0.userInterfaceStyle == .dark ? uiColor(dark) : uiColor(light) }
    }

    private static func dynamic(light: Int, dark: Int) -> Color {
        Color(uiColor: dynamicUIColor(light: light, dark: dark))
    }

    /// UIKit chrome that SwiftUI modifiers don't reach: navigation and tab
    /// bars, bar buttons and grouped-list backgrounds. Call once at launch.
    @MainActor
    static func applyAppearance() {
        let text = dynamicUIColor(light: navy, dark: ivory)
        let page = dynamicUIColor(light: ivory, dark: tuxedo)
        let separator = dynamicUIColor(light: 0xD8CCB4, dark: 0x30363D)

        let nav = UINavigationBarAppearance()
        nav.configureWithOpaqueBackground()
        nav.backgroundColor = page
        nav.shadowColor = .clear
        nav.titleTextAttributes = [.font: uiFont(.semibold, 17, .headline), .foregroundColor: text]
        nav.largeTitleTextAttributes = [.font: uiFont(.semibold, 34, .largeTitle), .foregroundColor: text]
        let button = UIBarButtonItemAppearance()
        button.normal.titleTextAttributes = [.font: uiFont(.medium, 17, .body)]
        nav.buttonAppearance = button
        nav.doneButtonAppearance = button
        UINavigationBar.appearance().standardAppearance = nav
        UINavigationBar.appearance().compactAppearance = nav
        UINavigationBar.appearance().scrollEdgeAppearance = nav

        let tab = UITabBarAppearance()
        tab.configureWithOpaqueBackground()
        tab.backgroundColor = page
        tab.shadowColor = separator
        for layout in [tab.stackedLayoutAppearance, tab.inlineLayoutAppearance, tab.compactInlineLayoutAppearance] {
            layout.normal.titleTextAttributes = [.font: uiFont(.medium, 11, .caption2)]
            layout.selected.titleTextAttributes = [.font: uiFont(.medium, 11, .caption2)]
        }
        UITabBar.appearance().standardAppearance = tab
        UITabBar.appearance().scrollEdgeAppearance = tab
    }

    enum Weight: String {
        case regular = "Jost-Regular"
        case medium = "Jost-Medium"
        case semibold = "Jost-SemiBold"
    }

    static func uiFont(_ weight: Weight, _ size: CGFloat, _ style: UIFont.TextStyle) -> UIFont {
        let base = UIFont(name: weight.rawValue, size: size) ?? .systemFont(ofSize: size)
        return UIFontMetrics(forTextStyle: style).scaledFont(for: base)
    }
}

extension Font {
    /// Jost at a Dynamic Type-relative size.
    static func jost(_ size: CGFloat, _ weight: Brand.Weight = .regular,
                     relativeTo style: Font.TextStyle = .body) -> Font {
        .custom(weight.rawValue, size: size, relativeTo: style)
    }
}

/// "Passkey" in Bodoni Moda with ".bond" in gold italic, as on the web and Android.
struct BrandWordmark: View {
    var size: CGFloat = 36

    var body: some View {
        (Text("Passkey")
            .font(.custom("BodoniModa-Medium", size: size, relativeTo: .largeTitle))
            .foregroundStyle(Brand.text)
         + Text(".bond")
            .font(.custom("BodoniModa-MediumItalic", size: size, relativeTo: .largeTitle))
            .foregroundStyle(Brand.gold))
            .accessibilityLabel("Passkey.bond")
    }
}

/// A grouped-list section header in the brand type, in sentence case. Lists
/// otherwise uppercase their headers, and the brand uses no all-caps labels.
struct BrandHeader: View {
    let title: String
    init(_ title: String) { self.title = title }

    var body: some View {
        Text(title)
            .font(.jost(15, .medium, relativeTo: .subheadline))
            .foregroundStyle(Brand.muted)
            .textCase(nil)
    }
}

/// A list section with a brand header and brand row background.
struct BrandSection<Content: View>: View {
    private let title: String
    private let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        Section {
            content
        } header: {
            BrandHeader(title)
        }
        .listRowBackground(Brand.surface)
        .textCase(nil)
        .headerProminence(.increased)
    }
}

extension View {
    /// Brand page background behind a List or Form, with brand-coloured rows.
    func brandList() -> some View {
        scrollContentBackground(.hidden)
            // Fill behind the keyboard too, or a sheet shows a white band
            // where the keyboard was.
            .background { Brand.page.ignoresSafeArea() }
            .textCase(nil)
    }

    /// Brand fonts, colours and tint for a screen's root view.
    func brandChrome() -> some View {
        font(.jost(17))
            .foregroundStyle(Brand.text)
            .tint(Brand.accent)
            .textCase(nil)
    }
}

/// The filled button used for the main action on a screen.
struct BrandProminentButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.jost(17, .medium, relativeTo: .body))
            .foregroundStyle(Brand.onAccent)
            .padding(.horizontal, 22)
            .padding(.vertical, 12)
            .background(Brand.accent.opacity(configuration.isPressed ? 0.85 : 1),
                        in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .opacity(isEnabled ? 1 : 0.5)
    }
}

extension ButtonStyle where Self == BrandProminentButtonStyle {
    static var brandProminent: BrandProminentButtonStyle { BrandProminentButtonStyle() }
}
#endif
