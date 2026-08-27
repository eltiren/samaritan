import SwiftUI
import UIKit

/// Iceberg, as published at terminalcolors.com/themes/iceberg.
///
/// Every token resolves through a `UIColor` dynamic provider, so light and dark follow the system
/// appearance without any view needing to read `@Environment(\.colorScheme)`.
enum Theme {

    /// Raw palette. Kept verbatim rather than tidied so it can be diffed against the source.
    private enum Iceberg {
        // Dark
        static let darkBackground: UInt32 = 0x161821
        static let darkBlack: UInt32      = 0x1e2132
        static let darkRed: UInt32        = 0xe27878
        static let darkGreen: UInt32      = 0xb4be82
        static let darkYellow: UInt32     = 0xe2a478
        static let darkBlue: UInt32       = 0x84a0c6
        static let darkPurple: UInt32     = 0xa093c7
        static let darkCyan: UInt32       = 0x89b8c2
        static let darkForeground: UInt32 = 0xc6c8d1
        static let darkBrightBlack: UInt32 = 0x6b7089
        static let darkBrightWhite: UInt32 = 0xd2d4de

        // Light
        static let lightBackground: UInt32 = 0xe8e9ec
        static let lightBlack: UInt32      = 0xdcdfe7
        static let lightRed: UInt32        = 0xcc517a
        static let lightGreen: UInt32      = 0x668e3d
        static let lightYellow: UInt32     = 0xc57339
        static let lightBlue: UInt32       = 0x2d539e
        static let lightPurple: UInt32     = 0x7759b4
        static let lightCyan: UInt32       = 0x3f83a6
        static let lightForeground: UInt32 = 0x33374c
        static let lightBrightBlack: UInt32 = 0x8389a3
        static let lightBrightWhite: UInt32 = 0x262a3f
    }

    // MARK: - Semantic tokens

    /// The page behind the list. Light inverts the pairing — Iceberg's light "black" (#dcdfe7) is
    /// *darker* than its background, so it serves as the recessed layer that grouped rows sit on.
    static let background = Color(light: Iceberg.lightBlack, dark: Iceberg.darkBackground)
    /// Row and card fill, one step forward from `background` in both appearances.
    static let surface = Color(light: Iceberg.lightBackground, dark: Iceberg.darkBlack)

    static let textPrimary = Color(light: Iceberg.lightForeground, dark: Iceberg.darkForeground)
    static let textSecondary = Color(light: Iceberg.lightBrightBlack, dark: Iceberg.darkBrightBlack)
    static let textStrong = Color(light: Iceberg.lightBrightWhite, dark: Iceberg.darkBrightWhite)

    static let accent = Color(light: Iceberg.lightBlue, dark: Iceberg.darkBlue)
    static let deny = Color(light: Iceberg.lightRed, dark: Iceberg.darkRed)
    static let allow = Color(light: Iceberg.lightGreen, dark: Iceberg.darkGreen)
    static let warning = Color(light: Iceberg.lightYellow, dark: Iceberg.darkYellow)
    static let info = Color(light: Iceberg.lightCyan, dark: Iceberg.darkCyan)
    static let escalate = Color(light: Iceberg.lightPurple, dark: Iceberg.darkPurple)

    /// Colour for a verdict label, so allow/deny/escalate read the same everywhere.
    static func color(for verdict: FlowRecord.Verdict) -> Color {
        switch verdict {
        case .drop, .controlDrop: deny
        case .allow, .controlAllow: allow
        case .needRules: escalate
        case .report: textSecondary
        }
    }

    /// Applies the palette to UIKit surfaces SwiftUI does not reach — the navigation bar and the
    /// list's own background.
    @MainActor
    static func applyGlobalAppearance() {
        let bar = UINavigationBarAppearance()
        bar.configureWithOpaqueBackground()
        bar.backgroundColor = UIColor(background)
        bar.titleTextAttributes = [.foregroundColor: UIColor(textStrong)]
        bar.largeTitleTextAttributes = [.foregroundColor: UIColor(textStrong)]
        UINavigationBar.appearance().standardAppearance = bar
        UINavigationBar.appearance().scrollEdgeAppearance = bar
        UINavigationBar.appearance().compactAppearance = bar
    }
}

extension Color {
    /// Resolves per system appearance, so no view has to observe the colour scheme itself.
    init(light: UInt32, dark: UInt32) {
        self.init(UIColor { traits in
            UIColor(rgb: traits.userInterfaceStyle == .dark ? dark : light)
        })
    }
}

extension UIColor {
    convenience init(rgb: UInt32) {
        self.init(red: CGFloat((rgb >> 16) & 0xFF) / 255,
                  green: CGFloat((rgb >> 8) & 0xFF) / 255,
                  blue: CGFloat(rgb & 0xFF) / 255,
                  alpha: 1)
    }
}
