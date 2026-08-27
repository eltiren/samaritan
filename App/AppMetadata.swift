import UIKit
import OSLog

/// Display name and icon for an installed app, by bundle identifier.
///
/// **There is no public iOS API for this.** `LSApplicationProxy` is private, and using it is a
/// deliberate choice for a development-signed build that will never be submitted to the App Store.
///
/// Constraints on how it is reached, so the project never depends on it:
///
/// * Confined to the containing app — never either extension, which have no business enumerating
///   installed apps.
/// * Everything goes through `NSClassFromString` / `NSSelectorFromString` with optional results, so
///   an iOS release that changes or removes the interface degrades to bundle-ID-only display rather
///   than crashing.
/// * `SAMARITAN_NO_PRIVATE_API` compiles it out entirely, leaving the monogram fallback.
@MainActor
enum AppMetadata {

    struct Entry {
        var displayName: String?
        var icon: UIImage?
    }

    private static var cache: [String: Entry] = [:]

    static func entry(forBundleID bundleID: String) -> Entry {
        if let cached = cache[bundleID] { return cached }
        let resolved = lookup(bundleID)
        cache[bundleID] = resolved
        return resolved
    }

    /// A stable colour per bundle ID, for the fallback tile.
    static func monogramColor(for bundleID: String) -> UIColor {
        var hasher = Hasher()
        hasher.combine(bundleID)
        let hue = Double(abs(hasher.finalize()) % 360) / 360
        return UIColor(hue: hue, saturation: 0.45, brightness: 0.75, alpha: 1)
    }

    static func monogram(for identity: AppIdentity) -> String {
        let name = identity.displayBundleID
        let parts = name.split(separator: ".").filter { !$0.isEmpty }
        guard let last = parts.last else { return "?" }
        return String(last.prefix(2)).uppercased()
    }

    #if SAMARITAN_NO_PRIVATE_API
    private static func lookup(_ bundleID: String) -> Entry { Entry() }
    #else
    private static func lookup(_ bundleID: String) -> Entry {
        guard let proxyClass = NSClassFromString("LSApplicationProxy") as? NSObject.Type else {
            return Entry()
        }
        let selector = NSSelectorFromString("applicationProxyForIdentifier:")
        guard proxyClass.responds(to: selector),
              let proxy = proxyClass.perform(selector, with: bundleID)?.takeUnretainedValue() as? NSObject
        else { return Entry() }

        var name: String?
        for key in ["localizedName", "localizedShortName"] {
            let getter = NSSelectorFromString(key)
            if proxy.responds(to: getter),
               let value = proxy.perform(getter)?.takeUnretainedValue() as? String,
               !value.isEmpty {
                name = value
                break
            }
        }
        return Entry(displayName: name, icon: icon(forBundleID: bundleID))
    }

    private static func icon(forBundleID bundleID: String) -> UIImage? {
        guard let imageClass = NSClassFromString("UIImage") as? NSObject.Type else { return nil }
        let selector = NSSelectorFromString("_applicationIconImageForBundleIdentifier:format:scale:")
        guard imageClass.responds(to: selector) else { return nil }
        typealias Fn = @convention(c) (AnyObject, Selector, NSString, Int, CGFloat) -> UIImage?
        let implementation = imageClass.method(for: selector)
        let function = unsafeBitCast(implementation, to: Fn.self)
        return function(imageClass, selector, bundleID as NSString, 2, UIScreen.main.scale)
    }
    #endif
}
