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

    /// The icon format argument is an undocumented enum whose accepted values differ per app and
    /// per iOS release: on this device format 2 produced a real icon for Mail and an all-black
    /// placeholder for everything else. So every format is tried and each result is checked for
    /// actual content — a uniform image means the lookup failed, and the monogram is better than a
    /// black square.
    private static func icon(forBundleID bundleID: String) -> UIImage? {
        guard let imageClass = NSClassFromString("UIImage") as? NSObject.Type else { return nil }
        let selector = NSSelectorFromString("_applicationIconImageForBundleIdentifier:format:scale:")
        guard imageClass.responds(to: selector) else { return nil }
        typealias Fn = @convention(c) (AnyObject, Selector, NSString, Int, CGFloat) -> UIImage?
        let function = unsafeBitCast(imageClass.method(for: selector), to: Fn.self)

        for format in [3, 2, 1, 0, 4, 5, 8] {
            guard let candidate = function(imageClass, selector, bundleID as NSString,
                                           format, UIScreen.main.scale),
                  hasVisibleContent(candidate) else { continue }
            return candidate
        }
        return nil
    }

    /// True when the image varies — a placeholder comes back as a single flat colour or fully
    /// transparent, and both should fall through to the monogram.
    private static func hasVisibleContent(_ image: UIImage) -> Bool {
        guard let cgImage = image.cgImage, cgImage.width > 0, cgImage.height > 0 else { return false }
        let side = 8
        var pixels = [UInt8](repeating: 0, count: side * side * 4)
        guard let context = CGContext(data: &pixels, width: side, height: side,
                                      bitsPerComponent: 8, bytesPerRow: side * 4,
                                      space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { return false }
        context.draw(cgImage, in: CGRect(x: 0, y: 0, width: side, height: side))

        var opaque = 0
        var minimum: (UInt8, UInt8, UInt8) = (255, 255, 255)
        var maximum: (UInt8, UInt8, UInt8) = (0, 0, 0)
        for index in stride(from: 0, to: pixels.count, by: 4) {
            guard pixels[index + 3] > 16 else { continue }
            opaque += 1
            minimum = (min(minimum.0, pixels[index]), min(minimum.1, pixels[index + 1]),
                       min(minimum.2, pixels[index + 2]))
            maximum = (max(maximum.0, pixels[index]), max(maximum.1, pixels[index + 1]),
                       max(maximum.2, pixels[index + 2]))
        }
        guard opaque > 8 else { return false }
        let spread = Int(maximum.0) - Int(minimum.0)
            + Int(maximum.1) - Int(minimum.1)
            + Int(maximum.2) - Int(minimum.2)
        return spread > 24
    }
    #endif
}
