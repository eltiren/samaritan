import Foundation
import OSLog

/// Locations inside the App Group container shared by the app, the data provider and the
/// control provider.
///
/// The App Group identifier is *not* hard-coded here. It is injected into every target's
/// `Info.plist` as `SamaritanAppGroupIdentifier` from the `SAMARITAN_APP_GROUP` build setting,
/// which is derived from `PRODUCT_BUNDLE_PREFIX` in `Config/Signing.xcconfig`. That keeps a single
/// source of truth and makes a mis-provisioned App Group fail loudly instead of silently.
public enum SharedContainer {

    public static let appGroupIdentifier: String = {
        let value = Bundle.main.object(forInfoDictionaryKey: "SamaritanAppGroupIdentifier") as? String
        guard let value, !value.isEmpty, value != "group." else {
            // Deliberately not a fatalError: inside a NetworkExtension a crash loop is far worse
            // than a degraded provider. The UI surfaces `containerURL == nil` instead.
            return ""
        }
        return value
    }()

    /// `nil` when the App Group is not provisioned for this binary. On iOS this is the single most
    /// common cause of "the extension runs but the app shows nothing".
    public static let containerURL: URL? = {
        guard !appGroupIdentifier.isEmpty else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)
    }()

    /// Which process is writing. Each writer owns its own ring file so that there is exactly one
    /// writer per file and no cross-process locking is required.
    public enum Writer: String, Sendable, CaseIterable {
        case dataProvider = "data"
        case controlProvider = "control"

        var ringFileName: String { "flows-\(rawValue).ring" }
    }

    public static func ringURL(for writer: Writer) -> URL? {
        containerURL?.appendingPathComponent(writer.ringFileName, isDirectory: false)
    }

    /// Configuration written by the app, read by both providers.
    public static var configurationURL: URL? {
        containerURL?.appendingPathComponent("spike-config.json", isDirectory: false)
    }

    /// The compiled policy blob. Written by the app, `mmap`ed read-only by the providers.
    public static var policyURL: URL? {
        containerURL?.appendingPathComponent("policy.bin", isDirectory: false)
    }

    /// The editable policy document, app-side only.
    public static var policyDocumentURL: URL? {
        containerURL?.appendingPathComponent("policy.json", isDirectory: false)
    }

    /// The bypass set. Its own file, not a section of `policy.bin`, because the data provider has
    /// to answer it before it touches the policy or its lock. See `BypassGate`.
    public static var bypassURL: URL? {
        containerURL?.appendingPathComponent(BypassList.fileName, isDirectory: false)
    }

    /// Diagnostic files must be readable while the device is locked — a content filter runs
    /// long before and long after the user unlocks. `completeUntilFirstUserAuthentication` is the
    /// weakest protection class that still guarantees that after the first unlock following boot.
    public static let fileProtection: FileProtectionType = .completeUntilFirstUserAuthentication
}
