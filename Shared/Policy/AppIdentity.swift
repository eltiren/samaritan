import Foundation

/// A parsed `NEFilterFlow.sourceAppIdentifier`.
///
/// Measured on device: the value is **`<teamID>.<bundleID>`**, not a bundle identifier.
/// Third-party apps carry a real team (`BQR82RBBHL.com.tinyspeck.chatlyio`); Apple's own binaries
/// have an empty team, so they arrive with a leading dot (`.com.apple.mobilesafari`).
///
/// Comparing the raw string against a bundle ID silently never matches, which is why this type
/// exists rather than string handling scattered through the resolver.
public struct AppIdentity: Hashable, Sendable {

    /// The whole `sourceAppIdentifier`. Policy is keyed on this, not on `bundleID` alone: keying on
    /// the bundle ID would let a different signer inherit another app's rules.
    public let raw: String
    public let teamID: Substring
    public let bundleID: Substring

    /// Reserved key for flows that arrived with no `sourceAppIdentifier`. Never observed on device,
    /// but under default-deny such a flow is dropped, so it needs somewhere visible to appear.
    public static let unattributedRaw = "<unattributed>"

    public init(raw: String) {
        self.raw = raw
        if let dot = raw.firstIndex(of: ".") {
            teamID = raw[raw.startIndex..<dot]
            bundleID = raw[raw.index(after: dot)...]
        } else {
            teamID = raw[raw.startIndex..<raw.startIndex]
            bundleID = raw[...]
        }
    }

    public init(sourceAppIdentifier: String?) {
        self.init(raw: (sourceAppIdentifier?.isEmpty == false)
                  ? sourceAppIdentifier! : Self.unattributedRaw)
    }

    public var isUnattributed: Bool { raw == Self.unattributedRaw }

    /// A platform binary: empty team **and** a `com.apple.` bundle prefix.
    ///
    /// Both halves matter. The empty team is what actually distinguishes an Apple binary; the
    /// trailing dot on the prefix stops a third-party `com.appleseed.*` from matching.
    public var isAppleSystemApp: Bool {
        teamID.isEmpty && bundleID.hasPrefix("com.apple.")
    }

    /// What to show in a list when no display name is available.
    public var displayBundleID: String {
        isUnattributed ? "Unattributed" : String(bundleID)
    }
}
