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

    /// How the team half reads when a bundle ID turns up under more than one of them.
    ///
    /// An empty team is not a missing value — it is the signature of a platform binary, and
    /// measured on device it is also how a flow a *system framework* makes on a third-party app's
    /// behalf arrives: NordVPN's own traffic came in as `W5W395V82Y.com.nordvpn.NordVPN` while its
    /// StoreKit traffic came in as `.com.nordvpn.NordVPN`. Both are that app in the Apps list and
    /// both show the same bundle ID, so without this they read as one row duplicated.
    public var displayTeamID: String {
        teamID.isEmpty ? "no team" : String(teamID)
    }

    /// Bundle IDs that turn up under more than one identifier in `appIDs`.
    ///
    /// A list row shows the bundle ID, not the identifier policy is keyed on, so two of these render
    /// identically and read as one app listed twice — the reported bug. They are genuinely separate
    /// policy targets, so the answer is to show `displayTeamID` on exactly the rows where it is
    /// doing the distinguishing, not to merge them.
    public static func collidingBundleIDs(in appIDs: some Sequence<String>) -> Set<String> {
        var firstSeen: [String: String] = [:]
        var colliding: Set<String> = []
        for appID in appIDs {
            let bundle = String(AppIdentity(raw: appID).bundleID)
            if let other = firstSeen[bundle] {
                // A repeat of the *same* identifier is not a collision — the caller concatenates
                // two lists and a duplicate across them would otherwise label every row.
                if other != appID { colliding.insert(bundle) }
            } else {
                firstSeen[bundle] = appID
            }
        }
        return colliding
    }
}
