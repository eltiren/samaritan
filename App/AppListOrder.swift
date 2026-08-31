import Foundation

/// What the Apps list is ordered by.
///
/// Kept out of the view because the two interesting decisions are not the picker. First, both the
/// sort key and the search run over the app's *displayed* name, and resolving a name is a private
/// API call per app — see `AppMetadata.displayName(forBundleID:)` for why that is not the same call
/// the rows make. Second, ties have to break somewhere fixed; see `ordered(_:by:ascending:)`.
enum AppListSort: String, CaseIterable, Identifiable {
    /// The order this list had before it was sortable: most recently seen first.
    case lastActivity
    case name
    case traffic

    var id: String { rawValue }

    var label: String {
        switch self {
        case .lastActivity: "Last activity"
        case .name: "Name"
        case .traffic: "Traffic"
        }
    }

    /// The direction this field reads best in, applied whenever the field is picked.
    var defaultsToAscending: Bool {
        switch self {
        case .lastActivity, .traffic: false
        case .name: true
        }
    }

    /// Direction labels are per field on purpose: "Ascending" over a byte count is a riddle, and
    /// over a date it is ambiguous in the way that matters.
    func directionLabel(ascending: Bool) -> String {
        switch self {
        case .lastActivity: ascending ? "Oldest first" : "Newest first"
        case .name: ascending ? "A to Z" : "Z to A"
        case .traffic: ascending ? "Least first" : "Most first"
        }
    }

    func compare(_ left: AppListEntry, _ right: AppListEntry) -> ComparisonResult {
        switch self {
        // Localised and numeric-aware, so the order matches what the row shows rather than UTF-8
        // order — which would sort every lowercase bundle ID after every capitalised app name.
        case .name: left.title.localizedStandardCompare(right.title)
        case .traffic: Self.compare(left.totalBytes, right.totalBytes)
        case .lastActivity: Self.compare(left.lastSeen, right.lastSeen)
        }
    }

    static func ordered(_ entries: [AppListEntry],
                        by field: AppListSort,
                        ascending: Bool) -> [AppListEntry] {
        entries.sorted { left, right in
            switch field.compare(left, right) {
            case .orderedAscending: ascending
            case .orderedDescending: !ascending
            // Ties break on the identifier, in a fixed direction whichever way the sort runs, so
            // the rows do not reshuffle under the finger. Sorting by traffic ties every app that
            // has moved nothing, `ObservedStore.snapshot()` comes out of a dictionary, and the
            // model re-reads it on a timer — without this the bottom of the list would reorder
            // itself once a second.
            case .orderedSame: left.appID < right.appID
            }
        }
    }

    private static func compare<Value: Comparable>(_ left: Value, _ right: Value) -> ComparisonResult {
        if left < right { return .orderedAscending }
        if right < left { return .orderedDescending }
        return .orderedSame
    }
}

/// One row of the Apps list, with everything the sort and the search need already resolved.
struct AppListEntry: Identifiable {
    /// The raw `sourceAppIdentifier`. Policy is keyed on this, so it is also the row's identity.
    let appID: String
    /// What the row shows as its title — the app's name when the lookup found one, else the bundle
    /// ID. Sorting and searching use this rather than the bundle ID alone, so that the order on
    /// screen matches the column being sorted.
    let title: String
    /// `nil` for an app that has a policy entry but has never been recorded.
    let observed: ObservedApp?

    var id: String { appID }

    var bytesInbound: UInt64 { observed?.bytesInbound ?? 0 }
    var bytesOutbound: UInt64 { observed?.bytesOutbound ?? 0 }
    var totalBytes: UInt64 { bytesInbound &+ bytesOutbound }
    var allowedCount: Int { observed?.allowedCount ?? 0 }
    var deniedCount: Int { observed?.deniedCount ?? 0 }
    var pendingCount: Int { observed?.destinations.values.filter(\.denied).count ?? 0 }

    /// An app with no recorded flow sorts as if it had never been seen, which leaves it at the
    /// bottom under the default order — exactly where it sat before this list had a sort at all.
    var lastSeen: Date { observed?.lastSeen ?? .distantPast }

    /// Matches the name and the whole identifier, so a bundle ID types as well as a name and a team
    /// ID finds the rows signed under it.
    func matches(_ query: String) -> Bool {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return true }
        return title.localizedCaseInsensitiveContains(trimmed)
            || appID.localizedCaseInsensitiveContains(trimmed)
    }
}
