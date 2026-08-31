import SwiftUI

/// Apps that have initiated network activity, plus any the policy already knows about.
struct AppListView: View {
    @Bindable var diagnostics: DiagnosticsModel
    @Bindable var policy: PolicyStore

    @State private var query = ""
    @State private var sort: AppListSort = .lastActivity
    @State private var ascending = AppListSort.lastActivity.defaultsToAscending

    var body: some View {
        let all = entries
        // Two rows can carry the same bundle ID under different teams, and a row shows the bundle
        // ID — so they render as one app duplicated. The team is what has to become visible.
        // Computed over every row rather than the filtered ones: the collision is a property of the
        // data, and a label that appeared and vanished as the query narrowed would be worse than
        // one that is simply always right.
        let ambiguous = AppIdentity.collidingBundleIDs(in: all.map(\.appID))
        let rows = AppListSort.ordered(all.filter { $0.matches(query) },
                                       by: sort, ascending: ascending)

        List {
            Section {
                if rows.isEmpty {
                    Text(query.isEmpty ? "No network activity recorded yet."
                                       : "No app matches \u{201C}\(query)\u{201D}.")
                        .foregroundStyle(Theme.textSecondary)
                }
                ForEach(rows) { entry in
                    NavigationLink {
                        AppDetailView(appID: entry.appID, diagnostics: diagnostics, policy: policy)
                    } label: {
                        AppRow(appID: entry.appID,
                               title: entry.title,
                               blanket: policy.document[entry.appID]?.blanket,
                               bypassed: policy.document[entry.appID]?.bypass ?? false,
                               allowed: entry.allowedCount, denied: entry.deniedCount,
                               pending: entry.pendingCount,
                               bytesInbound: entry.bytesInbound,
                               bytesOutbound: entry.bytesOutbound,
                               showsTeam: ambiguous.contains(String(AppIdentity(raw: entry.appID).bundleID)))
                    }
                }
            } header: {
                HStack {
                    Text(query.isEmpty ? "Apps" : "Apps — \(rows.count) of \(all.count)")
                    Spacer()
                    // The active order, always visible. Two of the three sorts can produce very
                    // similar lists — the busiest app is usually also the most recent one — so
                    // without this you cannot tell which one you are looking at.
                    Text(sort.directionLabel(ascending: ascending))
                }
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Per-app history is bounded at \(ObservedStore.maximumDestinationsPerApp) "
                         + "destinations each, evicting least-recently-seen, so a noisy app cannot "
                         + "crowd out a quiet one.")
                    Text("↓ received and ↑ sent are totals since the counting window began, from "
                         + "closed flows only. They are cleared for every app at once by Reset "
                         + "counters in Settings.")
                    if !ambiguous.isEmpty {
                        Text("Where two rows carry the same bundle ID, the team it was signed "
                             + "under follows it. \"no team\" is a platform-signed flow — traffic a "
                             + "system framework made on the app's behalf, such as a purchase. "
                             + "Rules are keyed on the whole identifier, so those rows are "
                             + "separate apps to the filter.")
                    }
                }
            }
            .icebergRows()
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.background)
        .foregroundStyle(Theme.textPrimary)
        .navigationTitle("Apps")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $query, prompt: "Name or bundle ID")
        // Bundle IDs are lowercase and full of dots. Autocapitalisation and autocorrection both
        // fight a query like "com.nordvpn".
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) { sortMenu }
        }
    }

    private var sortMenu: some View {
        Menu {
            // Inline, or each picker becomes a submenu and the whole thing takes two taps to
            // read let alone change.
            Picker("Sort by", selection: $sort) {
                ForEach(AppListSort.allCases) { field in
                    Text(field.label).tag(field)
                }
            }
            .pickerStyle(.inline)
            Picker("Order", selection: $ascending) {
                // The field's natural direction is listed first, so the menu never opens on
                // "Z to A, A to Z".
                let natural = sort.defaultsToAscending
                Text(sort.directionLabel(ascending: natural)).tag(natural)
                Text(sort.directionLabel(ascending: !natural)).tag(!natural)
            }
            .pickerStyle(.inline)
        } label: {
            Label("Sort", systemImage: "arrow.up.arrow.down")
        }
        .onChange(of: sort) { _, newField in
            // Picking a field resets the direction to the one that field reads best in. Without
            // this, choosing Name straight after Traffic lands you on Z to A, which reads as the
            // sort having failed.
            ascending = newField.defaultsToAscending
        }
    }

    /// One row per identifier, with the display name resolved up front.
    ///
    /// The rows used to resolve their own names as they scrolled into view, which was enough when
    /// the order was fixed. Sorting and searching both need a name for every app before the first
    /// row is drawn, so it is resolved here — through the name-only lookup, not the one that also
    /// decodes an icon.
    private var entries: [AppListEntry] {
        let observed = diagnostics.observedApps
        var seen = Set(observed.map(\.appID))
        var rows = observed.map {
            AppListEntry(appID: $0.appID, title: title(for: $0.appID), observed: $0)
        }
        // Apps with a policy entry but no recent traffic still need a row, or a rule you wrote
        // yesterday becomes unreachable.
        for appID in policy.document.apps.map(\.appID) where seen.insert(appID).inserted {
            rows.append(AppListEntry(appID: appID, title: title(for: appID), observed: nil))
        }
        return rows
    }

    private func title(for appID: String) -> String {
        let identity = AppIdentity(raw: appID)
        return AppMetadata.displayName(forBundleID: String(identity.bundleID))
            ?? identity.displayBundleID
    }
}

struct AppRow: View {
    let appID: String
    /// Resolved by the list, not here: it is the same string the list sorted and searched on, and
    /// two lookups of the same name are two chances for the row and the order to disagree.
    let title: String
    let blanket: BlanketMode?
    let bypassed: Bool
    let allowed: Int
    let denied: Int
    let pending: Int
    let bytesInbound: UInt64
    let bytesOutbound: UInt64
    /// Another row carries this bundle ID under a different team, so the bundle ID alone does not
    /// say which app this row is.
    let showsTeam: Bool

    private var identity: AppIdentity { AppIdentity(raw: appID) }
    private var subtitle: String {
        showsTeam ? "\(identity.displayBundleID) · \(identity.displayTeamID)"
                  : identity.displayBundleID
    }
    private var hasTraffic: Bool { bytesInbound > 0 || bytesOutbound > 0 }

    var body: some View {
        HStack(spacing: 10) {
            AppIconView(identity: identity)
                // A bypassed app is not being filtered at all, so its row should not read as a
                // participating one.
                .opacity(bypassed ? 0.45 : 1)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(title)
                        .font(.callout)
                        .lineLimit(1)
                    if bypassed {
                        Text("BYPASSED")
                            .font(.system(size: 9, weight: .semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Theme.warning.opacity(0.22), in: Capsule())
                            .foregroundStyle(Theme.warning)
                    }
                }
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(Theme.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: 8) {
                    if bypassed {
                        Text("not filtered — nothing recorded")
                            .foregroundStyle(Theme.textSecondary)
                    } else {
                        if allowed > 0 { Text("\(allowed) allowed").foregroundStyle(Theme.allow) }
                        if denied > 0 { Text("\(denied) denied").foregroundStyle(Theme.deny) }
                        if pending > 0 { Text("\(pending) pending").foregroundStyle(Theme.warning) }
                        if let blanket, blanket == .allowAll {
                            Text("allow all").foregroundStyle(Theme.info)
                        }
                    }
                }
                .font(.caption2)
            }
            if hasTraffic, !bypassed {
                Spacer(minLength: 6)
                VStack(alignment: .trailing, spacing: 2) {
                    Text("↓ \(DiagnosticsModel.bytes(bytesInbound))")
                    Text("↑ \(DiagnosticsModel.bytes(bytesOutbound))")
                        .foregroundStyle(Theme.textSecondary)
                }
                .font(.caption2)
                .monospacedDigit()
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
            }
        }
    }
}

struct AppIconView: View {
    let identity: AppIdentity

    var body: some View {
        let entry = AppMetadata.entry(forBundleID: String(identity.bundleID))
        Group {
            if let icon = entry.icon {
                Image(uiImage: icon).resizable()
            } else {
                // No public API gives us another app's icon, so a stable monogram stands in when
                // the private lookup is unavailable.
                ZStack {
                    Color(AppMetadata.monogramColor(for: String(identity.bundleID)))
                    Text(AppMetadata.monogram(for: identity))
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                }
            }
        }
        .frame(width: 32, height: 32)
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}
