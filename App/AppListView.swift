import SwiftUI

/// Apps that have initiated network activity, plus any the policy already knows about.
struct AppListView: View {
    @Bindable var diagnostics: DiagnosticsModel
    @Bindable var policy: PolicyStore

    var body: some View {
        let observed = diagnostics.observedApps
        // Apps with a policy entry but no recent traffic still need a row, or a rule you wrote
        // yesterday becomes unreachable.
        let quiet = policy.document.apps
            .map(\.appID)
            .filter { id in !observed.contains { $0.appID == id } }

        List {
            Section {
                if observed.isEmpty && quiet.isEmpty {
                    Text("No network activity recorded yet.")
                        .foregroundStyle(Theme.textSecondary)
                }
                ForEach(observed, id: \.appID) { app in
                    NavigationLink {
                        AppDetailView(appID: app.appID, diagnostics: diagnostics, policy: policy)
                    } label: {
                        AppRow(appID: app.appID,
                               blanket: policy.document[app.appID]?.blanket,
                               allowed: app.allowedCount, denied: app.deniedCount,
                               pending: app.destinations.values.filter(\.denied).count)
                    }
                }
                ForEach(quiet, id: \.self) { appID in
                    NavigationLink {
                        AppDetailView(appID: appID, diagnostics: diagnostics, policy: policy)
                    } label: {
                        AppRow(appID: appID, blanket: policy.document[appID]?.blanket,
                               allowed: 0, denied: 0, pending: 0)
                    }
                }
            } header: {
                Text("Apps")
            } footer: {
                Text("Per-app history is bounded at \(ObservedStore.maximumDestinationsPerApp) "
                     + "destinations each, evicting least-recently-seen, so a noisy app cannot "
                     + "crowd out a quiet one.")
            }
            .icebergRows()
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.background)
        .foregroundStyle(Theme.textPrimary)
        .navigationTitle("Apps")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct AppRow: View {
    let appID: String
    let blanket: BlanketMode?
    let allowed: Int
    let denied: Int
    let pending: Int

    private var identity: AppIdentity { AppIdentity(raw: appID) }

    var body: some View {
        HStack(spacing: 10) {
            AppIconView(identity: identity)
            VStack(alignment: .leading, spacing: 2) {
                Text(AppMetadata.entry(forBundleID: String(identity.bundleID)).displayName
                     ?? identity.displayBundleID)
                    .font(.callout)
                    .lineLimit(1)
                Text(identity.displayBundleID)
                    .font(.caption2)
                    .foregroundStyle(Theme.textSecondary)
                    .lineLimit(1)
                HStack(spacing: 8) {
                    if allowed > 0 { Text("\(allowed) allowed").foregroundStyle(Theme.allow) }
                    if denied > 0 { Text("\(denied) denied").foregroundStyle(Theme.deny) }
                    if pending > 0 { Text("\(pending) pending").foregroundStyle(Theme.warning) }
                    if let blanket, blanket == .allowAll {
                        Text("allow all").foregroundStyle(Theme.info)
                    }
                }
                .font(.caption2)
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
