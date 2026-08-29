import SwiftUI

/// One app's policy, laid out as specified: blanket toggle, allowed, denied, then everything it
/// asked for that no rule has decided.
struct AppDetailView: View {
    let appID: String
    @Bindable var diagnostics: DiagnosticsModel
    @Bindable var policy: PolicyStore

    @State private var pendingRule: RuleDraft?

    private var identity: AppIdentity { AppIdentity(raw: appID) }
    private var appPolicy: AppPolicy { policy.document[appID] ?? AppPolicy(appID: appID) }

    private var observed: [ObservedDestination] {
        let decided = Set(appPolicy.rules.map(\.value))
        // "Observed" is only what no rule has spoken for yet.
        return (diagnostics.observedApp(appID)?.destinations.values ?? [:].values)
            .filter { !decided.contains($0.host) }
            .sorted { $0.lastSeen > $1.lastSeen }
    }

    var body: some View {
        List {
            Section {
                Toggle("Allow all", isOn: Binding(
                    get: { appPolicy.blanket == .allowAll },
                    set: { policy.setBlanket($0 ? .allowAll : .denyAll, for: appID) }
                ))
            } header: {
                Text(identity.displayBundleID)
            } footer: {
                Text("Allow all permits everything this app is not specifically denied — by its own "
                     + "deny list or a global one. Off, it is denied everything not specifically "
                     + "allowed. Either way the lists below and the global lists win.")
            }
            .icebergRows()

            ruleSection(title: "Allowed", action: .allow)
            ruleSection(title: "Denied", action: .deny)

            Section {
                if observed.isEmpty {
                    Text("Nothing pending.").foregroundStyle(Theme.textSecondary)
                }
                ForEach(observed) { destination in
                    Button {
                        pendingRule = RuleDraft(target: destination.host,
                                                isAddress: IPPrefix(destination.host) != nil,
                                                appID: appID)
                    } label: {
                        DestinationRow(destination: destination)
                    }
                }
            } header: {
                Text("Observed (\(observed.count))")
            } footer: {
                Text("Destinations this app asked for that no rule decides. Under deny-all they were "
                     + "dropped. Tap one to allow or deny it.")
            }
            .icebergRows()
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.background)
        .foregroundStyle(Theme.textPrimary)
        .navigationTitle(AppMetadata.entry(forBundleID: String(identity.bundleID)).displayName
                         ?? identity.displayBundleID)
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $pendingRule) { draft in
            RuleEditorView(draft: draft, policy: policy)
        }
    }

    private func ruleSection(title: String, action: RuleAction) -> some View {
        let rules = appPolicy.rules.filter { $0.action == action }
        return Section(title) {
            if rules.isEmpty {
                Text("None.").foregroundStyle(Theme.textSecondary)
            }
            ForEach(rules, id: \.self) { rule in
                HStack {
                    Text(rule.displayValue)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                    Spacer()
                    Button("Remove") {
                        var updated = appPolicy
                        updated.rules.removeAll { $0 == rule }
                        policy.upsert(updated)
                    }
                    .font(.caption)
                    .foregroundStyle(Theme.deny)
                }
            }
        }
        .icebergRows()
    }
}

private struct DestinationRow: View {
    let destination: ObservedDestination

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(destination.host)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(Theme.textPrimary)
                    .lineLimit(1)
                Spacer()
                Text("×\(destination.attempts)")
                    .font(.caption2)
                    .foregroundStyle(destination.denied ? Theme.deny : Theme.textSecondary)
            }
            let detail = [
                destination.addresses.sorted().prefix(2).joined(separator: ", "),
                destination.ports.sorted().map(String.init).joined(separator: ","),
            ].filter { !$0.isEmpty }.joined(separator: "  ports ")
            if !detail.isEmpty {
                Text(detail)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .lineLimit(1)
            }
        }
    }
}

/// What the popover is editing.
struct RuleDraft: Identifiable {
    let target: String
    let isAddress: Bool
    /// `nil` means the rule goes into the global user list rather than one app's.
    let appID: String?
    var id: String { "\(appID ?? "global")|\(target)" }
}
