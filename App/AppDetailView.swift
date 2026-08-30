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
    private var isBypassed: Bool { appPolicy.bypass }
    /// `<unattributed>` is a display-only pseudo-identifier — no flow carries it, so a bypass on it
    /// could never fire. Offering the toggle would be offering a rule that silently does nothing.
    private var canBypass: Bool { !identity.isUnattributed }

    /// Other identifiers seen for the same bundle ID.
    ///
    /// One app routinely produces several: extensions and helper processes are signed into the same
    /// team but carry their own bundle IDs, and the same bundle can appear under more than one team.
    /// Each is a separate row and a separate policy, so bypassing one does not bypass the rest —
    /// which is exactly how a bypass ends up looking broken. They are listed rather than merged.
    private var siblings: [String] {
        let bundle = String(identity.bundleID)
        guard !identity.isUnattributed else { return [] }
        var candidates = Set(diagnostics.observedApps.map(\.appID))
        candidates.formUnion(policy.document.apps.map(\.appID))
        return candidates
            .filter { $0 != appID && AppIdentity(raw: $0).bundleID == bundle }
            .sorted()
    }

    private var observed: [ObservedDestination] {
        let decided = Set(appPolicy.rules.map(\.value))
        // "Observed" is only what no rule has spoken for yet.
        return (diagnostics.observedApp(appID)?.destinations.values ?? [:].values)
            .filter { !decided.contains($0.host) }
            .sorted { $0.lastSeen > $1.lastSeen }
    }

    /// What this app has moved, or zero when nothing has been recorded for it yet.
    private var traffic: (inbound: UInt64, outbound: UInt64) {
        let app = diagnostics.observedApp(appID)
        return (app?.bytesInbound ?? 0, app?.bytesOutbound ?? 0)
    }

    var body: some View {
        List {
            Section {
                LabeledContent("Received") {
                    Text(DiagnosticsModel.bytes(traffic.inbound)).monospacedDigit()
                }
                LabeledContent("Sent") {
                    Text(DiagnosticsModel.bytes(traffic.outbound)).monospacedDigit()
                }
                LabeledContent("Counting since") {
                    Text(diagnostics.countingWindowLabel)
                        .foregroundStyle(Theme.textSecondary)
                }
            } header: {
                Text("Traffic")
            } footer: {
                if isBypassed {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Frozen at what this app had moved before bypass was switched on.")
                            .foregroundStyle(Theme.warning)
                        Text("A bypassed flow is allowed before anything is inspected, so no bytes "
                             + "are attributed to it and this app's real usage is now unknown.")
                    }
                } else {
                    // Someone comparing this against Settings > Cellular will find it low, and the
                    // reason is not obvious: iOS reports a flow's byte counts once, when the flow
                    // closes. Say so here rather than let the gap look like a bug.
                    Text("This app's share of Reported bytes in/out in Settings, counted from "
                         + "closed flows only — iOS reports a connection's byte totals when it "
                         + "ends, so one that is still open contributes nothing yet, and a "
                         + "long-lived one can read zero for hours.\n\nCleared for every app at "
                         + "once by Reset counters in Settings; there is no per-app reset, because "
                         + "these totals and that counter have to stay comparable.")
                }
            }
            .icebergRows()

            Section {
                Toggle("Bypass all filters", isOn: Binding(
                    get: { isBypassed },
                    set: { policy.setBypass($0, for: appID) }
                ))
                .disabled(!canBypass)
                if isBypassed, let since = appPolicy.bypassSince {
                    LabeledContent("Bypassed since") {
                        Text(since.formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(Theme.textSecondary)
                    }
                }
            } header: {
                Text("Bypass")
            } footer: {
                if !canBypass {
                    Text("Flows that arrive with no source app cannot be bypassed. There is no "
                         + "identifier to match, and exempting everything unattributable would "
                         + "defeat the default-deny rule.")
                } else if isBypassed {
                    // Two Texts rather than one: `Text` only parses markdown in a literal, so
                    // emphasis inside a concatenated string would render as literal asterisks.
                    VStack(alignment: .leading, spacing: 4) {
                        Text("No destinations are recorded while this is on.")
                            .foregroundStyle(Theme.warning)
                        Text("This app is invisible to Samaritan. Its flows are allowed the moment "
                             + "they arrive, before anything is inspected — no counters move and "
                             + "nothing appears in Recent. The rules below, the global lists and "
                             + "Allow all are all ignored. The destinations listed further down are "
                             + "history from before bypass was switched on.")
                    }
                } else {
                    Text("Bypass exempts this app from Samaritan entirely — it is not a stronger "
                         + "Allow all. Allow all still watches the app and still lets a deny list "
                         + "override it; bypass records nothing and can be overridden by nothing.")
                }
            }
            .icebergRows()

            Section {
                Toggle("Allow all", isOn: Binding(
                    get: { appPolicy.blanket == .allowAll },
                    set: { policy.setBlanket($0 ? .allowAll : .denyAll, for: appID) }
                ))
                .disabled(isBypassed)
            } header: {
                Text(identity.displayBundleID)
            } footer: {
                Text("Allow all permits everything this app is not specifically denied — by its own "
                     + "deny list or a global one. Off, it is denied everything not specifically "
                     + "allowed. Either way the lists below and the global lists win.")
            }
            .icebergRows()

            if !siblings.isEmpty {
                Section {
                    ForEach(siblings, id: \.self) { sibling in
                        HStack {
                            Text(sibling)
                                .font(.system(.caption, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.head)
                            Spacer()
                            if policy.document[sibling]?.bypass == true {
                                Text("bypassed").font(.caption2).foregroundStyle(Theme.warning)
                            } else if isBypassed {
                                Button("Bypass too") { policy.setBypass(true, for: sibling) }
                                    .font(.caption)
                            }
                        }
                    }
                } header: {
                    Text("Same bundle, other identifiers")
                } footer: {
                    Text("Rules are keyed on the whole identifier the flow carries, so these are "
                         + "separate apps as far as the filter is concerned. Extensions, helper "
                         + "processes and re-signed builds all land here. Bypassing this row does "
                         + "not bypass them.")
                }
                .icebergRows()
            }

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
                        DestinationRow(destination: destination, staleSince: appPolicy.bypassSince)
                    }
                    .disabled(isBypassed)
                }
            } header: {
                Text(isBypassed ? "Observed (\(observed.count)) — stale"
                                : "Observed (\(observed.count))")
            } footer: {
                if isBypassed {
                    Text("Frozen. Nothing has been recorded for this app since bypass was switched "
                         + "on, and nothing will be until it is switched off. What is here is kept "
                         + "rather than deleted — it is still the truth about what the app did "
                         + "before.")
                } else {
                    Text("Destinations this app asked for that no rule decides. Under deny-all they "
                         + "were dropped. Tap one to allow or deny it.")
                }
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
    /// When bypass was switched on, or `nil` if it is off. Everything here predates it.
    var staleSince: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(destination.host)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(staleSince == nil ? Theme.textPrimary : Theme.textSecondary)
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
            if let staleSince {
                let when = staleSince.formatted(date: .abbreviated, time: .shortened)
                Text("stale — bypassed \(when)")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.warning)
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
