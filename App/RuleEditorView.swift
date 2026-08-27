import SwiftUI

/// The allow/deny popover: pick an action, a target from the specificity chain, and a scope.
struct RuleEditorView: View {
    let draft: RuleDraft
    @Bindable var policy: PolicyStore

    @Environment(\.dismiss) private var dismiss
    @State private var action: RuleAction = .deny
    @State private var selection = 0
    @State private var scopeIsGlobal = false

    /// For a hostname, the chain from the requirement: the exact name, then one subdomain rule per
    /// parent as labels drop from the left. For an address, the four CIDR presets.
    private var options: [PolicyRule] {
        if draft.isAddress {
            guard let prefix = IPPrefix(draft.target) else { return [] }
            return IPPrefix.presets(for: prefix).map {
                PolicyRule(kind: .address, value: $0.description, action: action)
            }
        }
        let chain = HostNormaliser.specificityChain(for: draft.target)
        var result = (chain[.domainExact] ?? []).map {
            PolicyRule(kind: .domainExact, value: $0, action: action)
        }
        result += (chain[.domainSuffix] ?? []).map {
            PolicyRule(kind: .domainSuffix, value: $0, action: action)
        }
        return result
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("Action", selection: $action) {
                        Text("Allow").tag(RuleAction.allow)
                        Text("Deny").tag(RuleAction.deny)
                    }
                    .pickerStyle(.segmented)
                }
                .icebergRows()

                Section {
                    ForEach(Array(options.enumerated()), id: \.offset) { index, rule in
                        Button {
                            selection = index
                        } label: {
                            HStack {
                                Text(rule.displayValue)
                                    .font(.system(.callout, design: .monospaced))
                                    .foregroundStyle(Theme.textPrimary)
                                Spacer()
                                if index == selection {
                                    Image(systemName: "checkmark").foregroundStyle(Theme.accent)
                                }
                            }
                        }
                    }
                } header: {
                    Text("Target")
                } footer: {
                    Text(draft.isAddress
                         ? "Stored as a CIDR prefix. The IPv4 forms are also written 8.8.8.x style."
                         : "A *.x rule covers subdomains only, never the domain itself — matching "
                           + "example.com as well takes a second rule.")
                }
                .icebergRows()

                if draft.appID != nil {
                    Section {
                        Picker("Scope", selection: $scopeIsGlobal) {
                            Text("This app").tag(false)
                            Text("All apps").tag(true)
                        }
                        .pickerStyle(.segmented)
                    } footer: {
                        Text("A per-app rule beats the global lists in both directions — it can "
                             + "allow what a list denies, and deny what a list allows.")
                    }
                    .icebergRows()
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.background)
            .foregroundStyle(Theme.textPrimary)
            .navigationTitle(draft.target)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        guard selection < options.count else { return }
                        policy.addRule(options[selection],
                                       toApp: scopeIsGlobal ? nil : draft.appID)
                        dismiss()
                    }
                    .disabled(options.isEmpty)
                }
            }
        }
    }
}
