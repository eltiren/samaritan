import SwiftUI

/// The two global tiers: hand-written rules, and subscriptions.
///
/// Both sit above every app's blanket setting and below any app's own rules, so a rule here reaches
/// every app — including ones never triaged — but a per-app rule still overrides it in either
/// direction.
struct GlobalListsView: View {
    @Bindable var policy: PolicyStore

    @State private var draftValue = ""
    @State private var draftKind: PolicyRule.Kind = .domainSuffix
    @State private var draftAction: RuleAction = .deny
    @State private var showingAddList = false

    var body: some View {
        List {
            addRuleSection
            userRulesSection
            subscriptionsSection
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.background)
        .foregroundStyle(Theme.textPrimary)
        .navigationTitle("Global")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showingAddList) {
            AddWebListView(policy: policy)
        }
    }

    private var addRuleSection: some View {
        Section {
            TextField("example.com or 8.8.8.0/24", text: $draftValue)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.system(.callout, design: .monospaced))

            Picker("Kind", selection: $draftKind) {
                Text("Exact").tag(PolicyRule.Kind.domainExact)
                Text("Subdomains").tag(PolicyRule.Kind.domainSuffix)
                Text("Contains").tag(PolicyRule.Kind.domainSubstring)
                Text("Address").tag(PolicyRule.Kind.address)
            }
            Picker("Action", selection: $draftAction) {
                Text("Allow").tag(RuleAction.allow)
                Text("Deny").tag(RuleAction.deny)
            }
            .pickerStyle(.segmented)

            let rule = PolicyRule(kind: draftKind, value: draftValue, action: draftAction)
            Button("Add rule") {
                policy.addRule(rule, toApp: nil)
                draftValue = ""
            }
            .disabled(!rule.isValid)
        } header: {
            Text("New global rule")
        } footer: {
            Text("Subdomains covers a.example.com but never example.com — matching the domain "
                 + "itself takes a second Exact rule. Contains matches anywhere in the hostname, "
                 + "which is the only kind that catches googleapis.com from a rule about google.")
        }
        .icebergRows()
    }

    private var userRulesSection: some View {
        Section("Global rules (\(policy.document.userRules.count))") {
            if policy.document.userRules.isEmpty {
                Text("None.").foregroundStyle(Theme.textSecondary)
            }
            ForEach(policy.document.userRules, id: \.self) { rule in
                HStack {
                    Text(rule.action == .allow ? "allow" : "deny")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(rule.action == .allow ? Theme.allow : Theme.deny)
                        .frame(width: 44, alignment: .leading)
                    Text(rule.displayValue)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                    Spacer()
                    Button("Remove") { policy.removeUserRule(rule) }
                        .font(.caption)
                        .foregroundStyle(Theme.deny)
                }
            }
        }
        .icebergRows()
    }

    private var subscriptionsSection: some View {
        Section {
            Button("Add subscription…") { showingAddList = true }
            if policy.document.webLists.isEmpty {
                Text("None.").foregroundStyle(Theme.textSecondary)
            }
            ForEach(policy.document.webLists) { list in
                WebListRow(list: list, policy: policy)
            }
        } header: {
            Text("Subscriptions")
        } footer: {
            Text("Entries are not editable; disable or remove the whole subscription instead. "
                 + "A bare domain in a fetched list covers the domain and its subdomains, which is "
                 + "what blocklist authors mean by it — unlike a rule you write by hand.")
        }
        .icebergRows()
    }
}

private struct WebListRow: View {
    let list: WebList
    @Bindable var policy: PolicyStore
    @State private var error: String?
    @State private var isRefreshing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(list.name).font(.callout).lineLimit(1)
                Spacer()
                Text(list.action == .allow ? "allow" : "deny")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(list.action == .allow ? Theme.allow : Theme.deny)
            }
            Text("\(list.lines.count) entries · fetched \(list.lastFetchedAt, format: .dateTime.hour().minute())")
                .font(.caption2)
                .foregroundStyle(Theme.textSecondary)
            if let error {
                Text(error).font(.caption2).foregroundStyle(Theme.warning)
            }
            HStack(spacing: 16) {
                Toggle("Enabled", isOn: Binding(
                    get: { list.isEnabled },
                    set: { policy.setEnabled($0, for: list) }
                ))
                .labelsHidden()
                Button(isRefreshing ? "Refreshing…" : "Refresh") {
                    Task {
                        isRefreshing = true
                        error = await policy.refresh(list)
                        isRefreshing = false
                    }
                }
                .font(.caption)
                .disabled(isRefreshing)
                Button("Remove") { policy.remove(list) }
                    .font(.caption)
                    .foregroundStyle(Theme.deny)
            }
        }
    }
}

/// The add-subscription flow. It cannot be completed until the URL fetches and parses, so a
/// subscription that has never succeeded can never exist.
private struct AddWebListView: View {
    @Bindable var policy: PolicyStore
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var urlText = ""
    @State private var action: RuleAction = .deny
    @State private var error: String?
    @State private var isFetching = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    TextField("Name (optional)", text: $name)
                    TextField("https://example.com/list.txt", text: $urlText)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .font(.system(.callout, design: .monospaced))
                    Picker("Action", selection: $action) {
                        Text("Allow").tag(RuleAction.allow)
                        Text("Deny").tag(RuleAction.deny)
                    }
                    .pickerStyle(.segmented)
                } footer: {
                    Text("One entry per line; # starts a comment. Domains, *.domains, addresses, "
                         + "CIDR and hosts-file format are all accepted. The list must fetch and "
                         + "parse before it can be added.")
                }
                .icebergRows()

                if let error {
                    Section { Text(error).foregroundStyle(Theme.deny) }.icebergRows()
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.background)
            .navigationTitle("Add subscription")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(isFetching ? "Fetching…" : "Add") { add() }
                        .disabled(isFetching || URL(string: urlText)?.host == nil)
                }
            }
        }
    }

    private func add() {
        guard let url = URL(string: urlText), url.host != nil else { return }
        Task {
            isFetching = true
            error = nil
            do {
                try await policy.addWebList(name: name, url: url, action: action)
                dismiss()
            } catch let failure as WebListParser.Failure {
                error = failure.message
            } catch {
                self.error = error.localizedDescription
            }
            isFetching = false
        }
    }
}
