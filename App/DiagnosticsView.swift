import SwiftUI
import UIKit

/// Diagnostic UI only — deliberately unstyled. Its job is to make the milestone-1 questions
/// answerable at a glance on a physical device, including while NordVPN is connected.
struct DiagnosticsView: View {
    @Bindable var filter: FilterController
    @Bindable var diagnostics: DiagnosticsModel
    @Bindable var policy: PolicyStore

    @State private var showingExport = false
    @State private var isConfirmingReset = false

    var body: some View {
        NavigationStack {
            List {
                // `.listRowBackground` has to be attached per Section — applied to the List it
                // never reaches rows nested inside one, which left every row on the system fill.
                statusSection.icebergRows()
                policySection.icebergRows()
                vpnSection.icebergRows()
                ringsSection.icebergRows()
                countersSection.icebergRows()
                probeSection.icebergRows()
                configurationSection.icebergRows()

            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.background)
            .foregroundStyle(Theme.textPrimary)
            .tint(Theme.accent)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Copy diagnostics") {
                            UIPasteboard.general.string = diagnostics.diagnosticsText()
                        }
                        Button("Clear observed history", role: .destructive) { diagnostics.clearObserved() }
                        Button("Remove filter configuration", role: .destructive) {
                            Task { await filter.removeConfiguration() }
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
        }
    }

    // MARK: - Sections

    private var statusSection: some View {
        Section("Filter") {
            LabeledContent("State", value: filter.status.label)
            Toggle("Enabled", isOn: Binding(
                get: { filter.isEnabled },
                set: { newValue in Task { await filter.setEnabled(newValue) } }
            ))
            .disabled(filter.isBusy)

            LabeledContent("App Group", value: diagnostics.appGroupIdentifier.isEmpty
                           ? "MISSING" : diagnostics.appGroupIdentifier)
            LabeledContent("Shared container", value: diagnostics.containerAvailable ? "available" : "UNAVAILABLE")
                .foregroundStyle(diagnostics.containerAvailable ? Theme.textPrimary : Theme.deny)

            if let detail = filter.lastErrorDetail {
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(Theme.deny)
                    .textSelection(.enabled)
            }
        }
    }


    private var policySection: some View {
        Section {
            LabeledContent("Generation", value: String(policy.stats.generation))
            LabeledContent("Apps", value: String(policy.stats.apps))
            LabeledContent("Domain rules", value: String(policy.stats.domainRules))
            LabeledContent("Address trie nodes", value: String(policy.stats.addressNodes))
            LabeledContent("Blob size") {
                Text(policy.lastCompiledSize == 0 ? "not published"
                     : "\(policy.lastCompiledSize) bytes")
                    .foregroundStyle(policy.lastCompiledSize == 0 ? Theme.warning : Theme.textPrimary)
            }

            Button("Seed apps from observed flows") {
                let observed = Array(Set(diagnostics.snapshot.records.map(\.sourceApp)))
                    .filter { !$0.isEmpty }
                policy.seed(fromObservedApps: observed)
            }
            Button("Publish policy") { policy.publish() }
            Button("Reset policy", role: .destructive) { policy.reset() }

            if let error = policy.lastError {
                Text(error).font(.footnote).foregroundStyle(Theme.deny)
            }
        } header: {
            Text("Policy engine")
        } footer: {
            Text("The app compiles rules into policy.bin; the providers mmap it read-only and pick "
                 + "up a new generation within a couple of seconds. Until a policy is published the "
                 + "providers fall back to the spike rule set, so behaviour never changes silently "
                 + "just because the file is missing.")
        }
    }

    private var vpnSection: some View {
        Section {
            LabeledContent("Tunnel interface", value: diagnostics.isVPNActive ? "PRESENT" : "none")
                .foregroundStyle(diagnostics.isVPNActive ? Theme.allow : Theme.textPrimary)
            ForEach(diagnostics.displayInterfaces, id: \.self) { interface in
                LabeledContent {
                    Text(interface.address).font(.system(.caption, design: .monospaced))
                } label: {
                    Text("\(interface.name) · \(interface.familyName)")
                        .fontWeight(interface.isRoutableTunnelAddress ? .semibold : .regular)
                }
            }
        } header: {
            Text("Network path")
        } footer: {
            Text("iOS always runs several utun* interfaces with fe80:: addresses (Wi-Fi Calling, "
                 + "AWDL, Private Relay); those are hidden. A utun* with a ROUTABLE address means a "
                 + "packet tunnel such as NordVPN is up. Compare a flow's local address against it: "
                 + "if they match, the filter is seeing the flow after it entered the tunnel.")
        }
    }

    private var ringsSection: some View {
        Section {
            ForEach(SharedContainer.Writer.allCases, id: \.self) { writer in
                let written = diagnostics.perWriter[writer]?.totalWritten ?? 0
                LabeledContent("\(writer.rawValue).ring") {
                    Text(written == 0 ? "no records" : "\(written) records")
                        .foregroundStyle(written == 0 ? Theme.warning : Theme.textPrimary)
                }
            }
        } header: {
            Text("Provider storage")
        } footer: {
            Text("On this device NEFilterDataProvider was denied write access to the App Group "
                 + "container (EPERM) while NEFilterControlProvider was not. If data.ring stays "
                 + "empty while flows appear in `log stream`, that restriction is still in force "
                 + "and the data provider can only report through OSLog.")
        }
    }

    private var countersSection: some View {
        Section {
            LabeledContent("Counting since") {
                Text(diagnostics.countingWindowLabel)
                    .foregroundStyle(Theme.textSecondary)
            }
            counter("Flows observed", .flowsObserved)
            counter("Allowed", .flowsAllowed)
            counter("Dropped", .flowsDropped)
            counter("needRules answered", .flowsNeedRules)
            counter("Control provider invoked", .controlFlowsHandled)
            counter("Report events → data provider", .reportsData)
            counter("Report events → control provider", .reportsControl)
            byteCounter("Reported bytes in", .reportedBytesInbound)
            byteCounter("Reported bytes out", .reportedBytesOutbound)
            counter("handleRulesChanged", .rulesChangedEvents)
            counter("Filter starts", .filterStarts)
            counter("Filter stops", .filterStops)
            counter("Ring write failures", .writeFailures)
            counter("Policy decisions", .policyDecisions)
            counter("Spike fallback decisions", .spikeFallbackDecisions)

            Button("Reset counters", role: .destructive) { isConfirmingReset = true }
        } header: {
            Text("Counters")
        } footer: {
            Text("Totals since the epoch above, across every flow on the device — system daemons "
                 + "included, not just the apps listed. They survive filter restarts and are only "
                 + "cleared by Reset counters.\n\nA report event is not a flow: iOS delivers one at "
                 + "newFlow and one at flowClosed, so a closed flow contributes two. Only the "
                 + "flowClosed event carries byte counts, so each flow's bytes are added exactly "
                 + "once.\n\nThe two byte figures are broken down per app on the Apps tab, from the "
                 + "same reports. Resetting here resets those too — they are one measurement and "
                 + "have to stay comparable.")
        }
        .confirmationDialog("Reset counters?", isPresented: $isConfirmingReset,
                            titleVisibility: .visible) {
            Button("Reset", role: .destructive) { diagnostics.resetCounters() }
            Button("Cancel", role: .cancel) {}
        } message: {
            // Worth a tap to confirm: the counters are only meaningful as a rate over their
            // window, and resetting throws that window away — a measurement that took a day and a
            // half to accumulate cannot be recovered.
            Text("\(diagnostics.countingDurationLabel) of measurement will be lost. This clears "
                 + "every counter, every app's received/sent totals and the recorded flows in both "
                 + "rings, and restarts the counting window from now.")
        }
    }

    private func counter(_ title: String, _ counter: DiagnosticsStore.Counter) -> some View {
        LabeledContent(title, value: diagnostics.snapshot[counter].formatted(.number))
    }

    /// Bytes three ways: a size to read at a glance, the exact grouped count, and the rate. A total
    /// on its own cannot be sanity-checked; a rate can be held against what the device plausibly
    /// moves in an hour.
    private func byteCounter(_ title: String, _ counter: DiagnosticsStore.Counter) -> some View {
        let value = diagnostics.snapshot[counter]
        return LabeledContent(title) {
            VStack(alignment: .trailing, spacing: 1) {
                Text(DiagnosticsModel.bytes(value))
                Text(rateSuffix(counter).map { "\(value.formatted(.number))  ·  \($0)" }
                     ?? value.formatted(.number))
                    .font(.caption2)
                    .foregroundStyle(Theme.textSecondary)
            }
        }
    }

    private func rateSuffix(_ counter: DiagnosticsStore.Counter) -> String? {
        diagnostics.snapshot.perHour(counter).map { "\(DiagnosticsModel.bytes(UInt64($0)))/h" }
    }

    private var probeSection: some View {
        Section {
            Button("Run drop test") {
                Task { await diagnostics.runProbe() }
            }
            Button("Run escalation stress test (40×)") {
                Task { await diagnostics.runStressTest() }
            }
            Picker("Deny mode", selection: $diagnostics.configuration.denyMode) {
                Text("inline .drop()").tag(SpikeConfiguration.DenyMode.inline)
                Text("escalate .needRules()").tag(SpikeConfiguration.DenyMode.escalate)
            }
            ForEach(diagnostics.probeResults, id: \.self) { line in
                Text(line).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            }
        } header: {
            Text("Traffic generator")
        } footer: {
            Text("Drop test: one blocked host and two control hosts — blocked should fail, controls "
                 + "should succeed. Stress test: 40 concurrent requests at a blocked host, which "
                 + "under escalate mode become 40 needRules round trips. Set the deny mode, tap "
                 + "Apply, then run it, and join the device log with tools/escalation-report.py.")
        }
    }

    private var configurationSection: some View {
        Section {
            TextField("Blocked host suffixes (comma separated)", text: Binding(
                get: { diagnostics.configuration.blockedHostSuffixes.joined(separator: ", ") },
                set: { diagnostics.configuration.blockedHostSuffixes = splitList($0) }
            ))
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()

            TextField("Blocked host substrings (comma separated)", text: Binding(
                get: { diagnostics.configuration.blockedHostSubstrings.joined(separator: ", ") },
                set: { diagnostics.configuration.blockedHostSubstrings = splitList($0) }
            ))
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()

            TextField("Blocked addresses (comma separated)", text: Binding(
                get: { diagnostics.configuration.blockedAddresses.joined(separator: ", ") },
                set: { diagnostics.configuration.blockedAddresses = splitList($0) }
            ))
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()

            Toggle("needRules() probe", isOn: $diagnostics.configuration.controlProbeEnabled)
            Toggle("Request NEFilterReport", isOn: $diagnostics.configuration.requestReports)
            Toggle("Log every flow to OSLog", isOn: $diagnostics.configuration.logEveryFlow)
            Toggle("Log new app identities (IDENT NEW)",
                   isOn: $diagnostics.configuration.logIdentities)

            Button("Apply") { diagnostics.saveConfiguration() }
            Button("Restore defaults") { diagnostics.resetConfiguration() }

            LabeledContent("Config file") {
                if let written = diagnostics.configurationWrittenAt {
                    Text(written, format: .dateTime.hour().minute().second())
                } else {
                    Text("NOT WRITTEN").foregroundStyle(Theme.warning)
                }
            }

            if let error = diagnostics.configurationError {
                Text(error).font(.footnote).foregroundStyle(Theme.deny)
            }
        } header: {
            Text("Spike configuration")
        } footer: {
            Text("Toggles and the deny-mode picker save immediately. Text fields need Apply, because "
                 + "saving per keystroke would push half-typed rules to the providers. Until the "
                 + "config file exists, both providers run on compiled-in defaults — check the "
                 + "device log for `source=compiled-in-default`.")
        }
    }


    private func splitList(_ text: String) -> [String] {
        text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}

extension View {
    func icebergRows() -> some View {
        listRowBackground(Theme.surface)
            .listRowSeparatorTint(Theme.textSecondary.opacity(0.3))
    }
}
