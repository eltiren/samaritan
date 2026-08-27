import SwiftUI
import UIKit

/// Diagnostic UI only — deliberately unstyled. Its job is to make the milestone-1 questions
/// answerable at a glance on a physical device, including while NordVPN is connected.
struct DiagnosticsView: View {
    @Bindable var filter: FilterController
    @Bindable var diagnostics: DiagnosticsModel

    @State private var showingExport = false

    var body: some View {
        NavigationStack {
            List {
                statusSection
                vpnSection
                ringsSection
                countersSection
                probeSection
                configurationSection
                flowsSection
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Samaritan")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Copy diagnostics") {
                            UIPasteboard.general.string = diagnostics.diagnosticsText()
                        }
                        Button("Reset counters", role: .destructive) { diagnostics.resetCounters() }
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
                .foregroundStyle(diagnostics.containerAvailable ? Color.primary : Color.red)

            if let detail = filter.lastErrorDetail {
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
        }
    }

    private var vpnSection: some View {
        Section {
            LabeledContent("Tunnel interface", value: diagnostics.isVPNActive ? "PRESENT" : "none")
                .foregroundStyle(diagnostics.isVPNActive ? Color.green : Color.primary)
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
                        .foregroundStyle(written == 0 ? Color.orange : Color.primary)
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
        Section("Counters") {
            counter("Flows observed", .flowsObserved)
            counter("Allowed", .flowsAllowed)
            counter("Dropped", .flowsDropped)
            counter("needRules answered", .flowsNeedRules)
            counter("Control provider invoked", .controlFlowsHandled)
            counter("Reports → data provider", .reportsData)
            counter("Reports → control provider", .reportsControl)
            counter("Reported bytes in", .reportedBytesInbound)
            counter("Reported bytes out", .reportedBytesOutbound)
            counter("handleRulesChanged", .rulesChangedEvents)
            counter("Filter starts", .filterStarts)
            counter("Filter stops", .filterStops)
            counter("Ring write failures", .writeFailures)
        }
    }

    private func counter(_ title: String, _ counter: DiagnosticsStore.Counter) -> some View {
        LabeledContent(title, value: String(diagnostics.snapshot[counter]))
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

            Button("Apply") { diagnostics.saveConfiguration() }
            Button("Restore defaults") { diagnostics.resetConfiguration() }

            if let error = diagnostics.configurationError {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
        } header: {
            Text("Spike configuration")
        } footer: {
            Text("Written to the App Group container. The data provider re-reads it within a couple "
                 + "of seconds — no need to toggle the filter.")
        }
    }

    private var flowsSection: some View {
        Section("Recent flows (\(diagnostics.snapshot.records.count))") {
            if diagnostics.snapshot.records.isEmpty {
                Text("No flows recorded yet.").foregroundStyle(.secondary)
            }
            ForEach(diagnostics.snapshot.records.prefix(100)) { record in
                FlowRow(record: record)
            }
        }
    }

    private func splitList(_ text: String) -> [String] {
        text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}

private struct FlowRow: View {
    let record: FlowRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(record.verdict.label)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(record.verdict.isDrop ? Color.red : Color.secondary)
                Text(record.origin == .dataProvider ? "D" : "C")
                    .font(.caption2).foregroundStyle(.secondary)
                Text(record.remoteDescription)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)
                Spacer()
                Text(record.timestamp, format: .dateTime.hour().minute().second())
                    .font(.caption2).foregroundStyle(.secondary)
            }
            Text(record.appDescription)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Text(detail)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .textSelection(.enabled)
    }

    private var detail: String {
        var parts = ["\(record.socketFamilyName)/\(record.socketProtocolName)"]
        if !record.localDescription.isEmpty { parts.append("local=\(record.localDescription)") }
        parts.append("path=[\(record.pathFlags.summary)]")
        if !record.matchedRule.isEmpty { parts.append("rule=\(record.matchedRule)") }
        if record.bytesInbound > 0 || record.bytesOutbound > 0 {
            parts.append("in=\(record.bytesInbound) out=\(record.bytesOutbound)")
        }
        parts.append("\(record.decisionNanos / 1000)us")
        return parts.joined(separator: " ")
    }
}
