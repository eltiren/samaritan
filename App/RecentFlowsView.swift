import SwiftUI

/// The raw flow log from the diagnostics rings — newest first, bounded, and shared across apps.
///
/// Deliberately not the source for per-app history: the ring is 2048 slots for the whole device, so
/// one app retrying can evict everything else. `ObservedStore` keeps that per app instead.
struct RecentFlowsView: View {
    @Bindable var diagnostics: DiagnosticsModel

    var body: some View {
        List {
            Section {
                if diagnostics.snapshot.records.isEmpty {
                    Text("No flows recorded yet.").foregroundStyle(Theme.textSecondary)
                }
                ForEach(diagnostics.snapshot.records.prefix(200)) { record in
                    FlowRow(record: record)
                }
            } header: {
                Text("\(diagnostics.snapshot.records.count) recent")
            } footer: {
                Text("Straight from the providers' ring buffers, shared across every app and "
                     + "overwritten oldest-first. Per-app history lives on each app's screen.")
            }
            .icebergRows()
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.background)
        .foregroundStyle(Theme.textPrimary)
        .navigationTitle("Recent")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct FlowRow: View {
    let record: FlowRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(record.verdict.label)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(Theme.color(for: record.verdict))
                Text(record.origin == .dataProvider ? "D" : "C")
                    .font(.caption2).foregroundStyle(Theme.textSecondary)
                Text(record.remoteDescription)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)
                Spacer()
                Text(record.timestamp, format: .dateTime.hour().minute().second())
                    .font(.caption2).foregroundStyle(Theme.textSecondary)
            }
            Text(record.appDescription)
                .font(.caption2)
                .foregroundStyle(Theme.textSecondary)
                .lineLimit(1)
            Text(detail)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
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
