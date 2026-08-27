import Foundation
import Observation
import OSLog

/// Reads both providers' ring buffers and merges them for display.
///
/// Polling, not push. There is no supported way for a content-filter extension to wake the
/// containing app, so the app polls the shared container while it is in the foreground.
@Observable
@MainActor
final class DiagnosticsModel {

    private(set) var snapshot = DiagnosticsStore.Snapshot()
    /// Kept per writer, not just merged: the data provider and the control provider turned out to
    /// have very different filesystem privileges, so "which ring has records" is diagnostic.
    private(set) var perWriter: [SharedContainer.Writer: DiagnosticsStore.Snapshot] = [:]
    private(set) var interfaces: [NetworkInterfaces.Interface] = []
    private(set) var containerAvailable = SharedContainer.containerURL != nil
    var configuration = SpikeConfiguration.load()
    private(set) var configurationError: String?

    /// Result of the built-in traffic generator, so the drop test can be run without leaving the app.
    private(set) var probeResults: [String] = []

    private var stores: [SharedContainer.Writer: DiagnosticsStore] = [:]
    private var timer: Timer?

    init() {
        for writer in SharedContainer.Writer.allCases {
            stores[writer] = DiagnosticsStore(writer: writer)
        }
        refresh()
    }

    var appGroupIdentifier: String { SharedContainer.appGroupIdentifier }

    /// Only routable tunnel addresses count. iOS always has a dozen `utun*` interfaces up with
    /// `fe80::` addresses; treating those as "VPN active" made the flag meaningless.
    var tunnelInterfaces: [NetworkInterfaces.Interface] {
        interfaces.filter(\.isRoutableTunnelAddress)
    }

    var isVPNActive: Bool { !tunnelInterfaces.isEmpty }

    /// Everything except the permanent `fe80::` clutter on system tunnel interfaces.
    var displayInterfaces: [NetworkInterfaces.Interface] {
        interfaces.filter { !($0.isTunnel && $0.isLinkLocal) }
    }

    // MARK: - Polling

    func startPolling() {
        guard timer == nil else { return }
        let timer = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stopPolling() {
        timer?.invalidate()
        timer = nil
    }

    func refresh() {
        var merged = DiagnosticsStore.Snapshot()
        var byWriter: [SharedContainer.Writer: DiagnosticsStore.Snapshot] = [:]
        for writer in SharedContainer.Writer.allCases {
            guard let store = stores[writer] else { continue }
            let single = store.snapshot(limit: 300)
            byWriter[writer] = single
            merged = merged.merged(with: single)
        }
        perWriter = byWriter
        snapshot = merged
        interfaces = NetworkInterfaces.current().filter { $0.isUp }
    }

    func resetCounters() {
        for store in stores.values { store.reset() }
        probeResults.removeAll()
        refresh()
    }

    // MARK: - Configuration

    func saveConfiguration() {
        do {
            try configuration.save()
            configurationError = nil
            Log.app.log("configuration saved")
        } catch {
            configurationError = error.localizedDescription
            Log.app.error("configuration save failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    func resetConfiguration() {
        configuration = .default
        saveConfiguration()
    }

    // MARK: - Traffic generator

    /// Issues one request to a host that should be dropped and one to a host that should be
    /// allowed, so the drop test is a single tap. Both use plain HTTP where possible to avoid HSTS
    /// upgrades and cached TLS connections confusing the result.
    func runProbe() async {
        probeResults = ["running…"]
        var results: [String] = []
        let targets: [(label: String, url: String)] = [
            ("BLOCKED suffix", "http://neverssl.com/"),
            ("control       ", "http://captive.apple.com/hotspot-detect.html"),
            ("control       ", "https://www.google.com/generate_204"),
        ]
        for target in targets {
            guard let url = URL(string: target.url) else { continue }
            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.timeoutInterval = 8
            let started = Date()
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                let code = (response as? HTTPURLResponse)?.statusCode ?? -1
                results.append("\(target.label) \(url.host ?? "") → HTTP \(code), \(data.count) bytes, \(Self.ms(since: started))")
            } catch {
                results.append("\(target.label) \(url.host ?? "") → \((error as NSError).code) \(error.localizedDescription), \(Self.ms(since: started))")
            }
        }
        probeResults = results
    }

    private static func ms(since date: Date) -> String {
        String(format: "%.0fms", Date().timeIntervalSince(date) * 1000)
    }

    // MARK: - Export

    /// Everything needed to report a milestone-1 result, as one pasteable block.
    func diagnosticsText() -> String {
        var lines: [String] = []
        lines.append("# Samaritan diagnostics \(Date().formatted(.iso8601))")
        lines.append("appGroup=\(appGroupIdentifier) container=\(containerAvailable)")
        lines.append("")
        lines.append("## Ring status")
        for writer in SharedContainer.Writer.allCases {
            let count = perWriter[writer]?.totalWritten ?? 0
            lines.append("\(writer.rawValue).ring records=\(count)")
        }
        lines.append("")
        lines.append("## Counters")
        for counter in DiagnosticsStore.Counter.allCases {
            lines.append("\(counter) = \(snapshot[counter])")
        }
        lines.append("")
        lines.append("## Interfaces")
        for interface in interfaces {
            let tag = interface.isRoutableTunnelAddress ? "  [TUNNEL]"
                    : interface.isTunnel ? "  [tunnel/link-local]" : ""
            lines.append("\(interface.name) \(interface.familyName) \(interface.address)\(tag)")
        }
        lines.append("")
        lines.append("## Probe")
        lines.append(contentsOf: probeResults)
        lines.append("")
        lines.append("## Recent flows (newest first)")
        for record in snapshot.records.prefix(150) {
            lines.append("""
                \(record.timestamp.formatted(date: .omitted, time: .standard)) \
                \(record.origin == .dataProvider ? "D" : "C") \
                \(record.verdict.label) \
                app=\(record.appDescription) \
                remote=\(record.remoteDescription) addr=\(record.remoteAddress) \
                host=\(record.remoteHostname.isEmpty ? "-" : record.remoteHostname) \
                local=\(record.localDescription) \
                \(record.socketFamilyName)/\(record.socketProtocolName) \
                path=[\(record.pathFlags.summary)] rule=\(record.matchedRule.isEmpty ? "-" : record.matchedRule) \
                in=\(record.bytesInbound) out=\(record.bytesOutbound) \(record.decisionNanos / 1000)us
                """)
        }
        return lines.joined(separator: "\n")
    }
}
