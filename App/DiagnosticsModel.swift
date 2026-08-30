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
    var configuration = SpikeConfiguration.load() {
        didSet {
            // Toggles and the deny-mode picker are discrete, unambiguous actions, so they persist
            // the moment they change; leaving them pending behind an Apply button is what caused a
            // whole device run to be spent measuring the default configuration.
            //
            // Text fields deliberately still need Apply. Saving them per keystroke would push
            // half-typed values to the providers, and a partial *substring* rule such as "g"
            // matches almost every hostname.
            guard configuration.denyMode != oldValue.denyMode
                    || configuration.controlProbeEnabled != oldValue.controlProbeEnabled
                    || configuration.requestReports != oldValue.requestReports
                    || configuration.logEveryFlow != oldValue.logEveryFlow
            else { return }
            saveConfiguration()
        }
    }
    private(set) var configurationError: String?

    /// When the providers' configuration file was last written, or `nil` if it does not exist.
    /// `nil` means both providers are running on compiled-in defaults regardless of what the UI shows.
    var configurationWrittenAt: Date? {
        guard let url = SharedContainer.configurationURL,
              let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        else { return nil }
        return attributes[.modificationDate] as? Date
    }

    /// Result of the built-in traffic generator, so the drop test can be run without leaving the app.
    private(set) var probeResults: [String] = []

    /// Per-app history, written by the control provider. Read-only here except for `clear`.
    private(set) var observedApps: [ObservedApp] = []
    private let observed = ObservedStore()

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
        observed?.reload()
        observedApps = observed?.snapshot() ?? []
        interfaces = NetworkInterfaces.current().filter { $0.isUp }
    }

    func resetCounters() {
        for store in stores.values { store.reset() }
        probeResults.removeAll()
        refresh()
    }

    func clearObserved() {
        observed?.clear()
        refresh()
    }

    func observedApp(_ appID: String) -> ObservedApp? {
        observedApps.first { $0.appID == appID }
    }

    // MARK: - Configuration

    func saveConfiguration() {
        do {
            try configuration.save()
            Log.app.log("configuration written deny=\(self.configuration.denyMode.rawValue, privacy: .public)")
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
            let outcome: ProbeOutcome
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                outcome = .reached(status: (response as? HTTPURLResponse)?.statusCode ?? -1,
                                   bytes: data.count)
            } catch {
                outcome = ProbeOutcome.classify(error)
            }
            results.append("\(target.label) \(url.host ?? "") → \(outcome.label), \(Self.ms(since: started))")
            Log.app.log("""
                PROBERESULT target=\(target.label.trimmingCharacters(in: .whitespaces), privacy: .public) \
                host=\(url.host ?? "?", privacy: .public) outcome=\(outcome.label, privacy: .public)
                """)
        }
        probeResults = results
    }

    /// Fires `count` concurrent requests at a host the rules deny, to see whether the escalation
    /// path holds up when it is the common case rather than the rare one.
    ///
    /// Every one of these becomes a `.needRules()` round trip under `denyMode == .escalate`. The
    /// numbers that matter are not here but in the device log: `tools/escalation-report.py` joins
    /// the data provider's ESCALATE lines to the control provider's CTLRECV/CTLDONE lines and
    /// reports how many never arrived.
    func runStressTest(count: Int = 40) async {
        let host = configuration.blockedHostSuffixes.first
            ?? configuration.blockedHostSubstrings.first
            ?? "neverssl.com"
        probeResults = ["stress: \(count) concurrent requests to \(host)…"]

        let started = Date()
        let outcomes = await withTaskGroup(of: ProbeOutcome.self, returning: [ProbeOutcome].self) { group in
            for index in 0..<count {
                group.addTask {
                    // Distinct paths so nothing is served from cache or a reused connection.
                    guard let url = URL(string: "http://\(host)/?samaritan-stress=\(index)") else {
                        return .inconclusive(reason: "bad URL")
                    }
                    var request = URLRequest(url: url)
                    request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
                    request.timeoutInterval = 10
                    do {
                        let (data, response) = try await URLSession.shared.data(for: request)
                        return .reached(status: (response as? HTTPURLResponse)?.statusCode ?? -1,
                                        bytes: data.count)
                    } catch {
                        return ProbeOutcome.classify(error)
                    }
                }
            }
            var results: [ProbeOutcome] = []
            for await outcome in group { results.append(outcome) }
            return results
        }

        let blocked = outcomes.filter(\.provesFiltering).count
        let inconclusive = outcomes.filter(\.isInconclusive).count
        let reached = count - blocked - inconclusive

        var lines = [
            "stress \(count)× \(host) in \(Self.ms(since: started))",
            "blocked: \(blocked)   reached: \(reached)   inconclusive: \(inconclusive)",
        ]
        if inconclusive > 0 {
            // Never claim a pass off requests that never reached the wire — that is exactly how the
            // neverssl.com ATS false positive slipped through.
            lines.append("INVALID — \(inconclusive) never created a flow, so nothing was tested")
            if let reason = outcomes.first(where: \.isInconclusive) { lines.append(reason.label) }
        } else if reached > 0 {
            lines.append("LEAK — \(reached) got through; escalation did not hold")
        } else {
            lines.append("PASS — every escalated flow was dropped")
        }
        lines.append("control handled: \(snapshot[.controlFlowsHandled]), drops issued: \(snapshot[.controlDropsIssued])")
        probeResults = lines

        // Also to OSLog: the harness's own conclusion belongs in the same capture as the evidence,
        // otherwise the log proves 41 drop verdicts were issued but not that 41 connections failed.
        let verdict = inconclusive > 0 ? "INVALID" : (reached > 0 ? "LEAK" : "PASS")
        Log.app.log("""
            STRESSRESULT host=\(host, privacy: .public) count=\(count) \
            blocked=\(blocked) reached=\(reached) inconclusive=\(inconclusive) \
            verdict=\(verdict, privacy: .public)
            """)
        refresh()
    }

    /// "6 Aug 14:02 (30.2 h)", or a prompt when the ring predates the epoch field.
    var countingWindowLabel: String {
        guard let since = snapshot.countersSince else {
            return "unknown — reset counters to start measuring"
        }
        let hours = Date().timeIntervalSince(since) / 3600
        let stamp = since.formatted(date: .abbreviated, time: .shortened)
        return hours < 1 ? "\(stamp) (\(Int(hours * 60)) min)"
                         : String(format: "%@ (%.1f h)", stamp, hours)
    }

    /// Just the span, for a sentence that already says what is being discarded.
    var countingDurationLabel: String {
        guard let seconds = snapshot.countingInterval else { return "An unknown amount" }
        let hours = seconds / 3600
        return hours < 1 ? "\(Int(seconds / 60)) minutes"
                         : String(format: "%.1f hours", hours)
    }

    /// Byte counters reach the tens of gigabytes, where a raw digit string cannot be read at a
    /// glance or checked against anything.
    static func bytes(_ value: UInt64) -> String {
        ByteCountFormatStyle(style: .file).format(Int64(clamping: value))
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
        lines.append("counting since \(snapshot.countersSince?.formatted(.iso8601) ?? "unknown") "
                     + "(\(countingDurationLabel))")
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
