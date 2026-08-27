import Foundation
import NetworkExtension
import OSLog

/// Reached only when `FilterDataProvider` answers `.needRules()`.
///
/// Purpose in milestone 1 is to answer, empirically:
///
/// 1. Is this process actually launched on a current iOS, and how quickly?
/// 2. Does it see the *same* flow metadata as the data provider (same `sourceAppIdentifier`,
///    same endpoint), or more/less?
/// 3. Does `allow(withUpdateRules: true)` reliably produce `handleRulesChanged()` in the data
///    provider — i.e. is this a usable push channel?
/// 4. Does `handleReport(_:)` fire here, there, or both?
///
/// Architectural note carried over from Sift (2018): the control provider is a *separate process*
/// with no shared memory with the data provider. The only channels are the App Group container and
/// the `updateRules` bit on the verdict. Unlike the data provider it is not on the hot path, so it
/// is the correct place for expensive work (network fetches, notifications, database writes).
final class FilterControlProvider: NEFilterControlProvider {

    private var store: DiagnosticsStore?
    private let lock = NSLock()
    /// Flip `updateRules` exactly once so the data provider's `handleRulesChanged()` can be
    /// observed without a rules-change storm.
    private var hasSignalledRulesChange = false
    private var sandboxProbeRan = false

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        Log.flows.log("CONTROL PROVIDER startFilter entered pid=\(getpid())")
        SandboxProbe.run()
        store = DiagnosticsStore(writer: .controlProvider)
        PathObserver.shared.start()
        Log.flows.log("""
            CONTROL PROVIDER startFilter ready container=\(SharedContainer.containerURL != nil, privacy: .public) \
            ring=\(self.store != nil, privacy: .public)
            """)
        store?.increment([.filterStarts: 1])
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Log.control.log("stopFilter reason=\(reason.rawValue, privacy: .public)")
        store?.increment([.filterStops: 1])
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow,
                                completionHandler: @escaping (NEFilterControlVerdict) -> Void) {
        let started = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        runSandboxProbeOnce()
        var record = FlowInspector.record(for: flow, origin: .controlProvider)

        // Paired with the data provider's ESCALATE line by flow id. Both use CLOCK_UPTIME_RAW,
        // which is system-wide monotonic, so the difference is the true cross-process round trip.
        Log.flows.log("CTLRECV id=\(record.flowIdentifier, privacy: .public) t=\(started)")

        let configuration = SpikeConfiguration.load()
        let rules = SpikeRuleSet(configuration: configuration)

        lock.lock()
        let signalRulesChange = !hasSignalledRulesChange
        hasSignalledRulesChange = true
        lock.unlock()

        let verdict: NEFilterControlVerdict
        var counters: [DiagnosticsStore.Counter: UInt64] = [.controlFlowsHandled: 1]

        if let label = rules.matchLabel(hostname: record.remoteHostname, address: record.remoteAddress) {
            record.verdict = .controlDrop
            record.matchedRule = label
            counters[.flowsDropped] = 1
            counters[.controlDropsIssued] = 1
            // Never `withUpdateRules: true` on a drop: under escalate mode this is the common path,
            // and each `true` triggers a handleRulesChanged in the data provider.
            verdict = .drop(withUpdateRules: false)
        } else {
            record.verdict = .controlAllow
            record.matchedRule = signalRulesChange ? "updateRules" : ""
            counters[.flowsAllowed] = 1
            verdict = .allow(withUpdateRules: signalRulesChange)
        }

        let finished = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        record.decisionNanos = finished &- started
        store?.append(record, incrementing: counters)

        Log.flows.log("""
            CTLDONE id=\(record.flowIdentifier, privacy: .public) t=\(finished) \
            verdict=\(record.verdict.label, privacy: .public)
            """)

        Log.flows.log("""
            CONTROL \(record.verdict.label, privacy: .public) \
            app=\(record.appDescription, privacy: .public) \
            remote=\(record.remoteDescription, privacy: .public) \
            addr=\(record.remoteAddress.isEmpty ? "<unresolved>" : record.remoteAddress, privacy: .public) \
            host=\(record.remoteHostname.isEmpty ? "<nil>" : record.remoteHostname, privacy: .public) \
            local=\(record.localDescription, privacy: .public) \
            path=[\(record.pathFlags.summary, privacy: .public)] \
            updateRules=\(signalRulesChange, privacy: .public) \
            id=\(record.flowIdentifier, privacy: .public) \
            \(record.decisionNanos / 1000)us
            """)

        completionHandler(verdict)
    }

    private func runSandboxProbeOnce() {
        lock.lock()
        let alreadyRan = sandboxProbeRan
        sandboxProbeRan = true
        lock.unlock()
        guard !alreadyRan else { return }
        DispatchQueue.global(qos: .utility).async { SandboxProbe.run() }
    }

    override func handleRemediation(for flow: NEFilterFlow,
                                    completionHandler: @escaping (NEFilterControlVerdict) -> Void) {
        Log.control.log("handleRemediation — unexpected in this spike, allowing")
        completionHandler(.allow(withUpdateRules: false))
    }

    override func handle(_ report: NEFilterReport) {
        guard let flow = report.flow else {
            Log.control.log("report without flow event=\(report.event.rawValue, privacy: .public)")
            return
        }
        var record = FlowInspector.record(for: flow, origin: .controlProvider)
        record.verdict = .report
        record.bytesInbound = UInt64(report.bytesInboundCount)
        record.bytesOutbound = UInt64(report.bytesOutboundCount)
        record.matchedRule = "event:\(report.event.rawValue) action:\(report.action.rawValue)"

        store?.append(record, incrementing: [
            .reportsControl: 1,
            .reportedBytesInbound: record.bytesInbound,
            .reportedBytesOutbound: record.bytesOutbound,
        ])

        Log.flows.log("""
            REPORT[control] id=\(record.flowIdentifier, privacy: .public) \
            event=\(report.event.rawValue) action=\(report.action.rawValue) \
            \(record.appDescription, privacy: .public) \
            \(record.remoteDescription, privacy: .public) \
            in=\(record.bytesInbound) out=\(record.bytesOutbound)
            """)
    }
}
