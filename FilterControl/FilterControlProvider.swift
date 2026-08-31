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
    private var policy: PolicySource?

    /// The control provider is the only one of the three processes that can write, so it owns the
    /// record of what each app asked for.
    private var observed: ObservedStore?

    /// The same bypass set the data provider reads.
    ///
    /// By construction this process should never see a bypassed flow: the data provider allows it
    /// without escalating and without `shouldReport`, so neither `handleNewFlow` nor `handle(_:)`
    /// can be reached. The check is here anyway to close the window where bypass is switched on
    /// while a flow is already in flight, which would otherwise append one more entry to the
    /// Observed list of an app that is supposed to have stopped updating.
    private let bypass = BypassGate()

    /// Flip `updateRules` exactly once so the data provider's `handleRulesChanged()` can be
    /// observed without a rules-change storm. Spent on the first *allowed* control flow, not the
    /// first control flow — see `RulesChangeSignal` for why that distinction is the whole point.
    private let rulesChange = RulesChangeSignal()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        Log.flows.log("CONTROL PROVIDER startFilter entered pid=\(getpid())")
        SandboxProbe.runAndRepeat()
        store = DiagnosticsStore(writer: .controlProvider)
        if let policyPath = SharedContainer.policyURL?.path {
            policy = PolicySource(path: policyPath)
        }
        observed = ObservedStore()
        bypass.start(url: SharedContainer.bypassURL)
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
        observed?.flush()
        store?.increment([.filterStops: 1])
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow,
                                completionHandler: @escaping (NEFilterControlVerdict) -> Void) {
        if let sourceApp = flow.sourceAppIdentifier, bypass.contains(sourceApp) {
            completionHandler(.allow(withUpdateRules: false))
            return
        }

        let started = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        var record = FlowInspector.record(for: flow, origin: .controlProvider)

        // Paired with the data provider's ESCALATE line by flow id. Both use CLOCK_UPTIME_RAW,
        // which is system-wide monotonic, so the difference is the true cross-process round trip.
        Log.flows.log("CTLRECV id=\(record.flowIdentifier, privacy: .public) t=\(started)")

        let configuration = SpikeConfiguration.load()
        let rules = SpikeRuleSet(configuration: configuration)

        let verdict: NEFilterControlVerdict
        var counters: [DiagnosticsStore.Counter: UInt64] = [.controlFlowsHandled: 1]

        // When a policy is loaded it decides outright — allow included. Falling through to the
        // spike rules on an explicit allow would let a stale test rule override real policy.
        let denialLabel: String?
        if let policy,
           let result = policy.evaluate(appID: record.sourceApp,
                                        hostname: record.remoteHostname.isEmpty ? nil : record.remoteHostname,
                                        address: record.remoteAddress.isEmpty ? nil : IPPrefix(record.remoteAddress),
                                        now: started) {
            denialLabel = result.verdict.action == .deny ? result.label : nil
        } else {
            denialLabel = rules.matchLabel(hostname: record.remoteHostname, address: record.remoteAddress)
        }

        // Passed the verdict rather than claimed unconditionally: a drop returns
        // `withUpdateRules: false`, so spending the one-shot on one would silence every later allow.
        let signalRulesChange = rulesChange.claim(forAllow: denialLabel == nil)

        if let label = denialLabel {
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

        observed?.record(appID: record.sourceApp,
                         host: record.remoteHostname,
                         address: record.remoteAddress,
                         port: record.remotePort,
                         denied: record.verdict.isDrop,
                         rule: record.matchedRule.isEmpty ? nil : record.matchedRule)
        observed?.flushIfNeeded(now: finished)

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
        if let sourceApp = flow.sourceAppIdentifier, bypass.contains(sourceApp) { return }
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

        // The same bytes again, split by app. Not a second measurement — the same one, so a per-app
        // figure that does not add up to the counter above is a bug in one of them.
        //
        // The epoch comes from the ring header, which `append` above has just re-read, and is how a
        // reset in the app reaches the per-app totals: they are cleared by the same tap that clears
        // the counters, and never on their own.
        observed?.addTraffic(appID: record.sourceApp,
                             inbound: record.bytesInbound,
                             outbound: record.bytesOutbound,
                             countersEpoch: store?.countersEpoch ?? 0)

        // Reports are the only sight the control provider gets of flows it never handled, so this is
        // where *allowed* destinations are recorded. Without it the app list would only ever show
        // apps that are blocked.
        observed?.record(appID: record.sourceApp,
                         host: record.remoteHostname,
                         address: record.remoteAddress,
                         port: record.remotePort,
                         denied: report.action == .drop,
                         rule: nil)
        observed?.flushIfNeeded(now: clock_gettime_nsec_np(CLOCK_UPTIME_RAW))

        Log.flows.log("""
            REPORT[control] id=\(record.flowIdentifier, privacy: .public) \
            event=\(report.event.rawValue) action=\(report.action.rawValue) \
            \(record.appDescription, privacy: .public) \
            \(record.remoteDescription, privacy: .public) \
            in=\(record.bytesInbound) out=\(record.bytesOutbound)
            """)
    }
}
