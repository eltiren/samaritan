import Foundation
import NetworkExtension
import OSLog

/// The hot path.
///
/// Milestone-1 scope: observe everything, allow by default, drop on one trivial rule, and record
/// enough per-flow metadata to answer the NordVPN coexistence questions after the fact.
///
/// Constraints this code is written against (verified in the iOS 26.5 SDK headers, not assumed):
///
/// * `applySettings(_:)`, `NEFilterSettings` and `NENetworkRule` are **macOS-only**. On iOS there is
///   no kernel-side prefilter — *every* flow lands in `handleNewFlow(_:)` and must be decided in
///   Swift. That is the single most important input to the milestone-2 policy engine design.
/// * `pauseVerdict`, `resumeFlow(_:with:)` and `updateFlow(_:using:for:)` are macOS-only. On iOS a
///   verdict is final at the moment it is returned; there is no "decide later".
/// * `sourceAppAuditToken` is macOS-only. `sourceAppIdentifier` is the only app identity we get.
/// `@unchecked Sendable`: every piece of mutable state on this class is guarded by `lock`, and the
/// provider is handed between the system's callback queue and the utility queue the sandbox probe
/// runs on.
final class FilterDataProvider: NEFilterDataProvider, @unchecked Sendable {

    /// Built inside `startFilter`, not as a stored-property initialiser: a stored property is
    /// constructed before the initialiser body, so a failure there would kill the extension before
    /// it could log anything at all.
    private var store: DiagnosticsStore?

    /// The compiled policy, memory-mapped read-only. `nil` verdicts mean no policy is loaded, in
    /// which case the spike's trivial rule set still applies — the filter never silently changes
    /// behaviour because a file is missing.
    private var policy: PolicySource?
    private let lock = NSLock()

    /// Apps exempt from Samaritan entirely. Read on the hot path without taking `lock` — see
    /// `BypassGate`, and `handleNewFlow` below for why it cannot be behind one.
    ///
    /// A stored property, unlike `store` and `policy`, because it must answer correctly for the
    /// very first flow and its initialiser does no I/O: it starts empty and is loaded in
    /// `startFilter`. An empty set means "bypass nothing", so a failure to load fails towards
    /// filtering rather than away from it.
    private let bypass = BypassGate()

    /// Distinct `sourceAppIdentifier` values seen, so each can be logged once with its raw form.
    /// Not on the bypass path — this is only reached by flows Samaritan is actually inspecting.
    private var seenIdentifiers = Set<String>()

    private var configuration = SpikeConfiguration.default
    private var rules = SpikeRuleSet(configuration: .default)
    private var configurationMTime: TimeInterval = 0
    private var lastConfigurationCheck: UInt64 = 0

    /// One `.needRules()` probe per source app, hard-capped, so the control-provider experiment can
    /// never wedge traffic on a personal device.
    /// The sandbox probe also runs lazily on the first flow. `startFilter` fires the moment the
    /// filter is enabled — often before you have `log stream` attached — so relying on it alone
    /// means the answer scrolls past unseen.
    private var sandboxProbeRan = false
    private var sandboxSummary = ""
    private var sandboxSummariesLogged = 0

    /// Destinations already escalated, so a retry storm does not pay a cross-process round trip per
    /// attempt. Measured: one blocked app produced 1839 escalations for a handful of destinations.
    ///
    /// In-memory only — the data provider cannot persist anything — which is fine: losing it costs
    /// one extra escalation per pair after a restart.
    private var escalationLedger = Set<Int>()
    private var ledgerGeneration: UInt64 = 0

    private var probedApps = Set<String>()
    private var probeBudget = SpikeConfiguration.default.controlProbeBudget

    // MARK: - Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Unconditional first line. If this appears and nothing else does, the crash is below.
        Log.flows.log("DATA PROVIDER startFilter entered pid=\(getpid())")

        SandboxProbe.run()

        let hasContainer = SharedContainer.containerURL != nil
        store = DiagnosticsStore(writer: .dataProvider)
        if let policyPath = SharedContainer.policyURL?.path {
            policy = PolicySource(path: policyPath)
        }
        bypass.start(url: SharedContainer.bypassURL)
        let hasStore = store != nil
        PathObserver.shared.start()
        reloadConfiguration(force: true)
        Log.flows.log("""
            DATA PROVIDER startFilter ready appGroup=\(SharedContainer.appGroupIdentifier, privacy: .public) \
            container=\(hasContainer, privacy: .public) ring=\(hasStore, privacy: .public)
            """)

        store?.increment([.filterStarts: 1])
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Log.data.log("stopFilter reason=\(reason.rawValue, privacy: .public)")
        store?.increment([.filterStops: 1])
        completionHandler()
    }

    // MARK: - Flows

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // L0 — BYPASS. Deliberately the first statement in the method, before the clock read.
        //
        // "Bypass" means the app is invisible to Samaritan, not "allowed after processing": no
        // metadata is extracted, nothing is written to the ring or the Observed list, no counter
        // moves, nothing is logged, no configuration is re-read and the sandbox probe is not run.
        // Anything below this line would be a side effect on a flow we promised not to look at.
        //
        // The membership test is against the identifier **exactly as the flow carries it**. See
        // `docs/firewall-rules.md` §1.3 — matching a bundle ID here would silently never fire.
        // A `nil` identifier is never bypassed: `AppIdentity.unattributedRaw` is a display-only
        // pseudo-identifier that no flow carries, so there is nothing to compare against, and
        // exempting all unattributable traffic is the hole default-deny exists to close.
        if let sourceApp = flow.sourceAppIdentifier, bypass.contains(sourceApp) {
            return .allow()
        }

        let started = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        runSandboxProbeOnce()
        reloadConfigurationIfStale(now: started)

        var record = FlowInspector.record(for: flow, origin: .dataProvider)
        noteIdentity(of: flow, record: record)

        lock.lock()
        let rules = self.rules
        let configuration = self.configuration
        lock.unlock()

        let verdict: NEFilterNewFlowVerdict
        var counters: [DiagnosticsStore.Counter: UInt64] = [.flowsObserved: 1]

        let outcome = resolve(record: record, rules: rules, configuration: configuration,
                              counters: &counters, now: started)

        switch outcome {
        case .denyInline(let label):
            record.verdict = .drop
            record.matchedRule = label
            counters[.flowsDropped] = 1
            verdict = .drop()

        case .denyEscalated(let label):
            record.verdict = .needRules
            record.matchedRule = "escalate:\(label)"
            counters[.flowsEscalated] = 1
            // CLOCK_UPTIME_RAW is system-wide monotonic, so this timestamp is directly comparable
            // with the one the control provider logs in another process. That pairing is what
            // `tools/escalation-report.py` joins on.
            Log.flows.log("""
                ESCALATE id=\(record.flowIdentifier, privacy: .public) \
                t=\(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)) \
                app=\(record.appDescription, privacy: .public) \
                host=\(record.remoteDescription, privacy: .public) \
                rule=\(label, privacy: .public)
                """)
            verdict = .needRules()

        case .allow:
            if configuration.controlProbeEnabled, shouldProbeControl(for: record.sourceApp) {
                record.verdict = .needRules
                record.matchedRule = "probe"
                counters[.flowsNeedRules] = 1
                // Hands this flow to FilterControlProvider in a separate process. The data provider
                // does not see the flow again; the control provider's verdict is applied directly.
                verdict = .needRules()
            } else {
                record.verdict = .allow
                counters[.flowsAllowed] = 1
                verdict = .allow()
            }
        }

        // The only route to byte counts on iOS: opt the flow into NEFilterReport delivery.
        verdict.shouldReport = configuration.requestReports

        record.decisionNanos = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) &- started
        store?.append(record, incrementing: counters)

        if configuration.logEveryFlow {
            log(record)
        }
        return verdict
    }

    /// Called after the control provider returns a verdict with `updateRules: true`.
    /// On iOS this is the *only* push notification the data provider gets, and it carries no
    /// payload — the actual rules must be read back out of the shared container.
    override func handleRulesChanged() {
        Log.data.log("handleRulesChanged — reloading configuration from shared container")
        store?.increment([.rulesChangedEvents: 1])
        reloadConfiguration(force: true)
        bypass.reload()
    }

    /// Delivered for flows whose verdict had `shouldReport = true`.
    /// Which process receives this on iOS — data provider, control provider, or both — is one of the
    /// open questions this spike answers, so both providers implement it and tag their records.
    override func handle(_ report: NEFilterReport) {
        guard let flow = report.flow else {
            Log.data.log("report without flow event=\(report.event.rawValue, privacy: .public)")
            return
        }
        var record = FlowInspector.record(for: flow, origin: .dataProvider)
        record.verdict = .report
        record.bytesInbound = UInt64(report.bytesInboundCount)
        record.bytesOutbound = UInt64(report.bytesOutboundCount)
        record.matchedRule = "event:\(reportEventName(report.event)) action:\(filterActionName(report.action))"

        store?.append(record, incrementing: [
            .reportsData: 1,
            .reportedBytesInbound: record.bytesInbound,
            .reportedBytesOutbound: record.bytesOutbound,
        ])

        Log.flows.log("""
            REPORT[data] id=\(record.flowIdentifier, privacy: .public) \
            \(record.appDescription, privacy: .public) \
            \(record.remoteDescription, privacy: .public) \
            event=\(self.reportEventName(report.event), privacy: .public) \
            action=\(self.filterActionName(report.action), privacy: .public) \
            in=\(record.bytesInbound) out=\(record.bytesOutbound)
            """)
    }

    // MARK: - Resolution

    /// Prefers the compiled policy; falls back to the spike rule set when none is loaded.
    private func resolve(record: FlowRecord,
                         rules: SpikeRuleSet,
                         configuration: SpikeConfiguration,
                         counters: inout [DiagnosticsStore.Counter: UInt64],
                         now: UInt64) -> PolicyOutcome {
        if let policy {
            let address = record.remoteAddress.isEmpty ? nil : IPPrefix(record.remoteAddress)
            let hostname = record.remoteHostname.isEmpty ? nil : record.remoteHostname
            if let result = policy.evaluate(appID: record.sourceApp, hostname: hostname,
                                            address: address, now: now) {
                counters[.policyDecisions] = 1
                guard result.verdict.action == .deny else { return .allow }
                guard configuration.denyMode == .escalate else {
                    return .denyInline(rule: result.label)
                }
                // Escalate the first time this destination is denied for this app; drop repeats
                // inline. Recording it once is all the Observed list needs.
                guard shouldEscalate(app: record.sourceApp,
                                     destination: record.remoteHostname.isEmpty
                                        ? record.remoteAddress : record.remoteHostname,
                                     generation: policy.currentGeneration ?? 0) else {
                    counters[.escalationsSuppressed] = 1
                    return .denyInline(rule: result.label)
                }
                return .denyEscalated(rule: result.label)
            }
        }
        counters[.spikeFallbackDecisions] = 1
        return SpikeResolver.evaluate(hostname: record.remoteHostname,
                                      address: record.remoteAddress,
                                      rules: rules,
                                      denyMode: configuration.denyMode)
    }

    /// Bounded, and reset whenever the policy changes so a rule edit re-records what it affects.
    private func shouldEscalate(app: String, destination: String, generation: UInt64) -> Bool {
        var hasher = Hasher()
        hasher.combine(app)
        hasher.combine(destination)
        let key = hasher.finalize()

        lock.lock()
        defer { lock.unlock() }
        if generation != ledgerGeneration {
            ledgerGeneration = generation
            escalationLedger.removeAll(keepingCapacity: true)
        }
        // Cap so a pathological app cannot grow this without bound in a memory-limited extension.
        if escalationLedger.count >= 4096 { escalationLedger.removeAll(keepingCapacity: true) }
        return escalationLedger.insert(key).inserted
    }

    // MARK: - Sandbox probe

    private func runSandboxProbeOnce() {
        lock.lock()
        let alreadyRan = sandboxProbeRan
        sandboxProbeRan = true
        lock.unlock()
        guard !alreadyRan else { return }
        // Off the hot path — this does real filesystem I/O and we only need it once.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let summary = SandboxProbe.summary(of: SandboxProbe.run())
            self?.lock.lock()
            self?.sandboxSummary = summary
            self?.lock.unlock()
        }
    }

    /// Returns the sandbox verdict for the first few flow lines, then stops repeating it.
    private func sandboxSuffix() -> String {
        lock.lock()
        defer { lock.unlock() }
        guard !sandboxSummary.isEmpty, sandboxSummariesLogged < 3 else { return "" }
        sandboxSummariesLogged += 1
        return " sandbox[\(sandboxSummary)]"
    }

    // MARK: - Control probe

    private func shouldProbeControl(for sourceApp: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard probeBudget > 0 else { return false }
        let key = sourceApp.isEmpty ? "<unknown>" : sourceApp
        guard !probedApps.contains(key) else { return false }
        probedApps.insert(key)
        probeBudget -= 1
        return true
    }

    // MARK: - Configuration

    private func reloadConfigurationIfStale(now: UInt64) {
        lock.lock()
        let last = lastConfigurationCheck
        lock.unlock()
        // Throttled `stat(2)` so app-side config edits land without toggling the filter, while
        // still costing nothing measurable on the hot path.
        guard now &- last > 2_000_000_000 else { return }
        reloadConfiguration(force: false)
    }

    private func reloadConfiguration(force: Bool) {
        let now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        var mtime: TimeInterval = 0
        if let url = SharedContainer.configurationURL {
            var info = stat()
            if stat(url.path, &info) == 0 {
                mtime = TimeInterval(info.st_mtimespec.tv_sec) + TimeInterval(info.st_mtimespec.tv_nsec) / 1e9
            }
        }

        lock.lock()
        lastConfigurationCheck = now
        let unchanged = !force && mtime == configurationMTime
        lock.unlock()
        guard !unchanged else { return }

        let loaded = SpikeConfiguration.load()
        lock.lock()
        configuration = loaded
        rules = SpikeRuleSet(configuration: loaded)
        configurationMTime = mtime
        probeBudget = max(probeBudget, loaded.controlProbeEnabled ? loaded.controlProbeBudget : 0)
        lock.unlock()

        Log.data.log("""
            configuration hosts=\(loaded.blockedHostSuffixes.joined(separator: ","), privacy: .public) \
            addrs=\(loaded.blockedAddresses.joined(separator: ","), privacy: .public) \
            probe=\(loaded.controlProbeEnabled, privacy: .public) \
            reports=\(loaded.requestReports, privacy: .public) \
            deny=\(loaded.denyMode.rawValue, privacy: .public) \
            source=\(mtime > 0 ? "file" : "compiled-in-default", privacy: .public)
            """)
    }

    // MARK: - Identity

    /// Logs each distinct `sourceAppIdentifier` once, verbatim.
    ///
    /// The point is to see what the flow *actually* carries rather than what the Apps list shows.
    /// `logEveryFlow` already prints the identifier per flow, but at Netflix volumes that is
    /// thousands of duplicate lines; the interesting question is how many *distinct* identifiers
    /// one app produces, and whether any of them is missing, empty, or belongs to a helper process
    /// or a system daemon rather than to the app itself.
    ///
    /// Never reached for a bypassed flow — that has already returned.
    private func noteIdentity(of flow: NEFilterFlow, record: FlowRecord) {
        let raw = flow.sourceAppIdentifier
        // Nil and empty are different failures and print differently: nil means the system did not
        // attribute the flow at all, empty would mean it attributed it to nothing.
        let key = raw.map { $0.isEmpty ? "<empty>" : $0 } ?? "<nil>"

        lock.lock()
        // Capped: an app that mints a new identifier per connection must not grow this without
        // bound inside a memory-limited extension.
        let isNew = seenIdentifiers.count < 512 && seenIdentifiers.insert(key).inserted
        lock.unlock()
        guard isNew else { return }

        let identity = AppIdentity(sourceAppIdentifier: raw)
        let team = identity.teamID.isEmpty ? "<empty>" : String(identity.teamID)
        let bypassed = raw.map { bypass.contains($0) } ?? false
        Log.flows.log("""
            IDENT NEW raw=\(key, privacy: .public) \
            team=\(team, privacy: .public) \
            bundle=\(String(identity.bundleID), privacy: .public) \
            apple=\(identity.isAppleSystemApp, privacy: .public) \
            bypassed=\(bypassed, privacy: .public) \
            proto=\(record.socketProtocolName, privacy: .public) \
            host=\(record.remoteHostname.isEmpty ? "<nil>" : record.remoteHostname, privacy: .public)
            """)
    }

    // MARK: - Logging

    private func log(_ record: FlowRecord) {
        Log.flows.log("""
            \(record.verdict.label, privacy: .public) \
            app=\(record.appDescription, privacy: .public) \
            ver=\(record.sourceAppVersion, privacy: .public) \
            remote=\(record.remoteDescription, privacy: .public) \
            addr=\(record.remoteAddress.isEmpty ? "<unresolved>" : record.remoteAddress, privacy: .public) \
            host=\(record.remoteHostname.isEmpty ? "<nil>" : record.remoteHostname, privacy: .public) \
            local=\(record.localDescription, privacy: .public) \
            \(record.socketFamilyName, privacy: .public)/\(record.socketProtocolName, privacy: .public) \
            dir=\(record.direction) \
            path=[\(record.pathFlags.summary, privacy: .public)] \
            rule=\(record.matchedRule.isEmpty ? "-" : record.matchedRule, privacy: .public) \
            id=\(record.flowIdentifier, privacy: .public) \
            \(record.decisionNanos / 1000)us\(self.sandboxSuffix(), privacy: .public)
            """)
    }

    private func reportEventName(_ event: NEFilterReport.Event) -> String {
        switch event {
        case .newFlow: "newFlow"
        case .dataDecision: "dataDecision"
        case .flowClosed: "flowClosed"
        @unknown default: "event\(event.rawValue)"
        }
    }

    private func filterActionName(_ action: NEFilterAction) -> String {
        switch action {
        case .allow: "allow"
        case .drop: "drop"
        case .remediate: "remediate"
        case .filterData: "filterData"
        case .invalid: "invalid"
        @unknown default: "action\(action.rawValue)"
        }
    }
}
