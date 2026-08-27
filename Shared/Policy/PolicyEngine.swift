import Foundation

/// The resolver from `docs/firewall-rules.md` §2.1, over a `CompiledPolicy`.
///
///     L1  per-app explicit rules      terminal if matched
///     L2  global user lists           terminal if matched
///     L3  global web lists            terminal if matched
///     L4  app blanket default         always terminal
///
/// Blanket settings are consulted **last** and never override a tier above them. There is no tier
/// for Apple apps: `com.apple.*` simply ships with `allowAll`, set when the `AppPolicy` is created.
public struct PolicyEngine: Sendable {

    public struct Verdict: Sendable, Equatable {
        public enum Source: String, Sendable {
            case perApp, userList, webList, blanket
        }

        public var action: RuleAction
        public var source: Source
        public var ruleIndex: UInt32?

        public var isAllowed: Bool { action == .allow }
    }

    public let policy: CompiledPolicy

    public init(policy: CompiledPolicy) {
        self.policy = policy
    }

    /// Resolves one flow.
    ///
    /// `hostname` and `address` are both optional because both genuinely go missing on device: a
    /// flow can arrive with only a hostname (`remoteFlowEndpoint == ::`), only an address, or
    /// neither. A rule that keys on an absent field simply cannot match, which under deny-all fails
    /// safe.
    public func evaluate(appID: String, hostname: String?, address: IPPrefix?) -> Verdict {
        var app = appID.isEmpty ? AppIdentity.unattributedRaw : appID
        var host = hostname.map(HostNormaliser.normalise) ?? ""

        return app.withUTF8 { appBytes in
            let entry = policy.appEntry(for: appBytes)

            return host.withUTF8 { hostBytesRaw -> Verdict in
                let hostBytes: UnsafeBufferPointer<UInt8>? = hostBytesRaw.isEmpty ? nil : hostBytesRaw

                // L1 — this app's own rules.
                if let entry, let match = policy.match(ruleSet: entry.ruleSetIndex,
                                                       host: hostBytes, address: address) {
                    return Verdict(action: match.action, source: .perApp, ruleIndex: match.ruleIndex)
                }
                // L2 — hand-edited global lists.
                if let match = policy.match(ruleSet: policy.userRuleSet, host: hostBytes, address: address) {
                    return Verdict(action: match.action, source: .userList, ruleIndex: match.ruleIndex)
                }
                // L3 — subscribed lists.
                if let match = policy.match(ruleSet: policy.webRuleSet, host: hostBytes, address: address) {
                    return Verdict(action: match.action, source: .webList, ruleIndex: match.ruleIndex)
                }
                // L4 — blanket default. An app with no entry inherits the default for its kind,
                // which is the only place an Apple bundle ID has any effect.
                let blanket: BlanketMode = entry.map { BlanketMode(rawValue: $0.blanket) ?? .denyAll }
                    ?? (AppIdentity(raw: appID).isAppleSystemApp ? .allowAll : .denyAll)
                return Verdict(action: blanket == .allowAll ? .allow : .deny,
                               source: .blanket, ruleIndex: nil)
            }
        }
    }

    /// Display label for a verdict's rule, materialised only when something is being reported.
    /// The hot path never touches it.
    public func label(for verdict: Verdict) -> String {
        guard let index = verdict.ruleIndex else { return verdict.source.rawValue }
        return "\(verdict.source.rawValue):\(policy.label(at: index))"
    }
}
