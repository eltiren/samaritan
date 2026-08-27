import Foundation

/// The decision the resolver reached for a flow, and how that decision should be delivered.
///
/// Kept separate from `NEFilterNewFlowVerdict` so the branch that matters — deny inline versus deny
/// by escalating to the control provider — is a pure value that can be tested without
/// NetworkExtension.
public enum PolicyOutcome: Equatable, Sendable {
    case allow
    /// Deny, decided and returned inline by the data provider.
    case denyInline(rule: String)
    /// Deny, but hand the flow to the control provider first so it can be recorded.
    ///
    /// This is only sane because the latency is free: the flow is going to be dropped, so the ~13 ms
    /// round trip costs nothing that matters. See `docs/firewall-rules.md` §5.
    case denyEscalated(rule: String)

    public var matchedRule: String? {
        switch self {
        case .allow: nil
        case .denyInline(let rule), .denyEscalated(let rule): rule
        }
    }

    public var isDeny: Bool { self != .allow }
}

/// Milestone-1.5 resolver: the trivial rule set plus the inline/escalate branch under test.
///
/// **This is not the policy engine.** It exists to answer two questions that gate the engine's
/// design, both of which need a device:
///
/// 1. Does `.needRules()` followed by a control-provider `.drop()` actually drop the flow?
///    Milestone 1 only ever exercised control verdicts of `allow`.
/// 2. Can the control provider keep up when escalation is the common case rather than the rare one?
public enum SpikeResolver {

    public static func evaluate(hostname: String,
                               address: String,
                               rules: SpikeRuleSet,
                               denyMode: SpikeConfiguration.DenyMode) -> PolicyOutcome {
        guard let rule = rules.matchLabel(hostname: hostname, address: address) else {
            return .allow
        }
        return denyMode == .escalate ? .denyEscalated(rule: rule) : .denyInline(rule: rule)
    }
}
