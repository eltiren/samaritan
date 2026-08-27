import Foundation
import Testing
@testable import SamaritanTests

@Suite("Resolver outcome and deny delivery")
struct SpikeResolverTests {

    private func rules(hosts: [String]) -> SpikeRuleSet {
        SpikeRuleSet(configuration: SpikeConfiguration(
            blockedHostSuffixes: hosts,
            blockedHostSubstrings: [],
            blockedAddresses: [],
            controlProbeEnabled: false,
            controlProbeBudget: 0,
            requestReports: false,
            logEveryFlow: false))
    }

    @Test("no match allows regardless of deny mode", arguments: SpikeConfiguration.DenyMode.allCases)
    func allowsWhenNothingMatches(mode: SpikeConfiguration.DenyMode) {
        let outcome = SpikeResolver.evaluate(hostname: "apple.com", address: "17.0.0.1",
                                             rules: rules(hosts: ["blocked.test"]), denyMode: mode)
        #expect(outcome == .allow)
        #expect(outcome.matchedRule == nil)
        #expect(!outcome.isDeny)
    }

    @Test("inline mode denies without escalating")
    func inlineDeny() {
        let outcome = SpikeResolver.evaluate(hostname: "blocked.test", address: "",
                                             rules: rules(hosts: ["blocked.test"]), denyMode: .inline)
        #expect(outcome == .denyInline(rule: "host:blocked.test"))
        #expect(outcome.isDeny)
    }

    @Test("escalate mode routes the same denial through the control provider")
    func escalatedDeny() {
        let outcome = SpikeResolver.evaluate(hostname: "blocked.test", address: "",
                                             rules: rules(hosts: ["blocked.test"]), denyMode: .escalate)
        #expect(outcome == .denyEscalated(rule: "host:blocked.test"))
        #expect(outcome.isDeny)
    }

    @Test("deny mode changes only delivery, never the decision",
          arguments: SpikeConfiguration.DenyMode.allCases)
    func modeDoesNotChangeTheDecision(mode: SpikeConfiguration.DenyMode) {
        let ruleSet = rules(hosts: ["blocked.test"])
        // Whatever the mode, the same flows are denied and the same rule is credited.
        #expect(SpikeResolver.evaluate(hostname: "a.blocked.test", address: "",
                                       rules: ruleSet, denyMode: mode).matchedRule == "host:blocked.test")
        #expect(SpikeResolver.evaluate(hostname: "allowed.test", address: "",
                                       rules: ruleSet, denyMode: mode).isDeny == false)
    }

    @Test("escalation is off unless explicitly enabled")
    func inlineIsTheDefault() {
        // Escalating every denial is the thing under test, not the resting state.
        #expect(SpikeConfiguration.default.denyMode == .inline)
    }

    @Test("a config written before deny modes existed still decodes")
    func decodesLegacyConfig() throws {
        let legacy = """
        {"blockedHostSuffixes":["a.test"],"blockedHostSubstrings":[],"blockedAddresses":[],
         "controlProbeEnabled":false,"controlProbeBudget":8,"requestReports":true,"logEveryFlow":true}
        """.data(using: .utf8)!
        #expect(try JSONDecoder().decode(SpikeConfiguration.self, from: legacy).denyMode == .inline)
    }

    @Test("deny mode survives a round trip", arguments: SpikeConfiguration.DenyMode.allCases)
    func denyModeRoundTrips(mode: SpikeConfiguration.DenyMode) throws {
        var configuration = SpikeConfiguration.default
        configuration.denyMode = mode
        let data = try JSONEncoder().encode(configuration)
        #expect(try JSONDecoder().decode(SpikeConfiguration.self, from: data).denyMode == mode)
    }
}
