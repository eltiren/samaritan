import Foundation
import Testing
@testable import SamaritanTests

@Suite("Spike rule matching")
struct SpikeRuleSetTests {

    private func rules(hosts: [String] = [], addresses: [String] = []) -> SpikeRuleSet {
        SpikeRuleSet(configuration: SpikeConfiguration(
            blockedHostSuffixes: hosts,
            blockedAddresses: addresses,
            controlProbeEnabled: false,
            controlProbeBudget: 0,
            requestReports: false,
            logEveryFlow: false))
    }

    @Test("matches an exact hostname")
    func exactHostname() {
        #expect(rules(hosts: ["neverssl.com"]).matchLabel(hostname: "neverssl.com", address: "") == "host:neverssl.com")
    }

    @Test("matches a subdomain but not a suffix collision")
    func subdomainOnly() {
        let ruleSet = rules(hosts: ["example.com"])
        #expect(ruleSet.matchLabel(hostname: "www.example.com", address: "") == "host:example.com")
        // "notexample.com" must not match "example.com" — suffix matching is label-aware.
        #expect(ruleSet.matchLabel(hostname: "notexample.com", address: "") == nil)
    }

    @Test("hostname matching is case-insensitive")
    func caseInsensitive() {
        #expect(rules(hosts: ["Example.COM"]).matchLabel(hostname: "WWW.example.com", address: "") != nil)
    }

    @Test("matches a literal address")
    func literalAddress() {
        #expect(rules(addresses: ["93.184.216.34"]).matchLabel(hostname: "", address: "93.184.216.34")
                == "ip:93.184.216.34")
    }

    @Test("address rules take precedence over hostname rules")
    func addressPrecedence() {
        let ruleSet = rules(hosts: ["example.com"], addresses: ["1.2.3.4"])
        #expect(ruleSet.matchLabel(hostname: "example.com", address: "1.2.3.4") == "ip:1.2.3.4")
    }

    @Test("allows when nothing matches")
    func allowsByDefault() {
        #expect(rules(hosts: ["blocked.test"]).matchLabel(hostname: "apple.com", address: "17.0.0.1") == nil)
        #expect(rules().matchLabel(hostname: "anything.test", address: "1.1.1.1") == nil)
    }

    @Test("an empty hostname never matches a hostname rule")
    func emptyHostname() {
        #expect(rules(hosts: [""]).isEmpty)
        #expect(rules(hosts: ["example.com"]).matchLabel(hostname: "", address: "") == nil)
    }

    @Test("the default configuration blocks its documented test host")
    func defaultConfiguration() {
        let ruleSet = SpikeRuleSet(configuration: .default)
        #expect(ruleSet.matchLabel(hostname: "neverssl.com", address: "") != nil)
        #expect(ruleSet.matchLabel(hostname: "apple.com", address: "") == nil)
    }
}
