import Foundation
import Testing
@testable import SamaritanTests

@Suite("Spike rule matching")
struct SpikeRuleSetTests {

    private func rules(hosts: [String] = [],
                       substrings: [String] = [],
                       addresses: [String] = []) -> SpikeRuleSet {
        SpikeRuleSet(configuration: SpikeConfiguration(
            blockedHostSuffixes: hosts,
            blockedHostSubstrings: substrings,
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

    @Test("substring rules catch what suffix rules miss", arguments: [
        "www.google.com",
        "play.google.com",
        "ogads-pa.clients6.google.com",
        "googleapis.com",
        "rr3---sn-x.googlevideo.com",
        "google.co.uk",
        "google-analytics.com",
    ])
    func substringMatches(host: String) {
        #expect(rules(substrings: ["google"]).matchLabel(hostname: host, address: "") == "substr:google")
    }

    @Test("a suffix rule on google.com would have missed these")
    func suffixRuleIsNarrower() {
        let suffixOnly = rules(hosts: ["google.com"])
        #expect(suffixOnly.matchLabel(hostname: "www.google.com", address: "") != nil)
        #expect(suffixOnly.matchLabel(hostname: "googleapis.com", address: "") == nil)
        #expect(suffixOnly.matchLabel(hostname: "rr3---sn-x.googlevideo.com", address: "") == nil)
    }

    @Test("substring rules do not match unrelated hosts")
    func substringNoFalsePositives() {
        let ruleSet = rules(substrings: ["google"])
        #expect(ruleSet.matchLabel(hostname: "apple.com", address: "") == nil)
        #expect(ruleSet.matchLabel(hostname: "slack.com", address: "") == nil)
        #expect(ruleSet.matchLabel(hostname: "", address: "8.8.8.8") == nil)
    }

    @Test("suffix rules win over substring rules for the label")
    func suffixPrecedence() {
        let ruleSet = rules(hosts: ["google.com"], substrings: ["google"])
        #expect(ruleSet.matchLabel(hostname: "www.google.com", address: "") == "host:google.com")
        #expect(ruleSet.matchLabel(hostname: "googleapis.com", address: "") == "substr:google")
    }
}

@Suite("Unspecified address handling")
struct UnspecifiedAddressTests {

    // Observed on device: IPv6 and QUIC flows frequently reach handleNewFlow with the remote
    // endpoint still `::`, while remoteHostname is already populated. Such a flow must never be
    // treated as having address `::`, or an address rule for `::` would match everything unresolved.

    @Test("recognises the unspecified addresses", arguments: ["::", "0.0.0.0"])
    func recognisesUnspecified(address: String) {
        #expect(FlowInspector.isUnspecified(address))
    }

    @Test("does not flag real addresses", arguments: ["::1", "0.0.0.1", "63.176.3.100", "2606:4700::1111"])
    func allowsRealAddresses(address: String) {
        #expect(!FlowInspector.isUnspecified(address))
    }

    @Test("a hostname-only flow is still matched by hostname rules")
    func hostnameOnlyStillMatches() {
        let rules = SpikeRuleSet(configuration: .default)
        // This is exactly the shape of the dropped Safe Browsing flows: no address, host present.
        #expect(rules.matchLabel(hostname: "apple-safebrowsing.googleapis.com", address: "") == "substr:google")
    }
}
