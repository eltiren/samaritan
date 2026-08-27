import Foundation
import Testing
@testable import SamaritanTests

/// The ten worked examples from `docs/firewall-rules.md` §2.5, executed rather than described.
/// These are the outcomes most likely to be mistaken for bugs later.
@Suite("Resolver — worked examples from the spec")
struct PolicyWorkedExampleTests {

    private let slack = "BQR82RBBHL.com.tinyspeck.chatlyio"
    private let mail = ".com.apple.mobilemail"
    private let safari = ".com.apple.mobilesafari"
    private let whatsapp = "57T9237FN3.net.whatsapp.WhatsApp"

    private func engine(_ document: PolicyDocument) -> PolicyEngine {
        PolicyEngine(policy: PolicyCompiler.compile(document))
    }

    private func webList(_ rules: [(String, PolicyRule.Kind)], action: RuleAction) -> WebList {
        WebList(name: "test", url: URL(string: "https://example.invalid/list")!, action: action,
                lines: rules.map { $0.1 == .domainSuffix ? "*.\($0.0)" : $0.0 },
                lastFetchedAt: Date())
    }

    @Test("1+2: a per-app deny beats a global allow, and only for that app")
    func perAppDenyBeatsGlobalAllow() {
        let document = PolicyDocument(
            apps: [AppPolicy(appID: slack, rules: [
                PolicyRule(kind: .domainExact, value: "apple.com", action: .deny)])],
            userRules: [PolicyRule(kind: .domainExact, value: "apple.com", action: .allow)])
        let engine = engine(document)

        #expect(engine.evaluate(appID: slack, hostname: "apple.com", address: nil).action == .deny)
        #expect(engine.evaluate(appID: mail, hostname: "apple.com", address: nil).action == .allow)
    }

    @Test("3: precedence is symmetric — a per-app allow beats a global deny")
    func perAppAllowBeatsGlobalDeny() {
        let document = PolicyDocument(
            apps: [AppPolicy(appID: slack, rules: [
                PolicyRule(kind: .domainExact, value: "tracker.example", action: .allow)])],
            webLists: [webList([("tracker.example", .domainExact)], action: .deny)])
        let engine = engine(document)

        #expect(engine.evaluate(appID: slack, hostname: "tracker.example", address: nil).action == .allow)
        #expect(engine.evaluate(appID: whatsapp, hostname: "tracker.example", address: nil).action == .deny)
    }

    @Test("4: a web list beats an app's Allow-all blanket")
    func webListBeatsBlanketAllow() {
        let document = PolicyDocument(
            apps: [AppPolicy(appID: slack, blanket: .allowAll)],
            webLists: [webList([("ads.example", .domainExact)], action: .deny)])
        let engine = engine(document)

        #expect(engine.evaluate(appID: slack, hostname: "ads.example", address: nil).action == .deny)
        #expect(engine.evaluate(appID: slack, hostname: "anything.else", address: nil).action == .allow)
    }

    @Test("5: a global allow reaches apps that have never been triaged")
    func globalAllowReachesUntriagedApps() {
        let document = PolicyDocument(
            userRules: [PolicyRule(kind: .domainSuffix, value: "slack.com", action: .allow)])
        let engine = engine(document)

        #expect(engine.evaluate(appID: whatsapp, hostname: "edge.slack.com", address: nil).action == .allow)
        #expect(engine.evaluate(appID: whatsapp, hostname: "edge.other.com", address: nil).action == .deny)
    }

    @Test("6: tier beats specificity — a broad per-app allow wins over a narrow global deny")
    func tierBeatsSpecificity() {
        let document = PolicyDocument(
            apps: [AppPolicy(appID: slack, rules: [
                PolicyRule(kind: .domainSuffix, value: "example.com", action: .allow)])],
            webLists: [webList([("s1.example.com", .domainExact)], action: .deny)])

        let verdict = engine(document).evaluate(appID: slack, hostname: "s1.example.com", address: nil)
        #expect(verdict.action == .allow)
        #expect(verdict.source == .perApp)
    }

    @Test("7+8: *.google.com blocks subdomains but never the apex")
    func suffixNeverCoversApex() {
        let document = PolicyDocument(
            userRules: [PolicyRule(kind: .domainSuffix, value: "google.com", action: .deny)])
        let engine = engine(document)

        #expect(engine.evaluate(appID: safari, hostname: "google.com", address: nil).action == .allow)
        #expect(engine.evaluate(appID: safari, hostname: "www.google.com", address: nil).action == .deny)
        #expect(engine.evaluate(appID: safari, hostname: "a.b.google.com", address: nil).action == .deny)
        // A different registrable domain is untouched, which is what the substring rule exists for.
        #expect(engine.evaluate(appID: safari, hostname: "googleapis.com", address: nil).action == .allow)
    }

    @Test("9: an address rule cannot match a flow that arrived without an address")
    func addressRuleNeedsAnAddress() {
        let document = PolicyDocument(apps: [AppPolicy(appID: slack, rules: [
            PolicyRule(kind: .address, value: "1.2.3.0/24", action: .allow)])])
        let engine = engine(document)

        // The measured case: remoteFlowEndpoint was `::`, so there is no address to match on.
        #expect(engine.evaluate(appID: slack, hostname: "s1.slack.com", address: nil).action == .deny)
        #expect(engine.evaluate(appID: slack, hostname: "s1.slack.com",
                                address: IPPrefix("1.2.3.4")).action == .allow)
    }

    @Test("10: the Apple default is only a toggle value, and can be turned off")
    func appleBlanketIsJustADefault() {
        #expect(engine(PolicyDocument()).evaluate(appID: safari, hostname: "example.com",
                                                  address: nil).action == .allow)

        let locked = PolicyDocument(apps: [AppPolicy(appID: safari, blanket: .denyAll)])
        let verdict = engine(locked).evaluate(appID: safari, hostname: "example.com", address: nil)
        #expect(verdict.action == .deny)
        #expect(verdict.source == .blanket)
    }
}

@Suite("Resolver — matching semantics")
struct PolicyMatchingTests {

    /// The app under test has Allow-all, so "no rule matched" resolves to allow. Without that,
    /// every unmatched host falls through to deny-all and the assertions would pass for the wrong
    /// reason — these tests are about *matching*, not about the blanket default.
    private let app = "TEAM.com.test.app"

    private func engine(_ rules: [PolicyRule]) -> PolicyEngine {
        PolicyEngine(policy: PolicyCompiler.compile(PolicyDocument(
            apps: [AppPolicy(appID: app, blanket: .allowAll)],
            userRules: rules)))
    }

    @Test("exact beats suffix regardless of declaration order")
    func exactBeatsSuffix() {
        let engine = engine([
            PolicyRule(kind: .domainSuffix, value: "example.com", action: .deny),
            PolicyRule(kind: .domainExact, value: "ok.example.com", action: .allow),
        ])
        #expect(engine.evaluate(appID: app, hostname: "ok.example.com", address: nil).action == .allow)
        #expect(engine.evaluate(appID: app, hostname: "no.example.com", address: nil).action == .deny)
    }

    @Test("the longer suffix wins")
    func longerSuffixWins() {
        let engine = engine([
            PolicyRule(kind: .domainSuffix, value: "example.com", action: .deny),
            PolicyRule(kind: .domainSuffix, value: "status.example.com", action: .allow),
        ])
        #expect(engine.evaluate(appID: app, hostname: "s1.status.example.com", address: nil).action == .allow)
        #expect(engine.evaluate(appID: app, hostname: "s1.other.example.com", address: nil).action == .deny)
    }

    @Test("deny wins when a domain allow and an address deny collide")
    func denyWinsCrossKindConflict() {
        let engine = engine([
            PolicyRule(kind: .domainExact, value: "host.example", action: .allow),
            PolicyRule(kind: .address, value: "9.9.9.0/24", action: .deny),
        ])
        let verdict = engine.evaluate(appID: app, hostname: "host.example",
                                      address: IPPrefix("9.9.9.9"))
        #expect(verdict.action == .deny)
    }

    @Test("deny wins when the same value is declared both ways")
    func denyWinsDuplicateRule() {
        let engine = engine([
            PolicyRule(kind: .domainExact, value: "dup.example", action: .allow),
            PolicyRule(kind: .domainExact, value: "dup.example", action: .deny),
        ])
        #expect(engine.evaluate(appID: app, hostname: "dup.example", address: nil).action == .deny)
    }

    @Test("substring rules catch registrable domains a suffix chain misses")
    func substringCatchesSiblings() {
        let engine = engine([PolicyRule(kind: .domainSubstring, value: "google", action: .deny)])
        for host in ["www.google.com", "googleapis.com", "rr3---sn-x.googlevideo.com", "google.co.uk"] {
            #expect(engine.evaluate(appID: app, hostname: host, address: nil).action == .deny)
        }
        #expect(engine.evaluate(appID: app, hostname: "apple.com", address: nil).action == .allow)
    }

    @Test("longest address prefix wins")
    func longestPrefixWins() {
        let engine = engine([
            PolicyRule(kind: .address, value: "10.0.0.0/8", action: .deny),
            PolicyRule(kind: .address, value: "10.1.0.0/16", action: .allow),
            PolicyRule(kind: .address, value: "10.1.2.3/32", action: .deny),
        ])
        #expect(engine.evaluate(appID: app, hostname: nil, address: IPPrefix("10.9.9.9")).action == .deny)
        #expect(engine.evaluate(appID: app, hostname: nil, address: IPPrefix("10.1.9.9")).action == .allow)
        #expect(engine.evaluate(appID: app, hostname: nil, address: IPPrefix("10.1.2.3")).action == .deny)
    }

    @Test("IPv6 prefixes match independently of IPv4")
    func ipv6Independent() {
        let engine = engine([
            PolicyRule(kind: .address, value: "2606:4700::/32", action: .deny),
            PolicyRule(kind: .address, value: "1.0.0.0/8", action: .allow),
        ])
        #expect(engine.evaluate(appID: app, hostname: nil,
                                address: IPPrefix("2606:4700:4700::1111")).action == .deny)
        #expect(engine.evaluate(appID: app, hostname: nil,
                                address: IPPrefix("2607:f8b0::1")).action != .deny)
        #expect(engine.evaluate(appID: app, hostname: nil, address: IPPrefix("1.2.3.4")).action == .allow)
    }

    @Test("a flow with neither hostname nor address falls to the blanket default")
    func noFactsFallsThrough() {
        let engine = engine([PolicyRule(kind: .domainExact, value: "x.example", action: .allow)])
        // An app with no entry inherits the default for its kind.
        #expect(engine.evaluate(appID: "TEAM.com.third.party", hostname: nil, address: nil).action == .deny)
        #expect(engine.evaluate(appID: ".com.apple.mobilesafari", hostname: nil, address: nil).action == .allow)
    }

    @Test("an unmatched host under deny-all is denied by the blanket, not by a rule")
    func unmatchedIsBlanketDenied() {
        let policy = PolicyCompiler.compile(PolicyDocument(
            userRules: [PolicyRule(kind: .domainSubstring, value: "google", action: .deny)]))
        let verdict = PolicyEngine(policy: policy)
            .evaluate(appID: "TEAM.com.third.party", hostname: "apple.com", address: nil)
        #expect(verdict.action == .deny)
        #expect(verdict.source == .blanket)   // the substring rule did not match
        #expect(verdict.ruleIndex == nil)
    }

    @Test("hostnames are matched case-insensitively and without a trailing dot")
    func hostNormalisation() {
        let engine = engine([PolicyRule(kind: .domainExact, value: "Example.COM", action: .deny)])
        for host in ["example.com", "EXAMPLE.com", "example.com."] {
            #expect(engine.evaluate(appID: app, hostname: host, address: nil).action == .deny)
        }
    }

    @Test("a matched verdict reports which tier and rule decided it")
    func verdictIsAttributable() {
        let engine = engine([PolicyRule(kind: .domainSuffix, value: "example.com", action: .deny)])
        let verdict = engine.evaluate(appID: app, hostname: "a.example.com", address: nil)
        #expect(verdict.source == .userList)
        #expect(engine.label(for: verdict) == "userList:deny:*.example.com")
    }
}
