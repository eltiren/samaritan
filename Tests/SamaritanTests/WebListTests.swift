import Foundation
import Testing
@testable import SamaritanTests

@Suite("Web list parsing and validation")
struct WebListTests {

    private func data(_ text: String) -> Data { Data(text.utf8) }

    @Test("a plain domain list parses")
    func plainList() throws {
        let lines = try WebListParser.lines(from: data("ads.example\ntracker.example\n"))
        #expect(lines == ["ads.example", "tracker.example"])
        #expect(try WebListParser.validate(lines: lines, action: .deny).count == 2)
    }

    @Test("comments and blank lines are ignored when compiling")
    func commentsIgnored() {
        let rules = PolicyDocument.rules(
            from: ["# header", "", "  ads.example  ", "keep.example # trailing"], action: .deny)
        let values = Set(rules.map(\.value))
        #expect(values == ["ads.example", "keep.example"])
    }

    @Test("hosts-file format drops the address column")
    func hostsFileFormat() {
        let rules = PolicyDocument.rules(from: ["0.0.0.0 bad.example", "127.0.0.1 also.example"],
                                         action: .deny)
        #expect(Set(rules.map(\.value)) == ["bad.example", "also.example"])
        #expect(!rules.contains { $0.kind == .address })
    }

    @Test("a bare domain in a list covers the domain and its subdomains")
    func bareDomainExpands() {
        // Blocklist authors write `doubleclick.net` meaning everything under it too. Applying the
        // strict hand-written semantics here would under-block by a wide margin, silently.
        let rules = PolicyDocument.rules(from: ["doubleclick.net"], action: .deny)
        #expect(rules.count == 2)
        #expect(rules.contains { $0.kind == .domainExact && $0.value == "doubleclick.net" })
        #expect(rules.contains { $0.kind == .domainSuffix && $0.value == "doubleclick.net" })
    }

    @Test("an explicit wildcard entry stays subdomains-only")
    func explicitWildcardStaysNarrow() {
        let rules = PolicyDocument.rules(from: ["*.doubleclick.net"], action: .deny)
        #expect(rules.count == 1)
        #expect(rules[0].kind == .domainSuffix)
    }

    @Test("CIDR and bare addresses become address rules")
    func addressEntries() {
        let rules = PolicyDocument.rules(from: ["10.0.0.0/8", "2606:4700::/32", "8.8.8.8"],
                                         action: .deny)
        #expect(rules.count == 3)
        #expect(rules.allSatisfy { $0.kind == .address })
    }

    @Test("empty input is rejected")
    func rejectsEmpty() {
        #expect(throws: WebListParser.Failure.empty) { _ = try WebListParser.lines(from: Data()) }
    }

    @Test("an oversized list is rejected before it is parsed")
    func rejectsOversized() {
        let big = Data(repeating: UInt8(ascii: "a"), count: WebListParser.maximumBytes + 1)
        #expect(throws: WebListParser.Failure.self) { _ = try WebListParser.lines(from: big) }
    }

    @Test("a page of HTML is rejected rather than subscribed to as zero rules")
    func rejectsHTML() throws {
        // Every line parses as *something* by shape, so the guard is that it must yield rules —
        // this is the realistic failure when a URL 404s to a styled error page.
        let lines = try WebListParser.lines(from: data("# <html>\n#   <body>404</body>\n# </html>"))
        #expect(throws: WebListParser.Failure.noUsableEntries) {
            _ = try WebListParser.validate(lines: lines, action: .deny)
        }
    }

    @Test("a disabled subscription contributes nothing")
    func disabledListIsInert() {
        var list = WebList(name: "l", url: URL(string: "https://x.invalid")!, action: .deny,
                           lines: ["blocked.example"], lastFetchedAt: Date())
        list.isEnabled = false
        let data = PolicyBlob.serialise(PolicyCompiler.compile(PolicyDocument(webLists: [list])))
        data.withUnsafeBytes { raw in
            let engine = PolicyEngine(view: try! PolicyBlob.view(over: raw.baseAddress!, length: raw.count))
            #expect(engine.evaluate(appID: ".com.apple.x", hostname: "blocked.example",
                                    address: nil).action == .allow)
        }
    }

    @Test("an enabled subscription reaches every app")
    func enabledListReachesEveryApp() {
        let list = WebList(name: "l", url: URL(string: "https://x.invalid")!, action: .deny,
                           lines: ["blocked.example"], lastFetchedAt: Date())
        let data = PolicyBlob.serialise(PolicyCompiler.compile(PolicyDocument(webLists: [list])))
        data.withUnsafeBytes { raw in
            let engine = PolicyEngine(view: try! PolicyBlob.view(over: raw.baseAddress!, length: raw.count))
            // Including Apple apps, whose Allow-all is only a blanket default.
            #expect(engine.evaluate(appID: ".com.apple.mobilesafari", hostname: "blocked.example",
                                    address: nil).action == .deny)
            #expect(engine.evaluate(appID: ".com.apple.mobilesafari", hostname: "sub.blocked.example",
                                    address: nil).action == .deny)
        }
    }
}
