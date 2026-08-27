import Foundation
import Testing
@testable import SamaritanTests

@Suite("Policy blob format")
struct PolicyBlobTests {

    private func sampleDocument() -> PolicyDocument {
        PolicyDocument(
            apps: [
                AppPolicy(appID: "TEAM.com.a.app", rules: [
                    PolicyRule(kind: .domainSuffix, value: "example.com", action: .allow),
                    PolicyRule(kind: .address, value: "10.0.0.0/8", action: .deny),
                ]),
                AppPolicy(appID: ".com.apple.mobilesafari"),
            ],
            userRules: [PolicyRule(kind: .domainExact, value: "user.example", action: .deny)],
            webLists: [WebList(name: "l", url: URL(string: "https://x.invalid")!, action: .deny,
                               lines: ["ads.example", "# comment", "0.0.0.0 hosts.example"],
                               lastFetchedAt: Date())],
            generation: 7)
    }

    @Test("a serialised policy resolves identically to the compiler's own arrays")
    func blobMatchesInMemory() {
        let compiled = PolicyCompiler.compile(sampleDocument())
        let data = PolicyBlob.serialise(compiled)

        let cases: [(String, String?, IPPrefix?)] = [
            ("TEAM.com.a.app", "a.example.com", nil),
            ("TEAM.com.a.app", nil, IPPrefix("10.1.2.3")),
            ("TEAM.com.a.app", "user.example", nil),
            ("TEAM.com.b.app", "ads.example", nil),
            ("TEAM.com.b.app", "sub.ads.example", nil),
            ("TEAM.com.b.app", "hosts.example", nil),
            (".com.apple.mobilesafari", "anything.example", nil),
            ("TEAM.com.unknown", "anything.example", nil),
        ]

        let direct = compiled.withView { view in
            cases.map { PolicyEngine(view: view).evaluate(appID: $0.0, hostname: $0.1, address: $0.2) }
        }
        let mapped = data.withUnsafeBytes { raw -> [PolicyEngine.Verdict] in
            let view = try! PolicyBlob.view(over: raw.baseAddress!, length: raw.count)
            return cases.map { PolicyEngine(view: view).evaluate(appID: $0.0, hostname: $0.1, address: $0.2) }
        }
        #expect(direct == mapped)
    }

    @Test("the generation survives the round trip and is readable from the header alone")
    func generationRoundTrips() throws {
        let data = PolicyBlob.serialise(PolicyCompiler.compile(sampleDocument()))
        data.withUnsafeBytes { raw in
            let view = try! PolicyBlob.view(over: raw.baseAddress!, length: raw.count)
            #expect(view.generation == 7)
        }

        // The hot-path staleness check reads only the header, never the whole file.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("policy-\(UUID().uuidString).bin")
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(PolicyBlob.generation(ofFileAt: url.path) == 7)
    }

    @Test("labels survive the round trip so a verdict stays attributable")
    func labelsRoundTrip() {
        let data = PolicyBlob.serialise(PolicyCompiler.compile(
            PolicyDocument(userRules: [PolicyRule(kind: .domainSuffix, value: "example.com", action: .deny)])))
        data.withUnsafeBytes { raw in
            let engine = PolicyEngine(view: try! PolicyBlob.view(over: raw.baseAddress!, length: raw.count))
            let verdict = engine.evaluate(appID: "T.app", hostname: "a.example.com", address: nil)
            #expect(engine.label(for: verdict) == "userList:deny:*.example.com")
        }
    }

    @Test("garbage is rejected rather than misread")
    func rejectsGarbage() {
        var data = Data(repeating: 0xAB, count: 512)
        data.withUnsafeBytes { raw in
            #expect(throws: PolicyBlob.LoadError.self) {
                _ = try PolicyBlob.view(over: raw.baseAddress!, length: raw.count)
            }
        }
    }

    @Test("a truncated file is rejected")
    func rejectsTruncation() {
        let full = PolicyBlob.serialise(PolicyCompiler.compile(sampleDocument()))
        let truncated = full.prefix(full.count / 2)
        truncated.withUnsafeBytes { raw in
            #expect(throws: PolicyBlob.LoadError.self) {
                _ = try PolicyBlob.view(over: raw.baseAddress!, length: raw.count)
            }
        }
    }

    @Test("a header shorter than the fixed size is rejected")
    func rejectsShortHeader() {
        let data = Data(repeating: 0, count: 8)
        data.withUnsafeBytes { raw in
            #expect(throws: PolicyBlob.LoadError.tooSmall) {
                _ = try PolicyBlob.view(over: raw.baseAddress!, length: raw.count)
            }
        }
    }

    @Test("record strides are what the header claims")
    func strideAgreement() {
        // The reader refuses a blob whose strides disagree, so a layout change fails loudly rather
        // than misreading every rule. These pin the current layout.
        #expect(MemoryLayout<CompiledPolicy.DomainEntry>.stride == 12)
        #expect(MemoryLayout<CompiledPolicy.TrieNode>.stride == 16)
        #expect(MemoryLayout<CompiledPolicy.RuleSet>.stride == 32)
        #expect(MemoryLayout<CompiledPolicy.AppEntry>.stride == 12)
        #expect(MemoryLayout<CompiledPolicy.LabelRef>.stride == 8)
    }

    @Test("an empty policy is still a valid blob that denies unknown apps")
    func emptyPolicyIsValid() {
        let data = PolicyBlob.serialise(PolicyCompiler.compile(PolicyDocument()))
        data.withUnsafeBytes { raw in
            let engine = PolicyEngine(view: try! PolicyBlob.view(over: raw.baseAddress!, length: raw.count))
            #expect(engine.evaluate(appID: "T.com.x", hostname: "a.example", address: nil).action == .deny)
            #expect(engine.evaluate(appID: ".com.apple.x", hostname: "a.example", address: nil).action == .allow)
        }
    }
}
