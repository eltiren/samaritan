import Foundation
import Testing
@testable import SamaritanTests

/// Bypass is the one tier that is *not* in `PolicyEngine` — it is decided in the provider before
/// the policy is consulted at all. What can be tested off-device is everything that decides whether
/// the hot path's single membership test will ever return true: what gets published, in what form,
/// and what happens when the file is missing or damaged.
@Suite("Bypass — publication and matching")
struct BypassTests {

    private let netflix = "A1B2C3D4E5.com.netflix.Netflix"
    private let slack = "BQR82RBBHL.com.tinyspeck.chatlyio"

    // MARK: - What gets published

    @Test("Only bypassed apps are published, as the raw identifier")
    func publishesOnlyBypassedApps() {
        let document = PolicyDocument(apps: [
            AppPolicy(appID: netflix, bypass: true),
            AppPolicy(appID: slack),
        ])
        #expect(document.bypassedIdentifiers == [netflix])
    }

    /// The whole rule class is worthless if the stored value is not what the flow carries.
    /// `sourceAppIdentifier` is `<teamID>.<bundleID>`, so a bundle ID never matches.
    @Test("A bundle ID is not a source app identifier and must not match")
    func bundleIDDoesNotMatch() throws {
        let gate = try publish([netflix])
        #expect(gate.contains(netflix))
        #expect(!gate.contains("com.netflix.Netflix"))
        #expect(!gate.contains(".com.netflix.Netflix"))
    }

    @Test("The unattributed pseudo-identifier is never published")
    func unattributedIsNeverPublished() {
        let document = PolicyDocument(apps: [
            AppPolicy(appID: AppIdentity.unattributedRaw, bypass: true),
        ])
        #expect(document.bypassedIdentifiers.isEmpty)
        #expect(BypassList.sanitise([AppIdentity.unattributedRaw, "", "   "]).isEmpty)
    }

    @Test("Sanitising dedupes, trims and sorts")
    func sanitiseNormalises() {
        #expect(BypassList.sanitise([" \(slack) ", netflix, slack]) == [netflix, slack].sorted())
    }

    // MARK: - Precedence

    /// Bypass beats everything, including a policy that denies the app outright. Nothing about the
    /// app's rules or blanket can suppress publication, because nothing about them is consulted.
    @Test("An app that policy denies everywhere is still published as bypassed")
    func bypassIsIndependentOfEveryOtherTier() {
        let document = PolicyDocument(
            apps: [AppPolicy(appID: netflix, blanket: .denyAll,
                             rules: [PolicyRule(kind: .domainSuffix, value: "*.nflxvideo.net",
                                                action: .deny)],
                             bypass: true)],
            userRules: [PolicyRule(kind: .domainSubstring, value: "netflix", action: .deny)])
        #expect(document.bypassedIdentifiers == [netflix])
    }

    // MARK: - Back-compatibility

    /// Adding a non-optional field to a synthesised `Codable` throws `keyNotFound` on every
    /// document written before it. For this type that would silently reset the entire firewall to
    /// empty on upgrade, so the decoder is hand-written and this pins it.
    @Test("A policy saved before bypass existed still decodes")
    func decodesDocumentsWrittenBeforeBypass() throws {
        let json = """
        {"apps":[{"appID":"\(netflix)","blanket":1,"rules":[]}],
         "userRules":[],"webLists":[],"generation":7}
        """
        let document = try JSONDecoder().decode(PolicyDocument.self, from: Data(json.utf8))
        #expect(document.apps.count == 1)
        #expect(document[netflix]?.bypass == false)
        #expect(document[netflix]?.bypassSince == nil)
        #expect(document[netflix]?.blanket == .allowAll)
    }

    @Test("Bypass survives a round trip")
    func roundTrips() throws {
        let when = Date(timeIntervalSince1970: 1_700_000_000)
        let original = PolicyDocument(apps: [
            AppPolicy(appID: netflix, bypass: true, bypassSince: when),
        ])
        let decoded = try JSONDecoder().decode(
            PolicyDocument.self, from: JSONEncoder().encode(original))
        #expect(decoded[netflix]?.bypass == true)
        #expect(decoded[netflix]?.bypassSince == when)
    }

    // MARK: - The gate

    @Test("An absent file means nothing is bypassed")
    func absentFileBypassesNothing() {
        let gate = BypassGate()
        gate.start(url: temporaryURL())
        #expect(gate.currentIdentifiers.isEmpty)
        #expect(!gate.contains(netflix))
    }

    @Test("A gate with no file at all bypasses nothing")
    func noURLBypassesNothing() {
        let gate = BypassGate()
        gate.start(url: nil)
        #expect(!gate.contains(netflix))
    }

    /// A damaged file must not silently disarm every bypass the user set. Failing towards the last
    /// good set is the opposite of the policy loader's rule for a *deny* list, and deliberately so:
    /// there, failing open would under-block; here, dropping a bypass would break a working app.
    @Test("A corrupt file keeps the last good set")
    func corruptFileKeepsLastGood() throws {
        let url = temporaryURL()
        let gate = try publish([netflix], at: url)
        #expect(gate.contains(netflix))

        try Data("{ not json".utf8).write(to: url)
        gate.reloadSynchronouslyForTesting()
        #expect(gate.contains(netflix))
    }

    @Test("A file from a future version keeps the last good set")
    func unknownVersionKeepsLastGood() throws {
        let url = temporaryURL()
        let gate = try publish([netflix], at: url)

        var future = BypassList(identifiers: [slack])
        future.version = BypassList.currentVersion + 1
        try JSONEncoder().encode(future).write(to: url)
        gate.reloadSynchronouslyForTesting()

        #expect(gate.contains(netflix))
        #expect(!gate.contains(slack))
    }

    @Test("Deleting the file clears the set")
    func deletedFileClearsTheSet() throws {
        let url = temporaryURL()
        let gate = try publish([netflix], at: url)
        #expect(gate.contains(netflix))

        try FileManager.default.removeItem(at: url)
        gate.reloadSynchronouslyForTesting()
        #expect(!gate.contains(netflix))
    }

    @Test("A new set replaces the old one")
    func republishReplaces() throws {
        let url = temporaryURL()
        let gate = try publish([netflix], at: url)
        try JSONEncoder().encode(BypassList(generation: 2, identifiers: [slack])).write(to: url)
        gate.reloadSynchronouslyForTesting()
        #expect(gate.contains(slack))
        #expect(!gate.contains(netflix))
    }

    // MARK: - Helpers

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("bypass-\(UUID().uuidString).json")
    }

    @discardableResult
    private func publish(_ identifiers: [String], at url: URL? = nil) throws -> BypassGate {
        let url = url ?? temporaryURL()
        try JSONEncoder().encode(BypassList(generation: 1, identifiers: identifiers)).write(to: url)
        let gate = BypassGate()
        gate.start(url: url)
        return gate
    }
}
