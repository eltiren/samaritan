import Foundation
import Testing
@testable import SamaritanTests

/// "Reset counters" is the app clearing a ring it does not write to — the one place the
/// single-writer rule is broken. The provider notices via a token in the header, so these pin the
/// property that token has to have: it must differ across *every* reset, including two that land in
/// the same second. A reset the provider does not notice is not a slow reset, it is a reset that
/// visibly works and then silently reverts on the next flow.
@Suite("Diagnostics reset")
struct DiagnosticsResetTests {

    private static let slots = 8

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("flows-\(UUID().uuidString).ring")
    }

    /// Two stores over one file, which is exactly the production shape here: `provider` is the
    /// long-lived writer holding cached counters, `app` is the process that clears them.
    private func stores() throws -> (provider: DiagnosticsStore, app: DiagnosticsStore, url: URL) {
        let url = temporaryURL()
        let provider = try #require(DiagnosticsStore(fileURL: url, slotCount: Self.slots))
        let app = try #require(DiagnosticsStore(fileURL: url, slotCount: Self.slots))
        return (provider, app, url)
    }

    // MARK: - The collisions

    /// The reported case: the ring is created and the user taps Reset in the same second. A
    /// second-resolution token writes back the value the provider already holds, so the provider
    /// sees no reset and its next write restores the counters and the sequence number.
    @Test("A reset in the same second as the ring's creation is still noticed")
    func resetImmediatelyAfterCreation() throws {
        let (provider, app, url) = try stores()
        defer { try? FileManager.default.removeItem(at: url) }

        provider.increment([.flowsObserved: 100, .flowsDropped: 7])
        app.reset()
        provider.increment([.flowsObserved: 1])

        let after = provider.snapshot()
        #expect(after[.flowsObserved] == 1)
        #expect(after[.flowsDropped] == 0)
    }

    /// Two taps in one second. The first reset is adopted; the second writes the same second again,
    /// so without a distinct token the provider keeps accumulating against a header it thinks it is
    /// already in step with.
    @Test("Two resets within one second are two resets")
    func twoResetsInOneSecond() throws {
        let (provider, app, url) = try stores()
        defer { try? FileManager.default.removeItem(at: url) }

        app.reset()
        provider.increment([.flowsObserved: 50])
        app.reset()
        provider.increment([.flowsObserved: 3])

        #expect(provider.snapshot()[.flowsObserved] == 3)
    }

    /// The token is what makes the two distinguishable, so it has to actually move — and keep
    /// moving, in the same direction, no matter how fast the taps come.
    @Test("The generation strictly increases across resets in the same second")
    func generationStrictlyIncreases() throws {
        let (provider, app, url) = try stores()
        defer { try? FileManager.default.removeItem(at: url) }

        var seen = [provider.countersGeneration]
        for _ in 0..<5 {
            app.reset()
            provider.increment([.flowsObserved: 1])
            seen.append(provider.countersGeneration)
        }
        #expect(seen == seen.sorted())
        #expect(Set(seen).count == seen.count)
    }

    // MARK: - What adoption has to clear

    /// The sequence number is cached too, and a stale one written back over a truncated file makes
    /// `snapshot` walk slots that no longer hold the records it thinks they do.
    @Test("Adopting a reset restarts the record sequence")
    func adoptionRestartsTheSequence() throws {
        let (provider, app, url) = try stores()
        defer { try? FileManager.default.removeItem(at: url) }

        for _ in 0..<5 { provider.append(FlowRecord()) }
        #expect(provider.snapshot().totalWritten == 5)

        app.reset()
        provider.append(FlowRecord())

        let after = provider.snapshot()
        #expect(after.totalWritten == 1)
        #expect(after.records.count == 1)
    }

    /// The counters epoch handed to `ObservedStore` is this token, so a reset the ring notices has
    /// to be a reset the per-app byte totals notice as well — they are the same measurement split
    /// by app, and one cleared without the other is a disagreement with no way to tell which side
    /// is wrong.
    @Test("The generation handed to the observed store changes on every reset")
    func generationReachesTheObservedStore() throws {
        let (provider, app, url) = try stores()
        defer { try? FileManager.default.removeItem(at: url) }

        let observedURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("observed-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: observedURL) }
        let observed = ObservedStore(fileURL: observedURL)

        observed.addTraffic(appID: "A1B2C3D4E5.com.netflix.Netflix", inbound: 9_000, outbound: 100,
                            countersEpoch: provider.countersGeneration)
        #expect(observed.snapshot().first?.bytesInbound == 9_000)

        app.reset()
        provider.increment([.flowsObserved: 1])
        observed.addTraffic(appID: "A1B2C3D4E5.com.netflix.Netflix", inbound: 5, outbound: 0,
                            countersEpoch: provider.countersGeneration)

        #expect(observed.snapshot().first?.bytesInbound == 5)
    }

    // MARK: - Compatibility

    /// Writes a ring in the shape that shipped before the generation existed: a valid header with
    /// nothing at the generation's offset. The offsets are spelled out rather than taken from the
    /// store, which is the point — if the counter block ever moves, every ring already on a device
    /// is misread, and this is the test that says so.
    private func legacyRing(at url: URL, epochSeconds: UInt64, flowsObserved: UInt64) throws {
        var bytes = [UInt8](repeating: 0, count: 4096 + Self.slots * FlowRecordCodec.slotSize)
        func store<T>(_ value: T, at offset: Int) {
            withUnsafeBytes(of: value) { raw in
                for (index, byte) in raw.enumerated() { bytes[offset + index] = byte }
            }
        }
        store(UInt32(0x53_4D_52_54), at: 0)                 // magic, "SMRT"
        store(UInt32(1), at: 4)                             // version
        store(UInt32(FlowRecordCodec.slotSize), at: 8)
        store(UInt32(Self.slots), at: 12)
        store(UInt64(1), at: 16)                            // nextSequence
        store(epochSeconds, at: 24)
        store(flowsObserved, at: 32)                        // counter block, .flowsObserved == 0
        // Offset 288 — the generation — is deliberately left zero: this ring predates the field.
        try Data(bytes).write(to: url)
    }

    /// A ring written before the generation existed reads 0 there. Every process opening it has to
    /// seed the same value, or one of them sees a reset that never happened and throws away
    /// counters nobody asked it to clear — the mirror image of the bug this token exists to fix.
    @Test("A ring predating the generation is not read as a reset")
    func legacyRingIsNotAPhantomReset() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }

        let epoch: UInt64 = 1_700_000_000
        try legacyRing(at: url, epochSeconds: epoch, flowsObserved: 42)

        let provider = try #require(DiagnosticsStore(fileURL: url, slotCount: Self.slots))
        let app = try #require(DiagnosticsStore(fileURL: url, slotCount: Self.slots))
        #expect(provider.countersGeneration == epoch)
        #expect(app.countersGeneration == epoch)

        provider.increment([.flowsObserved: 1])
        #expect(provider.snapshot()[.flowsObserved] == 43)
    }

    /// And once such a ring is reset, the token has to leave the seconds origin behind for good.
    @Test("A reset on a legacy ring moves past its seconds origin")
    func legacyRingResetsForward() throws {
        let url = temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }

        let epoch: UInt64 = 1_700_000_000
        try legacyRing(at: url, epochSeconds: epoch, flowsObserved: 42)

        let provider = try #require(DiagnosticsStore(fileURL: url, slotCount: Self.slots))
        let app = try #require(DiagnosticsStore(fileURL: url, slotCount: Self.slots))

        app.reset()
        #expect(app.countersGeneration > epoch)

        provider.increment([.flowsObserved: 1])
        #expect(provider.snapshot()[.flowsObserved] == 1)
        #expect(provider.countersGeneration == app.countersGeneration)
    }
}
