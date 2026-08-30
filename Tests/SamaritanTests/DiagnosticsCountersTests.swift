import Foundation
import Testing
@testable import SamaritanTests

/// The counters are the only quantitative claim the app makes, and a 12 GB total that nobody can
/// check is indistinguishable from an accounting bug. These pin the two properties that make one
/// checkable: it covers a known window, and no writer's contribution is counted twice.
@Suite("Diagnostics counters")
struct DiagnosticsCountersTests {

    private func snapshot(_ counters: [DiagnosticsStore.Counter: UInt64],
                          since: Date?) -> DiagnosticsStore.Snapshot {
        var snapshot = DiagnosticsStore.Snapshot()
        snapshot.counters = counters
        snapshot.countersSince = since
        return snapshot
    }

    @Test("A rate is derived from the counting window, not from wall clock alone")
    func rateUsesTheWindow() {
        let hour = Date().addingTimeInterval(-3600)
        let value = snapshot([.reportedBytesInbound: 1_000_000], since: hour)
        let rate = try! #require(value.perHour(.reportedBytesInbound))
        // One hour of accumulation, so the rate is the total, give or take the test's own runtime.
        #expect(abs(rate - 1_000_000) < 10_000)
    }

    @Test("Without an epoch there is no rate, rather than a made-up one")
    func noEpochMeansNoRate() {
        let value = snapshot([.reportedBytesInbound: 1_000_000], since: nil)
        #expect(value.perHour(.reportedBytesInbound) == nil)
        #expect(value.countingInterval == nil)
    }

    /// Merged totals only span as far back as the younger ring — the older one's extra history is
    /// not in the other's counters, so quoting the earlier epoch would understate every rate.
    @Test("Merging two rings reports the younger epoch")
    func mergeTakesTheYoungerEpoch() {
        let older = Date(timeIntervalSince1970: 1_000_000)
        let newer = Date(timeIntervalSince1970: 2_000_000)
        #expect(snapshot([:], since: older).merged(with: snapshot([:], since: newer))
                    .countersSince == newer)
        #expect(snapshot([:], since: newer).merged(with: snapshot([:], since: older))
                    .countersSince == newer)
    }

    @Test("A missing epoch on one side does not erase the other")
    func mergeToleratesAMissingEpoch() {
        let when = Date(timeIntervalSince1970: 1_000_000)
        #expect(snapshot([:], since: nil).merged(with: snapshot([:], since: when))
                    .countersSince == when)
        #expect(snapshot([:], since: nil).merged(with: snapshot([:], since: nil))
                    .countersSince == nil)
    }

    /// `merged` sums every counter, so a counter both providers increment for the *same*
    /// `NEFilterReport` would double every byte on the device. The byte counters therefore have
    /// exactly one writer. This is the regression test for reinstating the other one.
    @Test("Byte counters have a single writer, so merging cannot double them")
    func byteCountersAreNotDoubleCounted() throws {
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("FilterData/FilterDataProvider.swift"),
            encoding: .utf8)
        #expect(!source.contains("reportedBytesInbound"))
        #expect(!source.contains("reportedBytesOutbound"))
    }

    /// Summing is only ever correct for a counter one process owns. `reportsData` and
    /// `reportsControl` are separate for exactly this reason — both providers see every report.
    @Test("The two report counters are distinct")
    func reportCountersAreSeparate() {
        let data = snapshot([.reportsData: 3], since: nil)
        let control = snapshot([.reportsControl: 5], since: nil)
        let merged = data.merged(with: control)
        #expect(merged[.reportsData] == 3)
        #expect(merged[.reportsControl] == 5)
    }
}
