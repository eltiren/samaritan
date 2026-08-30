import Foundation
import Testing
@testable import SamaritanTests

/// Per-app byte totals are the global `reportedBytes*` counters split by app — the same reports,
/// the same arithmetic — so they are only worth anything if they add up to the same number and are
/// cleared by the same reset. These pin both, plus the upgrade path: the totals were added to a
/// file format that was already on devices holding history worth keeping.
@Suite("Per-app traffic")
struct AppTrafficTests {

    private let netflix = "A1B2C3D4E5.com.netflix.Netflix"
    private let slack = "BQR82RBBHL.com.tinyspeck.chatlyio"

    private func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("observed-\(UUID().uuidString).json")
    }

    // MARK: - Upgrading a file that is already on devices

    /// The trap `AppPolicy` hit first: synthesised `Codable` ignores property defaults, so a
    /// non-optional field added to a shipped type throws `keyNotFound` on every file written before
    /// it. Here that would have silently erased every app's destination history.
    @Test("An app written before the byte totals existed still decodes")
    func decodesAppsWrittenBeforeTraffic() throws {
        let json = """
        {"appID":"\(netflix)","destinations":{},"lastSeen":0,"allowedCount":3,"deniedCount":1}
        """
        let app = try JSONDecoder().decode(ObservedApp.self, from: Data(json.utf8))
        #expect(app.allowedCount == 3)
        #expect(app.bytesInbound == 0)
        #expect(app.bytesOutbound == 0)
    }

    @Test("Totals survive a round trip")
    func appRoundTrips() throws {
        let app = ObservedApp(appID: netflix, bytesInbound: 4_000, bytesOutbound: 900)
        let decoded = try JSONDecoder().decode(
            ObservedApp.self, from: JSONEncoder().encode(app))
        #expect(decoded.bytesInbound == 4_000)
        #expect(decoded.bytesOutbound == 900)
    }

    /// `observed.json` used to be a bare `[appID: ObservedApp]` map with no envelope around it.
    /// Reading one has to keep the history rather than start from empty.
    @Test("A legacy bare map is still readable, with the totals starting at zero")
    func readsLegacyBareMap() throws {
        let url = temporaryURL()
        let legacy = [netflix: ObservedApp(
            appID: netflix,
            destinations: ["nflxvideo.net": ObservedDestination(
                host: "nflxvideo.net", addresses: [], ports: [443], attempts: 7,
                firstSeen: Date(), lastSeen: Date(), denied: false, lastRule: nil)],
            lastSeen: Date(), allowedCount: 7, deniedCount: 0)]
        try JSONEncoder().encode(legacy).write(to: url)

        let store = ObservedStore(fileURL: url)
        let apps = store.snapshot()
        #expect(apps.count == 1)
        #expect(apps.first?.destinations.count == 1)
        #expect(apps.first?.bytesInbound == 0)
        #expect(store.currentCountersEpoch == 0)
    }

    /// The envelope's `version` is required precisely so this cannot happen: if every key were
    /// optional, a legacy map would decode as an empty envelope and wipe what it was meant to keep.
    @Test("A legacy map does not decode as an empty envelope")
    func legacyMapIsNotMistakenForAnEnvelope() throws {
        let legacy = [netflix: ObservedApp(appID: netflix)]
        let data = try JSONEncoder().encode(legacy)
        #expect((try? JSONDecoder().decode(ObservedFile.self, from: data)) == nil)
    }

    // MARK: - Accumulating

    @Test("Bytes accumulate per app and stay separate")
    func trafficAccumulates() {
        let store = ObservedStore(fileURL: temporaryURL())
        store.addTraffic(appID: netflix, inbound: 1_000, outbound: 200, countersEpoch: 1)
        store.addTraffic(appID: netflix, inbound: 500, outbound: 50, countersEpoch: 1)
        store.addTraffic(appID: slack, inbound: 7, outbound: 9, countersEpoch: 1)

        let apps = Dictionary(uniqueKeysWithValues: store.snapshot().map { ($0.appID, $0) })
        #expect(apps[netflix]?.bytesInbound == 1_500)
        #expect(apps[netflix]?.bytesOutbound == 250)
        #expect(apps[slack]?.bytesInbound == 7)
    }

    /// The invariant the whole feature rests on: this sum is what the `reportedBytes*` counters
    /// hold, because both are fed the same numbers from the same place.
    @Test("The per-app totals sum to what was reported")
    func totalsSumToTheReportedFigure() {
        let store = ObservedStore(fileURL: temporaryURL())
        let reports: [(String, UInt64, UInt64)] = [
            (netflix, 12_000, 300), (slack, 400, 1_100), (netflix, 8, 9), (slack, 1, 0),
        ]
        for (app, inbound, outbound) in reports {
            store.addTraffic(appID: app, inbound: inbound, outbound: outbound, countersEpoch: 1)
        }
        let snapshot = store.snapshot()
        #expect(snapshot.reduce(0) { $0 + $1.bytesInbound } == reports.reduce(0) { $0 + $1.1 })
        #expect(snapshot.reduce(0) { $0 + $1.bytesOutbound } == reports.reduce(0) { $0 + $1.2 })
    }

    /// A report can arrive with no source app. Its bytes still happened, and dropping them would
    /// put the per-app sum permanently below the counter it is supposed to match.
    @Test("Unattributed bytes are kept under the pseudo-identifier")
    func unattributedTrafficIsKept() {
        let store = ObservedStore(fileURL: temporaryURL())
        store.addTraffic(appID: "", inbound: 64, outbound: 32, countersEpoch: 1)
        #expect(store.snapshot().first?.appID == AppIdentity.unattributedRaw)
        #expect(store.snapshot().first?.bytesInbound == 64)
    }

    /// Most reports are `newFlow`, which carries no byte counts. They must not conjure app rows.
    @Test("A report with no bytes creates nothing")
    func zeroByteReportsCreateNothing() {
        let store = ObservedStore(fileURL: temporaryURL())
        store.addTraffic(appID: netflix, inbound: 0, outbound: 0, countersEpoch: 1)
        #expect(store.snapshot().isEmpty)
    }

    // MARK: - Reset

    /// The provider side of the handshake. The app resets the counters, which stamps a new epoch
    /// into the ring header; the provider sees it on the next report and clears its own totals.
    @Test("A new counters epoch clears the totals")
    func newEpochClearsTotals() {
        let store = ObservedStore(fileURL: temporaryURL())
        store.addTraffic(appID: netflix, inbound: 1_000, outbound: 1_000, countersEpoch: 1)
        store.addTraffic(appID: netflix, inbound: 5, outbound: 0, countersEpoch: 2)

        #expect(store.snapshot().first?.bytesInbound == 5)
        #expect(store.snapshot().first?.bytesOutbound == 0)
        #expect(store.currentCountersEpoch == 2)
    }

    @Test("The same epoch clears nothing")
    func sameEpochKeepsTotals() {
        let store = ObservedStore(fileURL: temporaryURL())
        store.addTraffic(appID: netflix, inbound: 1_000, outbound: 0, countersEpoch: 7)
        store.addTraffic(appID: netflix, inbound: 1, outbound: 0, countersEpoch: 7)
        #expect(store.snapshot().first?.bytesInbound == 1_001)
    }

    /// A ring written before the epoch field reads 0. Treating that as a reset would clear the
    /// totals on every single report.
    @Test("An unknown epoch is never adopted")
    func unknownEpochIsNotAReset() {
        let store = ObservedStore(fileURL: temporaryURL())
        store.addTraffic(appID: netflix, inbound: 1_000, outbound: 0, countersEpoch: 3)
        store.addTraffic(appID: netflix, inbound: 1, outbound: 0, countersEpoch: 0)
        #expect(store.snapshot().first?.bytesInbound == 1_001)
        #expect(store.currentCountersEpoch == 3)
    }

    /// The app's half of the reset: totals go, destinations stay. Clearing the history would throw
    /// away the only record of what an app has been reaching for, which is not what was asked for.
    @Test("Resetting the totals keeps the destination history")
    func resetKeepsDestinations() {
        let store = ObservedStore(fileURL: temporaryURL())
        store.record(appID: netflix, host: "nflxvideo.net", address: "1.2.3.4", port: 443,
                     denied: false, rule: nil)
        store.addTraffic(appID: netflix, inbound: 9_000, outbound: 100, countersEpoch: 1)

        store.resetTraffic(countersEpoch: 2)

        let app = store.snapshot().first
        #expect(app?.bytesInbound == 0)
        #expect(app?.bytesOutbound == 0)
        #expect(app?.destinations.count == 1)
        #expect(app?.allowedCount == 1)
        #expect(store.currentCountersEpoch == 2)
    }

    // MARK: - Across a restart

    /// Without the epoch on disk the provider could not tell "the app reset while I was not
    /// running" from "these are my own totals", so every filter restart would zero the totals.
    @Test("Totals and epoch survive reopening the file")
    func totalsSurviveARestart() {
        let url = temporaryURL()
        let first = ObservedStore(fileURL: url)
        first.addTraffic(appID: netflix, inbound: 2_048, outbound: 512, countersEpoch: 11)
        first.flush()

        let second = ObservedStore(fileURL: url)
        #expect(second.currentCountersEpoch == 11)
        #expect(second.snapshot().first?.bytesInbound == 2_048)

        // And the reopened store keeps counting rather than starting over.
        second.addTraffic(appID: netflix, inbound: 2, outbound: 0, countersEpoch: 11)
        #expect(second.snapshot().first?.bytesInbound == 2_050)
    }

    @Test("A reset performed while the provider was not running is adopted on the next report")
    func resetWhileStoppedIsAdopted() {
        let url = temporaryURL()
        let provider = ObservedStore(fileURL: url)
        provider.addTraffic(appID: netflix, inbound: 5_000, outbound: 5_000, countersEpoch: 1)
        provider.flush()

        // The app resets the counters with the provider stopped: the ring header gets epoch 2, and
        // the app zeroes the file itself so the change is visible immediately.
        ObservedStore(fileURL: url).resetTraffic(countersEpoch: 2)

        // Provider restarts, reads the zeroed file, and agrees with it.
        let restarted = ObservedStore(fileURL: url)
        #expect(restarted.currentCountersEpoch == 2)
        restarted.addTraffic(appID: netflix, inbound: 3, outbound: 0, countersEpoch: 2)
        #expect(restarted.snapshot().first?.bytesInbound == 3)
    }
}
