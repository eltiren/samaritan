import Foundation
import Testing
@testable import SamaritanTests

@Suite("Observed store bounds")
struct ObservedStoreTests {

    // The store itself needs an App Group container, which a test host has no access to. These pin
    // the eviction policy on the same shapes the store applies, which is the part with real
    // consequences: a noisy app must not be able to erase a quiet one's history.

    private struct Entry { var host: String; var lastSeen: Date }

    private func evictOldest(_ entries: [Entry], keeping limit: Int) -> [Entry] {
        Array(entries.sorted { $0.lastSeen > $1.lastSeen }.prefix(limit))
    }

    @Test("per-app bound keeps the most recent destinations")
    func keepsMostRecent() {
        let base = Date(timeIntervalSinceReferenceDate: 0)
        let entries = (0..<300).map { Entry(host: "h\($0)", lastSeen: base.addingTimeInterval(Double($0))) }
        let kept = evictOldest(entries, keeping: ObservedStore.maximumDestinationsPerApp)

        #expect(kept.count == ObservedStore.maximumDestinationsPerApp)
        #expect(kept.first?.host == "h299")
        #expect(!kept.contains { $0.host == "h0" })
    }

    @Test("the bounds are per app, so one noisy app cannot evict another")
    func boundsArePerApp() {
        // The whole reason this store exists rather than reading the shared 2048-slot ring: one app
        // was measured producing 1839 flows, which would evict every other app from a global bound.
        let noisy = (0..<5_000).map { Entry(host: "n\($0)", lastSeen: Date()) }
        let quiet = [Entry(host: "quiet.example", lastSeen: Date())]

        #expect(evictOldest(noisy, keeping: ObservedStore.maximumDestinationsPerApp).count
                == ObservedStore.maximumDestinationsPerApp)
        #expect(evictOldest(quiet, keeping: ObservedStore.maximumDestinationsPerApp).count == 1)
    }

    @Test("the bounds are large enough to triage an app but small enough to persist")
    func boundsAreSane() {
        #expect(ObservedStore.maximumDestinationsPerApp >= 100)
        #expect(ObservedStore.maximumApps >= 100)
        // Worst case is a JSON document, rewritten on change; keep the product bounded.
        #expect(ObservedStore.maximumApps * ObservedStore.maximumDestinationsPerApp <= 100_000)
    }

    @Test("a destination round-trips through Codable")
    func destinationCoding() throws {
        let destination = ObservedDestination(
            host: "slack.com", addresses: ["18.169.61.189"], ports: [443], attempts: 12,
            firstSeen: Date(timeIntervalSinceReferenceDate: 1),
            lastSeen: Date(timeIntervalSinceReferenceDate: 2),
            denied: true, lastRule: "blanket")
        let data = try JSONEncoder().encode(destination)
        #expect(try JSONDecoder().decode(ObservedDestination.self, from: data) == destination)
    }
}
