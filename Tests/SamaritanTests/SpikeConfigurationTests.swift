import Foundation
import Testing
@testable import SamaritanTests

@Suite("Spike configuration coding")
struct SpikeConfigurationTests {

    @Test("survives a JSON round trip")
    func jsonRoundTrip() throws {
        let original = SpikeConfiguration(
            blockedHostSuffixes: ["a.test", "b.test"],
            blockedAddresses: ["10.0.0.1"],
            controlProbeEnabled: true,
            controlProbeBudget: 5,
            requestReports: false,
            logEveryFlow: true)

        let data = try JSONEncoder().encode(original)
        #expect(try JSONDecoder().decode(SpikeConfiguration.self, from: data) == original)
    }

    @Test("load falls back to defaults when nothing is stored")
    func loadFallsBack() {
        // In the test host there is no App Group container, so `load()` must not trap.
        #expect(SpikeConfiguration.load() == .default)
    }

    @Test("the probe budget is bounded so a stuck control provider cannot wedge traffic")
    func boundedProbeBudget() {
        #expect(SpikeConfiguration.default.controlProbeBudget > 0)
        #expect(SpikeConfiguration.default.controlProbeBudget <= 128)
    }
}
