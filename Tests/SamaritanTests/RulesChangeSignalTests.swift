import Foundation
import Testing
@testable import SamaritanTests

/// The `updateRules` bit is the data provider's only push channel, and the control provider gets to
/// use it once. Which flow spends it is not a detail: only `allow(withUpdateRules:)` carries the
/// bit, so a one-shot claimed by a dropped flow is a signal that is consumed and never sent.
@Suite("Rules-change signal")
struct RulesChangeSignalTests {

    /// The regression. Under `denyMode = escalate` an escalated deny is the *common* first control
    /// flow, and it returns `withUpdateRules: false`. Claiming the flag before the verdict was
    /// known burned it there, so every later allow reported `false` and `handleRulesChanged()` was
    /// never asked for — silently, on exactly the runs the escalation experiment cares about.
    @Test("A dropped first flow does not consume the signal")
    func dropFirstThenAllow() {
        let signal = RulesChangeSignal()
        #expect(signal.claim(forAllow: false) == false)
        #expect(signal.hasSignalled == false)
        #expect(signal.claim(forAllow: true) == true)
        #expect(signal.hasSignalled)
    }

    @Test("An allowed first flow consumes it, and no later flow signals again")
    func allowFirstThenAllow() {
        let signal = RulesChangeSignal()
        #expect(signal.claim(forAllow: true) == true)
        #expect(signal.claim(forAllow: true) == false)
        #expect(signal.claim(forAllow: false) == false)
    }

    /// A drop must never report `true`, whether or not the signal is still available: the verdict
    /// it is attached to cannot carry the bit at all.
    @Test("A drop never signals, before or after the one-shot is spent")
    func dropNeverSignals() {
        let signal = RulesChangeSignal()
        for _ in 0..<10 { #expect(signal.claim(forAllow: false) == false) }
        #expect(signal.claim(forAllow: true) == true)
        #expect(signal.claim(forAllow: false) == false)
    }

    /// The escalate-mode shape end to end: a run of drops, then one allow, then nothing more.
    @Test("Exactly one flow in a mixed sequence carries the bit")
    func exactlyOneSignalInASequence() {
        let signal = RulesChangeSignal()
        let isAllow = [false, false, false, true, false, true, true]
        let signalled = isAllow.map { signal.claim(forAllow: $0) }
        #expect(signalled.filter { $0 }.count == 1)
        #expect(signalled == [false, false, false, true, false, false, false])
    }
}
