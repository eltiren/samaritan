import Foundation

/// The one-shot `updateRules` bit the control provider spends to make the data provider's
/// `handleRulesChanged()` observable exactly once, without a rules-change storm.
///
/// A plain `Bool` was not enough, and the way it failed is the reason this is a type. The flag was
/// claimed before the control provider knew whether it would allow or drop, but only
/// `allow(withUpdateRules:)` can carry the bit — `drop` is always `withUpdateRules: false`. Under
/// `denyMode = escalate` a drop is the *common* first flow, so the one-shot was routinely spent on
/// a verdict that could not signal, and every later allow then reported `false`. Nothing failed
/// loudly; the milestone question "does `updateRules: true` reliably produce
/// `handleRulesChanged()`?" simply became unanswerable on those runs.
///
/// Taking the verdict as the argument is what fixes that for good: the signal cannot be spent by a
/// caller that is about to drop, whatever order the caller writes its branches in.
public final class RulesChangeSignal: @unchecked Sendable {

    private let lock = NSLock()
    private var isSpent = false

    public init() {}

    /// Returns `true` at most once, and only for a verdict that can carry the bit.
    ///
    /// - Parameter isAllow: whether the caller is about to return `allow(withUpdateRules:)`. A
    ///   drop never spends the signal, so a later allow can still deliver it.
    public func claim(forAllow isAllow: Bool) -> Bool {
        guard isAllow else { return false }
        lock.lock()
        defer { lock.unlock() }
        guard !isSpent else { return false }
        isSpent = true
        return true
    }

    /// Whether the signal has been delivered. Diagnostics and tests.
    public var hasSignalled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isSpent
    }
}
