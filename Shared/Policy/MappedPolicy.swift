import Foundation
import OSLog

/// A policy file mapped read-only into this process.
///
/// `mmap` with `PROT_READ` is the whole point: the data provider was measured to have **no write
/// access anywhere** — not the App Group, not its own container — but read access to the App Group
/// works. Mapping means a large policy costs address space rather than heap, which matters in an
/// extension with a tight memory limit.
public final class MappedPolicy: @unchecked Sendable {

    private let base: UnsafeRawPointer
    private let length: Int
    public let view: PolicyView
    public let generation: UInt64

    private init(base: UnsafeRawPointer, length: Int, view: PolicyView) {
        self.base = base
        self.length = length
        self.view = view
        self.generation = view.generation
    }

    deinit {
        munmap(UnsafeMutableRawPointer(mutating: base), length)
    }

    public static func open(path: String) -> Result<MappedPolicy, Error> {
        let fd = Darwin.open(path, O_RDONLY)
        guard fd >= 0 else {
            return .failure(POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO))
        }
        defer { close(fd) }

        var info = stat()
        guard fstat(fd, &info) == 0, info.st_size > 0 else {
            return .failure(PolicyBlob.LoadError.tooSmall)
        }
        let length = Int(info.st_size)

        guard let mapped = mmap(nil, length, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0),
              mapped != MAP_FAILED else {
            return .failure(POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO))
        }

        do {
            let base = UnsafeRawPointer(mapped)
            let view = try PolicyBlob.view(over: base, length: length)
            return .success(MappedPolicy(base: base, length: length, view: view))
        } catch {
            munmap(mapped, length)
            return .failure(error)
        }
    }
}

/// Holds the current policy for a provider and swaps it when the file's generation changes.
///
/// Reload is driven by a throttled generation check on the hot path rather than by
/// `handleRulesChanged()`, which carries no payload and only fires as a side effect of a
/// `.needRules()` round trip.
public final class PolicySource: @unchecked Sendable {

    private let path: String
    private let lock = NSLock()
    private var mapped: MappedPolicy?
    private var lastCheck: UInt64 = 0
    private var lastError: String?

    /// How long to wait between `pread`s of the 96-byte header. Cheap, but not free.
    private let checkInterval: UInt64 = 2_000_000_000

    public init(path: String) {
        self.path = path
        _ = reload(force: true)
    }

    public var currentGeneration: UInt64? {
        lock.lock(); defer { lock.unlock() }
        return mapped?.generation
    }

    public var loadError: String? {
        lock.lock(); defer { lock.unlock() }
        return lastError
    }

    /// Runs the resolver against the current policy. Returns `nil` when no policy is loaded, which
    /// the caller must treat as "no opinion" rather than as allow.
    public func evaluate(appID: String, hostname: String?, address: IPPrefix?,
                         now: UInt64) -> (verdict: PolicyEngine.Verdict, label: String)? {
        reloadIfStale(now: now)
        lock.lock()
        let policy = mapped
        lock.unlock()
        guard let policy else { return nil }

        let engine = PolicyEngine(view: policy.view)
        let verdict = engine.evaluate(appID: appID, hostname: hostname, address: address)
        return (verdict, engine.label(for: verdict))
    }

    private func reloadIfStale(now: UInt64) {
        lock.lock()
        let due = now &- lastCheck > checkInterval
        if due { lastCheck = now }
        lock.unlock()
        guard due else { return }

        let onDisk = PolicyBlob.generation(ofFileAt: path)
        lock.lock()
        let current = mapped?.generation
        lock.unlock()
        guard onDisk != current else { return }
        _ = reload(force: true)
    }

    @discardableResult
    public func reload(force: Bool) -> Bool {
        switch MappedPolicy.open(path: path) {
        case .success(let policy):
            lock.lock()
            mapped = policy
            lastError = nil
            lock.unlock()
            Log.policy.log("""
                [\(Log.process, privacy: .public)] policy loaded generation=\(policy.generation) \
                apps=\(policy.view.apps.count) domains=\(policy.view.domains.count) \
                nodes=\(policy.view.nodes.count)
                """)
            return true
        case .failure(let error):
            lock.lock()
            let hadPolicy = mapped != nil
            lastError = "\(error)"
            // Keep the last good policy rather than falling back to no policy at all: dropping it
            // would silently change every verdict.
            lock.unlock()
            if !hadPolicy {
                Log.policy.log("[\(Log.process, privacy: .public)] no policy: \(String(describing: error), privacy: .public)")
            }
            return false
        }
    }
}
