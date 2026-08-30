import Foundation
import OSLog
import Synchronization

/// The set of apps that are exempt from Samaritan entirely.
///
/// Deliberately a **separate file from `policy.bin`**, not a section inside it. The compiled policy
/// is consulted after a throttled `stat(2)` on the hot path and behind the provider's lock; bypass
/// has to be decided before any of that happens, so it needs a delivery path of its own that the
/// policy reload machinery cannot slow down or serialise against.
///
/// Entries are raw `sourceAppIdentifier` strings — `<teamID>.<bundleID>` — exactly as the flow
/// carries them. See `docs/firewall-rules.md` §1.3: comparing against a bundle ID silently never
/// matches, and a bypass rule that silently never fires is worse than no rule at all.
public struct BypassList: Codable, Sendable, Equatable {

    public static let currentVersion = 1
    public static let fileName = "bypass.json"

    public var version: Int
    /// Mirrors `PolicyDocument.generation` so a log line can tie the two together.
    public var generation: UInt64
    public var identifiers: [String]
    public var updatedAt: Date

    public init(version: Int = BypassList.currentVersion,
                generation: UInt64 = 0,
                identifiers: [String] = [],
                updatedAt: Date = Date()) {
        self.version = version
        self.generation = generation
        self.identifiers = identifiers
        self.updatedAt = updatedAt
    }

    /// Drops anything that cannot correspond to a real flow.
    ///
    /// `<unattributed>` is filtered out here rather than rejected at the UI alone: it is a
    /// display-only pseudo-identifier (`AppIdentity.unattributedRaw`), so no flow can ever carry
    /// it, and publishing it would put a permanently dead entry in the hot path's set. Bypassing
    /// "every flow we cannot attribute" is also precisely the hole default-deny exists to close.
    public static func sanitise(_ identifiers: some Sequence<String>) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for identifier in identifiers {
            let trimmed = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed != AppIdentity.unattributedRaw else { continue }
            guard seen.insert(trimmed).inserted else { continue }
            result.append(trimmed)
        }
        return result.sorted()
    }
}

/// Publishes an immutable bypass set that the data provider's hot path can read without locking.
///
/// The hot path is one atomic pointer load and one `Set` membership test. Everything else —
/// reading the file, decoding it, building the set — happens on a private serial queue driven by a
/// directory watch and a slow timer, never by a flow.
///
/// `@unchecked Sendable`: `current` is atomic, and every other mutable field is touched only on
/// `queue` or under `publishLock`.
public final class BypassGate: @unchecked Sendable {

    /// One published generation of the set. Immutable once constructed, which is what makes it safe
    /// to hand to readers by bare pointer.
    private final class Snapshot {
        let identifiers: Set<String>
        let generation: UInt64
        init(identifiers: Set<String>, generation: UInt64) {
            self.identifiers = identifiers
            self.generation = generation
        }
    }

    /// The currently published snapshot, as an unmanaged pointer so a reader never has to take a
    /// lock to get at it. `nil` until the first publish.
    private let current = Atomic<UnsafeRawPointer?>(nil)

    /// Every snapshot ever published, kept alive for the life of the process.
    ///
    /// Readers hold a bare pointer with no reference count, so a snapshot may not be freed while
    /// any `contains` call could still be inside it. Knowing when that is true needs a quiescence
    /// protocol (hazard pointers, RCU, epochs) that would cost the hot path exactly what this
    /// design exists to avoid. Instead nothing is ever freed, and growth is bounded from the other
    /// end: `publish` is a no-op when the set is unchanged, so re-reading the file on every timer
    /// tick costs nothing, and a new snapshot only appears when the user actually edits a bypass.
    /// Each one is a handful of short strings inside a process the system restarts routinely.
    private var retained: [Snapshot] = []
    private let publishLock = NSLock()

    private let queue = DispatchQueue(label: "app.samaritan.bypass", qos: .utility)
    private var url: URL?
    private var directorySource: DispatchSourceFileSystemObject?
    private var timer: DispatchSourceTimer?
    private var lastSignature: (mtime: TimeInterval, size: Int)?

    public init() {}

    deinit {
        directorySource?.cancel()
        timer?.cancel()
    }

    // MARK: - Hot path

    /// The only thing `handleNewFlow` is allowed to call.
    ///
    /// One acquiring load and one hash lookup. No lock, no allocation, no I/O, no `stat`.
    @inline(__always)
    public func contains(_ identifier: String) -> Bool {
        guard let raw = current.load(ordering: .acquiring) else { return false }
        return Unmanaged<Snapshot>.fromOpaque(raw).takeUnretainedValue()
            .identifiers.contains(identifier)
    }

    /// Diagnostics only — never called from a flow.
    public var currentIdentifiers: Set<String> {
        guard let raw = current.load(ordering: .acquiring) else { return [] }
        return Unmanaged<Snapshot>.fromOpaque(raw).takeUnretainedValue().identifiers
    }

    public var currentGeneration: UInt64 {
        guard let raw = current.load(ordering: .acquiring) else { return 0 }
        return Unmanaged<Snapshot>.fromOpaque(raw).takeUnretainedValue().generation
    }

    // MARK: - Lifecycle

    /// Loads the file synchronously, then watches for changes. Call from `startFilter`, so the very
    /// first flow already sees the right answer.
    public func start(url: URL?) {
        self.url = url
        reloadNow()
        guard let directory = url?.deletingLastPathComponent() else { return }
        watch(directory: directory)
        startTimer()
    }

    /// Cheap enough to call from `handleRulesChanged`; the work happens on `queue`.
    public func reload() {
        queue.async { [weak self] in self?.reloadNow() }
    }

    /// Blocks until the file has been re-read. Tests only — production callers must never wait on
    /// I/O, least of all from a provider callback.
    public func reloadSynchronouslyForTesting() {
        queue.sync { self.reloadNow() }
    }

    // MARK: - Loading

    /// Confined to `queue`, with one exception: `start` calls it directly, before the timer or the
    /// directory source exist, so nothing can be running concurrently at that point.
    private func reloadNow() {
        guard let url else {
            publish(identifiers: [], generation: 0)
            return
        }

        var info = stat()
        guard stat(url.path, &info) == 0 else {
            // Absent means "nothing is bypassed", which is the safe direction: everything stays
            // filtered. Only a file that exists but cannot be decoded keeps the last good set.
            lastSignature = nil
            publish(identifiers: [], generation: 0)
            return
        }

        let signature = (mtime: TimeInterval(info.st_mtimespec.tv_sec)
                         + TimeInterval(info.st_mtimespec.tv_nsec) / 1e9,
                         size: Int(info.st_size))
        if let lastSignature, lastSignature == signature { return }

        guard let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder().decode(BypassList.self, from: data)
        else {
            Log.flows.error("""
                [\(Log.process, privacy: .public)] BYPASS reload failed — keeping the last good set \
                (\(self.currentIdentifiers.count) entries)
                """)
            return
        }

        lastSignature = signature
        guard list.version == BypassList.currentVersion else {
            Log.flows.error("""
                [\(Log.process, privacy: .public)] BYPASS unsupported version=\(list.version) \
                — keeping the last good set
                """)
            return
        }
        publish(identifiers: Set(BypassList.sanitise(list.identifiers)), generation: list.generation)
    }

    private func publish(identifiers: Set<String>, generation: UInt64) {
        // Unchanged sets are not republished, which is what keeps `retained` from growing on every
        // timer tick. Generation alone is not enough — the policy bumps it on every save.
        if let raw = current.load(ordering: .acquiring),
           Unmanaged<Snapshot>.fromOpaque(raw).takeUnretainedValue().identifiers == identifiers {
            return
        }

        let snapshot = Snapshot(identifiers: identifiers, generation: generation)
        publishLock.lock()
        retained.append(snapshot)
        publishLock.unlock()
        current.store(UnsafeRawPointer(Unmanaged.passUnretained(snapshot).toOpaque()),
                      ordering: .releasing)

        // The one place bypass is observable at all. Nothing is counted or logged on the hot path,
        // so this line is the only evidence that a bypass is live — and the only way to catch an
        // identifier that was stored in a form no flow will ever carry.
        let listed = identifiers.sorted().joined(separator: " ")
        Log.flows.log("""
            [\(Log.process, privacy: .public)] BYPASS published generation=\(generation) \
            count=\(identifiers.count) ids=[\(listed, privacy: .public)]
            """)
    }

    // MARK: - Watching

    /// Watches the **directory**, not the file.
    ///
    /// The app writes with `Data.write(.atomic)`, which creates a temporary file and renames it
    /// over the target. A vnode source on the file's descriptor would keep pointing at the old,
    /// now-unlinked inode and never fire again. A directory source sees the rename.
    private func watch(directory: URL) {
        let descriptor = open(directory.path, O_EVTONLY)
        guard descriptor >= 0 else {
            Log.flows.error("""
                [\(Log.process, privacy: .public)] BYPASS cannot watch container (errno=\(errno)) \
                — falling back to the timer
                """)
            return
        }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor, eventMask: [.write, .attrib, .delete, .rename], queue: queue)
        source.setEventHandler { [weak self] in self?.reloadNow() }
        source.setCancelHandler { close(descriptor) }
        source.resume()
        directorySource = source
    }

    /// Belt and braces. The directory watch is the fast path, but a content-filter extension is a
    /// sandbox where "this worked in the app" proves nothing, and a bypass that needs a filter
    /// restart to take effect would look exactly like a bypass that does not work.
    private func startTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5.0, leeway: .seconds(2))
        timer.setEventHandler { [weak self] in self?.reloadNow() }
        timer.resume()
        self.timer = timer
    }
}
