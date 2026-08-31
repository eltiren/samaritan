import Foundation
import OSLog

/// Fixed-size, single-writer ring buffer of `FlowRecord`s plus a counter block, backed by one file
/// in the App Group container.
///
/// Design constraints this satisfies:
///
/// * **Bounded.** A content filter is a long-lived process. The file never grows.
/// * **No invented IPC.** Plain `pread(2)`/`pwrite(2)` on a shared-container file — the only
///   app↔extension channel Apple supports besides `.needRules()`.
/// * **No cross-process lock.** Each writing process owns its own file (`SharedContainer.Writer`),
///   so there is exactly one writer and the reader only needs the seqlock words in each slot.
/// * **Works while locked.** The file is created with
///   `.completeUntilFirstUserAuthentication` protection.
///
/// File layout: a 4096-byte header followed by `slotCount` × 512-byte slots.
public final class DiagnosticsStore {

    /// Aggregate counters. Order is the on-disk order; append new cases at the end only.
    public enum Counter: Int, CaseIterable, Sendable {
        case flowsObserved = 0
        case flowsAllowed
        case flowsDropped
        case flowsNeedRules
        case controlFlowsHandled
        case reportsData
        case reportsControl
        case reportedBytesInbound
        case reportedBytesOutbound
        case filterStarts
        case filterStops
        case writeFailures
        case rulesChangedEvents
        case flowsEscalated
        case controlDropsIssued
        case policyDecisions
        case spikeFallbackDecisions
        case escalationsSuppressed
    }

    public struct Snapshot: Sendable {
        public var counters: [Counter: UInt64] = [:]
        public var records: [FlowRecord] = []
        public var totalWritten: UInt64 = 0

        /// When these counters started, or `nil` for a ring written before the epoch existed.
        ///
        /// Without this a total is unfalsifiable: "8.5 GB" cannot be checked against anything, and
        /// the obvious question — is that a real 30 hours of traffic or an accounting bug? — has no
        /// answer. With it, every total divides into a rate that can be sanity-checked.
        public var countersSince: Date?

        public subscript(counter: Counter) -> UInt64 { counters[counter] ?? 0 }

        /// Seconds the counters have been accumulating, or `nil` if the epoch is unknown.
        public var countingInterval: TimeInterval? {
            countersSince.map { max(1, Date().timeIntervalSince($0)) }
        }

        /// A counter as a per-hour rate, for comparing against a plausible figure.
        public func perHour(_ counter: Counter) -> Double? {
            countingInterval.map { Double(self[counter]) / $0 * 3600 }
        }
    }

    private static let magic: UInt32 = 0x53_4D_52_54 // "SMRT"
    private static let version: UInt32 = 1
    private static let headerSize = 4096
    private static let counterBase = 32
    /// Byte offset of `Header.epochSeconds`, derived rather than written down so it cannot drift
    /// away from the struct if a field is ever inserted above it.
    private static let epochOffset = MemoryLayout<Header>.offset(of: \Header.epochSeconds) ?? 24
    /// Byte offset of `Header.resetGeneration`, derived for the same reason. Read on the hot path
    /// by `adoptExternalResetLocked`.
    private static let generationOffset =
        MemoryLayout<Header>.offset(of: \Header.resetGeneration) ?? 288

    public static let defaultSlotCount = 2048

    private let url: URL
    private let slotCount: Int
    private let descriptor: Int32
    private let lock = NSLock()
    private var nextSequence: UInt64 = 1
    private var counters = [UInt64](repeating: 0, count: Counter.allCases.count)
    private var epochSeconds: UInt64 = 0
    private var resetGeneration: UInt64 = 0
    /// Reusable scratch so the hot path allocates nothing per flow.
    private let scratch: UnsafeMutableRawBufferPointer

    /// Opens (creating if needed) the ring for `writer`. Returns `nil` if the App Group container
    /// is unavailable — which is exactly the condition the diagnostics UI needs to surface.
    public convenience init?(writer: SharedContainer.Writer,
                             slotCount: Int = DiagnosticsStore.defaultSlotCount) {
        guard let url = SharedContainer.ringURL(for: writer) else {
            Log.storage.error("No App Group container; diagnostics ring unavailable for \(writer.rawValue, privacy: .public)")
            return nil
        }
        self.init(fileURL: url, slotCount: slotCount)
    }

    /// Tests only. Production goes through `init?(writer:)` so the App Group container stays the
    /// single source of truth for where a ring lives — and so the one-writer-per-file rule that
    /// makes the seqlock sufficient is enforced by the `Writer` enum rather than by a caller.
    ///
    /// Two stores over the same URL is not a production shape but *is* the shape a reset test needs:
    /// the app clears a ring a provider process has open, and the bug being pinned lives entirely in
    /// how the second one notices.
    public init?(fileURL url: URL, slotCount: Int = DiagnosticsStore.defaultSlotCount) {
        self.url = url
        self.slotCount = slotCount

        let fd = open(url.path, O_RDWR | O_CREAT, 0o644)
        guard fd >= 0 else {
            Log.storage.error("open(\(url.lastPathComponent, privacy: .public)) failed: \(String(cString: strerror(errno)), privacy: .public)")
            return nil
        }
        self.descriptor = fd
        self.scratch = .allocate(byteCount: FlowRecordCodec.slotSize, alignment: 16)

        try? FileManager.default.setAttributes(
            [.protectionKey: SharedContainer.fileProtection], ofItemAtPath: url.path)

        let expectedSize = off_t(Self.headerSize + slotCount * FlowRecordCodec.slotSize)
        var header = Header()
        let read = pread(fd, &header, MemoryLayout<Header>.size, 0)

        if read == MemoryLayout<Header>.size, header.magic == Self.magic,
           header.version == Self.version, header.slotCount == UInt32(slotCount) {
            nextSequence = max(1, header.nextSequence)
            epochSeconds = header.epochSeconds
            resetGeneration = Self.seedGeneration(header.resetGeneration, epoch: header.epochSeconds)
            withUnsafeBytes(of: header.counters) { raw in
                for i in 0..<min(counters.count, Header.counterSlots) {
                    counters[i] = raw.loadUnaligned(fromByteOffset: i * 8, as: UInt64.self)
                }
            }
        } else {
            // New or incompatible file: truncate to zero then to full size so old slots cannot be
            // mistaken for fresh ones.
            ftruncate(fd, 0)
            ftruncate(fd, expectedSize)
            nextSequence = 1
            counters = .init(repeating: 0, count: Counter.allCases.count)
            epochSeconds = UInt64(Date().timeIntervalSince1970)
            resetGeneration = Self.seedGeneration(0, epoch: epochSeconds)
            flushHeaderLocked()
        }
        ftruncate(fd, expectedSize)
        Log.storage.log("[\(Log.process, privacy: .public)] ring open: \(url.lastPathComponent, privacy: .public) slots=\(slotCount) seq=\(self.nextSequence)")
    }

    deinit {
        scratch.deallocate()
        if descriptor >= 0 { close(descriptor) }
    }

    // MARK: - Epoch

    /// Opaque token identifying the counter epoch this process is in, as it last saw it.
    ///
    /// Strictly increasing, and deliberately *not* `epochSeconds`. The wall clock is what the UI
    /// shows, but at second resolution it is not a usable identity: a reset in the same second as
    /// the previous one writes back the value every process already holds, and a reset nobody can
    /// see is a reset that silently does not happen.
    ///
    /// `append` and `increment` re-read it from the header, so a caller that has just written is
    /// reading a current value. The control provider hands it to `ObservedStore` so the per-app byte
    /// totals — the same measurement, split by app — are cleared by the same reset.
    public var countersGeneration: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return resetGeneration
    }

    /// Seeds the in-memory generation when a ring is opened.
    ///
    /// A ring written before the field exists reads 0, and every process opening it must arrive at
    /// the *same* seed or one of them would see a phantom reset. `epochSeconds` is the token those
    /// rings already agreed on, so it is what the generation continues from; `reset` only ever
    /// increments past whatever is on disk, so the seconds origin never collides with a later value.
    ///
    /// The seed is why `adoptExternalResetLocked` has to ignore a zero on disk: until the ring's
    /// owner writes once, memory holds the seed and the file still holds nothing.
    private static func seedGeneration(_ stored: UInt64, epoch: UInt64) -> UInt64 {
        stored != 0 ? stored : epoch
    }

    // MARK: - Writing

    /// Appends one record and applies counter deltas atomically with respect to other calls in
    /// this process. Safe to call from `handleNewFlow(_:)`.
    public func append(_ record: FlowRecord, incrementing deltas: [Counter: UInt64] = [:]) {
        lock.lock()
        defer { lock.unlock() }
        adoptExternalResetLocked()

        let sequence = nextSequence
        nextSequence &+= 1
        FlowRecordCodec.encode(record, sequence: sequence, into: scratch)

        let slot = Int((sequence &- 1) % UInt64(slotCount))
        let offset = off_t(Self.headerSize + slot * FlowRecordCodec.slotSize)
        let written = pwrite(descriptor, scratch.baseAddress!, FlowRecordCodec.slotSize, offset)
        if written != FlowRecordCodec.slotSize {
            counters[Counter.writeFailures.rawValue] &+= 1
        }
        for (counter, delta) in deltas {
            counters[counter.rawValue] &+= delta
        }
        flushHeaderLocked()
    }

    /// Bumps counters without writing a slot.
    public func increment(_ deltas: [Counter: UInt64]) {
        lock.lock()
        defer { lock.unlock() }
        adoptExternalResetLocked()
        for (counter, delta) in deltas { counters[counter.rawValue] &+= delta }
        flushHeaderLocked()
    }

    /// Notices a reset performed by the app in another process, and adopts it.
    ///
    /// Resetting is the one place the single-writer rule is broken: the app clears a ring it does
    /// not write to. Without this the provider's next flush would put its stale in-memory counters
    /// straight back over the cleared header, so "Reset counters" would appear to work and then
    /// silently revert on the very next flow — which is worse than not offering it.
    ///
    /// An 8-byte `pread` against the ~296-byte `pwrite` that follows it, so the cost is noise, and
    /// the generation is the natural token: it changes on exactly the two events that invalidate a
    /// process's cached counters, a reset and a fresh file, and on nothing else.
    private func adoptExternalResetLocked() {
        var generation: UInt64 = 0
        // Zero is "this ring predates the field", not a reset. A legacy ring is seeded in memory
        // from `epochSeconds` while still holding 0 on disk, so comparing the two directly would
        // fire a phantom reset on the very first write and throw away counters nobody cleared. The
        // state is self-healing: the next `flushHeaderLocked` puts the seed on disk.
        guard pread(descriptor, &generation, 8, off_t(Self.generationOffset)) == 8,
              generation != 0, generation != resetGeneration else { return }
        resetGeneration = generation
        // Second `pread`, but only on the adopt path, which runs once per reset rather than once
        // per flow. The display epoch has to follow the generation: without it this process's next
        // flush would put its own stale start time back over the one the reset wrote, and every
        // rate derived from it would be computed over the wrong window.
        var epoch: UInt64 = 0
        if pread(descriptor, &epoch, 8, off_t(Self.epochOffset)) == 8 {
            epochSeconds = epoch
        }
        counters = .init(repeating: 0, count: Counter.allCases.count)
        nextSequence = 1
    }

    private func flushHeaderLocked() {
        var header = Header()
        header.magic = Self.magic
        header.version = Self.version
        header.slotSize = UInt32(FlowRecordCodec.slotSize)
        header.slotCount = UInt32(slotCount)
        header.nextSequence = nextSequence
        header.epochSeconds = epochSeconds
        header.resetGeneration = resetGeneration
        withUnsafeMutableBytes(of: &header.counters) { raw in
            for i in 0..<min(counters.count, Header.counterSlots) {
                raw.storeBytes(of: counters[i], toByteOffset: i * 8, as: UInt64.self)
            }
        }
        _ = withUnsafeBytes(of: header) { raw in
            pwrite(descriptor, raw.baseAddress!, raw.count, 0)
        }
    }

    // MARK: - Reading

    /// Reads every valid slot plus the counter block. Called from the app, never from the hot path.
    public func snapshot(limit: Int = DiagnosticsStore.defaultSlotCount) -> Snapshot {
        var snapshot = Snapshot()

        var header = Header()
        guard pread(descriptor, &header, MemoryLayout<Header>.size, 0) == MemoryLayout<Header>.size,
              header.magic == Self.magic else { return snapshot }

        snapshot.totalWritten = header.nextSequence &- 1
        if header.epochSeconds > 0 {
            snapshot.countersSince = Date(timeIntervalSince1970: TimeInterval(header.epochSeconds))
        }
        withUnsafeBytes(of: header.counters) { raw in
            for counter in Counter.allCases where counter.rawValue < Header.counterSlots {
                snapshot.counters[counter] = raw.loadUnaligned(fromByteOffset: counter.rawValue * 8, as: UInt64.self)
            }
        }

        let count = Int(header.slotCount)
        guard count > 0 else { return snapshot }
        let wanted = min(limit, count, Int(snapshot.totalWritten))
        guard wanted > 0 else { return snapshot }

        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: FlowRecordCodec.slotSize, alignment: 16)
        defer { buffer.deallocate() }

        var records: [FlowRecord] = []
        records.reserveCapacity(wanted)
        // Walk backwards from the most recent sequence so we get the newest `wanted` records.
        var sequence = snapshot.totalWritten
        while records.count < wanted, sequence > 0 {
            let slot = Int((sequence &- 1) % UInt64(count))
            let offset = off_t(Self.headerSize + slot * FlowRecordCodec.slotSize)
            if pread(descriptor, buffer.baseAddress!, FlowRecordCodec.slotSize, offset) == FlowRecordCodec.slotSize,
               let record = FlowRecordCodec.decode(from: UnsafeRawBufferPointer(buffer)),
               record.sequence == sequence {
                records.append(record)
            }
            sequence &-= 1
        }
        snapshot.records = records
        return snapshot
    }

    /// Clears records and counters. Only ever called from the app.
    public func reset() {
        lock.lock()
        defer { lock.unlock() }

        // Read before truncating, and take the larger of disk and memory: the new generation has to
        // be greater than anything any process could already be holding, or a provider mid-flush
        // would not recognise the reset and would flush its cached counters back over the cleared
        // header. `&+ 1` off that maximum is the whole guarantee, and it is what makes two resets in
        // the same second — or a reset in the second the ring was created — distinguishable.
        var onDisk: UInt64 = 0
        if pread(descriptor, &onDisk, 8, off_t(Self.generationOffset)) != 8 { onDisk = 0 }

        ftruncate(descriptor, 0)
        ftruncate(descriptor, off_t(Self.headerSize + slotCount * FlowRecordCodec.slotSize))
        nextSequence = 1
        counters = .init(repeating: 0, count: Counter.allCases.count)
        epochSeconds = UInt64(Date().timeIntervalSince1970)
        resetGeneration = max(onDisk, resetGeneration) &+ 1
        flushHeaderLocked()
    }

    // MARK: - Header

    private struct Header {
        static let counterSlots = 32

        var magic: UInt32 = 0
        var version: UInt32 = 0
        var slotSize: UInt32 = 0
        var slotCount: UInt32 = 0
        var nextSequence: UInt64 = 0
        /// Unix seconds when the counters started. Occupies what used to be a reserved word, so the
        /// header layout is unchanged and an older ring simply reads 0 — meaning "unknown".
        var epochSeconds: UInt64 = 0
        // 32 × UInt64 counter slots. Fixed-size tuple so `Header` stays a C-layout POD.
        var counters: (
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64
        ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        /// Strictly increasing token bumped by every `reset()`. Deliberately **after** the counter
        /// tuple: putting it above would shift the counter block and silently misread every ring
        /// already on disk. A ring written before it exists reads 0 from the zero-filled header,
        /// which `seedGeneration` treats as "continue from `epochSeconds`" rather than as a reset.
        var resetGeneration: UInt64 = 0
    }
}

extension DiagnosticsStore.Snapshot {
    /// Merges another writer's snapshot: counters sum, records interleave newest-first by time.
    ///
    /// **Summing is only correct for a counter one writer owns.** Both providers receive the same
    /// `NEFilterReport` stream, so a counter incremented from `handle(_:)` in both would be added
    /// twice here for a single flow. That is why the byte counters are incremented in the control
    /// provider alone, and why `reportsData` / `reportsControl` are separate counters rather than
    /// one shared "reports" counter. Anything added to `handle(_:)` in future must pick one owner.
    public func merged(with other: Self) -> Self {
        var result = Self()
        result.totalWritten = totalWritten &+ other.totalWritten
        for counter in DiagnosticsStore.Counter.allCases {
            result.counters[counter] = self[counter] &+ other[counter]
        }
        // The merged totals only span as far back as the *younger* ring: the older one's extra
        // history is not represented in the other's counters, so quoting the earlier epoch would
        // understate every rate.
        result.countersSince = [countersSince, other.countersSince].compactMap { $0 }.max()
        result.records = (records + other.records).sorted { $0.timestamp > $1.timestamp }
        return result
    }
}
