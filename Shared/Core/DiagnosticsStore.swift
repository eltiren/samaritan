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
    }

    public struct Snapshot: Sendable {
        public var counters: [Counter: UInt64] = [:]
        public var records: [FlowRecord] = []
        public var totalWritten: UInt64 = 0

        public subscript(counter: Counter) -> UInt64 { counters[counter] ?? 0 }
    }

    private static let magic: UInt32 = 0x53_4D_52_54 // "SMRT"
    private static let version: UInt32 = 1
    private static let headerSize = 4096
    private static let counterBase = 32

    public static let defaultSlotCount = 2048

    private let url: URL
    private let slotCount: Int
    private let descriptor: Int32
    private let lock = NSLock()
    private var nextSequence: UInt64 = 1
    private var counters = [UInt64](repeating: 0, count: Counter.allCases.count)
    /// Reusable scratch so the hot path allocates nothing per flow.
    private let scratch: UnsafeMutableRawBufferPointer

    /// Opens (creating if needed) the ring for `writer`. Returns `nil` if the App Group container
    /// is unavailable — which is exactly the condition the diagnostics UI needs to surface.
    public init?(writer: SharedContainer.Writer, slotCount: Int = DiagnosticsStore.defaultSlotCount) {
        guard let url = SharedContainer.ringURL(for: writer) else {
            Log.storage.error("No App Group container; diagnostics ring unavailable for \(writer.rawValue, privacy: .public)")
            return nil
        }
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
            flushHeaderLocked()
        }
        ftruncate(fd, expectedSize)
        Log.storage.log("[\(Log.process, privacy: .public)] ring open: \(url.lastPathComponent, privacy: .public) slots=\(slotCount) seq=\(self.nextSequence)")
    }

    deinit {
        scratch.deallocate()
        if descriptor >= 0 { close(descriptor) }
    }

    // MARK: - Writing

    /// Appends one record and applies counter deltas atomically with respect to other calls in
    /// this process. Safe to call from `handleNewFlow(_:)`.
    public func append(_ record: FlowRecord, incrementing deltas: [Counter: UInt64] = [:]) {
        lock.lock()
        defer { lock.unlock() }

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
        for (counter, delta) in deltas { counters[counter.rawValue] &+= delta }
        flushHeaderLocked()
    }

    private func flushHeaderLocked() {
        var header = Header()
        header.magic = Self.magic
        header.version = Self.version
        header.slotSize = UInt32(FlowRecordCodec.slotSize)
        header.slotCount = UInt32(slotCount)
        header.nextSequence = nextSequence
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
        ftruncate(descriptor, 0)
        ftruncate(descriptor, off_t(Self.headerSize + slotCount * FlowRecordCodec.slotSize))
        nextSequence = 1
        counters = .init(repeating: 0, count: Counter.allCases.count)
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
        var reserved: UInt64 = 0
        // 32 × UInt64 counter slots. Fixed-size tuple so `Header` stays a C-layout POD.
        var counters: (
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64
        ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

extension DiagnosticsStore.Snapshot {
    /// Merges another writer's snapshot: counters sum, records interleave newest-first by time.
    public func merged(with other: Self) -> Self {
        var result = Self()
        result.totalWritten = totalWritten &+ other.totalWritten
        for counter in DiagnosticsStore.Counter.allCases {
            result.counters[counter] = self[counter] &+ other[counter]
        }
        result.records = (records + other.records).sorted { $0.timestamp > $1.timestamp }
        return result
    }
}
