import Foundation

/// Fixed-width binary encoding of a `FlowRecord` into a single ring-buffer slot.
///
/// Layout (little-endian, `slotSize` = 512 bytes):
///
///     0    UInt64  sequence          (leading seqlock word; 0 == empty slot)
///     8    Double  timestamp         (seconds since reference date)
///     16   UInt64  bytesInbound
///     24   UInt64  bytesOutbound
///     32   UInt64  decisionNanos
///     40   Int32   socketFamily
///     44   Int32   socketType
///     48   Int32   socketProtocol
///     52   UInt16  remotePort
///     54   UInt16  localPort
///     56   UInt16  pathFlags
///     58   UInt8   origin
///     59   UInt8   verdict
///     60   UInt8   direction
///     61   3 bytes reserved
///     64   string area: 7 × (UInt8 length + UTF-8 bytes), each capped per field
///     504  UInt64  sequence          (trailing seqlock word; must equal the leading one)
///
/// A single writer per file plus matching leading/trailing sequence words is enough to detect a
/// torn record on the reader side. There is no cross-process lock and none is needed: every ring
/// file has exactly one writing process.
enum FlowRecordCodec {

    static let slotSize = 512
    private static let stringAreaOffset = 64
    private static let trailerOffset = 504

    /// Per-field UTF-8 caps. Sum + 7 length bytes must be <= trailerOffset - stringAreaOffset (440).
    private enum Field: Int, CaseIterable {
        case flowIdentifier, sourceApp, sourceAppVersion, remoteHostname, remoteAddress, localAddress, matchedRule

        var capacity: Int {
            switch self {
            case .flowIdentifier: 40
            case .sourceApp: 96
            case .sourceAppVersion: 24
            case .remoteHostname: 128
            case .remoteAddress: 48
            case .localAddress: 48
            case .matchedRule: 48
            }
        }
    }

    // MARK: - Encoding

    /// Encodes into `buffer`, which must be exactly `slotSize` bytes. Performs no heap allocation.
    static func encode(_ record: FlowRecord, sequence: UInt64, into buffer: UnsafeMutableRawBufferPointer) {
        precondition(buffer.count == slotSize)
        let base = buffer.baseAddress!
        memset(base, 0, slotSize)

        base.storeBytes(of: sequence.littleEndian, toByteOffset: 0, as: UInt64.self)
        base.storeBytes(of: record.timestamp.timeIntervalSinceReferenceDate.bitPattern.littleEndian,
                        toByteOffset: 8, as: UInt64.self)
        base.storeBytes(of: record.bytesInbound.littleEndian, toByteOffset: 16, as: UInt64.self)
        base.storeBytes(of: record.bytesOutbound.littleEndian, toByteOffset: 24, as: UInt64.self)
        base.storeBytes(of: record.decisionNanos.littleEndian, toByteOffset: 32, as: UInt64.self)
        base.storeBytes(of: record.socketFamily.littleEndian, toByteOffset: 40, as: Int32.self)
        base.storeBytes(of: record.socketType.littleEndian, toByteOffset: 44, as: Int32.self)
        base.storeBytes(of: record.socketProtocol.littleEndian, toByteOffset: 48, as: Int32.self)
        base.storeBytes(of: record.remotePort.littleEndian, toByteOffset: 52, as: UInt16.self)
        base.storeBytes(of: record.localPort.littleEndian, toByteOffset: 54, as: UInt16.self)
        base.storeBytes(of: record.pathFlags.rawValue.littleEndian, toByteOffset: 56, as: UInt16.self)
        base.storeBytes(of: record.origin.rawValue, toByteOffset: 58, as: UInt8.self)
        base.storeBytes(of: record.verdict.rawValue, toByteOffset: 59, as: UInt8.self)
        base.storeBytes(of: record.direction, toByteOffset: 60, as: UInt8.self)

        var cursor = stringAreaOffset
        for field in Field.allCases {
            write(string(for: field, in: record), capacity: field.capacity, at: &cursor, base: base)
        }

        base.storeBytes(of: sequence.littleEndian, toByteOffset: trailerOffset, as: UInt64.self)
    }

    private static func string(for field: Field, in record: FlowRecord) -> String {
        switch field {
        case .flowIdentifier: record.flowIdentifier
        case .sourceApp: record.sourceApp
        case .sourceAppVersion: record.sourceAppVersion
        case .remoteHostname: record.remoteHostname
        case .remoteAddress: record.remoteAddress
        case .localAddress: record.localAddress
        case .matchedRule: record.matchedRule
        }
    }

    /// Writes a length-prefixed, UTF-8-truncated string. Truncation happens on a UTF-8 code-unit
    /// boundary walk so we never emit an invalid partial scalar.
    private static func write(_ value: String, capacity: Int, at cursor: inout Int, base: UnsafeMutableRawPointer) {
        var written = 0
        let lengthOffset = cursor
        cursor += 1
        for byte in value.utf8 {
            guard written < capacity else { break }
            base.storeBytes(of: byte, toByteOffset: cursor + written, as: UInt8.self)
            written += 1
        }
        // A cap can land mid-scalar. Walk back to the last lead byte and drop the scalar if its
        // continuation bytes did not fit, so the slot always holds well-formed UTF-8.
        var scan = written
        while scan > 0, base.load(fromByteOffset: cursor + scan - 1, as: UInt8.self) & 0xC0 == 0x80 {
            scan -= 1
        }
        if scan > 0 {
            let lead = base.load(fromByteOffset: cursor + scan - 1, as: UInt8.self)
            let expected: Int
            if lead & 0x80 == 0 { expected = 1 }
            else if lead & 0xE0 == 0xC0 { expected = 2 }
            else if lead & 0xF0 == 0xE0 { expected = 3 }
            else if lead & 0xF8 == 0xF0 { expected = 4 }
            else { expected = 1 }
            if written - (scan - 1) < expected { written = scan - 1 }
        }
        base.storeBytes(of: UInt8(written), toByteOffset: lengthOffset, as: UInt8.self)
        cursor += capacity
    }

    // MARK: - Decoding

    /// Returns `nil` for empty or torn slots.
    static func decode(from buffer: UnsafeRawBufferPointer) -> FlowRecord? {
        guard buffer.count == slotSize, let base = buffer.baseAddress else { return nil }

        let sequence = UInt64(littleEndian: base.loadUnaligned(fromByteOffset: 0, as: UInt64.self))
        let trailer = UInt64(littleEndian: base.loadUnaligned(fromByteOffset: trailerOffset, as: UInt64.self))
        guard sequence != 0, sequence == trailer else { return nil }

        var record = FlowRecord()
        record.sequence = sequence
        let bits = UInt64(littleEndian: base.loadUnaligned(fromByteOffset: 8, as: UInt64.self))
        record.timestamp = Date(timeIntervalSinceReferenceDate: Double(bitPattern: bits))
        record.bytesInbound = UInt64(littleEndian: base.loadUnaligned(fromByteOffset: 16, as: UInt64.self))
        record.bytesOutbound = UInt64(littleEndian: base.loadUnaligned(fromByteOffset: 24, as: UInt64.self))
        record.decisionNanos = UInt64(littleEndian: base.loadUnaligned(fromByteOffset: 32, as: UInt64.self))
        record.socketFamily = Int32(littleEndian: base.loadUnaligned(fromByteOffset: 40, as: Int32.self))
        record.socketType = Int32(littleEndian: base.loadUnaligned(fromByteOffset: 44, as: Int32.self))
        record.socketProtocol = Int32(littleEndian: base.loadUnaligned(fromByteOffset: 48, as: Int32.self))
        record.remotePort = UInt16(littleEndian: base.loadUnaligned(fromByteOffset: 52, as: UInt16.self))
        record.localPort = UInt16(littleEndian: base.loadUnaligned(fromByteOffset: 54, as: UInt16.self))
        record.pathFlags = FlowRecord.PathFlags(
            rawValue: UInt16(littleEndian: base.loadUnaligned(fromByteOffset: 56, as: UInt16.self)))
        record.origin = FlowRecord.Origin(rawValue: base.load(fromByteOffset: 58, as: UInt8.self)) ?? .dataProvider
        record.verdict = FlowRecord.Verdict(rawValue: base.load(fromByteOffset: 59, as: UInt8.self)) ?? .allow
        record.direction = base.load(fromByteOffset: 60, as: UInt8.self)

        var cursor = stringAreaOffset
        for field in Field.allCases {
            let value = read(capacity: field.capacity, at: &cursor, base: base)
            switch field {
            case .flowIdentifier: record.flowIdentifier = value
            case .sourceApp: record.sourceApp = value
            case .sourceAppVersion: record.sourceAppVersion = value
            case .remoteHostname: record.remoteHostname = value
            case .remoteAddress: record.remoteAddress = value
            case .localAddress: record.localAddress = value
            case .matchedRule: record.matchedRule = value
            }
        }
        return record
    }

    private static func read(capacity: Int, at cursor: inout Int, base: UnsafeRawPointer) -> String {
        let length = Int(base.load(fromByteOffset: cursor, as: UInt8.self))
        cursor += 1
        defer { cursor += capacity }
        guard length > 0, length <= capacity else { return "" }
        let bytes = UnsafeRawBufferPointer(start: base.advanced(by: cursor), count: length)
        return String(decoding: bytes, as: UTF8.self)
    }
}
