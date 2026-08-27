import Foundation
import Testing
@testable import SamaritanTests

// Pure-Swift logic only. Nothing here mocks NetworkExtension — the parts of the system that only a
// device can answer are answered on a device, not in a test.

@Suite("FlowRecord binary codec")
struct FlowRecordCodecTests {

    private func roundTrip(_ record: FlowRecord, sequence: UInt64 = 42) -> FlowRecord? {
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: FlowRecordCodec.slotSize, alignment: 16)
        defer { buffer.deallocate() }
        FlowRecordCodec.encode(record, sequence: sequence, into: buffer)
        return FlowRecordCodec.decode(from: UnsafeRawBufferPointer(buffer))
    }

    @Test("round-trips every field")
    func roundTripsFields() throws {
        var record = FlowRecord()
        record.timestamp = Date(timeIntervalSinceReferenceDate: 123_456.789)
        record.origin = .controlProvider
        record.verdict = .drop
        record.direction = 2
        record.socketFamily = AF_INET6
        record.socketType = SOCK_STREAM
        record.socketProtocol = IPPROTO_TCP
        record.pathFlags = [.satisfied, .wifi, .tunnelPresent, .localIsTunnel]
        record.remotePort = 443
        record.localPort = 51_234
        record.bytesInbound = 9_001
        record.bytesOutbound = 17
        record.decisionNanos = 621_000
        record.flowIdentifier = "A1B2C3D4"
        record.sourceApp = "com.example.SomeApp"
        record.sourceAppVersion = "3.2.1"
        record.remoteHostname = "news.example.com"
        record.remoteAddress = "2606:4700:4700::1111"
        record.localAddress = "10.5.0.2"
        record.matchedRule = "host:example.com"

        let decoded = try #require(roundTrip(record))

        #expect(decoded.sequence == 42)
        #expect(abs(decoded.timestamp.timeIntervalSinceReferenceDate - 123_456.789) < 0.000_001)
        #expect(decoded.origin == .controlProvider)
        #expect(decoded.verdict == .drop)
        #expect(decoded.direction == 2)
        #expect(decoded.socketFamily == AF_INET6)
        #expect(decoded.socketType == SOCK_STREAM)
        #expect(decoded.socketProtocol == IPPROTO_TCP)
        #expect(decoded.pathFlags == [.satisfied, .wifi, .tunnelPresent, .localIsTunnel])
        #expect(decoded.remotePort == 443)
        #expect(decoded.localPort == 51_234)
        #expect(decoded.bytesInbound == 9_001)
        #expect(decoded.bytesOutbound == 17)
        #expect(decoded.decisionNanos == 621_000)
        #expect(decoded.flowIdentifier == "A1B2C3D4")
        #expect(decoded.sourceApp == "com.example.SomeApp")
        #expect(decoded.sourceAppVersion == "3.2.1")
        #expect(decoded.remoteHostname == "news.example.com")
        #expect(decoded.remoteAddress == "2606:4700:4700::1111")
        #expect(decoded.localAddress == "10.5.0.2")
        #expect(decoded.matchedRule == "host:example.com")
    }

    @Test("rejects an empty slot")
    func rejectsEmptySlot() {
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: FlowRecordCodec.slotSize, alignment: 16)
        defer { buffer.deallocate() }
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
        #expect(FlowRecordCodec.decode(from: UnsafeRawBufferPointer(buffer)) == nil)
    }

    @Test("rejects a torn slot")
    func rejectsTornSlot() {
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: FlowRecordCodec.slotSize, alignment: 16)
        defer { buffer.deallocate() }
        FlowRecordCodec.encode(FlowRecord(), sequence: 7, into: buffer)
        // Simulate a reader catching the writer mid-slot: the trailing seqlock word is stale.
        buffer.baseAddress!.storeBytes(of: UInt64(6).littleEndian, toByteOffset: 504, as: UInt64.self)
        #expect(FlowRecordCodec.decode(from: UnsafeRawBufferPointer(buffer)) == nil)
    }

    @Test("truncates an over-long hostname without producing invalid UTF-8")
    func truncatesLongHostname() throws {
        var record = FlowRecord()
        // Multi-byte scalars guarantee the 128-byte cap lands mid-scalar.
        record.remoteHostname = String(repeating: "日", count: 100)

        let decoded = try #require(roundTrip(record))

        #expect(decoded.remoteHostname.utf8.count <= 128)
        #expect(!decoded.remoteHostname.isEmpty)
        #expect(!decoded.remoteHostname.unicodeScalars.contains { $0 == "\u{FFFD}" })
        #expect(decoded.remoteHostname.allSatisfy { $0 == "日" })
    }

    @Test("empty strings round-trip as empty")
    func emptyStrings() throws {
        let decoded = try #require(roundTrip(FlowRecord(), sequence: 1))
        #expect(decoded.sourceApp.isEmpty)
        #expect(decoded.remoteHostname.isEmpty)
        #expect(decoded.matchedRule.isEmpty)
    }
}
