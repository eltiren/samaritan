import Foundation

/// An IPv4 or IPv6 network prefix, stored masked so equal prefixes compare equal.
///
/// The address is held as two `UInt64`s rather than a byte tuple so bit access on the hot path is a
/// shift and a mask. IPv4 lives in the top 32 bits of `hi`, which lets one bit-walk serve both
/// families.
public struct IPPrefix: Hashable, Sendable, CustomStringConvertible {

    public enum Family: UInt8, Sendable {
        case v4 = 4
        case v6 = 6

        public var bitWidth: Int { self == .v4 ? 32 : 128 }
    }

    public let hi: UInt64
    public let lo: UInt64
    public let length: UInt8
    public let family: Family

    public init(hi: UInt64, lo: UInt64, length: UInt8, family: Family) {
        let bits = min(Int(length), family.bitWidth)
        self.length = UInt8(bits)
        self.family = family
        // Mask off host bits so `1.2.3.4/24` and `1.2.3.0/24` are the same prefix.
        if bits >= 64 {
            self.hi = hi
            self.lo = bits == 64 ? 0 : lo & ~(UInt64.max >> UInt64(bits - 64))
        } else {
            self.hi = bits == 0 ? 0 : hi & ~(UInt64.max >> UInt64(bits))
            self.lo = 0
        }
    }

    /// Parses `1.2.3.4`, `1.2.3.0/24`, `2606:4700::1111`, `2606:4700::/32`.
    /// A bare address gets the family's full prefix length.
    public init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let addressText = String(parts[0])
        guard !addressText.isEmpty else { return nil }

        var explicitLength: UInt8?
        if parts.count == 2 {
            guard let value = UInt8(parts[1]) else { return nil }
            explicitLength = value
        }

        // IPv6 first: an IPv4-mapped form such as ::ffff:1.2.3.4 parses as v6, which is correct.
        var v6 = in6_addr()
        if addressText.contains(":"), inet_pton(AF_INET6, addressText, &v6) == 1 {
            let bytes = withUnsafeBytes(of: v6) { Array($0) }
            guard bytes.count >= 16 else { return nil }
            let hi = bytes[0..<8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let lo = bytes[8..<16].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let length = explicitLength ?? 128
            guard length <= 128 else { return nil }
            self.init(hi: hi, lo: lo, length: length, family: .v6)
            return
        }

        var v4 = in_addr()
        if inet_pton(AF_INET, addressText, &v4) == 1 {
            // in_addr is network byte order; shift into the top 32 bits of `hi`.
            let host = UInt64(UInt32(bigEndian: v4.s_addr))
            let length = explicitLength ?? 32
            guard length <= 32 else { return nil }
            self.init(hi: host << 32, lo: 0, length: length, family: .v4)
            return
        }
        return nil
    }

    /// Bit at `index`, counted from the most significant bit of the address.
    @inline(__always)
    public func bit(at index: Int) -> Bool {
        if index < 64 {
            return (hi >> UInt64(63 - index)) & 1 == 1
        }
        return (lo >> UInt64(127 - index)) & 1 == 1
    }

    /// True when `self` (a rule) covers `address` (a flow's endpoint).
    public func contains(_ address: IPPrefix) -> Bool {
        guard family == address.family else { return false }
        guard length <= address.length else { return false }
        let masked = IPPrefix(hi: address.hi, lo: address.lo, length: length, family: family)
        return masked.hi == hi && masked.lo == lo
    }

    public var description: String {
        switch family {
        case .v4:
            let value = UInt32(truncatingIfNeeded: hi >> 32)
            let text = "\((value >> 24) & 0xFF).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
            return length == 32 ? text : "\(text)/\(length)"
        case .v6:
            var storage = in6_addr()
            withUnsafeMutableBytes(of: &storage) { raw in
                for offset in 0..<8 { raw[offset] = UInt8((hi >> UInt64(56 - 8 * offset)) & 0xFF) }
                for offset in 0..<8 { raw[8 + offset] = UInt8((lo >> UInt64(56 - 8 * offset)) & 0xFF) }
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let text = inet_ntop(AF_INET6, &storage, &buffer, socklen_t(buffer.count)).map {
                String(cString: $0)
            } ?? "::"
            return length == 128 ? text : "\(text)/\(length)"
        }
    }

    /// The presets the rule popover offers, coarsest last.
    public static func presets(for address: IPPrefix) -> [IPPrefix] {
        let lengths: [UInt8] = address.family == .v4 ? [32, 24, 16, 8] : [128, 64, 48, 32]
        return lengths.map {
            IPPrefix(hi: address.hi, lo: address.lo, length: $0, family: address.family)
        }
    }
}
