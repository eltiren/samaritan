import Foundation

/// Thin `getifaddrs(3)` wrapper.
///
/// Used for the NordVPN coexistence experiment: it tells us which `utun*` interfaces exist and
/// which addresses they own, so a flow's *local* address can be classified as "inside the tunnel"
/// or "on the physical interface". That distinction is what answers question 5 of the experiment —
/// whether the content filter sits above or below the packet tunnel.
public enum NetworkInterfaces {

    public struct Interface: Sendable, Hashable {
        public let name: String
        public let address: String
        public let family: Int32
        public let isUp: Bool

        public var isTunnel: Bool {
            name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp")
        }

        /// Link-local (`fe80::/10`, `169.254.0.0/16`). Never the source address of internet traffic.
        public var isLinkLocal: Bool {
            address.lowercased().hasPrefix("fe80:") || address.hasPrefix("169.254.")
        }

        /// A tunnel address a flow could actually be sourced from.
        ///
        /// iOS keeps a dozen or more `utun*` interfaces up at all times for Wi-Fi Calling, AWDL,
        /// Handoff and iCloud Private Relay, and auto-assigns a `fe80::` address to each. Counting
        /// those made "is a VPN up?" permanently true, so link-local addresses are excluded and the
        /// signal is narrowed to routable addresses on tunnel interfaces.
        public var isRoutableTunnelAddress: Bool {
            isTunnel && isUp && !isLinkLocal
        }

        public var familyName: String {
            switch family {
            case AF_INET: "IPv4"
            case AF_INET6: "IPv6"
            default: "af\(family)"
            }
        }
    }

    public static func current() -> [Interface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var result: [Interface] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let sa = entry.pointee.ifa_addr else { continue }
            let family = Int32(sa.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len),
                              &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
            else { continue }

            var address = host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
            // Strip the IPv6 scope suffix so addresses compare equal to what NetworkExtension gives us.
            if let percent = address.firstIndex(of: "%") { address = String(address[..<percent]) }

            result.append(Interface(name: String(cString: entry.pointee.ifa_name),
                                    address: address,
                                    family: family,
                                    isUp: entry.pointee.ifa_flags & UInt32(IFF_UP) != 0))
        }
        return result
    }

    /// Routable addresses currently owned by tunnel interfaces — see `isRoutableTunnelAddress`.
    public static func tunnelAddresses() -> Set<String> {
        Set(current().filter(\.isRoutableTunnelAddress).map(\.address))
    }

    /// `utun3=10.5.0.2` style listing, for logs.
    public static func tunnelDescription() -> String {
        let entries = current().filter(\.isRoutableTunnelAddress)
            .map { "\($0.name)=\($0.address)" }
            .sorted()
        return entries.isEmpty ? "none" : entries.joined(separator: ",")
    }
}
