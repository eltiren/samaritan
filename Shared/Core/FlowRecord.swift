import Foundation

/// One observation of one network flow, as seen by a provider.
///
/// Deliberately flat and fixed-width on disk (see `FlowRecordCodec`) so the hot path in
/// `NEFilterDataProvider.handleNewFlow(_:)` can persist it with a single `pwrite(2)` and no
/// serialisation machinery.
public struct FlowRecord: Sendable, Equatable, Identifiable {

    public enum Origin: UInt8, Sendable {
        case dataProvider = 1
        case controlProvider = 2
    }

    /// What the provider actually returned (or, for `.report`, what the system told us afterwards).
    public enum Verdict: UInt8, Sendable {
        case allow = 1
        case drop = 2
        case needRules = 3
        case controlAllow = 4
        case controlDrop = 5
        case report = 6

        public var label: String {
            switch self {
            case .allow: "allow"
            case .drop: "DROP"
            case .needRules: "needRules"
            case .controlAllow: "ctl-allow"
            case .controlDrop: "ctl-DROP"
            case .report: "report"
            }
        }

        public var isDrop: Bool { self == .drop || self == .controlDrop }
    }

    /// Snapshot of `NWPathMonitor` state at the moment the flow was seen. This is the primary
    /// instrument for the NordVPN coexistence experiment: it records whether a tunnel interface
    /// was part of the satisfied path when the filter made its decision.
    public struct PathFlags: OptionSet, Sendable, Equatable {
        public let rawValue: UInt16
        public init(rawValue: UInt16) { self.rawValue = rawValue }

        public static let satisfied      = PathFlags(rawValue: 1 << 0)
        public static let wifi           = PathFlags(rawValue: 1 << 1)
        public static let cellular       = PathFlags(rawValue: 1 << 2)
        public static let wiredEthernet  = PathFlags(rawValue: 1 << 3)
        public static let loopback       = PathFlags(rawValue: 1 << 4)
        /// `NWInterface.InterfaceType.other` — this is how a `utun` VPN interface presents itself.
        public static let otherInterface = PathFlags(rawValue: 1 << 5)
        /// A `utun*` interface with an assigned address existed when the record was written.
        public static let tunnelPresent  = PathFlags(rawValue: 1 << 6)
        /// The flow's *local* address matched an address owned by a `utun*` interface, i.e. the
        /// socket is bound inside the tunnel.
        public static let localIsTunnel  = PathFlags(rawValue: 1 << 7)
        public static let expensive      = PathFlags(rawValue: 1 << 8)
        public static let constrained    = PathFlags(rawValue: 1 << 9)

        public var summary: String {
            var parts: [String] = []
            if contains(.wifi) { parts.append("wifi") }
            if contains(.cellular) { parts.append("cell") }
            if contains(.wiredEthernet) { parts.append("eth") }
            if contains(.otherInterface) { parts.append("other") }
            if contains(.loopback) { parts.append("lo") }
            if contains(.tunnelPresent) { parts.append("utun") }
            if contains(.localIsTunnel) { parts.append("in-tunnel") }
            if !contains(.satisfied) { parts.append("unsatisfied") }
            return parts.isEmpty ? "-" : parts.joined(separator: ",")
        }
    }

    public var sequence: UInt64 = 0
    public var timestamp: Date = .init()
    public var origin: Origin = .dataProvider
    public var verdict: Verdict = .allow

    /// Raw value of `NETrafficDirection` (0 any, 1 inbound, 2 outbound).
    public var direction: UInt8 = 0
    public var socketFamily: Int32 = 0
    public var socketType: Int32 = 0
    public var socketProtocol: Int32 = 0
    public var pathFlags: PathFlags = []

    public var remotePort: UInt16 = 0
    public var localPort: UInt16 = 0

    /// Only populated on `.report` records — iOS delivers byte counts via `NEFilterReport`
    /// (`NEFilterReportEvent.flowClosed`), never on the flow object itself.
    public var bytesInbound: UInt64 = 0
    public var bytesOutbound: UInt64 = 0

    /// Wall time spent inside our verdict function. Kept because the hot path budget is the whole
    /// reason the future policy engine has to be a prefix trie rather than a linear scan.
    public var decisionNanos: UInt64 = 0

    public var flowIdentifier: String = ""
    public var sourceApp: String = ""
    public var sourceAppVersion: String = ""
    /// `NEFilterSocketFlow.remoteHostname` (iOS 14+). Frequently `nil` — that is itself a finding.
    public var remoteHostname: String = ""
    public var remoteAddress: String = ""
    public var localAddress: String = ""
    public var matchedRule: String = ""

    public var id: UInt64 { sequence }

    public init() {}

    public var socketProtocolName: String {
        switch socketProtocol {
        case IPPROTO_TCP: "TCP"
        case IPPROTO_UDP: "UDP"
        case IPPROTO_ICMP: "ICMP"
        case IPPROTO_ICMPV6: "ICMPv6"
        case 0: "-"
        default: "proto\(socketProtocol)"
        }
    }

    public var socketFamilyName: String {
        switch socketFamily {
        case AF_INET: "IPv4"
        case AF_INET6: "IPv6"
        case 0: "-"
        default: "af\(socketFamily)"
        }
    }

    /// Best available human label for the destination: hostname if the system gave us one,
    /// otherwise the literal address.
    public var remoteDescription: String {
        let host = remoteHostname.isEmpty ? remoteAddress : remoteHostname
        guard !host.isEmpty else { return "?" }
        return remotePort == 0 ? host : "\(host):\(remotePort)"
    }

    public var localDescription: String {
        guard !localAddress.isEmpty else { return "?" }
        return localPort == 0 ? localAddress : "\(localAddress):\(localPort)"
    }

    public var appDescription: String {
        sourceApp.isEmpty ? "<no sourceAppIdentifier>" : sourceApp
    }
}
