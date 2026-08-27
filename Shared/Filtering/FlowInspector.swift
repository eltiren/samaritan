import Foundation
import Network
import NetworkExtension

/// Extracts every piece of metadata the current (iOS 26 SDK) NetworkExtension API exposes about a
/// flow, into a plain `FlowRecord`.
///
/// What is and is not available here is a milestone-1 deliverable in itself. Verified against
/// `NEFilterFlow.h` in the iOS 26.5 SDK:
///
/// | Property                    | iOS                    | Notes                                   |
/// |-----------------------------|------------------------|-----------------------------------------|
/// | `sourceAppIdentifier`       | 11.0+                  | iOS-only; unavailable on macOS          |
/// | `sourceAppUniqueIdentifier` | 11.0+                  | opaque `Data`                           |
/// | `sourceAppVersion`          | 11.0+                  |                                         |
/// | `identifier`                | 13.1+                  | stable per flow, joins report → flow    |
/// | `direction`                 | 13.0+                  |                                         |
/// | `remoteHostname`            | 14.0+                  | often `nil`                             |
/// | `remoteFlowEndpoint`        | 18.0+                  | replaces deprecated `remoteEndpoint`    |
/// | `localFlowEndpoint`         | 18.0+                  | replaces deprecated `localEndpoint`     |
/// | `remoteHostname` on report  | 14.0+                  | see `NEFilterReport`                    |
/// | `sourceAppAuditToken`       | **macOS only**         | not available to us                     |
///
/// There is no byte count on the flow object. Byte counts arrive only via `NEFilterReport`
/// (`bytesInboundCount` / `bytesOutboundCount`, iOS 13+), which requires `shouldReport = true`.
public enum FlowInspector {

    public static func record(for flow: NEFilterFlow, origin: FlowRecord.Origin) -> FlowRecord {
        var record = FlowRecord()
        record.origin = origin
        record.timestamp = Date()
        record.flowIdentifier = String(flow.identifier.uuidString.prefix(8))
        record.sourceApp = flow.sourceAppIdentifier ?? ""
        record.sourceAppVersion = flow.sourceAppVersion ?? ""
        record.direction = UInt8(clamping: flow.direction.rawValue)

        if let url = flow.url, let host = url.host {
            record.remoteHostname = host
        }

        switch flow {
        case let socketFlow as NEFilterSocketFlow:
            record.socketFamily = socketFlow.socketFamily
            record.socketType = socketFlow.socketType
            record.socketProtocol = socketFlow.socketProtocol

            if let hostname = socketFlow.remoteHostname, !hostname.isEmpty {
                record.remoteHostname = hostname
            }

            let remote = describe(socketFlow.remoteFlowEndpoint)
            record.remoteAddress = remote.address
            record.remotePort = remote.port
            if record.remoteHostname.isEmpty { record.remoteHostname = remote.hostname }

            let local = describe(socketFlow.localFlowEndpoint)
            record.localAddress = local.address.isEmpty ? local.hostname : local.address
            record.localPort = local.port

        case let browserFlow as NEFilterBrowserFlow:
            // NEFilterBrowserFlow only ever appears when `filterBrowsers` is set, and in practice
            // modern iOS does not deliver these to third-party filters. Handled for completeness so
            // the spike can report "browser flows: 0" as evidence rather than as an omission.
            if let host = browserFlow.request?.url?.host, record.remoteHostname.isEmpty {
                record.remoteHostname = host
            }

        default:
            break
        }

        record.pathFlags = PathObserver.shared.flags(localAddress: record.localAddress)
        return record
    }

    // MARK: - Endpoints

    /// `remoteFlowEndpoint` / `localFlowEndpoint` (iOS 18+, replacing the deprecated
    /// `remoteEndpoint` / `localEndpoint`) bridge into Swift as `Network.NWEndpoint`, which has to
    /// be disambiguated from `NetworkExtension`'s legacy `NWEndpoint` class of the same name.
    static func describe(_ endpoint: Network.NWEndpoint?) -> (hostname: String, address: String, port: UInt16) {
        guard let endpoint else { return ("", "", 0) }

        switch endpoint {
        case .hostPort(let host, let port):
            switch host {
            case .ipv4(let address):
                return ("", strippingScope(String(describing: address)), port.rawValue)
            case .ipv6(let address):
                return ("", strippingScope(String(describing: address)), port.rawValue)
            case .name(let name, _):
                return (name, "", port.rawValue)
            @unknown default:
                return ("", "", port.rawValue)
            }

        case .url(let url):
            return (url.host ?? "", "", UInt16(exactly: url.port ?? 0) ?? 0)

        case .unix(let path):
            return ("", path, 0)

        case .service(let name, _, _, _):
            return (name, "", 0)

        case .opaque(let value):
            // Endpoints the overlay cannot model as host/port — proxied or relayed flows land here.
            // Worth recording verbatim: seeing these under a VPN or iCloud Private Relay is itself
            // an answer to "what does remoteEndpoint contain while the tunnel is up?".
            return (String(describing: value), "", 0)

        @unknown default:
            return ("", "", 0)
        }
    }

    /// IPv6 literals can carry a `%interface` scope suffix; strip it so addresses compare cleanly
    /// against `getifaddrs` output when classifying a flow as inside or outside a tunnel.
    private static func strippingScope(_ address: String) -> String {
        guard let percent = address.firstIndex(of: "%") else { return address }
        return String(address[..<percent])
    }
}
