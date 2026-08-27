import Foundation
import Network
import OSLog

/// Tracks the current `NWPath` and the set of tunnel-interface addresses.
///
/// Every `FlowRecord` is stamped with this state, which is what makes the NordVPN experiment
/// answerable after the fact: for each flow we know whether a tunnel existed, whether the path
/// included an `.other` (utun) interface, and whether the flow's own local address belonged to
/// that tunnel.
public final class PathObserver: @unchecked Sendable {

    public static let shared = PathObserver()

    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "app.samaritan.path", qos: .utility)
    private let lock = NSLock()
    private var baseFlags: FlowRecord.PathFlags = []
    private var tunnels: Set<String> = []
    private var started = false

    private init() {}

    public func start() {
        lock.lock()
        guard !started else { lock.unlock(); return }
        started = true
        lock.unlock()

        monitor.pathUpdateHandler = { [weak self] path in
            self?.update(with: path)
        }
        monitor.start(queue: queue)
        update(with: monitor.currentPath)
    }

    private func update(with path: NWPath) {
        var flags: FlowRecord.PathFlags = []
        if path.status == .satisfied { flags.insert(.satisfied) }
        if path.usesInterfaceType(.wifi) { flags.insert(.wifi) }
        if path.usesInterfaceType(.cellular) { flags.insert(.cellular) }
        if path.usesInterfaceType(.wiredEthernet) { flags.insert(.wiredEthernet) }
        if path.usesInterfaceType(.loopback) { flags.insert(.loopback) }
        // A `utun` VPN interface reports as `.other`. This is the cheapest in-extension signal that
        // a packet tunnel is carrying traffic.
        if path.usesInterfaceType(.other) { flags.insert(.otherInterface) }
        if path.isExpensive { flags.insert(.expensive) }
        if path.isConstrained { flags.insert(.constrained) }

        let tunnelAddresses = NetworkInterfaces.tunnelAddresses()
        if !tunnelAddresses.isEmpty { flags.insert(.tunnelPresent) }

        lock.lock()
        baseFlags = flags
        tunnels = tunnelAddresses
        lock.unlock()

        Log.path.log("""
            [\(Log.process, privacy: .public)] path status=\(String(describing: path.status), privacy: .public) \
            flags=\(flags.summary, privacy: .public) \
            interfaces=\(path.availableInterfaces.map(\.name).joined(separator: ","), privacy: .public) \
            tunnels=\(NetworkInterfaces.tunnelDescription(), privacy: .public)
            """)
    }

    /// Current flags, additionally marking whether `localAddress` is owned by a tunnel interface.
    public func flags(localAddress: String) -> FlowRecord.PathFlags {
        lock.lock()
        var flags = baseFlags
        let isTunnel = !localAddress.isEmpty && tunnels.contains(localAddress)
        lock.unlock()
        if isTunnel { flags.insert(.localIsTunnel) }
        return flags
    }

    public var tunnelAddresses: Set<String> {
        lock.lock()
        defer { lock.unlock() }
        return tunnels
    }
}
