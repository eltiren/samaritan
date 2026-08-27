import Foundation

/// Per-app view of what the providers recorded, built from the diagnostics rings.
///
/// Destinations are coalesced by hostname where one exists, otherwise by address. One blocked app
/// was measured producing 1839 flows across a handful of destinations, so a row per flow would be
/// unreadable and would evict everything else.
struct ObservedActivity {

    struct Destination: Identifiable, Hashable {
        var hostname: String
        var addresses: Set<String>
        var attempts: Int
        var lastSeen: Date
        var wasDenied: Bool
        var ports: Set<UInt16>

        var id: String { hostname.isEmpty ? addresses.sorted().joined(separator: ",") : hostname }

        /// What the rule popover keys on: the hostname if we have one, otherwise a literal address.
        var ruleTarget: String {
            hostname.isEmpty ? (addresses.sorted().first ?? "") : hostname
        }

        var isAddressOnly: Bool { hostname.isEmpty }
    }

    struct App: Identifiable, Hashable {
        var appID: String
        var destinations: [Destination]
        var allowed: Int
        var denied: Int
        var lastSeen: Date

        var id: String { appID }
        var identity: AppIdentity { AppIdentity(raw: appID) }
    }

    private(set) var apps: [App] = []

    init(records: [FlowRecord]) {
        var byApp: [String: [String: Destination]] = [:]
        var allowed: [String: Int] = [:]
        var denied: [String: Int] = [:]
        var lastSeen: [String: Date] = [:]

        for record in records {
            let appID = record.sourceApp.isEmpty ? AppIdentity.unattributedRaw : record.sourceApp
            let key = record.remoteHostname.isEmpty ? record.remoteAddress : record.remoteHostname
            guard !key.isEmpty else { continue }

            if record.verdict.isDrop || record.verdict == .needRules {
                denied[appID, default: 0] += 1
            } else if record.verdict == .allow || record.verdict == .controlAllow {
                allowed[appID, default: 0] += 1
            }
            lastSeen[appID] = max(lastSeen[appID] ?? .distantPast, record.timestamp)

            var destinations = byApp[appID] ?? [:]
            var destination = destinations[key] ?? Destination(
                hostname: record.remoteHostname, addresses: [], attempts: 0,
                lastSeen: record.timestamp, wasDenied: false, ports: [])
            destination.attempts += 1
            if !record.remoteAddress.isEmpty { destination.addresses.insert(record.remoteAddress) }
            if record.remotePort != 0 { destination.ports.insert(record.remotePort) }
            destination.lastSeen = max(destination.lastSeen, record.timestamp)
            destination.wasDenied = destination.wasDenied
                || record.verdict.isDrop || record.verdict == .needRules
            destinations[key] = destination
            byApp[appID] = destinations
        }

        apps = byApp.map { appID, destinations in
            App(appID: appID,
                destinations: destinations.values.sorted { $0.lastSeen > $1.lastSeen },
                allowed: allowed[appID] ?? 0,
                denied: denied[appID] ?? 0,
                lastSeen: lastSeen[appID] ?? .distantPast)
        }
        .sorted { $0.lastSeen > $1.lastSeen }
    }

    func app(_ appID: String) -> App? {
        apps.first { $0.appID == appID }
    }
}
