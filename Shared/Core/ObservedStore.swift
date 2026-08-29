import Foundation
import OSLog

/// One destination an app tried to reach.
public struct ObservedDestination: Codable, Sendable, Hashable, Identifiable {
    /// Hostname when the flow carried one, otherwise the literal address. Coalescing on this is what
    /// turns a retry storm — one app produced 1839 flows across a handful of hosts — into a few rows.
    public var host: String
    public var addresses: [String]
    public var ports: [UInt16]
    public var attempts: Int
    public var firstSeen: Date
    public var lastSeen: Date
    public var denied: Bool
    public var lastRule: String?

    public var id: String { host }
    public var isAddressOnly: Bool { addresses.contains(host) && !host.contains(where: \.isLetter) }
}

public struct ObservedApp: Codable, Sendable {
    public var appID: String
    public var destinations: [String: ObservedDestination]
    public var lastSeen: Date
    public var allowedCount: Int
    public var deniedCount: Int
}

/// Per-app, bounded, persisted record of what each app asked for.
///
/// Separate from the diagnostics ring on purpose. The ring is 2048 slots shared across every app, so
/// one blocked app retrying can evict every other app's history before you get to triage it — which
/// is exactly the case this store has to survive.
///
/// **Only the control provider writes it.** The data provider cannot write anywhere. The app reads
/// it, and may clear it; that is the one place two writers can race, and it is a deliberate
/// last-write-wins because clearing is an explicit user action.
public final class ObservedStore: @unchecked Sendable {

    public static let maximumDestinationsPerApp = 200
    public static let maximumApps = 300

    private let url: URL
    private let lock = NSLock()
    private var apps: [String: ObservedApp] = [:]
    private var isDirty = false
    private var lastFlush: UInt64 = 0
    private let flushInterval: UInt64 = 2_000_000_000

    public init?() {
        guard let url = SharedContainer.containerURL?
            .appendingPathComponent("observed.json", isDirectory: false) else { return nil }
        self.url = url
        load()
    }

    // MARK: - Reading

    public func snapshot() -> [ObservedApp] {
        lock.lock()
        defer { lock.unlock() }
        return apps.values.sorted { $0.lastSeen > $1.lastSeen }
    }

    public func reload() {
        lock.lock()
        defer { lock.unlock() }
        loadLocked()
    }

    // MARK: - Writing

    public func record(appID: String, host: String, address: String, port: UInt16,
                       denied: Bool, rule: String?, at date: Date = Date()) {
        let appKey = appID.isEmpty ? AppIdentity.unattributedRaw : appID
        let key = host.isEmpty ? address : host
        guard !key.isEmpty else { return }

        lock.lock()
        defer { lock.unlock() }

        var app = apps[appKey] ?? ObservedApp(appID: appKey, destinations: [:],
                                              lastSeen: date, allowedCount: 0, deniedCount: 0)
        var destination = app.destinations[key] ?? ObservedDestination(
            host: key, addresses: [], ports: [], attempts: 0,
            firstSeen: date, lastSeen: date, denied: denied, lastRule: rule)

        destination.attempts += 1
        destination.lastSeen = date
        destination.denied = denied
        if let rule { destination.lastRule = rule }
        if !address.isEmpty, !destination.addresses.contains(address) {
            destination.addresses.append(address)
            // A single hostname was measured resolving to eight addresses in 45 ms; keep a few.
            if destination.addresses.count > 8 { destination.addresses.removeFirst() }
        }
        if port != 0, !destination.ports.contains(port) {
            destination.ports.append(port)
            if destination.ports.count > 8 { destination.ports.removeFirst() }
        }

        app.destinations[key] = destination
        app.lastSeen = date
        if denied { app.deniedCount += 1 } else { app.allowedCount += 1 }

        // Bound per app, evicting least-recently-seen, so a busy destination cannot crowd out the
        // rest of *this* app's history either.
        if app.destinations.count > Self.maximumDestinationsPerApp {
            let survivors = app.destinations.values
                .sorted { $0.lastSeen > $1.lastSeen }
                .prefix(Self.maximumDestinationsPerApp)
            app.destinations = Dictionary(uniqueKeysWithValues: survivors.map { ($0.host, $0) })
        }
        apps[appKey] = app

        if apps.count > Self.maximumApps {
            let survivors = apps.values.sorted { $0.lastSeen > $1.lastSeen }.prefix(Self.maximumApps)
            apps = Dictionary(uniqueKeysWithValues: survivors.map { ($0.appID, $0) })
        }
        isDirty = true
    }

    /// Throttled write. Cheap now that the data provider escalates each `(app, host)` only once, so
    /// this is called on the order of once per new destination rather than once per flow.
    public func flushIfNeeded(now: UInt64) {
        lock.lock()
        guard isDirty, now &- lastFlush > flushInterval else { lock.unlock(); return }
        lastFlush = now
        isDirty = false
        let payload = apps
        lock.unlock()
        write(payload)
    }

    public func flush() {
        lock.lock()
        let payload = apps
        isDirty = false
        lock.unlock()
        write(payload)
    }

    public func clear() {
        lock.lock()
        apps = [:]
        isDirty = false
        lock.unlock()
        write([:])
    }

    // MARK: - Persistence

    private func load() {
        lock.lock()
        defer { lock.unlock() }
        loadLocked()
    }

    private func loadLocked() {
        guard let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode([String: ObservedApp].self, from: data)
        else { return }
        apps = decoded
    }

    private func write(_ payload: [String: ObservedApp]) {
        do {
            let data = try JSONEncoder().encode(payload)
            try data.write(to: url, options: .atomic)
            // Providers run before first unlock after a reboot; without this the write fails there.
            try? FileManager.default.setAttributes(
                [.protectionKey: SharedContainer.fileProtection], ofItemAtPath: url.path)
        } catch {
            Log.storage.error("[\(Log.process, privacy: .public)] observed store write failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
