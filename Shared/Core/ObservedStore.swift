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

    /// Bytes this app has received and sent since the counters epoch.
    ///
    /// Same source as the global `reportedBytesInbound`/`reportedBytesOutbound` counters and the
    /// same arithmetic — this is that total, split by app — so the two are checkable against each
    /// other. Sum every app here and you get the global figure back, less whatever eviction has
    /// since dropped (`maximumApps`) and less anything a bypassed app moved, which is recorded
    /// nowhere by design.
    ///
    /// Only the `flowClosed` report carries byte counts, so a connection contributes nothing until
    /// it ends: an app streaming video for an hour can legitimately read zero throughout.
    public var bytesInbound: UInt64
    public var bytesOutbound: UInt64

    public init(appID: String, destinations: [String: ObservedDestination] = [:],
                lastSeen: Date = Date(), allowedCount: Int = 0, deniedCount: Int = 0,
                bytesInbound: UInt64 = 0, bytesOutbound: UInt64 = 0) {
        self.appID = appID
        self.destinations = destinations
        self.lastSeen = lastSeen
        self.allowedCount = allowedCount
        self.deniedCount = deniedCount
        self.bytesInbound = bytesInbound
        self.bytesOutbound = bytesOutbound
    }

    /// Written out rather than synthesised, for the same reason as `AppPolicy`'s: synthesised
    /// `Codable` ignores property defaults and throws `keyNotFound`, so adding the byte totals
    /// would have made every `observed.json` written before them undecodable — silently erasing
    /// every app's destination history on upgrade.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        appID = try container.decode(String.self, forKey: .appID)
        destinations = try container.decode([String: ObservedDestination].self, forKey: .destinations)
        lastSeen = try container.decode(Date.self, forKey: .lastSeen)
        allowedCount = try container.decode(Int.self, forKey: .allowedCount)
        deniedCount = try container.decode(Int.self, forKey: .deniedCount)
        bytesInbound = try container.decodeIfPresent(UInt64.self, forKey: .bytesInbound) ?? 0
        bytesOutbound = try container.decodeIfPresent(UInt64.self, forKey: .bytesOutbound) ?? 0
    }
}

/// On-disk shape of `observed.json`.
///
/// The map used to be the whole file. It is wrapped now because the byte totals need to carry the
/// counters epoch they belong to: without it a provider restart could not tell "the app reset the
/// counters while I was not running" from "these totals are mine", and would either re-zero on
/// every launch or never notice a reset at all.
struct ObservedFile: Codable {
    var version: Int
    /// The `DiagnosticsStore` counters epoch these byte totals accumulate against. 0 = unknown.
    var countersEpoch: UInt64
    var apps: [String: ObservedApp]

    init(version: Int = ObservedStore.fileVersion, countersEpoch: UInt64 = 0,
         apps: [String: ObservedApp] = [:]) {
        self.version = version
        self.countersEpoch = countersEpoch
        self.apps = apps
    }

    /// `version` is deliberately **required**. It is the only thing distinguishing this envelope
    /// from a legacy bare `[appID: ObservedApp]` map, and if every key were optional a legacy file
    /// would decode successfully as an empty envelope and wipe the history it was meant to preserve.
    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        countersEpoch = try container.decodeIfPresent(UInt64.self, forKey: .countersEpoch) ?? 0
        apps = try container.decodeIfPresent([String: ObservedApp].self, forKey: .apps) ?? [:]
    }
}

/// Per-app, bounded, persisted record of what each app asked for and how much it moved.
///
/// Separate from the diagnostics ring on purpose. The ring is 2048 slots shared across every app, so
/// one blocked app retrying can evict every other app's history before you get to triage it — which
/// is exactly the case this store has to survive.
///
/// **Only the control provider writes it.** The data provider cannot write anywhere. The app reads
/// it, and may clear it or reset the byte totals; that is the one place two writers can race, and it
/// is a deliberate last-write-wins because both are explicit user actions.
public final class ObservedStore: @unchecked Sendable {

    public static let maximumDestinationsPerApp = 200
    public static let maximumApps = 300
    public static let fileVersion = 1

    private let url: URL
    private let lock = NSLock()
    private var apps: [String: ObservedApp] = [:]
    private var countersEpoch: UInt64 = 0
    private var isDirty = false
    private var lastFlush: UInt64 = 0
    private let flushInterval: UInt64 = 2_000_000_000

    public init?() {
        guard let url = SharedContainer.containerURL?
            .appendingPathComponent("observed.json", isDirectory: false) else { return nil }
        self.url = url
        load()
    }

    /// Tests only. Production goes through `init?()` so the App Group container stays the single
    /// source of truth for where this lives.
    public init(fileURL: URL) {
        self.url = fileURL
        load()
    }

    // MARK: - Reading

    public func snapshot() -> [ObservedApp] {
        lock.lock()
        defer { lock.unlock() }
        return apps.values.sorted { $0.lastSeen > $1.lastSeen }
    }

    /// The counters epoch the byte totals belong to. Diagnostics and tests.
    public var currentCountersEpoch: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return countersEpoch
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

        var app = apps[appKey] ?? ObservedApp(appID: appKey, lastSeen: date)
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
        enforceAppBoundLocked()
        isDirty = true
    }

    /// Adds one report's bytes to an app's running totals.
    ///
    /// Deliberately not folded into `record(_:)`. That call is keyed on a destination and drops a
    /// flow carrying neither hostname nor address; the bytes would go with it, and a byte total
    /// that quietly omits some flows is worse than no byte total. Byte accounting is per app and
    /// answers to nothing but the report.
    ///
    /// `epoch` is the ring header's counters epoch, passed in rather than read here so this store
    /// stays independent of `DiagnosticsStore`. A change means the app reset the counters, and the
    /// per-app totals are the same measurement, so they are cleared by the same tap.
    public func addTraffic(appID: String, inbound: UInt64, outbound: UInt64,
                           countersEpoch epoch: UInt64, at date: Date = Date()) {
        let appKey = appID.isEmpty ? AppIdentity.unattributedRaw : appID

        lock.lock()
        defer { lock.unlock() }
        adoptCountersEpochLocked(epoch)
        guard inbound > 0 || outbound > 0 else { return }

        var app = apps[appKey] ?? ObservedApp(appID: appKey, lastSeen: date)
        app.bytesInbound &+= inbound
        app.bytesOutbound &+= outbound
        app.lastSeen = date
        apps[appKey] = app
        enforceAppBoundLocked()
        isDirty = true
    }

    /// Zeroes every app's byte totals and adopts `epoch`, keeping the destination history.
    ///
    /// Called from the app when the counters are reset. The control provider does the same thing
    /// independently the next time a report arrives, having seen the new epoch in the ring header —
    /// both writers converge on the same state, so the race between them is benign. Doing it here
    /// too is what makes the reset visible immediately, including when the filter is switched off
    /// and no provider is running to notice.
    public func resetTraffic(countersEpoch epoch: UInt64) {
        lock.lock()
        countersEpoch = epoch
        for key in apps.keys {
            apps[key]?.bytesInbound = 0
            apps[key]?.bytesOutbound = 0
        }
        isDirty = false
        let payload = apps
        let stamp = countersEpoch
        lock.unlock()
        write(payload, countersEpoch: stamp)
    }

    /// Throttled write. Cheap now that the data provider escalates each `(app, host)` only once, so
    /// this is called on the order of once per new destination rather than once per flow.
    public func flushIfNeeded(now: UInt64) {
        lock.lock()
        guard isDirty, now &- lastFlush > flushInterval else { lock.unlock(); return }
        lastFlush = now
        isDirty = false
        let payload = apps
        let stamp = countersEpoch
        lock.unlock()
        write(payload, countersEpoch: stamp)
    }

    public func flush() {
        lock.lock()
        let payload = apps
        let stamp = countersEpoch
        isDirty = false
        lock.unlock()
        write(payload, countersEpoch: stamp)
    }

    public func clear() {
        lock.lock()
        apps = [:]
        isDirty = false
        let stamp = countersEpoch
        lock.unlock()
        write([:], countersEpoch: stamp)
    }

    // MARK: - Bounds

    private func enforceAppBoundLocked() {
        guard apps.count > Self.maximumApps else { return }
        let survivors = apps.values.sorted { $0.lastSeen > $1.lastSeen }.prefix(Self.maximumApps)
        apps = Dictionary(uniqueKeysWithValues: survivors.map { ($0.appID, $0) })
    }

    // MARK: - Epoch

    /// Notices a counter reset performed by the app and adopts it.
    ///
    /// Zero means "no epoch available" — an old ring, or a store opened without one — and is never
    /// adopted, because clearing on an unknown epoch would zero the totals on every report.
    private func adoptCountersEpochLocked(_ epoch: UInt64) {
        guard epoch != 0, epoch != countersEpoch else { return }
        countersEpoch = epoch
        for key in apps.keys {
            apps[key]?.bytesInbound = 0
            apps[key]?.bytesOutbound = 0
        }
        isDirty = true
    }

    // MARK: - Persistence

    private func load() {
        lock.lock()
        defer { lock.unlock() }
        loadLocked()
    }

    private func loadLocked() {
        guard let data = try? Data(contentsOf: url) else { return }
        if let file = try? JSONDecoder().decode(ObservedFile.self, from: data) {
            apps = file.apps
            countersEpoch = file.countersEpoch
            return
        }
        // Files written before the byte totals existed are a bare `[appID: ObservedApp]` map.
        // Decoding them keeps every app's destination history across the upgrade; the totals simply
        // start from zero on the next report.
        if let legacy = try? JSONDecoder().decode([String: ObservedApp].self, from: data) {
            apps = legacy
            countersEpoch = 0
        }
    }

    private func write(_ payload: [String: ObservedApp], countersEpoch epoch: UInt64) {
        do {
            let data = try JSONEncoder().encode(
                ObservedFile(countersEpoch: epoch, apps: payload))
            try data.write(to: url, options: .atomic)
            // Providers run before first unlock after a reboot; without this the write fails there.
            try? FileManager.default.setAttributes(
                [.protectionKey: SharedContainer.fileProtection], ofItemAtPath: url.path)
        } catch {
            Log.storage.error("[\(Log.process, privacy: .public)] observed store write failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
