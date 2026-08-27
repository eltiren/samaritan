import Foundation
import OSLog

/// The one knob-set for the milestone-1 spike. Written by the app into the App Group container,
/// read by both providers.
///
/// This deliberately is **not** the future policy engine. It exists to (a) prove that
/// app → extension configuration over the shared container works at all, and (b) let the on-device
/// VPN experiment be re-targeted without a rebuild.
public struct SpikeConfiguration: Codable, Sendable, Equatable {

    /// Blocked if the flow's hostname equals one of these or ends in `"." + suffix`.
    public var blockedHostSuffixes: [String]

    /// Blocked on exact literal-address match. Use this when `remoteHostname` turns out to be
    /// `nil` on device — which is common for flows that were resolved before the filter saw them.
    public var blockedAddresses: [String]

    /// When true the data provider answers `.needRules()` for the first flow of each newly-seen
    /// `sourceAppIdentifier`, to measure whether and how the control provider is invoked.
    public var controlProbeEnabled: Bool

    /// Hard cap on `.needRules()` answers so a misbehaving control provider can never wedge
    /// traffic on a personal device.
    public var controlProbeBudget: Int

    /// Sets `NEFilterVerdict.shouldReport`, which is the only way to get byte counts on iOS.
    public var requestReports: Bool

    /// Emit an OSLog line per flow in addition to the ring buffer.
    public var logEveryFlow: Bool

    public static let `default` = SpikeConfiguration(
        // neverssl.com is plain HTTP with no HSTS and no connection reuse, which makes it the
        // cleanest reliable drop test on iOS: a browser cannot silently satisfy the request from
        // a cached TLS connection or an HSTS upgrade.
        blockedHostSuffixes: ["neverssl.com"],
        blockedAddresses: [],
        controlProbeEnabled: true,
        controlProbeBudget: 32,
        requestReports: true,
        logEveryFlow: true
    )

    public init(blockedHostSuffixes: [String],
                blockedAddresses: [String],
                controlProbeEnabled: Bool,
                controlProbeBudget: Int,
                requestReports: Bool,
                logEveryFlow: Bool) {
        self.blockedHostSuffixes = blockedHostSuffixes
        self.blockedAddresses = blockedAddresses
        self.controlProbeEnabled = controlProbeEnabled
        self.controlProbeBudget = controlProbeBudget
        self.requestReports = requestReports
        self.logEveryFlow = logEveryFlow
    }

    // MARK: - Persistence

    public static func load() -> SpikeConfiguration {
        guard let url = SharedContainer.configurationURL,
              let data = try? Data(contentsOf: url),
              let value = try? JSONDecoder().decode(SpikeConfiguration.self, from: data)
        else { return .default }
        return value
    }

    public func save() throws {
        guard let url = SharedContainer.configurationURL else {
            throw CocoaError(.fileNoSuchFile)
        }
        let data = try JSONEncoder().encode(self)
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes(
            [.protectionKey: SharedContainer.fileProtection], ofItemAtPath: url.path)
    }
}

/// Trivial matcher for the spike's one hard-coded blocking rule.
///
/// Linear scan over a handful of entries, on purpose. The real engine (radix trie over IPv4/IPv6
/// prefixes) belongs to milestone 2 and must not be started until the on-device results in
/// `README.md` are filled in.
public struct SpikeRuleSet: Sendable {

    private let hostSuffixes: [String]
    private let addresses: Set<String>

    public init(configuration: SpikeConfiguration) {
        hostSuffixes = configuration.blockedHostSuffixes
            .map { $0.lowercased().trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        addresses = Set(configuration.blockedAddresses
            .map { $0.lowercased().trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty })
    }

    /// Returns a human-readable rule label when the flow should be dropped, `nil` to allow.
    public func matchLabel(hostname: String, address: String) -> String? {
        if !address.isEmpty, addresses.contains(address.lowercased()) {
            return "ip:\(address)"
        }
        guard !hostname.isEmpty else { return nil }
        let host = hostname.lowercased()
        for suffix in hostSuffixes where host == suffix || host.hasSuffix("." + suffix) {
            return "host:\(suffix)"
        }
        return nil
    }

    public var isEmpty: Bool { hostSuffixes.isEmpty && addresses.isEmpty }
}
