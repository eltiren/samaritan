import Foundation

/// The app's blanket setting. See `docs/firewall-rules.md` §2.2 — these are exact mirrors, and both
/// are consulted last.
public enum BlanketMode: UInt8, Codable, Sendable, CaseIterable {
    /// Deny everything not permitted by this app's allow list or a global allow list.
    case denyAll = 0
    /// Allow everything not banned by this app's deny list or a global deny list.
    case allowAll = 1

    public var label: String { self == .allowAll ? "Allow all" : "Deny all" }
}

public struct AppPolicy: Codable, Sendable, Identifiable, Hashable {
    /// The full `sourceAppIdentifier` — `<teamID>.<bundleID>`.
    public var appID: String
    public var blanket: BlanketMode
    public var rules: [PolicyRule]

    public var id: String { appID }

    public init(appID: String, blanket: BlanketMode? = nil, rules: [PolicyRule] = []) {
        self.appID = appID
        // Apple's binaries ship with Allow-all on. This is the *only* place an Apple bundle ID
        // influences anything — the resolver has no special tier for it (§2.2).
        self.blanket = blanket ?? (AppIdentity(raw: appID).isAppleSystemApp ? .allowAll : .denyAll)
        self.rules = rules
    }
}

/// A subscribed list. Entries are not individually editable; the whole subscription carries one
/// polarity, and it cannot be created until its first fetch succeeds (§4, Q5).
public struct WebList: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var name: String
    public var url: URL
    public var action: RuleAction
    public var isEnabled: Bool
    /// Raw lines as fetched. Parsed by the compiler, never mutated here.
    public var lines: [String]
    public var lastFetchedAt: Date

    public init(id: UUID = UUID(), name: String, url: URL, action: RuleAction,
                isEnabled: Bool = true, lines: [String], lastFetchedAt: Date) {
        self.id = id
        self.name = name
        self.url = url
        self.action = action
        self.isEnabled = isEnabled
        self.lines = lines
        self.lastFetchedAt = lastFetchedAt
    }
}

/// Everything the user can edit. Compiled by `PolicyCompiler` into the immutable form the data
/// provider reads.
public struct PolicyDocument: Codable, Sendable {
    public var apps: [AppPolicy]
    public var userRules: [PolicyRule]
    public var webLists: [WebList]
    /// Bumped on every save so the data provider's generation check can detect a new policy.
    public var generation: UInt64

    public init(apps: [AppPolicy] = [], userRules: [PolicyRule] = [],
                webLists: [WebList] = [], generation: UInt64 = 1) {
        self.apps = apps
        self.userRules = userRules
        self.webLists = webLists
        self.generation = generation
    }

    public subscript(appID: String) -> AppPolicy? {
        apps.first { $0.appID == appID }
    }

    public mutating func upsert(_ policy: AppPolicy) {
        if let index = apps.firstIndex(where: { $0.appID == policy.appID }) {
            apps[index] = policy
        } else {
            apps.append(policy)
        }
    }

    /// Parses a subscription's raw lines into rules.
    ///
    /// A **bare domain expands to exact + subdomains**, unlike a hand-written rule. Every blocklist
    /// in circulation writes `doubleclick.net` meaning the domain and everything under it; applying
    /// the strict semantics of §3.1 to imported entries would under-block by a wide margin and
    /// silently. An explicit `*.x` entry stays subdomains-only.
    public static func rules(from lines: [String], action: RuleAction) -> [PolicyRule] {
        var result: [PolicyRule] = []
        for line in lines {
            var text = line
            if let hash = text.firstIndex(of: "#") { text = String(text[..<hash]) }
            text = text.trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty else { continue }

            // Hosts-file format: `0.0.0.0 badhost.example` — drop the address column.
            let fields = text.split(separator: " ", omittingEmptySubsequences: true)
            if fields.count >= 2, IPPrefix(String(fields[0])) != nil {
                text = String(fields[1])
            } else if fields.count > 1 {
                text = String(fields[0])
            }

            if text.hasPrefix("*.") {
                result.append(PolicyRule(kind: .domainSuffix, value: text, action: action))
            } else if IPPrefix(text) != nil {
                result.append(PolicyRule(kind: .address, value: text, action: action))
            } else {
                result.append(PolicyRule(kind: .domainExact, value: text, action: action))
                result.append(PolicyRule(kind: .domainSuffix, value: text, action: action))
            }
        }
        return result
    }
}
