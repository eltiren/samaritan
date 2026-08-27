import Foundation

public enum RuleAction: UInt8, Codable, Sendable, CaseIterable {
    case allow = 1
    case deny = 2

    public var label: String { self == .allow ? "allow" : "deny" }
}

/// One editable rule. See `docs/firewall-rules.md` §3.
public struct PolicyRule: Hashable, Codable, Sendable {

    public enum Kind: String, Codable, Sendable, CaseIterable {
        /// `s1.example.com` — that name only.
        case domainExact
        /// `*.example.com` — any descendant at any depth, **not** the apex.
        case domainSuffix
        /// `google` — matches anywhere in the hostname. Not part of the popover's specificity chain;
        /// kept because milestone 1 showed it catches what a suffix chain cannot
        /// (`googleapis.com`, `googlevideo.com`).
        case domainSubstring
        /// A CIDR prefix. Bare addresses are stored at full length.
        case address
    }

    public var kind: Kind
    /// Normalised at construction: lowercase, no trailing dot, no leading `*.`.
    public var value: String
    public var action: RuleAction

    public init(kind: Kind, value: String, action: RuleAction) {
        self.kind = kind
        self.action = action
        self.value = Self.normalise(value, kind: kind)
    }

    static func normalise(_ value: String, kind: Kind) -> String {
        var text = value.trimmingCharacters(in: .whitespaces).lowercased()
        switch kind {
        case .domainExact, .domainSuffix, .domainSubstring:
            if text.hasPrefix("*.") { text.removeFirst(2) }
            while text.hasSuffix(".") { text.removeLast() }
        case .address:
            break
        }
        return text
    }

    /// The parsed prefix for an `.address` rule, `nil` for anything else or an unparseable value.
    public var prefix: IPPrefix? {
        kind == .address ? IPPrefix(value) : nil
    }

    public var isValid: Bool {
        guard !value.isEmpty else { return false }
        return kind == .address ? prefix != nil : true
    }

    public var displayValue: String {
        switch kind {
        case .domainExact: value
        case .domainSuffix: "*.\(value)"
        case .domainSubstring: "*\(value)*"
        case .address: prefix?.description ?? value
        }
    }

    /// How specific this rule is, for "most specific wins" within a tier.
    ///
    /// Only comparable between rules of the same shape. A domain rule and an address rule are not
    /// ranked against each other — §2.5 resolves that conflict with "deny wins" instead.
    public var specificity: Int {
        switch kind {
        case .domainExact: 1_000_000
        case .domainSuffix: value.reduce(into: 1) { count, char in if char == "." { count += 1 } } * 1_000
        case .domainSubstring: value.count
        case .address: Int(prefix?.length ?? 0)
        }
    }
}

/// Hostname normalisation shared by the compiler and the matcher, so a rule and a flow are always
/// compared in the same form.
public enum HostNormaliser {
    public static func normalise(_ hostname: String) -> String {
        var text = hostname.trimmingCharacters(in: .whitespaces).lowercased()
        while text.hasSuffix(".") { text.removeLast() }
        return text
    }

    /// The specificity chain the rule popover offers for a hostname, most specific first.
    ///
    /// For `s1.c1.status.example.com`: the exact name, then one subdomain rule per parent as labels
    /// are dropped from the left, ending at `*.com`. The apex is deliberately absent — `*.x` never
    /// covers `x`, so a rule for `example.com` itself only appears when a flow actually reaches it.
    public static func specificityChain(for hostname: String) -> [PolicyRule.Kind: [String]] {
        let host = normalise(hostname)
        guard !host.isEmpty else { return [:] }
        var suffixes: [String] = []
        var labels = host.split(separator: ".").map(String.init)
        while labels.count > 1 {
            labels.removeFirst()
            suffixes.append(labels.joined(separator: "."))
        }
        return [.domainExact: [host], .domainSuffix: suffixes]
    }

    /// Parent suffixes of a hostname, longest first — what the matcher probes for suffix rules.
    public static func parentSuffixes(of host: String) -> [Substring] {
        var result: [Substring] = []
        var remainder = host[...]
        while let dot = remainder.firstIndex(of: ".") {
            let parent = remainder[remainder.index(after: dot)...]
            guard parent.contains(".") || !parent.isEmpty else { break }
            result.append(parent)
            remainder = parent
        }
        return result
    }
}
