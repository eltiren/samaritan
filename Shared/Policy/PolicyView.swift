import Foundation

/// A read-only view over a compiled policy's flat storage.
///
/// The matchers live here rather than on `CompiledPolicy` so the identical code runs over Swift
/// arrays (the compiler's output, and tests) and over `mmap`'d file memory (the data provider,
/// which cannot allocate a policy because it cannot write anywhere). Nothing here copies, and
/// nothing here allocates.
/// `@unchecked Sendable`: the buffers point at immutable storage — either a compiled policy held
/// alive by `withView`, or a read-only `mmap`. Nothing writes through them.
public struct PolicyView: @unchecked Sendable {

    public typealias DomainEntry = CompiledPolicy.DomainEntry
    public typealias TrieNode = CompiledPolicy.TrieNode
    public typealias RuleSet = CompiledPolicy.RuleSet
    public typealias AppEntry = CompiledPolicy.AppEntry
    public typealias LabelRef = CompiledPolicy.LabelRef

    public let generation: UInt64
    public let strings: UnsafeBufferPointer<UInt8>
    public let domains: UnsafeBufferPointer<DomainEntry>
    public let nodes: UnsafeBufferPointer<TrieNode>
    public let ruleSets: UnsafeBufferPointer<RuleSet>
    public let apps: UnsafeBufferPointer<AppEntry>
    public let labels: UnsafeBufferPointer<LabelRef>
    public let userRuleSet: UInt32
    public let webRuleSet: UInt32

    public init(generation: UInt64,
                strings: UnsafeBufferPointer<UInt8>,
                domains: UnsafeBufferPointer<DomainEntry>,
                nodes: UnsafeBufferPointer<TrieNode>,
                ruleSets: UnsafeBufferPointer<RuleSet>,
                apps: UnsafeBufferPointer<AppEntry>,
                labels: UnsafeBufferPointer<LabelRef>,
                userRuleSet: UInt32,
                webRuleSet: UInt32) {
        self.generation = generation
        self.strings = strings
        self.domains = domains
        self.nodes = nodes
        self.ruleSets = ruleSets
        self.apps = apps
        self.labels = labels
        self.userRuleSet = userRuleSet
        self.webRuleSet = webRuleSet
    }

    /// Materialises a rule's display label. Only called when something is being reported; the hot
    /// path never touches it.
    public func label(at index: UInt32) -> String {
        guard Int(index) < labels.count else { return "?" }
        let ref = labels[Int(index)]
        let start = Int(ref.offset), length = Int(ref.length)
        guard start >= 0, length > 0, start + length <= strings.count else { return "?" }
        return String(decoding: UnsafeBufferPointer(rebasing: strings[start..<(start + length)]),
                      as: UTF8.self)
    }

    // MARK: - Matching

    /// Outcome of matching one rule set. `nil` means the tier had nothing to say.
    public struct Match: Sendable, Equatable {
        public var action: RuleAction
        public var ruleIndex: UInt32
    }

    /// Matches a rule set against a flow.
    ///
    /// Domain rules and address rules are matched independently. Within each, the most specific hit
    /// wins. Between them there is no ordering — §2.5 resolves a disagreement with **deny wins**,
    /// which is the fail-safe direction.
    public func match(ruleSet index: UInt32, host: UnsafeBufferPointer<UInt8>?, address: IPPrefix?) -> Match? {
        guard Int(index) < ruleSets.count else { return nil }
        let set = ruleSets[Int(index)]
        if set.isEmpty { return nil }

        let domainMatch = host.flatMap { matchDomain(set, host: $0) }
        let addressMatch = address.flatMap { matchAddress(set, address: $0) }

        switch (domainMatch, addressMatch) {
        case (nil, nil): return nil
        case (let d?, nil): return d
        case (nil, let a?): return a
        case (let d?, let a?):
            if d.action == a.action { return d }
            return d.action == .deny ? d : a   // deny wins a cross-kind disagreement
        }
    }

    private func matchDomain(_ set: RuleSet, host: UnsafeBufferPointer<UInt8>) -> Match? {
        guard !host.isEmpty else { return nil }

        // Exact is the most specific thing there is, so a hit here ends it.
        if let entry = search(start: set.exactStart, count: set.exactCount, key: host, from: 0) {
            return Match(action: RuleAction(rawValue: entry.action) ?? .deny, ruleIndex: entry.ruleIndex)
        }

        // Parent suffixes, longest first — so the first hit is already the most specific.
        if set.suffixCount > 0 {
            var start = 0
            while let dot = nextDot(in: host, from: start) {
                let suffixStart = dot + 1
                guard suffixStart < host.count else { break }
                if let entry = search(start: set.suffixStart, count: set.suffixCount,
                                      key: host, from: suffixStart) {
                    return Match(action: RuleAction(rawValue: entry.action) ?? .deny,
                                 ruleIndex: entry.ruleIndex)
                }
                start = suffixStart
            }
        }

        // Substrings cannot be indexed, so this is a linear scan. Kept last and only entered when
        // the set actually has substring rules.
        if set.substringCount > 0 {
            var best: DomainEntry?
            for offset in 0..<Int(set.substringCount) {
                let entry = domains[Int(set.substringStart) + offset]
                guard contains(host: host, needle: entry) else { continue }
                if best == nil || entry.nameLength > best!.nameLength { best = entry }
            }
            if let best {
                return Match(action: RuleAction(rawValue: best.action) ?? .deny, ruleIndex: best.ruleIndex)
            }
        }
        return nil
    }

    private func matchAddress(_ set: RuleSet, address: IPPrefix) -> Match? {
        let root = address.family == .v4 ? set.v4Root : set.v6Root
        guard root != 0 else { return nil }

        var current = Int(root)
        var best: TrieNode?
        let width = address.family.bitWidth

        for depth in 0...width {
            let node = nodes[current]
            if node.action != 0 { best = node }          // remember the longest match so far
            guard depth < width else { break }
            let next = address.bit(at: depth) ? node.right : node.left
            guard next != 0 else { break }
            current = Int(next)
        }

        guard let best else { return nil }
        return Match(action: RuleAction(rawValue: best.action) ?? .deny, ruleIndex: best.ruleIndex)
    }

    // MARK: - Byte helpers

    @inline(__always)
    private func nextDot(in host: UnsafeBufferPointer<UInt8>, from index: Int) -> Int? {
        var i = index
        while i < host.count {
            if host[i] == 0x2E { return i }   // '.'
            i += 1
        }
        return nil
    }

    /// Binary search over a sorted slice of `domains`, comparing the stored name against
    /// `key[from...]`. Operates directly on the byte arrays — no String is created.
    private func search(start: UInt32, count: UInt32,
                        key: UnsafeBufferPointer<UInt8>, from: Int) -> DomainEntry? {
        guard count > 0 else { return nil }
        var low = Int(start)
        var high = Int(start) + Int(count) - 1
        while low <= high {
            let mid = (low + high) / 2
            let entry = domains[mid]
            switch compare(entry: entry, key: key, from: from) {
            case .orderedSame: return entry
            case .orderedAscending: low = mid + 1
            case .orderedDescending: high = mid - 1
            }
        }
        return nil
    }

    private func compare(entry: DomainEntry, key: UnsafeBufferPointer<UInt8>, from: Int) -> ComparisonResult {
        let stored = Int(entry.nameOffset)
        let storedLength = Int(entry.nameLength)
        let keyLength = key.count - from
        let shared = min(storedLength, keyLength)
        var i = 0
        while i < shared {
            let a = strings[stored + i]
            let b = key[from + i]
            if a != b { return a < b ? .orderedAscending : .orderedDescending }
            i += 1
        }
        if storedLength == keyLength { return .orderedSame }
        return storedLength < keyLength ? .orderedAscending : .orderedDescending
    }

    private func contains(host: UnsafeBufferPointer<UInt8>, needle entry: DomainEntry) -> Bool {
        let length = Int(entry.nameLength)
        guard length > 0, length <= host.count else { return false }
        let offset = Int(entry.nameOffset)
        for start in 0...(host.count - length) {
            var i = 0
            while i < length, strings[offset + i] == host[start + i] { i += 1 }
            if i == length { return true }
        }
        return false
    }

    // MARK: - Apps

    public func appEntry(for appID: UnsafeBufferPointer<UInt8>) -> AppEntry? {
        guard !apps.isEmpty else { return nil }
        var low = 0, high = apps.count - 1
        while low <= high {
            let mid = (low + high) / 2
            let entry = apps[mid]
            let stored = Int(entry.idOffset), storedLength = Int(entry.idLength)
            let shared = min(storedLength, appID.count)
            var i = 0
            var order = ComparisonResult.orderedSame
            while i < shared {
                if strings[stored + i] != appID[i] {
                    order = strings[stored + i] < appID[i] ? .orderedAscending : .orderedDescending
                    break
                }
                i += 1
            }
            if order == .orderedSame, storedLength != appID.count {
                order = storedLength < appID.count ? .orderedAscending : .orderedDescending
            }
            switch order {
            case .orderedSame: return entry
            case .orderedAscending: low = mid + 1
            case .orderedDescending: high = mid - 1
            }
        }
        return nil
    }
}
