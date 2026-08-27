import Foundation

/// The immutable, flat form of a policy — what the data provider matches against.
///
/// Every structure here is a fixed-size record in a contiguous array, referenced by index. There is
/// no object graph and no dictionary, because the data provider will eventually `mmap` these arrays
/// read-only and must not build anything: it cannot write, anywhere (see `README.md`). Keeping the
/// matchers index-based means the same code works unchanged over mapped memory.
public struct CompiledPolicy: Sendable {

    // MARK: - Records

    public struct DomainEntry: Sendable, Equatable {
        public var nameOffset: UInt32
        public var nameLength: UInt16
        public var action: UInt8
        public var kind: UInt8
        public var ruleIndex: UInt32
    }

    /// A node in a bitwise (patricia-style) trie. Child index `0` means absent — node 0 is a
    /// reserved sentinel so zero can mean "no child" without a separate flag.
    public struct TrieNode: Sendable, Equatable {
        public var left: UInt32       // bit 0
        public var right: UInt32      // bit 1
        public var ruleIndex: UInt32
        public var action: UInt8      // 0 = no rule terminates here
    }

    public struct RuleSet: Sendable, Equatable {
        public var exactStart: UInt32 = 0, exactCount: UInt32 = 0
        public var suffixStart: UInt32 = 0, suffixCount: UInt32 = 0
        public var substringStart: UInt32 = 0, substringCount: UInt32 = 0
        public var v4Root: UInt32 = 0, v6Root: UInt32 = 0

        public var isEmpty: Bool {
            exactCount == 0 && suffixCount == 0 && substringCount == 0 && v4Root == 0 && v6Root == 0
        }
    }

    /// A display label, interned into `strings` like every other name.
    public struct LabelRef: Sendable, Equatable {
        public var offset: UInt32
        public var length: UInt16
        public var pad: UInt16 = 0
    }

    public struct AppEntry: Sendable, Equatable {
        public var idOffset: UInt32
        public var idLength: UInt16
        public var blanket: UInt8
        public var ruleSetIndex: UInt32
    }

    // MARK: - Storage

    public var generation: UInt64 = 0
    /// UTF-8 bytes for every name in the policy, referenced by (offset, length).
    public var strings: [UInt8] = []
    public var domains: [DomainEntry] = []
    public var nodes: [TrieNode] = [TrieNode(left: 0, right: 0, ruleIndex: 0, action: 0)]
    public var ruleSets: [RuleSet] = []
    /// Display labels, indexed by `ruleIndex`. Only materialised when something is being reported.
    public var labels: [LabelRef] = []
    public var apps: [AppEntry] = []
    public var userRuleSet: UInt32 = 0
    public var webRuleSet: UInt32 = 0

    public init() {}

    /// Hands the flat storage to `body` as a set of buffer views, so the matching code is the same
    /// whether the policy came from the compiler or from a memory-mapped file.
    public func withView<R>(_ body: (PolicyView) throws -> R) rethrows -> R {
        try strings.withUnsafeBufferPointer { strings in
            try domains.withUnsafeBufferPointer { domains in
                try nodes.withUnsafeBufferPointer { nodes in
                    try ruleSets.withUnsafeBufferPointer { ruleSets in
                        try apps.withUnsafeBufferPointer { apps in
                            try labels.withUnsafeBufferPointer { labels in
                                try body(PolicyView(generation: generation, strings: strings,
                                                    domains: domains, nodes: nodes,
                                                    ruleSets: ruleSets, apps: apps, labels: labels,
                                                    userRuleSet: userRuleSet, webRuleSet: webRuleSet))
                            }
                        }
                    }
                }
            }
        }
    }

}
