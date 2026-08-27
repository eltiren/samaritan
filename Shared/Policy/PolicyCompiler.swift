import Foundation

/// Turns the editable `PolicyDocument` into the immutable `CompiledPolicy`.
///
/// All of this runs in the containing app. The data provider cannot write anywhere, so the compiled
/// form has to arrive complete: sorted, deduplicated, with every index resolved and nothing left to
/// build at match time.
public enum PolicyCompiler {

    public static func compile(_ document: PolicyDocument) -> CompiledPolicy {
        var policy = CompiledPolicy()
        policy.generation = document.generation

        var stringOffsets: [String: UInt32] = [:]

        func intern(_ text: String) -> (offset: UInt32, length: UInt16) {
            let bytes = Array(text.utf8)
            let length = UInt16(min(bytes.count, Int(UInt16.max)))
            if let existing = stringOffsets[text] { return (existing, length) }
            let offset = UInt32(policy.strings.count)
            policy.strings.append(contentsOf: bytes)
            stringOffsets[text] = offset
            return (offset, length)
        }

        func addLabel(_ rule: PolicyRule) -> UInt32 {
            // Labels are interned like every other name, so the blob has one string table and no
            // section needs a different reader.
            let text = intern("\(rule.action.label):\(rule.displayValue)")
            policy.labels.append(.init(offset: text.offset, length: text.length))
            return UInt32(policy.labels.count - 1)
        }

        /// Builds one rule set. Conflicts are resolved here rather than at match time: for a given
        /// kind and value, **deny wins**, so the matcher never has to consider two entries.
        func buildRuleSet(_ rules: [PolicyRule]) -> UInt32 {
            var byKind: [PolicyRule.Kind: [String: PolicyRule]] = [:]
            var addresses: [IPPrefix: PolicyRule] = [:]

            for rule in rules where rule.isValid {
                if rule.kind == .address {
                    guard let prefix = rule.prefix else { continue }
                    if let existing = addresses[prefix], existing.action == .deny { continue }
                    addresses[prefix] = rule
                } else {
                    var bucket = byKind[rule.kind] ?? [:]
                    if let existing = bucket[rule.value], existing.action == .deny { continue }
                    bucket[rule.value] = rule
                    byKind[rule.kind] = bucket
                }
            }

            var set = CompiledPolicy.RuleSet()

            func appendDomains(_ kind: PolicyRule.Kind) -> (UInt32, UInt32) {
                let entries = (byKind[kind] ?? [:]).values.sorted { $0.value < $1.value }
                guard !entries.isEmpty else { return (0, 0) }
                let start = UInt32(policy.domains.count)
                for rule in entries {
                    let name = intern(rule.value)
                    policy.domains.append(.init(nameOffset: name.offset,
                                                nameLength: name.length,
                                                action: rule.action.rawValue,
                                                kind: UInt8(PolicyRule.Kind.allCases.firstIndex(of: kind) ?? 0),
                                                ruleIndex: addLabel(rule)))
                }
                return (start, UInt32(entries.count))
            }

            // Sorted by raw UTF-8 so the matcher's binary search compares bytes, never Strings.
            (set.exactStart, set.exactCount) = appendDomains(.domainExact)
            (set.suffixStart, set.suffixCount) = appendDomains(.domainSuffix)
            (set.substringStart, set.substringCount) = appendDomains(.domainSubstring)

            for (prefix, rule) in addresses.sorted(by: { $0.key.length < $1.key.length }) {
                let root = prefix.family == .v4 ? set.v4Root : set.v6Root
                let newRoot = insert(prefix, ruleIndex: addLabel(rule), action: rule.action,
                                     root: root, into: &policy)
                if prefix.family == .v4 { set.v4Root = newRoot } else { set.v6Root = newRoot }
            }

            policy.ruleSets.append(set)
            return UInt32(policy.ruleSets.count - 1)
        }

        // Global tiers first so their rule-set indices are stable and small.
        policy.userRuleSet = buildRuleSet(document.userRules)

        var webRules: [PolicyRule] = []
        for list in document.webLists where list.isEnabled {
            webRules.append(contentsOf: PolicyDocument.rules(from: list.lines, action: list.action))
        }
        policy.webRuleSet = buildRuleSet(webRules)

        // Apps sorted by raw UTF-8 of the full sourceAppIdentifier, for binary search at match time.
        for app in document.apps.sorted(by: { $0.appID.utf8.lexicographicallyPrecedes($1.appID.utf8) }) {
            let id = intern(app.appID)
            let ruleSet = buildRuleSet(app.rules)
            policy.apps.append(.init(idOffset: id.offset, idLength: id.length,
                                     blanket: app.blanket.rawValue, ruleSetIndex: ruleSet))
        }
        return policy
    }

    /// Inserts one prefix into a bitwise trie, creating nodes as needed. Returns the (possibly new)
    /// root index. Node 0 is the reserved "absent" sentinel, so a real root is never 0.
    private static func insert(_ prefix: IPPrefix, ruleIndex: UInt32, action: RuleAction,
                               root: UInt32, into policy: inout CompiledPolicy) -> UInt32 {
        var rootIndex = root
        if rootIndex == 0 {
            policy.nodes.append(.init(left: 0, right: 0, ruleIndex: 0, action: 0))
            rootIndex = UInt32(policy.nodes.count - 1)
        }

        var current = Int(rootIndex)
        for depth in 0..<Int(prefix.length) {
            let goRight = prefix.bit(at: depth)
            let child = goRight ? policy.nodes[current].right : policy.nodes[current].left
            if child == 0 {
                policy.nodes.append(.init(left: 0, right: 0, ruleIndex: 0, action: 0))
                let created = UInt32(policy.nodes.count - 1)
                if goRight { policy.nodes[current].right = created } else { policy.nodes[current].left = created }
                current = Int(created)
            } else {
                current = Int(child)
            }
        }

        // Deny wins if two rules land on the same prefix.
        if policy.nodes[current].action == RuleAction.deny.rawValue { return rootIndex }
        policy.nodes[current].action = action.rawValue
        policy.nodes[current].ruleIndex = ruleIndex
        return rootIndex
    }
}
