import Foundation

/// On-disk format for a compiled policy.
///
/// Written by the containing app, read by the providers. The data provider `mmap`s it read-only and
/// matches in place — it cannot allocate a policy of its own, because it cannot write anywhere.
///
/// Layout: a 96-byte header, then each section 8-byte aligned in the order below.
///
///     strings   raw UTF-8 for every name and label
///     domains   sorted DomainEntry records
///     nodes     TrieNode records; index 0 is the reserved "absent" sentinel
///     ruleSets  RuleSet records
///     apps      AppEntry records, sorted by identifier bytes
///     labels    LabelRef records
///
/// Record layouts are Swift structs of trivial fixed-width fields, which the compiler lays out in
/// declaration order. That is stable for a given toolchain but is not an ABI promise, so the header
/// records each record's `stride` and the reader refuses a blob whose strides disagree. A mismatch
/// then fails loudly instead of silently misreading every rule.
public enum PolicyBlob {

    static let magic: UInt32 = 0x53_50_4F_4C   // 'SPOL'
    static let version: UInt32 = 1
    static let headerSize = 96

    private enum Field {
        static let magic = 0, version = 4, generation = 8
        static let stringsOffset = 16, stringsCount = 20
        static let domainsOffset = 24, domainsCount = 28
        static let nodesOffset = 32, nodesCount = 36
        static let ruleSetsOffset = 40, ruleSetsCount = 44
        static let appsOffset = 48, appsCount = 52
        static let labelsOffset = 56, labelsCount = 60
        static let userRuleSet = 64, webRuleSet = 68
        static let domainStride = 72, nodeStride = 74
        static let ruleSetStride = 76, appStride = 78, labelStride = 80
        static let totalSize = 84
    }

    // MARK: - Writing

    public static func serialise(_ policy: CompiledPolicy) -> Data {
        var body = Data()
        var sections: [(offset: UInt32, count: UInt32)] = []

        func align() {
            let remainder = (headerSize + body.count) % 8
            if remainder != 0 { body.append(contentsOf: [UInt8](repeating: 0, count: 8 - remainder)) }
        }

        func append<T>(_ values: [T]) {
            align()
            let offset = UInt32(headerSize + body.count)
            values.withUnsafeBufferPointer { buffer in
                body.append(UnsafeRawBufferPointer(buffer).bindMemory(to: UInt8.self))
            }
            sections.append((offset, UInt32(values.count)))
        }

        append(policy.strings)
        append(policy.domains)
        append(policy.nodes)
        append(policy.ruleSets)
        append(policy.apps)
        append(policy.labels)

        var header = Data(repeating: 0, count: headerSize)
        header.store(UInt32(magic), at: Field.magic)
        header.store(UInt32(version), at: Field.version)
        header.store(policy.generation, at: Field.generation)
        for (index, field) in [Field.stringsOffset, Field.domainsOffset, Field.nodesOffset,
                               Field.ruleSetsOffset, Field.appsOffset, Field.labelsOffset].enumerated() {
            header.store(sections[index].offset, at: field)
            header.store(sections[index].count, at: field + 4)
        }
        header.store(policy.userRuleSet, at: Field.userRuleSet)
        header.store(policy.webRuleSet, at: Field.webRuleSet)
        header.store(UInt16(MemoryLayout<CompiledPolicy.DomainEntry>.stride), at: Field.domainStride)
        header.store(UInt16(MemoryLayout<CompiledPolicy.TrieNode>.stride), at: Field.nodeStride)
        header.store(UInt16(MemoryLayout<CompiledPolicy.RuleSet>.stride), at: Field.ruleSetStride)
        header.store(UInt16(MemoryLayout<CompiledPolicy.AppEntry>.stride), at: Field.appStride)
        header.store(UInt16(MemoryLayout<CompiledPolicy.LabelRef>.stride), at: Field.labelStride)
        header.store(UInt32(headerSize + body.count), at: Field.totalSize)

        return header + body
    }

    // MARK: - Reading

    public enum LoadError: Error, Equatable {
        case tooSmall
        case badMagic
        case unsupportedVersion(UInt32)
        /// The reader's record layout differs from the writer's. Never silently tolerated.
        case strideMismatch(String)
        case sectionOutOfBounds(String)
    }

    /// Builds a view over already-mapped memory. Does not copy and does not take ownership.
    public static func view(over base: UnsafeRawPointer, length: Int) throws -> PolicyView {
        guard length >= headerSize else { throw LoadError.tooSmall }
        func u16(_ at: Int) -> UInt16 { base.loadUnaligned(fromByteOffset: at, as: UInt16.self) }
        func u32(_ at: Int) -> UInt32 { base.loadUnaligned(fromByteOffset: at, as: UInt32.self) }
        func u64(_ at: Int) -> UInt64 { base.loadUnaligned(fromByteOffset: at, as: UInt64.self) }

        guard u32(Field.magic) == magic else { throw LoadError.badMagic }
        let fileVersion = u32(Field.version)
        guard fileVersion == version else { throw LoadError.unsupportedVersion(fileVersion) }
        guard Int(u32(Field.totalSize)) <= length else { throw LoadError.tooSmall }

        for (name, field, expected) in [
            ("domain", Field.domainStride, MemoryLayout<CompiledPolicy.DomainEntry>.stride),
            ("node", Field.nodeStride, MemoryLayout<CompiledPolicy.TrieNode>.stride),
            ("ruleSet", Field.ruleSetStride, MemoryLayout<CompiledPolicy.RuleSet>.stride),
            ("app", Field.appStride, MemoryLayout<CompiledPolicy.AppEntry>.stride),
            ("label", Field.labelStride, MemoryLayout<CompiledPolicy.LabelRef>.stride),
        ] where Int(u16(field)) != expected {
            throw LoadError.strideMismatch(name)
        }

        func buffer<T>(_ offsetField: Int, _ countField: Int, _ name: String) throws -> UnsafeBufferPointer<T> {
            let offset = Int(u32(offsetField))
            let count = Int(u32(countField))
            let bytes = count * MemoryLayout<T>.stride
            guard offset >= headerSize, offset + bytes <= length else {
                throw LoadError.sectionOutOfBounds(name)
            }
            return UnsafeBufferPointer(start: base.advanced(by: offset).assumingMemoryBound(to: T.self),
                                       count: count)
        }

        return PolicyView(
            generation: u64(Field.generation),
            strings: try buffer(Field.stringsOffset, Field.stringsCount, "strings"),
            domains: try buffer(Field.domainsOffset, Field.domainsCount, "domains"),
            nodes: try buffer(Field.nodesOffset, Field.nodesCount, "nodes"),
            ruleSets: try buffer(Field.ruleSetsOffset, Field.ruleSetsCount, "ruleSets"),
            apps: try buffer(Field.appsOffset, Field.appsCount, "apps"),
            labels: try buffer(Field.labelsOffset, Field.labelsCount, "labels"),
            userRuleSet: u32(Field.userRuleSet),
            webRuleSet: u32(Field.webRuleSet))
    }

    /// Reads the generation without mapping the whole file — used by the hot-path staleness check.
    public static func generation(ofFileAt path: String) -> UInt64? {
        let fd = open(path, O_RDONLY)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var header = [UInt8](repeating: 0, count: headerSize)
        guard pread(fd, &header, headerSize, 0) == headerSize else { return nil }
        return header.withUnsafeBytes { raw -> UInt64? in
            guard raw.loadUnaligned(fromByteOffset: Field.magic, as: UInt32.self) == magic else { return nil }
            return raw.loadUnaligned(fromByteOffset: Field.generation, as: UInt64.self)
        }
    }
}

private extension Data {
    mutating func store<T>(_ value: T, at offset: Int) {
        withUnsafeMutableBytes { raw in
            raw.storeBytes(of: value, toByteOffset: offset, as: T.self)
        }
    }
}
