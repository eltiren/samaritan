import Foundation

/// Validation and parsing for subscribed lists.
///
/// A subscription cannot be created until its first fetch succeeds and yields usable entries
/// (`docs/firewall-rules.md` §4), so failures here have to be specific enough to show the user.
public enum WebListParser {

    public enum Failure: Error, Equatable {
        case empty
        case noUsableEntries
        case tooLarge(bytes: Int)
        case notText

        public var message: String {
            switch self {
            case .empty: "The list is empty."
            case .noUsableEntries: "Nothing in the list parsed as a domain or address."
            case .tooLarge(let bytes): "The list is \(bytes / 1_000_000) MB, over the 8 MB limit."
            case .notText: "The response was not text."
            }
        }
    }

    /// Refuses anything that would take an implausible amount of the extension's memory once
    /// compiled. The data provider maps the blob, but the app still has to build it.
    public static let maximumBytes = 8_000_000
    public static let maximumEntries = 250_000

    public static func lines(from data: Data) throws -> [String] {
        guard !data.isEmpty else { throw Failure.empty }
        guard data.count <= maximumBytes else { throw Failure.tooLarge(bytes: data.count) }
        guard let text = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1) else { throw Failure.notText }

        let lines = text.split(whereSeparator: \.isNewline)
            .prefix(maximumEntries)
            .map(String.init)
        guard !lines.isEmpty else { throw Failure.empty }
        return lines
    }

    /// Parses and checks the list produces at least one rule, so a page of HTML is rejected rather
    /// than silently subscribed to as a list of zero rules.
    public static func validate(lines: [String], action: RuleAction) throws -> [String] {
        let rules = PolicyDocument.rules(from: lines, action: action)
        guard !rules.isEmpty else { throw Failure.noUsableEntries }
        return lines
    }
}
