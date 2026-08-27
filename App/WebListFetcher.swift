import Foundation
import OSLog

/// Downloads subscribed lists.
///
/// Only the containing app can do this: the data provider has no network access and cannot write
/// anywhere, and the control provider is not on a schedule.
enum WebListFetcher {

    static func fetch(url: URL, action: RuleAction) async throws -> [String] {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 30

        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw NSError(domain: "WebList", code: http.statusCode, userInfo: [
                NSLocalizedDescriptionKey: "Server returned HTTP \(http.statusCode)."])
        }
        let lines = try WebListParser.lines(from: data)
        return try WebListParser.validate(lines: lines, action: action)
    }
}
