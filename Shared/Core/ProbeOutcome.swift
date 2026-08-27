import Foundation

/// What a traffic-generator request actually proved.
///
/// The distinction exists because of a real false positive: `http://neverssl.com` was reported as
/// `BLOCKED` when in fact App Transport Security refused it inside the app with `-1022`, no socket
/// was ever created, and the content filter never saw a flow. A failed request is only evidence of
/// filtering if the failure happened *on the wire*.
public enum ProbeOutcome: Equatable, Sendable {
    /// The request completed. If the target was supposed to be denied, the filter did not drop it.
    case reached(status: Int, bytes: Int)
    /// Failed in a way consistent with the flow being dropped.
    case blocked(detail: String)
    /// Failed before a flow could exist, so it says nothing about the filter.
    case inconclusive(reason: String)

    public var provesFiltering: Bool {
        if case .blocked = self { return true }
        return false
    }

    public var isInconclusive: Bool {
        if case .inconclusive = self { return true }
        return false
    }

    /// Classifies a `URLSession` failure by whether a socket could plausibly have been created.
    public static func classify(_ error: Error) -> ProbeOutcome {
        let nsError = error as NSError
        guard nsError.domain == NSURLErrorDomain else {
            return .blocked(detail: "\(nsError.domain) \(nsError.code)")
        }

        switch nsError.code {
        case NSURLErrorAppTransportSecurityRequiresSecureConnection:
            return .inconclusive(reason: "ATS refused it in-process (-1022); no socket was created")
        case NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed:
            return .inconclusive(reason: "DNS failed (\(nsError.code)); no socket was created")
        case NSURLErrorNotConnectedToInternet:
            return .inconclusive(reason: "device is offline (\(nsError.code))")
        case NSURLErrorUnsupportedURL, NSURLErrorBadURL:
            return .inconclusive(reason: "malformed request (\(nsError.code))")
        default:
            // -1005 connection lost, -1001 timed out, -1004 cannot connect, -1200 TLS failure:
            // all consistent with a verdict of drop on an established or attempted flow.
            return .blocked(detail: "\(nsError.code) \(nsError.localizedDescription)")
        }
    }

    public var label: String {
        switch self {
        case .reached(let status, let bytes): "HTTP \(status), \(bytes) bytes"
        case .blocked(let detail): "blocked — \(detail)"
        case .inconclusive(let reason): "INCONCLUSIVE — \(reason)"
        }
    }
}
