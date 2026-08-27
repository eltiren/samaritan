import Foundation
import Testing
@testable import SamaritanTests

@Suite("Probe outcome classification")
struct ProbeOutcomeTests {

    private func urlError(_ code: Int) -> NSError {
        NSError(domain: NSURLErrorDomain, code: code, userInfo: nil)
    }

    // The regression this type exists for: http://neverssl.com was reported as BLOCKED when ATS had
    // refused it inside the app. No socket, no flow, nothing tested — but the harness said pass.
    @Test("ATS refusal is inconclusive, not evidence of filtering")
    func atsIsInconclusive() {
        let outcome = ProbeOutcome.classify(
            urlError(NSURLErrorAppTransportSecurityRequiresSecureConnection))
        #expect(outcome.isInconclusive)
        #expect(!outcome.provesFiltering)
        #expect(outcome.label.contains("no socket"))
    }

    @Test("failures before a socket exists are inconclusive", arguments: [
        NSURLErrorCannotFindHost,
        NSURLErrorDNSLookupFailed,
        NSURLErrorNotConnectedToInternet,
        NSURLErrorUnsupportedURL,
        NSURLErrorBadURL,
    ])
    func preSocketFailuresAreInconclusive(code: Int) {
        #expect(ProbeOutcome.classify(urlError(code)).isInconclusive)
    }

    @Test("on-the-wire failures are evidence of a drop", arguments: [
        NSURLErrorNetworkConnectionLost,
        NSURLErrorTimedOut,
        NSURLErrorCannotConnectToHost,
        NSURLErrorSecureConnectionFailed,
    ])
    func onWireFailuresProveFiltering(code: Int) {
        let outcome = ProbeOutcome.classify(urlError(code))
        #expect(outcome.provesFiltering)
        #expect(!outcome.isInconclusive)
    }

    @Test("a non-URL error is treated as a block rather than silently ignored")
    func foreignDomainCountsAsBlocked() {
        let outcome = ProbeOutcome.classify(NSError(domain: "SomeOther", code: 42))
        #expect(outcome.provesFiltering)
    }

    @Test("a completed request proves the flow was not dropped")
    func reachedProvesNothingWasBlocked() {
        let outcome = ProbeOutcome.reached(status: 200, bytes: 69)
        #expect(!outcome.provesFiltering)
        #expect(!outcome.isInconclusive)
        #expect(outcome.label == "HTTP 200, 69 bytes")
    }
}
