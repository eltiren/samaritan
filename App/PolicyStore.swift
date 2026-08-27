import Foundation
import Observation
import OSLog

/// Owns the editable policy and publishes compiled versions to the providers.
///
/// All compilation happens here. The data provider cannot write anywhere, so what reaches it has to
/// be complete: sorted, deduplicated, every index resolved, nothing left to build at match time.
@Observable
@MainActor
final class PolicyStore {

    private(set) var document: PolicyDocument
    private(set) var lastCompiledSize: Int = 0
    private(set) var lastError: String?
    private(set) var stats = Stats()

    struct Stats: Sendable {
        var apps = 0
        var domainRules = 0
        var addressNodes = 0
        var generation: UInt64 = 0
    }

    init() {
        if let url = SharedContainer.policyDocumentURL,
           let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode(PolicyDocument.self, from: data) {
            document = decoded
        } else {
            document = PolicyDocument()
        }
        refreshStats()
    }

    /// Compiles and writes both the document and the blob. Generation is bumped on every publish so
    /// the providers' staleness check has something to compare.
    func publish() {
        document.generation &+= 1
        let compiled = PolicyCompiler.compile(document)
        let blob = PolicyBlob.serialise(compiled)

        do {
            guard let blobURL = SharedContainer.policyURL,
                  let documentURL = SharedContainer.policyDocumentURL else {
                throw CocoaError(.fileNoSuchFile)
            }
            try JSONEncoder().encode(document).write(to: documentURL, options: .atomic)
            try blob.write(to: blobURL, options: .atomic)
            // Providers run while the device is locked; without this the mapping fails after a
            // reboot until first unlock.
            for url in [blobURL, documentURL] {
                try? FileManager.default.setAttributes(
                    [.protectionKey: SharedContainer.fileProtection], ofItemAtPath: url.path)
            }
            lastCompiledSize = blob.count
            lastError = nil
            Log.policy.log("""
                [\(Log.process, privacy: .public)] policy published generation=\(self.document.generation) \
                bytes=\(blob.count) apps=\(compiled.apps.count)
                """)
        } catch {
            lastError = error.localizedDescription
            Log.policy.error("policy publish failed: \(error.localizedDescription, privacy: .public)")
        }
        refreshStats(compiled)
    }

    private func refreshStats(_ compiled: CompiledPolicy? = nil) {
        let policy = compiled ?? PolicyCompiler.compile(document)
        stats = Stats(apps: policy.apps.count,
                      domainRules: policy.domains.count,
                      addressNodes: max(0, policy.nodes.count - 1),
                      generation: policy.generation)
    }

    // MARK: - Editing

    func upsert(_ app: AppPolicy) {
        document.upsert(app)
        publish()
    }

    func setBlanket(_ blanket: BlanketMode, for appID: String) {
        var app = document[appID] ?? AppPolicy(appID: appID)
        app.blanket = blanket
        upsert(app)
    }

    func addRule(_ rule: PolicyRule, toApp appID: String?) {
        guard rule.isValid else { return }
        if let appID {
            var app = document[appID] ?? AppPolicy(appID: appID)
            app.rules.removeAll { $0.kind == rule.kind && $0.value == rule.value }
            app.rules.append(rule)
            upsert(app)
        } else {
            document.userRules.removeAll { $0.kind == rule.kind && $0.value == rule.value }
            document.userRules.append(rule)
            publish()
        }
    }

    func removeUserRule(_ rule: PolicyRule) {
        document.userRules.removeAll { $0 == rule }
        publish()
    }

    /// Creates an entry for every app the providers have recorded, so the app list has rows to show
    /// before any rule has been written. Apple's apps arrive with Allow-all already on.
    func seed(fromObservedApps appIDs: [String]) {
        var added = 0
        for appID in appIDs where document[appID] == nil {
            document.apps.append(AppPolicy(appID: appID))
            added += 1
        }
        guard added > 0 else { return }
        publish()
    }

    func reset() {
        document = PolicyDocument()
        publish()
    }
}
