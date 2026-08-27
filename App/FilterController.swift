import Foundation
import NetworkExtension
import Observation
import OSLog

/// Thin wrapper over `NEFilterManager`.
///
/// `NEFilterManager` on iOS is a process-wide singleton with exactly one content-filter
/// configuration per device. There is no `filterDataProviderBundleIdentifier` on iOS (that property
/// is macOS-only): the system finds the providers by looking at the app extensions embedded in this
/// app's bundle. So there is nothing to point at — embedding the two appexes *is* the wiring.
@Observable
@MainActor
final class FilterController {

    enum Status: Equatable {
        case unknown
        case notConfigured
        case disabled
        case enabled
        case failed(String)

        var label: String {
            switch self {
            case .unknown: "Unknown"
            case .notConfigured: "Not configured"
            case .disabled: "Configured, disabled"
            case .enabled: "Enabled"
            case .failed(let message): "Failed — \(message)"
            }
        }
    }

    private(set) var status: Status = .unknown
    private(set) var isBusy = false
    private(set) var lastErrorDetail: String?

    private let manager = NEFilterManager.shared()
    /// `nonisolated(unsafe)` only so `deinit` can unregister it; it is written once in `init`.
    @ObservationIgnored private nonisolated(unsafe) var observer: NSObjectProtocol?

    init() {
        observer = NotificationCenter.default.addObserver(
            forName: .NEFilterConfigurationDidChange, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    var isEnabled: Bool { status == .enabled }

    // MARK: - Actions

    func refresh() async {
        do {
            try await manager.loadFromPreferences()
            if manager.providerConfiguration == nil {
                status = .notConfigured
            } else {
                status = manager.isEnabled ? .enabled : .disabled
            }
            lastErrorDetail = nil
        } catch {
            status = .failed(Self.describe(error))
            lastErrorDetail = Self.detail(for: error)
            Log.manager.error("loadFromPreferences failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// First call shows the system prompt ("… would like to filter network content"). Declining it,
    /// or running on a device where content filters are not permitted, surfaces as
    /// `NEFilterManagerError.configurationPermissionDenied` — see `detail(for:)`.
    func setEnabled(_ enabled: Bool) async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await manager.loadFromPreferences()

            if manager.providerConfiguration == nil {
                let configuration = NEFilterProviderConfiguration()
                // Socket flows are what we want: TCP/UDP with app identity.
                configuration.filterSockets = true
                // Browser flows (NEFilterBrowserFlow) are legacy and are not delivered to
                // third-party filters on modern iOS. Left off; the spike reports the absence.
                configuration.filterBrowsers = false
                manager.providerConfiguration = configuration
            }
            manager.localizedDescription = "Samaritan"
            manager.isEnabled = enabled

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()

            status = manager.isEnabled ? .enabled : .disabled
            lastErrorDetail = nil
            Log.manager.log("saveToPreferences ok, enabled=\(enabled, privacy: .public)")
        } catch {
            status = .failed(Self.describe(error))
            lastErrorDetail = Self.detail(for: error)
            Log.manager.error("saveToPreferences failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    func removeConfiguration() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await manager.removeFromPreferences()
            await refresh()
        } catch {
            status = .failed(Self.describe(error))
            lastErrorDetail = Self.detail(for: error)
        }
    }

    // MARK: - Error reporting

    private static func describe(_ error: Error) -> String {
        let nsError = error as NSError
        guard nsError.domain == NEFilterErrorDomain,
              let code = NEFilterManagerError(rawValue: nsError.code)
        else { return nsError.localizedDescription }

        switch code {
        case .configurationInvalid: return "configurationInvalid"
        case .configurationDisabled: return "configurationDisabled"
        case .configurationStale: return "configurationStale"
        case .configurationCannotBeRemoved: return "configurationCannotBeRemoved"
        case .configurationPermissionDenied: return "configurationPermissionDenied"
        case .configurationInternalError: return "configurationInternalError"
        @unknown default: return "NEFilterManagerError(\(nsError.code))"
        }
    }

    /// The deployment question in one place. `permissionDenied` here is the exact signal that
    /// separates "development build on an unsupervised device works" from "it does not".
    private static func detail(for error: Error) -> String {
        let nsError = error as NSError
        guard nsError.domain == NEFilterErrorDomain else { return nsError.localizedDescription }

        switch NEFilterManagerError(rawValue: nsError.code) {
        case .configurationPermissionDenied:
            return """
            The system refused the content-filter configuration.

            Either you declined the "filter network content" prompt, or this build is not allowed to \
            configure a content filter on this device. Per TN3134, in a *distribution* build a global \
            iOS content filter requires a supervised device. A *development*-signed build (get-task-allow \
            = true, installed from Xcode) is the path this spike targets; if you see this error on a \
            development build, that is a milestone-1 result worth recording in README.md.
            """
        case .configurationInvalid:
            return """
            The configuration was rejected. Check that both app extensions are embedded in the app \
            bundle, that all three targets carry the content-filter-provider entitlement, and that \
            the App IDs exist in the developer portal with Network Extensions enabled.
            """
        case .configurationStale:
            return "Another process changed the configuration. Reload and retry."
        default:
            return nsError.localizedDescription
        }
    }
}
