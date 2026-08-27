import SwiftUI

@main
struct SamaritanApp: App {
    @State private var filter = FilterController()
    @State private var diagnostics = DiagnosticsModel()

    init() {
        Theme.applyGlobalAppearance()
    }

    var body: some Scene {
        WindowGroup {
            DiagnosticsView(filter: filter, diagnostics: diagnostics)
                .tint(Theme.accent)
                .task {
                    SandboxProbe.run()
                    PathObserver.shared.start()
                    await filter.refresh()
                    diagnostics.startPolling()
                }
        }
    }
}
