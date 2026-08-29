import SwiftUI

@main
struct SamaritanApp: App {
    @State private var filter = FilterController()
    @State private var diagnostics = DiagnosticsModel()
    @State private var policy = PolicyStore()

    init() {
        Theme.applyGlobalAppearance()
    }

    var body: some Scene {
        WindowGroup {
            RootView(filter: filter, diagnostics: diagnostics, policy: policy)
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
