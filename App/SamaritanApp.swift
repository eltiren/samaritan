import SwiftUI

@main
struct SamaritanApp: App {
    @State private var filter = FilterController()
    @State private var diagnostics = DiagnosticsModel()

    var body: some Scene {
        WindowGroup {
            DiagnosticsView(filter: filter, diagnostics: diagnostics)
                .task {
                    SandboxProbe.run()
                    PathObserver.shared.start()
                    await filter.refresh()
                    diagnostics.startPolling()
                }
        }
    }
}
