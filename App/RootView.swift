import SwiftUI

struct RootView: View {
    @Bindable var filter: FilterController
    @Bindable var diagnostics: DiagnosticsModel
    @Bindable var policy: PolicyStore

    var body: some View {
        TabView {
            Tab("Apps", systemImage: "square.grid.2x2") {
                NavigationStack { AppListView(diagnostics: diagnostics, policy: policy) }
            }
            Tab("Global", systemImage: "list.bullet.rectangle") {
                NavigationStack { GlobalListsView(policy: policy) }
            }
            Tab("Recent", systemImage: "clock") {
                NavigationStack { RecentFlowsView(diagnostics: diagnostics) }
            }
            Tab("Settings", systemImage: "gearshape") {
                NavigationStack { DiagnosticsView(filter: filter, diagnostics: diagnostics, policy: policy) }
            }
        }
        .tint(Theme.accent)
    }
}
