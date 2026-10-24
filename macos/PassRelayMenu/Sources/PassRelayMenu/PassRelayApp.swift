import SwiftUI

@main
struct PassRelayApp: App {
    @StateObject private var model = AppModel()

    init() {
        // Writing a PIN to a CLI that already exited must not kill the app.
        signal(SIGPIPE, SIG_IGN)
    }

    var body: some Scene {
        MenuBarExtra {
            MenuView().environmentObject(model)
        } label: {
            Image(systemName: model.symbol)
                .accessibilityLabel("PassRelay: \(model.status?.stateText ?? "unavailable")")
        }
        .menuBarExtraStyle(.window)

        Window("PassRelay Items", id: WindowID.items) {
            ItemsView().environmentObject(model).trackWindow(model)
        }
        .defaultSize(width: 820, height: 520)

        Window("PassRelay Approvals", id: WindowID.approvals) {
            ApprovalsView().environmentObject(model).trackWindow(model)
        }
        .defaultSize(width: 720, height: 480)

        Window("PassRelay History", id: WindowID.history) {
            HistoryView().environmentObject(model).trackWindow(model)
        }
        .defaultSize(width: 820, height: 520)

        Window("PassRelay Settings", id: WindowID.settings) {
            SettingsView().environmentObject(model).trackWindow(model)
        }
        .windowResizability(.contentSize)

        Window("Re-authenticate", id: WindowID.auth) {
            AuthView().environmentObject(model).trackWindow(model)
        }
        .windowResizability(.contentSize)
    }
}

enum WindowID {
    static let items = "items", approvals = "approvals", history = "history"
    static let settings = "settings", auth = "auth"
}

extension View {
    /// Counts open windows so polling can back off when nothing is visible.
    func trackWindow(_ model: AppModel) -> some View {
        onAppear { model.windowAppeared() }.onDisappear { model.windowDisappeared() }
    }
}

/// Inline error text with a dismiss button, used by every window.
struct ErrorBanner: View {
    @Binding var message: String?

    var body: some View {
        if let message {
            HStack(alignment: .top) {
                Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red)
                Text(message).font(.callout).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button { self.message = nil } label: { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
            }
            .padding(8)
            .background(.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
        }
    }
}

extension Binding where Value == Bool {
    /// True while `value` is non-nil; setting false clears it.
    static func present<T>(_ value: Binding<T?>) -> Binding<Bool> {
        Binding(get: { value.wrappedValue != nil }, set: { if !$0 { value.wrappedValue = nil } })
    }
}
