import ServiceManagement
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @AppStorage(CLIClient.pathKey) private var cliPath = ""
    @State private var notifications = true
    @State private var deletionPolicy = "ask"
    @State private var serviceInstalled = false
    @State private var menuAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loaded = false
    @State private var error: String?
    @State private var note: String?
    @State private var needsRestart = false

    var body: some View {
        Form {
            Section("Command-line tool") {
                HStack {
                    TextField("passrelay path", text: $cliPath, prompt: Text(detectedPath ?? "/opt/homebrew/bin/passrelay"))
                    Button("Choose…", action: choosePath)
                }
                Text(cliPathStatus).font(.caption).foregroundStyle(.secondary)
            }

            Section("Sync") {
                Toggle("Pause syncing", isOn: Binding(
                    get: { model.status?.paused ?? false },
                    set: { v in Task { error = await model.setPaused(v) } }))
                    .disabled(model.status?.setupDone != true)
                Toggle("Show notifications", isOn: Binding(
                    get: { notifications },
                    set: { v in set("notifications", v ? "true" : "false") { notifications = v } }))
                Picker("When an item is deleted on one side", selection: Binding(
                    get: { deletionPolicy },
                    set: { v in set("deletion_policy", v) { deletionPolicy = v; needsRestart = serviceInstalled } })) {
                    Text("Ask me").tag("ask")
                    Text("Delete it on the other side too").tag("propagate")
                    Text("Keep the other copy").tag("keep")
                }
            }
            .disabled(!loaded)

            Section("Login") {
                Toggle("Start the PassRelay daemon at login", isOn: Binding(
                    get: { serviceInstalled },
                    set: { v in Task { await setService(v) } }))
                Toggle("Open this menu bar app at login", isOn: Binding(
                    get: { menuAtLogin }, set: setMenuAtLogin))
                if needsRestart {
                    HStack {
                        Text("Restart the daemon to apply the deletion policy.").font(.caption)
                        Button("Restart daemon") {
                            Task { error = await model.perform(["service", "restart"]).error; needsRestart = false }
                        }
                    }
                }
                if let note { Text(note).font(.caption) }
            }

            ErrorBanner(message: $error)
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .task(id: cliPath) { await load() }
    }

    private var detectedPath: String? { try? CLIClient.resolvedPath() }

    private var cliPathStatus: String {
        if let p = detectedPath { return cliPath.isEmpty ? "Using \(p)" : "Found." }
        return cliPath.isEmpty ? "Not found in the default locations. Enter the full path." : "Not executable."
    }

    private func choosePath() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.directoryURL = URL(fileURLWithPath: "/opt/homebrew/bin")
        if panel.runModal() == .OK, let url = panel.url { cliPath = url.path }
    }

    private func load() async {
        await model.refreshStatus()
        if case .ok(let j) = await model.fetch(["config", "get"]), let cfg = j.obj("config") {
            notifications = cfg.bool("notifications") ?? true
            deletionPolicy = cfg.str("deletion_policy") ?? "ask"
            loaded = true
        } else {
            loaded = false
        }
        if case .ok(let j) = await model.fetch(["service", "status"]) {
            serviceInstalled = j.obj("service")?.bool("installed") ?? false
        }
        menuAtLogin = SMAppService.mainApp.status == .enabled
    }

    private func set(_ key: String, _ value: String, onSuccess: @escaping () -> Void) {
        Task {
            switch await model.perform(["config", "set", key, value]) {
            case .ok: onSuccess()
            case .failed(_, let m): error = m
            }
        }
    }

    private func setService(_ install: Bool) async {
        switch await model.perform(["service", install ? "install" : "uninstall"]) {
        case .ok(let j): serviceInstalled = j.obj("service")?.bool("installed") ?? install
        case .failed(_, let m): error = m
        }
    }

    private func setMenuAtLogin(_ enable: Bool) {
        do {
            if enable { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            self.error = "Could not change login item: \(error.localizedDescription)"
        }
        menuAtLogin = SMAppService.mainApp.status == .enabled
        if SMAppService.mainApp.status == .requiresApproval {
            note = "Approve PassRelay in System Settings > General > Login Items."
        }
    }
}
