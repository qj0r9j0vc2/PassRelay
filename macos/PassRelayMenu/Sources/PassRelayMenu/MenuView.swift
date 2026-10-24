import SwiftUI

struct MenuView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if let s = model.status { details(s) }
            ErrorBanner(message: $error)
            Divider()
            actions
            Divider()
            windows
            Divider()
            Button("Quit PassRelay Menu") { NSApp.terminate(nil) }
                .buttonStyle(.borderless)
                .keyboardShortcut("q")
        }
        .padding(14)
        .frame(width: 310)
        .trackWindow(model)
        .task { await model.refreshStatus() }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: model.symbol).font(.title2)
                .foregroundStyle(model.status?.state == "ok" ? Color.secondary : Color.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text("PassRelay").font(.headline)
                if let s = model.status {
                    Text(s.stateText).font(.subheadline)
                } else {
                    Text(model.statusError ?? "Loading…").font(.subheadline).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            if model.runningAction != nil { ProgressView().controlSize(.small) }
        }
    }

    @ViewBuilder
    private func details(_ s: DaemonStatus) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Last sync: \(relative(s.lastSuccess))").foregroundStyle(.secondary)
            if s.domainsPending > 0 {
                Text("Checking \(s.domainsPending) more website\(s.domainsPending == 1 ? "" : "s")…")
                    .foregroundStyle(.secondary)
                if s.domainsTotal > 0 {
                    ProgressView(value: Double(s.domainsChecked), total: Double(s.domainsTotal))
                }
            }
            if !s.daemonRunning && s.setupDone {
                Text("The background daemon is not running.").foregroundStyle(.orange)
            }
            ForEach(s.auth, id: \.name) { a in
                Label(a.hint, systemImage: "lock").foregroundStyle(.orange).font(.caption)
            }
        }
        .font(.callout)

        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 2) {
            countRow("Linked items", s.linked)
            countRow("Conflicts", s.conflicts)
            countRow("Pending deletions", s.deletions)
            countRow("Plans awaiting approval", s.plans)
            countRow("Review queue", s.queue)
        }
        .font(.callout)
    }

    private func countRow(_ label: String, _ n: Int) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text("\(n)").monospacedDigit().fontWeight(n > 0 && label != "Linked items" ? .semibold : .regular)
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Button(model.runningAction ?? "Sync Now") {
                    Task { error = await model.syncNow() }
                }
                .disabled(model.runningAction != nil || model.status?.setupDone != true)
                if let s = model.status, s.setupDone {
                    Button(s.paused ? "Resume" : "Pause") {
                        Task { error = await model.setPaused(!s.paused) }
                    }
                }
            }
            if model.status?.needsAuth == true {
                Button("Re-authenticate…") { open(WindowID.auth) }
            }
        }
    }

    private var windows: some View {
        VStack(alignment: .leading, spacing: 4) {
            menuButton("Items…", WindowID.items)
            menuButton(approvalsTitle, WindowID.approvals)
            menuButton("History…", WindowID.history)
            menuButton("Settings…", WindowID.settings)
        }
    }

    private var approvalsTitle: String {
        let n = model.status.map { $0.conflicts + $0.deletions + $0.plans + $0.queue } ?? 0
        return n > 0 ? "Approvals (\(n))…" : "Approvals…"
    }

    private func menuButton(_ title: String, _ id: String) -> some View {
        Button(title) { open(id) }.buttonStyle(.borderless)
    }

    private func open(_ id: String) {
        openWindow(id: id)
        NSApp.bringToFront()
    }
}
