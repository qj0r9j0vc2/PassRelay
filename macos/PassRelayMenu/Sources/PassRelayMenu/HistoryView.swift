import SwiftUI

struct HistoryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var entries: [HistoryEntry] = []
    @State private var selection: HistoryEntry.ID?
    @State private var error: String?
    /// Set when a restore was refused because the item changed since the snapshot.
    @State private var refused: (entry: HistoryEntry, message: String)?
    @State private var confirmForce: HistoryEntry?

    private var selected: HistoryEntry? { entries.first { $0.id == selection } }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ErrorBanner(message: $error)
            Table(entries, selection: $selection) {
                TableColumn("Time", value: \.timeText).width(min: 120, ideal: 150)
                TableColumn("Action", value: \.action)
                TableColumn("Side", value: \.side).width(min: 50, ideal: 60)
                TableColumn("Site", value: \.site)
                TableColumn("Username", value: \.username)
                TableColumn("Path", value: \.path)
            }
            HStack {
                Text("Every write keeps an encrypted snapshot of the value it replaced.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Restore") { if let e = selected { Task { await restore(e, force: false) } } }
                    .disabled(selected == nil)
            }
        }
        .padding()
        .frame(minWidth: 640, minHeight: 360)
        .task(id: model.refreshToken) { await load() }
        .alert("Restore refused", isPresented: .present($refused), presenting: refused) { r in
            Button("Restore anyway…") { confirmForce = r.entry }
            Button("Cancel", role: .cancel) {}
        } message: { r in
            Text(r.message)
        }
        .confirmationDialog("Restore anyway?", isPresented: .present($confirmForce), presenting: confirmForce) { e in
            Button("Overwrite with snapshot", role: .destructive) { Task { await restore(e, force: true) } }
        } message: { _ in
            Text("The item changed after this snapshot. Restoring overwrites the newer value (it is kept in history).")
        }
    }

    private func load() async {
        switch await model.fetch(["history", "--names", "--limit", "200"]) {
        case .ok(let j): entries = j.arr("history").map(HistoryEntry.init)
        case .failed(_, let m): error = m
        }
    }

    private func restore(_ e: HistoryEntry, force: Bool) async {
        let args = ["restore", e.id] + (force ? ["--force"] : [])
        guard case .failed(let kind, let message) = await model.perform(args) else { return }
        if !force, ["stale", "refused", "changed", "superseded", "conflict"].contains(kind ?? "") {
            refused = (e, message)
        } else {
            error = message
        }
    }
}
