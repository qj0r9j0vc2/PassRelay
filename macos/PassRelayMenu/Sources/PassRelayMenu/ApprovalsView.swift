import LocalAuthentication
import SwiftUI

struct ApprovalsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        TabView {
            ConflictsTab().tabItem { Text(label("Conflicts", model.status?.conflicts)) }
            DeletionsTab().tabItem { Text(label("Deletions", model.status?.deletions)) }
            PlansTab().tabItem { Text(label("Plans", model.status?.plans)) }
            QueueTab().tabItem { Text(label("Queue", model.status?.queue)) }
        }
        .padding()
        .frame(minWidth: 600, minHeight: 360)
    }

    private func label(_ title: String, _ n: Int?) -> String {
        (n ?? 0) > 0 ? "\(title) (\(n!))" : title
    }
}

/// Loads one listing and reloads it whenever the model's refresh token changes.
private struct ListingContainer<Row: Identifiable, Content: View>: View {
    @EnvironmentObject private var model: AppModel
    let args: [String]
    let key: String
    let parse: (JSON) -> Row
    let empty: String
    @Binding var error: String?
    @ViewBuilder let row: (Row) -> Content
    @State private var rows: [Row] = []
    @State private var loaded = false

    var body: some View {
        VStack(alignment: .leading) {
            ErrorBanner(message: $error)
            if loaded && rows.isEmpty {
                Spacer()
                Text(empty).foregroundStyle(.secondary).frame(maxWidth: .infinity)
                Spacer()
            } else {
                List(rows) { row($0).padding(.vertical, 4) }
            }
        }
        .task(id: model.refreshToken) { await load() }
    }

    private func load() async {
        switch await model.fetch(args) {
        case .ok(let j): rows = j.arr(key).map(parse); loaded = true
        case .failed(_, let m): error = m
        }
    }
}

// MARK: Conflicts

private struct ConflictsTab: View {
    @EnvironmentObject private var model: AppModel
    @State private var error: String?
    @State private var revealed: RevealedConflict?

    var body: some View {
        ListingContainer(args: ["conflicts", "--names"], key: "conflicts", parse: Conflict.init,
                         empty: "No conflicts.", error: $error) { c in
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(c.who.title).font(.headline)
                    Text(c.who.subtitle).foregroundStyle(.secondary)
                    Text("\(c.kind == "initial" ? "Different values when first linked" : "Changed on both sides")"
                         + (c.fields.isEmpty ? "" : ": " + c.fields.joined(separator: ", ")))
                        .font(.caption)
                }
                Spacer()
                Button("Show values…") { Task { await reveal(c) } }
                Button("Keep pass") { resolve(c, "pass") }
                Button("Keep Apple") { resolve(c, "apple") }
            }
        }
        .sheet(item: $revealed) { _ in RevealSheet(revealed: $revealed) }
    }

    private func resolve(_ c: Conflict, _ side: String) {
        Task { error = await model.perform(["resolve", c.id, "--keep", side]).error }
    }

    private func reveal(_ c: Conflict) async {
        let context = LAContext()
        var authError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError) else {
            error = authError?.localizedDescription ?? "Device authentication is unavailable."
            return
        }
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication,
                                                   localizedReason: "show the conflicting values") else { return }
        } catch {
            return  // cancelled or failed: show nothing
        }
        switch await model.fetch(["conflicts", "show", c.id, "--reveal"]) {
        case .ok(let j): revealed = RevealedConflict(id: c.id, values: j.obj("values") ?? [:])
        case .failed(_, let m): error = m
        }
    }
}

private struct RevealSheet: View {
    @Binding var revealed: RevealedConflict?
    @State private var showPasswords = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Conflicting values").font(.headline)
            if let r = revealed {
                Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 8) {
                    GridRow {
                        Text("")
                        Text("pass").bold()
                        Text("Apple Passwords").bold()
                    }
                    ForEach(r.rows, id: \.field) { row in
                        GridRow {
                            Text(row.field).foregroundStyle(.secondary)
                            value(row.pass, secret: row.field == "password")
                            value(row.apple, secret: row.field == "password")
                        }
                    }
                }
            }
            HStack {
                Toggle("Show passwords", isOn: $showPasswords)
                Spacer()
                Button("Done") { revealed = nil }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 520)
        .onDisappear { revealed = nil }  // drop the values as soon as the sheet goes away
    }

    private func value(_ text: String, secret: Bool) -> some View {
        Text(secret && !showPasswords ? String(repeating: "•", count: min(text.count, 12)) : text)
            .font(.body.monospaced())
            .textSelection(.enabled)
            .frame(maxWidth: 220, alignment: .leading)
    }
}

// MARK: Deletions

private struct DeletionsTab: View {
    @EnvironmentObject private var model: AppModel
    @State private var error: String?
    @State private var confirm: Deletion?

    var body: some View {
        ListingContainer(args: ["deletions", "--names"], key: "deletions", parse: Deletion.init,
                         empty: "No pending deletions.", error: $error) { d in
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(d.who.title).font(.headline)
                    Text(d.who.subtitle).foregroundStyle(.secondary)
                    Text("Deleted in \(d.deletedIn == "pass" ? "pass" : "Apple Passwords")").font(.caption)
                    if d.otherModified {
                        Text("The other copy was modified after the deletion.").font(.caption).foregroundStyle(.orange)
                    }
                }
                Spacer()
                Button("Approve delete") { confirm = d }
                Button("Restore") { run(["deletions", "restore", d.id]) }
            }
        }
        .confirmationDialog("Delete the remaining copy too?", isPresented: .present($confirm),
                            presenting: confirm) { d in
            Button("Delete", role: .destructive) { confirm = nil; run(["deletions", "approve", d.id]) }
            Button("Cancel", role: .cancel) { confirm = nil }
        } message: { d in
            Text("\(d.who.title) will be removed from both sides. History keeps a snapshot for restore.")
        }
    }

    private func run(_ args: [String]) { Task { error = await model.perform(args).error } }
}

// MARK: Plans

private struct PlansTab: View {
    @EnvironmentObject private var model: AppModel
    @State private var error: String?
    @State private var confirm: Plan?

    var body: some View {
        ListingContainer(args: ["plans"], key: "plans", parse: Plan.init,
                         empty: "No plans waiting for approval.", error: $error) { p in
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Bulk change of \(p.size) item\(p.size == 1 ? "" : "s")").font(.headline)
                    ForEach(p.summary, id: \.0) { kind, n in
                        Text("\(kind): \(n)").font(.callout).foregroundStyle(.secondary)
                    }
                    if let t = p.time { Text(relative(t)).font(.caption) }
                }
                Spacer()
                Button("Approve…") { confirm = p }
                Button("Reject") { run(["plans", "reject", p.id]) }
            }
        }
        .confirmationDialog("Apply this bulk change?", isPresented: .present($confirm),
                            presenting: confirm) { p in
            Button("Approve", role: .destructive) { confirm = nil; run(["plans", "approve", p.id]) }
            Button("Cancel", role: .cancel) { confirm = nil }
        } message: { p in
            Text(p.summary.map { "\($0.0): \($0.1)" }.joined(separator: ", "))
        }
    }

    private func run(_ args: [String]) { Task { error = await model.perform(args).error } }
}

// MARK: Queue

private struct QueueTab: View {
    @State private var error: String?

    var body: some View {
        ListingContainer(args: ["queue", "--names"], key: "queue", parse: QueueItem.init,
                         empty: "Nothing to review.", error: $error) { q in
            QueueRow(item: q, error: $error)
        }
    }
}

private struct QueueRow: View {
    @EnvironmentObject private var model: AppModel
    let item: QueueItem
    @Binding var error: String?
    @State private var path = ""
    @State private var site = ""
    @State private var username = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(item.who.title).font(.headline)
            if !item.who.subtitle.isEmpty { Text(item.who.subtitle).foregroundStyle(.secondary) }
            Text(item.explanation).font(.caption)
            switch item.kind {
            case "missing-info":
                HStack {
                    TextField("Site (example.com)", text: $site)
                    TextField("Username", text: $username)
                    Button("Save") {
                        run(["queue", "info", item.id, "--site", site, "--username", username])
                    }
                    .disabled(site.trimmingCharacters(in: .whitespaces).isEmpty
                              || username.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            case "ambiguous-rename" where !item.paths.isEmpty:
                HStack {
                    Picker("Path", selection: $path) {
                        ForEach(item.paths, id: \.self) { Text($0).tag($0) }
                    }
                    Button("Accept") { run(["queue", "accept", item.id, "--path", path]) }
                        .disabled(path.isEmpty)
                }
                .onAppear { if path.isEmpty { path = item.paths[0] } }
            default:
                Button("Accept") { run(["queue", "accept", item.id]) }
            }
        }
    }

    private func run(_ args: [String]) { Task { error = await model.perform(args).error } }
}
