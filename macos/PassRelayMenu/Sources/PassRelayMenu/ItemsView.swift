import SwiftUI

struct ItemsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var items: [Item] = []
    @State private var excluded = (pass: 0, apple: 0)
    @State private var selection: Item.ID?
    @State private var filter = ""
    @State private var error: String?
    @State private var confirm: (action: String, item: Item)?

    private var shown: [Item] {
        guard !filter.isEmpty else { return items }
        return items.filter { i in
            [i.path, i.site, i.username, i.status].contains { $0.localizedCaseInsensitiveContains(filter) }
        }
    }

    private var selected: Item? { items.first { $0.id == selection } }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ErrorBanner(message: $error)
            Table(shown, selection: $selection) {
                TableColumn("Path", value: \.path)
                TableColumn("Site", value: \.site)
                TableColumn("Username", value: \.username)
                TableColumn("Status", value: \.status).width(min: 70, ideal: 90)
                TableColumn("Notice", value: \.notice)
            }
            detail
            Text("\(items.count) linked · excluded: \(excluded.pass) in pass, \(excluded.apple) in Apple Passwords")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding()
        .searchable(text: $filter)
        .frame(minWidth: 640, minHeight: 360)
        .task(id: model.refreshToken) { await load() }
        .confirmationDialog(confirmTitle, isPresented: .present($confirm), presenting: confirm) { c in
            Button(c.action == "exclude" ? "Exclude" : "Unlink", role: .destructive) {
                let args = ["items", c.action, c.item.id]
                Task { error = await model.perform(args).error }
            }
        } message: { c in
            Text(c.action == "exclude"
                 ? "\(c.item.site) stops syncing. Both copies are kept."
                 : "The link for \(c.item.site) is removed. Both copies are kept.")
        }
    }

    @ViewBuilder
    private var detail: some View {
        if let item = selected {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Field support").font(.headline)
                    ForEach(item.support, id: \.0) { field, info in
                        Text("\(field): \(info)").font(.callout)
                    }
                    if item.support.isEmpty { Text("No field information.").foregroundStyle(.secondary) }
                }
                Spacer()
                Button("Exclude…") { confirm = ("exclude", item) }
                Button("Unlink…") { confirm = ("unlink", item) }
            }
            .padding(8)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
        }
    }

    private var confirmTitle: String {
        confirm?.action == "exclude" ? "Exclude this item from sync?" : "Unlink this item?"
    }

    private func load() async {
        switch await model.fetch(["items", "--names"]) {
        case .ok(let j):
            items = j.arr("items").map(Item.init)
            let ex = j.obj("excluded") ?? [:]
            excluded = (ex.int("pass") ?? 0, ex.int("apple") ?? 0)
            if selected == nil { selection = nil }
        case .failed(_, let m):
            error = m
        }
    }
}
