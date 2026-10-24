import Foundation

/// JSON objects are read leniently so fields added by newer CLI versions never break parsing.
typealias JSON = [String: Any]

extension Dictionary where Key == String, Value == Any {
    func str(_ key: String) -> String? { self[key] as? String }
    func num(_ key: String) -> Double? { (self[key] as? NSNumber)?.doubleValue }
    func int(_ key: String) -> Int? { (self[key] as? NSNumber)?.intValue }
    func bool(_ key: String) -> Bool? { self[key] as? Bool }
    func obj(_ key: String) -> JSON? { self[key] as? JSON }
    func arr(_ key: String) -> [JSON] { self[key] as? [JSON] ?? [] }
    func date(_ key: String) -> Date? { num(key).map { Date(timeIntervalSince1970: $0) } }
    /// Any non-null value, rendered as text (used for auth hints and revealed values).
    func text(_ key: String) -> String? { describe(self[key]) }
}

func describe(_ value: Any?) -> String? {
    switch value {
    case nil, is NSNull: return nil
    case let s as String: return s
    case let list as [Any]: return list.compactMap(describe).joined(separator: "\n")
    case let n as NSNumber: return n.stringValue
    case let other?: return String(describing: other)
    }
}

struct DaemonStatus {
    var state: String
    var setupDone: Bool
    var paused: Bool
    var daemonRunning: Bool
    var lastSuccess: Date?
    var auth: [(name: String, hint: String)]
    var linked, conflicts, deletions, queue, plans, attention: Int
    var domainsChecked, domainsTotal, domainsPending: Int

    init(_ j: JSON) {
        state = j.str("state") ?? "error"
        setupDone = j.bool("setup_done") ?? false
        paused = j.bool("paused") ?? false
        daemonRunning = j.obj("daemon")?.bool("running") ?? false
        lastSuccess = j.date("last_success")
        let authObj = j.obj("auth") ?? [:]
        auth = authObj.keys.sorted().compactMap { k in authObj.text(k).map { (k, $0) } }
        let c = j.obj("counts") ?? [:]
        linked = c.int("linked") ?? 0
        conflicts = c.int("conflicts") ?? 0
        deletions = c.int("deletions_pending") ?? 0
        queue = c.int("queue") ?? 0
        plans = c.int("plans_pending") ?? 0
        attention = j.int("attention") ?? 0
        let p = j.obj("apple_progress") ?? [:]
        domainsChecked = p.int("domains_checked") ?? 0
        domainsTotal = p.int("domains_total") ?? 0
        domainsPending = p.int("domains_pending") ?? 0
    }

    func authHint(_ name: String) -> String? { auth.first { $0.name == name }?.hint }
    var needsAuth: Bool { authHint("apple") != nil || authHint("gpg") != nil }
    /// Changes whenever something listed in the Approvals or Items windows probably changed.
    var signature: String { "\(linked)/\(conflicts)/\(deletions)/\(queue)/\(plans)/\(lastSuccess?.timeIntervalSince1970 ?? 0)" }

    var symbol: String {
        switch state {
        case "ok": return "key.horizontal"
        case "syncing": return "arrow.triangle.2.circlepath"
        case "paused": return "pause.circle"
        case "attention": return "exclamationmark.triangle"
        case "auth": return "lock.trianglebadge.exclamationmark"
        case "error": return "xmark.octagon"
        default: return "key.slash"
        }
    }

    var stateText: String {
        switch state {
        case "ok": return "Up to date"
        case "syncing": return "Syncing…"
        case "paused": return "Paused"
        case "attention": return "Needs your attention"
        case "auth": return "Authentication needed"
        case "error": return "Sync error"
        case "not-setup": return "Not set up (run `passrelay setup`)"
        case "stopped": return "Background service stopped"
        default: return state.capitalized
        }
    }
}

/// Fields shared by most listing rows: masked or real (with `--names`) identity.
struct Identity {
    var passPath: String?, site: String?, username: String?
    init(_ j: JSON) { passPath = j.str("pass_path"); site = j.str("site"); username = j.str("username") }
    var title: String { site ?? passPath ?? "(unknown)" }
    var subtitle: String { [username, passPath].compactMap { $0 }.joined(separator: " · ") }
}

struct Conflict: Identifiable {
    let id: String, link: String, kind: String, fields: [String], time: Date?, who: Identity
    init(_ j: JSON) {
        id = j.str("id") ?? ""; link = j.str("link") ?? ""; kind = j.str("kind") ?? ""
        fields = j["fields"] as? [String] ?? []; time = j.date("time"); who = Identity(j)
    }
}

struct Deletion: Identifiable {
    let id: String, deletedIn: String, otherModified: Bool, time: Date?, who: Identity
    init(_ j: JSON) {
        id = j.str("id") ?? ""; deletedIn = j.str("deleted_in") ?? "?"
        otherModified = j.bool("other_modified") ?? false; time = j.date("time"); who = Identity(j)
    }
}

struct Plan: Identifiable {
    let id: String, time: Date?, size: Int, summary: [(String, Int)]
    init(_ j: JSON) {
        id = j.str("id") ?? ""; time = j.date("time"); size = j.int("size") ?? 0
        let s = j.obj("summary") ?? [:]
        summary = s.keys.sorted().map { ($0, s.int($0) ?? 0) }
    }
}

struct QueueItem: Identifiable {
    let id: String, kind: String, time: Date?, paths: [String], who: Identity
    init(_ j: JSON) {
        id = j.str("id") ?? ""; kind = j.str("kind") ?? ""; time = j.date("time")
        paths = j["paths"] as? [String] ?? []; who = Identity(j)
    }

    var explanation: String {
        switch kind {
        case "missing-info": return "This pass entry has no website or username."
        case "confirm-link": return "Confirm linking these two entries."
        case "confirm-create": return "Confirm creating the missing copy."
        case "duplicate-identity": return "Several entries share this website and username."
        case "ambiguous-rename": return "Choose which pass entry this item was renamed to."
        case "relink-suggested": return "A better link target was found."
        case "identity-collision": return "Another entry already uses this identity."
        case "apple-delete-manual": return "Delete the item in the Passwords app, then accept."
        case "apple-write-unavailable": return "Apple Passwords could not be written."
        case "outside-pass-scope": return "The entry is outside the synced part of the store."
        default: return kind
        }
    }
}

struct Item: Identifiable {
    let id: String, path: String, site: String, username: String, status: String, notice: String
    let support: [(String, String)]
    init(_ j: JSON) {
        id = j.str("id") ?? ""; path = j.str("pass_path") ?? ""; site = j.str("site") ?? ""
        username = j.str("username") ?? ""; status = j.str("status") ?? ""; notice = j.text("notice") ?? ""
        let s = j.obj("support") ?? [:]
        support = s.keys.sorted().compactMap { k in s.text(k).map { (k, $0) } }
    }
}

struct HistoryEntry: Identifiable {
    let id: String, time: Date?, action: String, side: String, link: String
    let site: String, username: String, path: String
    init(_ j: JSON) {
        id = j.str("id") ?? ""; time = j.date("time"); action = j.str("action") ?? ""
        side = j.str("side") ?? ""; link = j.str("link") ?? ""
        site = j.str("site") ?? ""; username = j.str("username") ?? ""; path = j.str("pass_path") ?? ""
    }
    var timeText: String { time.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "" }
}

/// Revealed conflict values. Lives only while the sheet is open.
struct RevealedConflict: Identifiable {
    let id: String
    let rows: [(field: String, pass: String, apple: String)]
    init(id: String, values: JSON) {
        self.id = id
        let pass = values.obj("pass") ?? [:], apple = values.obj("apple") ?? [:]
        let fields = Set(pass.keys).union(apple.keys).sorted { a, b in
            let order = ["password", "username", "urls", "notes"]
            return (order.firstIndex(of: a) ?? 99, a) < (order.firstIndex(of: b) ?? 99, b)
        }
        rows = fields.map { ($0, pass.text($0) ?? "—", apple.text($0) ?? "—") }
    }
}

func relative(_ date: Date?) -> String {
    guard let date else { return "never" }
    let f = RelativeDateTimeFormatter()
    f.unitsStyle = .full
    return f.localizedString(for: date, relativeTo: Date())
}
