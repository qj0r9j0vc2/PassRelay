import AppKit
import Foundation
import os

enum Outcome {
    case ok(JSON)
    case failed(kind: String?, message: String)

    var json: JSON? { if case .ok(let j) = self { return j } else { return nil } }
    var error: String? { if case .failed(_, let m) = self { return m } else { return nil } }
}

/// Shared state: polls `passrelay status` and runs every other CLI command for the views.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var status: DaemonStatus?
    @Published private(set) var statusError: String?
    @Published private(set) var runningAction: String?
    /// Bumped after actions and whenever status counts change, so open windows reload.
    @Published private(set) var refreshToken = 0

    private var openWindows = 0
    private var pollTask: Task<Void, Never>?
    private let log = Logger(subsystem: "io.passrelay.menubar", category: "app")

    init() { restartPolling() }

    var symbol: String { status?.symbol ?? "key.slash" }

    // MARK: Polling

    private var pollInterval: UInt64 {
        let quiet = openWindows == 0 && (status?.state ?? "") == "ok"
        return (quiet ? 30 : 5) * 1_000_000_000
    }

    private func restartPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refreshStatus()
                try? await Task.sleep(nanoseconds: self.pollInterval)
            }
        }
    }

    func windowAppeared() {
        openWindows += 1
        if openWindows == 1 { restartPolling() }  // leave the 30 s back-off immediately
    }

    func windowDisappeared() { openWindows = max(0, openWindows - 1) }

    func refreshStatus() async {
        do {
            let r = try await CLIClient.run(["status"], timeout: 20)
            if r.isBusy { return }  // keep the last known status; retry on the next tick
            guard r.ok || r.needsAuth || r.exitCode == 3, r.json.str("state") != nil else {
                statusError = r.errorMessage
                return
            }
            let new = DaemonStatus(r.json)
            if new.signature != status?.signature { refreshToken += 1 }
            status = new
            statusError = nil
        } catch {
            status = nil
            statusError = error.localizedDescription
        }
    }

    // MARK: Commands

    /// Runs a command, quietly retrying while the daemon holds the lock (exit 5).
    func perform(_ args: [String], stdin: Data? = nil, timeout: TimeInterval? = 120,
                 label: String? = nil, refresh: Bool = true) async -> Outcome {
        if let label { runningAction = label }
        defer { if label != nil { runningAction = nil } }
        var outcome: Outcome = .failed(kind: "busy", message: "PassRelay is busy. Try again in a moment.")
        for attempt in 0..<6 {
            if attempt > 0 { try? await Task.sleep(nanoseconds: 2_000_000_000) }
            do {
                let r = try await CLIClient.run(args, stdin: stdin, timeout: timeout)
                if r.isBusy { continue }
                if r.ok {
                    outcome = .ok(r.json)
                } else if r.needsAuth {
                    outcome = .failed(kind: r.errorKind ?? "auth",
                                      message: r.errorMessage + "\nUse Re-authenticate… in the PassRelay menu.")
                } else {
                    outcome = .failed(kind: r.errorKind, message: r.errorMessage)
                }
            } catch {
                outcome = .failed(kind: nil, message: error.localizedDescription)
            }
            break
        }
        if refresh {
            refreshToken += 1
            await refreshStatus()
        }
        return outcome
    }

    /// Read-only listing; does not bump the refresh token.
    func fetch(_ args: [String]) async -> Outcome {
        await perform(args, timeout: 60, refresh: false)
    }

    func syncNow() async -> String? {
        await perform(["sync"], timeout: 180, label: "Syncing…").error
    }

    func setPaused(_ paused: Bool) async -> String? {
        await perform([paused ? "pause" : "resume"], timeout: 30).error
    }
}

extension NSApplication {
    /// Menu bar (LSUIElement) apps must activate explicitly for their windows to come forward.
    func bringToFront() { activate(ignoringOtherApps: true) }
}
