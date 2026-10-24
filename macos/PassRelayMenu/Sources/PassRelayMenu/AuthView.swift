import SwiftUI

/// Re-authentication for Apple Passwords (APW PIN challenge) and GPG (pinentry-mac).
struct AuthView: View {
    @EnvironmentObject private var model: AppModel
    @State private var awaitingPIN = false
    @State private var pin = ""
    @State private var working: String?
    @State private var error: String?
    @State private var done: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Re-authenticate").font(.title3.bold())
            ErrorBanner(message: $error)
            if let done { Label(done, systemImage: "checkmark.circle").foregroundStyle(.green) }

            GroupBox("Apple Passwords") {
                VStack(alignment: .leading, spacing: 8) {
                    hint(model.status?.authHint("apple"))
                    if awaitingPIN {
                        Text("Enter the 6-digit PIN that macOS is showing.")
                        HStack {
                            TextField("PIN", text: $pin)
                                .font(.title3.monospacedDigit())
                                .frame(width: 120)
                                .onChange(of: pin) { pin = String($0.filter(\.isNumber).prefix(6)) }
                                .onSubmit(submitPIN)
                            Button("Submit", action: submitPIN).disabled(pin.count != 6 || working != nil)
                            Button("Cancel") { awaitingPIN = false; pin = "" }
                        }
                    } else {
                        Button("Request PIN…") { Task { await requestPIN() } }.disabled(working != nil)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            GroupBox("GPG key") {
                VStack(alignment: .leading, spacing: 8) {
                    hint(model.status?.authHint("gpg"))
                    Button("Unlock GPG key…") { Task { await unlockGPG() } }.disabled(working != nil)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            if let working {
                HStack { ProgressView().controlSize(.small); Text(working).foregroundStyle(.secondary) }
            }
        }
        .padding(20)
        .frame(width: 420)
        .onDisappear { pin = ""; awaitingPIN = false }
    }

    @ViewBuilder
    private func hint(_ text: String?) -> some View {
        if let text {
            Text(text).font(.callout).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
        } else {
            Text("No authentication needed.").font(.callout).foregroundStyle(.secondary)
        }
    }

    /// Step 1: ask APW for a challenge. The CLI answers with an auth hint (exit 4) by design.
    private func requestPIN() async {
        error = nil; done = nil
        working = "Requesting a PIN from macOS…"
        defer { working = nil }
        switch await model.perform(["auth", "apple", "--request"], timeout: 60) {
        case .ok(let j) where j.obj("auth")?.text("apple") == nil:
            done = "Apple Passwords is already authenticated."
        case .ok:
            awaitingPIN = true
        case .failed(let kind, let m):
            if kind == "auth" { awaitingPIN = true } else { error = m }
        }
    }

    /// Step 2: the PIN goes to the CLI's stdin, never into argv.
    private func submitPIN() {
        guard pin.count == 6 else { return }
        let data = Data((pin + "\n").utf8)
        pin = ""
        Task {
            working = "Verifying PIN…"
            defer { working = nil }
            let outcome = await model.perform(["auth", "apple", "--pin-stdin"], stdin: data, timeout: 60)
            if let j = outcome.json, j.obj("auth")?.text("apple") == nil {
                awaitingPIN = false
                done = "Apple Passwords authenticated."
            } else {
                error = outcome.error ?? outcome.json?.obj("auth")?.text("apple") ?? "PIN was not accepted."
            }
        }
    }

    private func unlockGPG() async {
        error = nil; done = nil
        working = "Waiting for the GPG passphrase prompt…"
        defer { working = nil }
        // No timeout: pinentry-mac waits for the user.
        let outcome = await model.perform(["auth", "gpg"], timeout: nil)
        if let j = outcome.json, j.obj("auth")?.text("gpg") == nil {
            done = "GPG key unlocked."
        } else {
            error = outcome.error ?? outcome.json?.obj("auth")?.text("gpg") ?? "GPG unlock failed."
        }
    }
}
