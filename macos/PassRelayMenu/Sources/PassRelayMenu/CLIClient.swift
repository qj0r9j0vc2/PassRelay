import Foundation
import os

/// One parsed `passrelay --json` invocation.
struct CLIResponse {
    let exitCode: Int32
    let json: JSON
    /// Last line of stderr, only for showing to the user (never logged).
    let stderrTail: String?

    var ok: Bool { json.bool("ok") ?? (exitCode == 0 || exitCode == 3) }
    var isBusy: Bool { exitCode == 5 }
    var needsAuth: Bool { exitCode == 4 }
    var errorKind: String? { json.obj("error")?.str("kind") }
    var errorMessage: String {
        if let message = json.obj("error")?.str("message") { return message }
        if let tail = stderrTail, !tail.isEmpty { return tail }
        return "passrelay exited with code \(exitCode)"
    }
}

enum CLIError: LocalizedError {
    case notFound(configured: String?)
    case launch(String)
    case noJSON(Int32, String?)

    var errorDescription: String? {
        switch self {
        case .notFound(let configured?):
            return "The passrelay CLI at \(configured) is not executable. Fix the path in Settings."
        case .notFound(nil):
            return "The passrelay CLI was not found. Install it or set its path in Settings."
        case .launch(let why):
            return "Could not start passrelay: \(why)"
        case .noJSON(let code, let tail):
            return "passrelay returned no JSON (exit \(code))" + (tail.map { ": \($0)" } ?? ".")
        }
    }
}

/// Runs the `passrelay` CLI with an argv array (never through a shell), always with `--json`.
enum CLIClient {
    static let pathKey = "cliPath"
    static let candidates = [
        "/opt/homebrew/bin/passrelay",
        "/usr/local/bin/passrelay",
        NSString(string: "~/.local/bin/passrelay").expandingTildeInPath,
    ]
    private static let log = Logger(subsystem: "io.passrelay.menubar", category: "cli")

    /// The configured path if one is set, otherwise the first executable default location.
    static func resolvedPath() throws -> String {
        let fm = FileManager.default
        if let configured = UserDefaults.standard.string(forKey: pathKey)?
            .trimmingCharacters(in: .whitespaces), !configured.isEmpty {
            let expanded = NSString(string: configured).expandingTildeInPath
            guard fm.isExecutableFile(atPath: expanded) else { throw CLIError.notFound(configured: expanded) }
            return expanded
        }
        guard let found = candidates.first(where: fm.isExecutableFile(atPath:)) else {
            throw CLIError.notFound(configured: nil)
        }
        return found
    }

    /// Runs off the main thread. `timeout` nil means wait indefinitely (interactive auth).
    static func run(_ args: [String], stdin: Data? = nil, timeout: TimeInterval? = 60) async throws -> CLIResponse {
        let path = try resolvedPath()
        return try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                do { cont.resume(returning: try runSync(path: path, args: args, stdin: stdin, timeout: timeout)) }
                catch { cont.resume(throwing: error) }
            }
        }
    }

    private static func runSync(path: String, args: [String], stdin: Data?, timeout: TimeInterval?) throws -> CLIResponse {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--json"] + args

        // GUI apps get a minimal PATH; pass, gpg and pinentry usually live in Homebrew prefixes.
        var env = ProcessInfo.processInfo.environment
        let extra = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        env["PATH"] = (extra + [env["PATH"] ?? ""]).filter { !$0.isEmpty }.joined(separator: ":")
        process.environment = env

        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        let inPipe = stdin == nil ? nil : Pipe()
        process.standardInput = inPipe ?? FileHandle.nullDevice

        do { try process.run() } catch { throw CLIError.launch(error.localizedDescription) }
        // Only the subcommand is logged: later arguments may carry site or user names.
        log.info("passrelay \(args.first ?? "", privacy: .public) started")

        if let inPipe, let stdin {
            let handle = inPipe.fileHandleForWriting
            try? handle.write(contentsOf: stdin)
            try? handle.close()
        }

        var errData = Data()
        let errDone = DispatchGroup()
        errDone.enter()
        DispatchQueue.global(qos: .utility).async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            errDone.leave()
        }
        if let timeout {
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak process] in
                if let process, process.isRunning { process.terminate() }
            }
        }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        errDone.wait()

        let code = process.terminationStatus
        log.info("passrelay \(args.first ?? "", privacy: .public) exited \(code, privacy: .public)")
        let tail = String(data: errData, encoding: .utf8)?
            .split(whereSeparator: \.isNewline).last.map { String($0.prefix(300)) }

        guard let json = (try? JSONSerialization.jsonObject(with: outData)) as? JSON else {
            if code == 5 { return CLIResponse(exitCode: code, json: [:], stderrTail: tail) }
            throw CLIError.noJSON(code, tail)
        }
        return CLIResponse(exitCode: code, json: json, stderrTail: tail)
    }
}
