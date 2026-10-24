# PassRelay menu bar app

A small SwiftUI menu bar app for the PassRelay daemon. It shows sync state, lets you approve
conflicts, deletions, bulk plans and queued items, browse linked items and history, and handle
re-authentication. It talks to the daemon only by running the `passrelay` CLI with `--json`
(see [docs/CLI.md](../../docs/CLI.md)); it has no network access, analytics or third-party
dependencies.

## Build

Requires macOS 13+ and Swift 5.9+ (Command Line Tools are enough; Xcode is not needed).

```sh
scripts/build-app.sh          # produces build/PassRelay.app (ad-hoc signed)
```

The version comes from the `VERSION` file at the repository root. To sign with a real identity:

```sh
PASSRELAY_SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" scripts/build-app.sh
```

For development, `swift build` / `swift run` inside this directory also work.

## Install

```sh
cp -R build/PassRelay.app /Applications/
open /Applications/PassRelay.app
```

Enable "Open this menu bar app at login" in Settings to start it at login. "Start the PassRelay
daemon at login" installs the daemon's LaunchAgent (`passrelay service install`).

## CLI path

The app looks for `passrelay` at `/opt/homebrew/bin/passrelay`, `/usr/local/bin/passrelay` and
`~/.local/bin/passrelay`, in that order. If it lives elsewhere, set the full path in Settings.
The CLI is run directly (no shell) with `/opt/homebrew/bin` and `/usr/local/bin` added to
`PATH`, so `pass`, `gpg` and `pinentry-mac` from Homebrew are found.

## Distribution

An ad-hoc signed build runs on the machine that built it. Distributing it to other Macs needs a
Developer ID certificate and notarization; see `scripts/release.sh`.
