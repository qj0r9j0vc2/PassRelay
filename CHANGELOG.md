# Changelog

All notable changes are listed here. Versions follow semantic versioning. The JSON output of the
CLI (docs/CLI.md) is covered by the compatibility promise.

## 0.1.0 — unreleased

First version built from the product specification and the `pass-apple-sync` prototype.

- Two-way sync between pass and Apple Passwords (APW socket backend or bridge protocol v2).
- Automatic discovery and linking by website and username; path inference; review queue for
  missing information, duplicates, and ambiguous matches.
- Field-level three-way merge for password, username, websites, and notes (when the backend
  supports notes), preserving unknown pass lines.
- Conflicts, deletion policies (`ask`/`propagate`/`keep`) with tombstones, bulk-change plans.
- Encrypted state and change history (Keychain-held key), `history`/`restore`.
- Background daemon with sleep/wake detection, authentication back-off, and notifications;
  LaunchAgent management; SwiftUI menu bar app.
- `passrelay` CLI with a documented JSON contract and exit codes; `doctor` diagnostics.

Supported: macOS 13 Ventura or later (menu bar app); CLI and daemon need Python 3.10+.
APW requires macOS 14 or later.
