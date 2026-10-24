# Security

## What PassRelay stores

| Data | Where | Protection |
| --- | --- | --- |
| Passwords in pass | your store, unchanged | GPG, as before |
| Passwords in Apple Passwords | iCloud Keychain, unchanged | Apple |
| Sync state: links (paths, websites, usernames), HMAC fingerprints of field values, pending decisions | `~/Library/Application Support/PassRelay/state.enc` | AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, macOS CommonCrypto), 0600 file in a 0700 directory |
| Change history: the value replaced by each write | `.../history/*.enc` | same encryption; pruned after `history_retention_days` (default 30) |
| Master key (32 random bytes) | login Keychain, service `PassRelay`, account `state-key` | Keychain. Created via `security -i` reading stdin, so the key never appears in a process argv |
| status.json, control.json, daemon.log | state directory | Plaintext with no secrets, no websites, and no usernames: counts, timestamps, and pause flag only |

No plaintext password cache exists. Values are decrypted at the moment they are compared or
written and are discarded at the end of the cycle (Python cannot guarantee zeroing memory).

## Where secrets never go

- **Process arguments.** `pass insert` gets the entry on stdin. APW requests travel over its
  0600 Unix socket. The APW PIN is sent over the socket too (`auth apple --pin-stdin`). Bridge
  requests go on stdin.
- **Logs and errors.** Messages are fixed strings plus counts. `pass`/`gpg`/bridge stderr is read
  only to tell "locked" from "failed" and is then discarded.
- **Output.** `status`, `doctor`, `items`, `sync` never print passwords. Websites and usernames
  are masked unless `--names` is given. Only `conflicts show --reveal` prints values. The menu bar
  app asks for Touch ID or your login password first.
- **Network.** PassRelay makes no network connections. No server, account, or telemetry. Apple
  data moves only through Apple's own iCloud sync.

## Trust boundaries

- **APW** is a third-party tool (MIT) that runs a headless browser with Apple's iCloud Passwords
  extension. PassRelay trusts it the same way you do when you install it. The socket must be owned
  by your user, and PassRelay refuses it otherwise.
- **Bridge executables** run with your privileges. Configure only programs you trust.
- An attacker who can read both the Keychain key and the state can try offline guesses against
  the fingerprints. Such an attacker already has your login keychain.
- macOS security features stay on: no SIP or Gatekeeper changes, no Full Disk Access, no
  Accessibility permission. GPG and Apple authentication are always done by their own prompts.

## Permissions requested

- Keychain access to the `PassRelay` item, on first run.
- Notifications, if enabled.
- The menu bar app uses LocalAuthentication before revealing conflict values.
- Login items: one LaunchAgent for the daemon and, optionally, one for the menu bar app.

## Removing PassRelay

`passrelay uninstall` removes the LaunchAgents. `--purge` also deletes state, history, and the
Keychain key. Passwords in pass and in Apple Passwords are never modified by uninstalling.

## Reporting

Please report vulnerabilities privately to the maintainers rather than in a public issue.
