# PassRelay

PassRelay keeps **Apple Passwords** and a **[pass](https://www.passwordstore.org/)** store in sync
on macOS, in both directions, in the background. Keep using the Passwords app on your iPhone and
Mac, and `pass` in the terminal. A login added or changed on either side shows up on the other.
You only hear from PassRelay when it needs a decision (a conflict, a deletion) or a sign-in.

```
iPhone ─iCloud─► Apple Passwords ◄─► PassRelay daemon ◄─► ~/.password-store ◄─ pass / git
```

- Your `pass` workflow is unchanged: `pass insert`, `edit`, `generate`, `mv`, `rm`, `git pull`
  are all detected. Nothing is wrapped or replaced.
- Logins are matched by website + username, never by "same password".
- Conflicts keep both values until you choose; deletions wait for approval by default.
- Every overwrite is preceded by an encrypted snapshot you can restore.
- Local only: no server, no account, no telemetry.

## Requirements

- macOS 14 Sonoma or later (APW requirement); the menu bar app needs macOS 13+
- Python 3.10+ (`brew install python`)
- `pass` with an initialized store and a GPG key (`brew install pass`)
- [APW](https://github.com/bendews/apw) with a supported browser and Apple's iCloud Passwords
  extension. APW is how PassRelay reaches Apple Passwords:
  ```sh
  brew install bendews/homebrew-tap/apw
  brew services start apw
  apw auth            # macOS shows a PIN; needed again after every reboot
  ```

## Install

```sh
pipx install .            # or: python3 -m pip install --user .
scripts/build-app.sh      # optional: builds build/PassRelay.app (menu bar)
cp -R build/PassRelay.app /Applications/
```

## Set up

```sh
# 1. Write the config and see the initial plan (links, creations, conflicts). Nothing is written.
passrelay setup

#    Apple Passwords cannot be enumerated through APW. To let PassRelay find Apple logins whose
#    websites are not in pass yet, export once from Passwords (File > Export All Passwords) and:
passrelay setup --import-apple-csv ~/Downloads/Passwords.csv   # reads only the URL column
rm -P ~/Downloads/Passwords.csv

# 2. Run the first sync, then resolve whatever it reports.
passrelay setup --apply
passrelay conflicts
passrelay queue

# 3. Run in the background from now on (and start the menu bar app at login).
passrelay service install --menubar /Applications/PassRelay.app
```

Scope: `--include 'web/*' --exclude 'private/*'` limits which pass paths take part, and
`apple_include`/`apple_exclude` in the config filter websites. Entries outside the scope are
never read or written.

## Everyday use

There is nothing to do. `passrelay status` (or the menu bar icon) shows the state. When something
needs you:

| You see | Do |
| --- | --- |
| Conflict | `passrelay conflicts`, then `passrelay resolve ID --keep pass` (or `apple`). `conflicts show ID --reveal` shows both values. |
| Pending deletion | `passrelay deletions approve ID` (delete the other copy) or `restore ID`. |
| Plan waiting | `passrelay plans` and `plans approve ID`, for more than `bulk_threshold` deletions/overwrites at once. |
| Queue item | `passrelay queue`, then `queue accept ID` or `queue info ID --site HOST --username NAME`. |
| Apple sign-in needed | `passrelay auth apple` (after a reboot, APW needs its PIN again). |
| GPG locked | `passrelay auth gpg`. |
| Something odd | `passrelay doctor`. |

Undo: `passrelay history` and `passrelay restore ID`.

## How entries look in pass

```
the-password
username: alice@example.com
url: https://example.com
note: anything
custom-field: kept untouched
```

See [docs/FORMAT.md](docs/FORMAT.md).

## Documentation

- [CLI reference and JSON contract](docs/CLI.md): automation, exit codes
- [Architecture and sync rules](docs/ARCHITECTURE.md): what happens in a cycle, deletions, limits
- [Security](docs/SECURITY.md): what is stored where, and which permissions are used
- [Configuration](docs/CONFIG.md)
- [Bridge protocol](docs/BRIDGE.md): plug in a different Apple Passwords backend
- [Benchmarks](docs/BENCHMARKS.md)
- [Changelog](CHANGELOG.md)

## What the APW backend cannot do

Measured with real APW: each save to Apple Passwords asks you to click **Save** in a macOS prompt,
and each password read takes 1–5 seconds. So changes you make in pass reach Apple as soon as you
confirm, but edits made on your iPhone are picked up by a slow rotation (minutes to about an hour,
depending on how many logins are synced). See [BENCHMARKS.md](docs/BENCHMARKS.md).

APW reaches Apple Passwords through the same interface as the iCloud Passwords browser extension.
That interface looks logins up per website and can create or update a password. It cannot list
the whole vault, delete, rename a username, read notes, or tell shared-group logins apart.
PassRelay reports each of these per item instead of guessing. Examples: "delete this login in the
Passwords app" after you `pass rm`; "extra pass URLs kept in pass"; notes stay in pass. A bridge
with more capabilities ([BRIDGE.md](docs/BRIDGE.md)) lifts these limits without other changes.
Passkeys and Apple-side verification codes are outside the sync. `otpauth://` lines in pass are
kept.

## Uninstall

```sh
passrelay uninstall          # stop and remove the background service
passrelay uninstall --purge  # also delete state, history, and the Keychain key
```

Your passwords in pass and in Apple Passwords stay as they are.

## Development

```sh
python3 -m unittest discover -s tests -t .   # unit, engine, real pass/gpg, and daemon tests
python3 bench/bench.py engine --sizes 100 1000 10000
python3 bench/bench.py real --sizes 100 1000
```

The integration tests use the real `pass` and `gpg` with a throwaway key in a temporary
`GNUPGHOME`, plus a fake APW socket server. They never touch your store or Apple Passwords.
Release builds: `scripts/release.sh` (signing and notarization need a Developer ID; see the script).
