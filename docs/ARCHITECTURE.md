# Architecture

```
 pass CLI / git pull ──► ~/.password-store (*.gpg) ◄── PassStore (runs the real `pass`)
                                                          │
                     passrelay daemon (LaunchAgent) ── Engine ── StateStore (encrypted state + history)
                                                          │
 iPhone ─iCloud─► Apple Passwords ◄── APW daemon socket ◄─┘   (or a bridge executable)
                                                          │
             PassRelay.app (menu bar) ── passrelay CLI --json ──┘
```

| Module | Role |
| --- | --- |
| `passstore.py` | Lists entries by stat + ciphertext hash (no decryption), reads/writes through `pass show` / `pass insert -m -f` / `pass rm -f` with `--pinentry-mode error` so a background process never pops up pinentry. |
| `passfmt.py` | Parses/renders the metadata format in [FORMAT.md](FORMAT.md), preserving unknown lines. |
| `apple/apw.py` | Talks to the APW daemon's Unix socket (`~/.apw/apw.sock`). |
| `apple/bridge.py` | Capability-based JSON protocol for other Apple access tools ([BRIDGE.md](BRIDGE.md)). |
| `engine.py` | Discovery, matching, three-way merge, deletion policy, bulk guard, apply/verify. |
| `state.py`, `crypto.py`, `keystore.py` | Encrypted state and history at rest; key in the login Keychain. |
| `daemon.py` | Poll loop, sleep/wake detection, back-off, notifications. |
| `cli.py`, `status.py` | CLI and the non-secret status contract used by the menu bar app. |
| `macos/PassRelayMenu` | SwiftUI menu bar app; drives everything through `passrelay --json`. |

## A sync cycle

1. **Scan pass.** Walk the store and hash each `.gpg` file, re-hashing only files whose
   mtime/size/inode changed. Only entries whose hash changed are decrypted and parsed. Their
   field fingerprints (HMAC-SHA256 with a key from the Keychain) are cached in the encrypted state.
2. **Poll Apple.** With an enumerating backend, list everything. With APW (no enumeration), look
   up the websites PassRelay knows about: linked items, website hosts from pass entries,
   `watch_domains`, and websites imported from a Passwords export. Websites with fresh pass
   changes or pending work go first; the rest rotate through `apple_budget` lookups per cycle.
3. **Renames.** A linked pass path that vanished, plus exactly one new path with the same
   ciphertext or the same identity, is a `pass mv`. The link follows it.
4. **Per link:** locate the Apple record (by record ID if available, else by identity). If a side
   is missing *and that side was positively checked*, apply the deletion policy. Otherwise merge.
5. **Merge.** For each field, compare the pass fingerprint, Apple fingerprint, and baseline:

   | pass vs baseline | Apple vs baseline | Result |
   | --- | --- | --- |
   | same | same | nothing |
   | changed | same | write pass value to Apple |
   | same | changed | write Apple value to pass |
   | changed | changed, equal to pass | nothing to write, baseline moves |
   | changed | changed, different | conflict: both kept, user decides |
   | one side cannot hold the field | | not compared, never erased |

6. **Discover.** Unlinked pass entries and Apple logins with the same identity are linked: equal
   passwords link silently, different passwords become an `initial` conflict. A login present
   on one side only is created on the other, but only after its website was looked up in this
   cycle. Duplicates and ambiguous matches go to the queue. Nothing is linked because two
   passwords match.
7. **Bulk guard.** If more than `bulk_threshold` deletions/overwrites are due in one cycle, they
   are held as a plan for approval (`passrelay plans`). An approval covers exactly the changes
   shown: each key includes the direction and the fingerprints of both sides, so if the values
   change before the next cycle, a new plan is raised.
8. **Apply.** For each write: re-read the target and compare with what was planned (abort on
   change), save an encrypted pre-change snapshot to history, write, re-read and verify, then
   advance the baseline. Any failure leaves the baseline alone, so the next cycle re-evaluates
   from scratch.

## Crash safety

The baseline only advances after verification, and every operation is idempotent by identity.
If the process dies between a write and saving state, the next cycle sees both sides equal
(baseline advances), or sees the new item on both sides and links it instead of creating a
duplicate. Pending conflicts, deletions, plans, queue items, and tombstones live in the
encrypted state, which is replaced atomically (write temp file, fsync, rename).

## Deletions

| Policy | One side deleted |
| --- | --- |
| `ask` (default) | `deletion-pending`; nothing changes until `deletions approve` (delete the survivor) or `deletions restore` (re-create the deleted copy). |
| `propagate` | Delete the survivor, unless it was modified since the last sync; that case falls back to `ask`. |
| `keep` | Unlink and tombstone the survivor so it is neither re-created nor re-linked. |

"Modified" means any synced field changed since the last sync (password, username, websites,
notes), not only the password. A pending deletion is withdrawn automatically if the deleted copy
reappears, and approving one re-checks that it is still gone. A linked entry moved out of the
pass scope is unlinked, not deleted; if a move out of scope cannot be recognised for certain
(`pass mv` re-encrypted the file), the deletion falls back to `ask` regardless of policy. With
record IDs, an Apple login missing from its website is looked up by ID first, since its website
may have changed.

A failed or unauthenticated lookup is never a deletion: a link is only considered deleted on the
Apple side when its website was listed successfully in that cycle and the login was absent.
Tombstones carry the content fingerprint, so a *new* login later saved at the same path or
identity syncs normally.

APW cannot delete or rename Apple logins. When a deletion or username change needs that,
PassRelay records a `apple-delete-manual` queue item ("delete it in the Passwords app") and
tombstones the old login so it is not imported back.

## Sleep, reboot, authentication

The daemon compares wall-clock and monotonic time each loop. A jump means the Mac slept, and
a full cycle runs right after wake. After a reboot, APW requires `apw auth` again. The cycle reports
`auth.apple`, the daemon backs off (up to 16× the poll interval), the menu bar shows the lock
icon, and one notification is sent. `passrelay auth apple` (or the menu bar's Re-authenticate)
completes the PIN pairing over the socket and wakes the daemon. GPG works the same way:
`--pinentry-mode error` turns a locked key into `auth.gpg` rather than a hidden prompt.

## Known limits (APW backend)

- Every write to Apple Passwords shows the macOS "Save password?" prompt. pass→Apple changes
  wait for that confirmation (up to `apple_confirm_seconds`) and are not unattended.
- A password read takes about 1–5 s, so Apple-side edits are found by a slow rotation (see
  BENCHMARKS.md). Changes made in pass are always read and pushed immediately.
- Apple does not store logins for reserved test domains such as `.example`.

- No vault enumeration: an Apple login on a website PassRelay has never heard of is found only
  after that website is known (a pass entry, `watch_domains`, or `setup --import-apple-csv`).
- No change stamps in the documented APW output: every check of a website re-reads its
  passwords. Apple-to-pass latency grows with the number of websites (see BENCHMARKS.md).
- No delete/rename and no notes: reported per item; handled by manual steps as described above.
- Shared-group membership is not exposed by APW; with APW, shared logins are indistinguishable
  from personal ones. Use `apple_exclude` for websites you only reach through shared groups.
- Passkeys and Apple-side one-time codes are out of scope. `otpauth://` lines in pass are kept
  and reported as not synced.
