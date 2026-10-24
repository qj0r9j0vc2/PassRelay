# PassRelay CLI

`passrelay` manages synchronization. Day-to-day password work keeps using the normal `pass`
commands; PassRelay notices those changes on its own.

```
passrelay [--config PATH] [--json] COMMAND [ARGS]
```

`--json` switches every command to machine-readable output: exactly one JSON object on stdout.
Human output is for people and may change between versions. The JSON shapes below are a
compatibility contract (fields may be added, never removed or renamed within a major version).

No command prints a plaintext password unless it is given `--reveal`. Status, items, and doctor
output never include passwords. Websites and usernames appear only in `items`, `conflicts`,
`deletions`, `queue`, and `history`, and only with `--names` (otherwise they are masked like
`ex*****.com` / `al***`).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, nothing needs attention |
| 1 | Error (backend failure, unexpected state) |
| 2 | Usage or configuration error |
| 3 | Success, but something needs the user (conflict, pending deletion, plan, queue item) |
| 4 | Authentication required (Apple Passwords/APW, GPG, or Keychain) |
| 5 | Busy: another PassRelay process holds the state lock |

Errors in `--json` mode are printed as `{"ok": false, "error": {"kind": "...", "message": "..."}}`
with the matching exit code. Successful responses carry `"ok": true`.

## Commands

### `setup`

```
passrelay setup [--pass-store DIR] [--apple-backend apw|bridge] [--bridge-command JSON_ARRAY]
                [--include GLOB]... [--exclude GLOB]... [--watch-domain HOST]...
                [--import-apple-csv FILE] [--new-items auto|review]
                [--deletion-policy ask|propagate|keep] [--key-store keychain|file] [--apply]
```

Writes the configuration, creates the state key in the login Keychain, discovers both sides, and
prints the initial plan (links, creations, expected conflicts) without writing anything. Running
it again with `--apply` (or `passrelay setup --apply` alone) performs the first sync.

`--import-apple-csv` reads only the URL and Username columns of a Passwords app export
(File > Export All Passwords) to learn which websites exist in Apple Passwords; passwords in the
file are ignored. Delete the export afterwards.

JSON: `{"ok": true, "config": "<path>", "applied": bool, "report": REPORT}`

### `status`

Reads non-secret status files only, so it works even when the Keychain or GPG is locked.

```json
{"ok": true, "setup_done": true, "paused": false,
 "daemon": {"running": true, "pid": 123},
 "service": {"installed": true},
 "last_success": 1761300000.0, "last_cycle": {"time": 1761300000.0, "ok": true},
 "auth": {"apple": null, "gpg": "unlock your GPG key with `passrelay auth gpg`"},
 "counts": {"linked": 120, "by_status": {"ok": 118, "conflict": 1, "error": 1},
            "conflicts": 1, "deletions_pending": 0, "queue": 2, "plans_pending": 0},
 "apple_progress": {"domains_checked": 80, "domains_total": 95, "domains_pending": 15},
 "attention": 3, "state": "attention"}
```

`state` is one of `ok`, `syncing`, `paused`, `attention`, `auth`, `error`, `not-setup`,
`stopped`. Exit code 3 when `attention > 0` or the state is `not-setup` (then `message` says why),
4 when any `auth` value is non-null.

### `sync [--dry-run]`

Runs one cycle now (waits up to 30 s for the lock). JSON: `{"ok": true, "report": REPORT}`.

REPORT:

```json
{"started": 0.0, "finished": 0.0, "dry_run": false, "setup_done": true,
 "actions": [{"kind": "update", "link": "l1a2b3", "to_pass": ["password"], "to_apple": []}],
 "errors": [{"side": "apple", "reason": "website lookup failed"}],
 "auth": {"apple": "run `passrelay auth apple` ..."},
 "apple_progress": {...}, "counts": {...}}
```

Action kinds: `link`, `create-pass`, `create-apple`, `update`, `conflict`, `deletion-pending`,
`delete-pass`, `delete-apple`, `deleted`, `pass-renamed`, `apple-identity-changed`,
`unlinked-after-delete`, `removed-both`, `queued`, `plan-pending`, `held-for-approval`,
`manual-action`.

### `pause` / `resume`

JSON: `{"ok": true, "paused": bool}`. The daemon keeps running but skips cycles while paused.

### `items`

```
passrelay items [--names] [--status STATUS]
passrelay items exclude ID            # stop syncing this link; both copies are kept
passrelay items include --path PATH   # undo an exclusion
passrelay items link --path PATH --site HOST --username NAME
passrelay items unlink ID
```

JSON for the listing:

```json
{"ok": true, "items": [{"id": "l1a2b3", "pass_path": "web/ex***", "site": "ex*****.com",
  "username": "al***", "status": "ok", "notice": null,
  "support": {"password": "synced", "username": "synced", "urls": "...", "notes": "..."}}],
 "excluded": {"pass": 1, "apple": 0}}
```

Link statuses: `ok`, `pending`, `conflict`, `deletion-pending`, `needs-review`, `manual-action`,
`error`.

### `conflicts`

```
passrelay conflicts [--names]
passrelay conflicts show ID [--reveal]
passrelay resolve ID --keep pass|apple
```

Listing JSON: `{"ok": true, "conflicts": [{"id", "link", "kind", "fields", "time", "pass_path",
"site", "username"}]}`. `kind` is `initial` (different values when first linked) or
`both-changed`.

`show --reveal` adds `"values": {"pass": {"password", "username", "urls", "notes"}, "apple": {...}}`.
Without `--reveal` the values object only says which fields differ.

`resolve` JSON: `{"ok": true, "link": "l1a2b3"}`. It refuses (exit 1, kind `stale`) when either
side changed since the conflict was recorded.

### `deletions`

```
passrelay deletions [--names]
passrelay deletions approve ID    # delete the surviving copy too
passrelay deletions restore ID    # re-create the deleted copy from the survivor
```

Listing JSON: `{"ok": true, "deletions": [{"id", "link", "deleted_in": "pass"|"apple",
"other_modified": bool, "time", "pass_path", "site", "username"}]}`.

### `plans`

```
passrelay plans
passrelay plans approve ID
passrelay plans reject ID
```

Bulk deletions/overwrites above `bulk_threshold` wait here.
JSON: `{"ok": true, "plans": [{"id", "time", "size", "summary": {"overwrite-pass": 12}}]}`.

### `queue`

```
passrelay queue [--names]
passrelay queue accept ID [--path PATH]
passrelay queue info ID --site HOST --username NAME
```

Kinds: `missing-info` (pass entry without username/website; `queue info` writes `username:` and
`url:` lines into it once), `confirm-link`, `confirm-create` (when `new_items` is `review`),
`duplicate-identity`, `ambiguous-rename`, `relink-suggested`, `identity-collision`,
`apple-delete-manual` (delete the item in the Passwords app, then accept), `apple-write-unavailable`,
`outside-pass-scope`.

JSON: `{"ok": true, "queue": [{"id", "kind", "time", "pass_path"?, "site"?, "username"?}]}`.

### `auth`

```
passrelay auth                 # everything that currently needs authentication
passrelay auth apple           # starts APW if needed and runs `apw auth` (macOS PIN prompt)
passrelay auth apple --request # step 1 for GUIs: ask APW for a PIN challenge
passrelay auth apple --pin-stdin  # step 2 for GUIs: read the 6-digit PIN from stdin
passrelay auth gpg             # decrypt one entry interactively so gpg-agent caches the key
passrelay auth keychain        # verify the PassRelay key is readable
```

JSON: `{"ok": true, "auth": {"apple": null, "gpg": null, "keychain": null}}` (null means fine).

### `history` / `restore`

```
passrelay history [--names] [--limit N]
passrelay restore HISTORY_ID [--force]
```

Every write is preceded by an encrypted snapshot of the value it replaces. `restore` writes the
snapshot back to the side it came from (the normal sync then carries it to the other side). It
refuses, unless `--force`, when the item changed after that snapshot was superseded.

History JSON: `{"ok": true, "history": [{"id", "time", "action", "side", "link", "site"?,
"username"?, "pass_path"?}]}`. Restore JSON: `{"ok": true, "restored": "<id>"}`.

### `service`

```
passrelay service install [--menubar APP_PATH]   # LaunchAgent for the daemon (+ menu bar app)
passrelay service uninstall
passrelay service start | stop | restart
passrelay service status
```

JSON: `{"ok": true, "service": {"installed": bool, "loaded": bool, "plist": "<path>",
"menubar_installed": bool}}`.

### `config`

```
passrelay config get [KEY]
passrelay config set KEY VALUE     # VALUE is parsed as JSON when possible
```

JSON: `{"ok": true, "config": {...}}` or `{"ok": true, "key": "...", "value": ...}`.

### `doctor`

Checks Python, `pass`, `gpg`, the store and its `.gpg-id`, gpg-agent unlock state, git, APW binary,
socket, and authentication, Keychain access, state decryption, LaunchAgent, and permissions.

```json
{"ok": true, "checks": [{"name": "pass binary", "status": "ok"|"warn"|"fail", "detail": "..."}]}
```

Exit code 1 if any check fails.

### `uninstall [--purge]`

Stops and removes the LaunchAgents. `--purge` also deletes the state directory, history, and the
Keychain key. Passwords in pass and Apple Passwords are never touched.

### `daemon`

Runs the background loop (used by the LaunchAgent). Not meant to be called by hand.
