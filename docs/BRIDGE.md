# Apple bridge protocol (version 2)

The default Apple backend is APW. A *bridge* is any executable you trust that implements this
protocol, for example a future tool with richer Apple Passwords access. Configure it with:

```json
{"apple_backend": "bridge", "bridge_command": ["/usr/local/bin/my-bridge", "--flag"]}
```

`bridge_command` is an argv array, never a shell string. PassRelay runs it once per request,
writes one JSON object to stdin, and reads one JSON object from stdout within 30 seconds. The
bridge must not print secrets to stderr. Every request carries `"version": 2`.

## Errors

- Any failure: exit non-zero or reply `{"ok": false}`.
- Authentication needed: `{"ok": false, "error": "auth", "hint": "short instruction"}`.
  PassRelay pauses that side and asks the user to authenticate. It never treats this as missing data.
- "Not found" must be reported only when the bridge positively knows the item does not exist.

## Operations

`hello` declares capabilities. Unknown keys are ignored, and missing keys mean `false`.

```json
{"op": "hello"}
{"ok": true, "capabilities": {"enumerate": true, "write": true, "delete": true, "rename": true,
  "notes": true, "urls_write": true, "record_ids": true, "change_tokens": true}}
```

`check` verifies the bridge is usable now: `{"op": "check"}` → `{"ok": true}`.

`list` takes an optional `domain`. Without it (requires `enumerate`) it lists every login.

```json
{"op": "list", "domain": "example.com"}
{"ok": true, "items": [{"id": "rec-1", "domain": "example.com", "username": "alice",
  "urls": ["https://example.com"], "title": "Example", "modified": "2026-10-24T10:00:00Z",
  "group": null}]}
```

`group` is non-null for logins in a shared group; those are skipped unless `include_shared` is on.
`modified` must change whenever any field changes, so PassRelay can skip reading unchanged items.

`get`:

```json
{"op": "get", "domain": "example.com", "username": "alice", "id": "rec-1"}
{"ok": true, "found": true, "item": {"id": "rec-1", "domain": "example.com", "username": "alice",
  "password": "...", "urls": [...], "notes": "...", "title": "..."}}
{"ok": true, "found": false}
```

`put` creates the login or updates it in place. `id` is set when updating a known record; `notes`
and `urls` are sent only when the matching capability is on. The reply returns the record id.

```json
{"op": "put", "domain": "example.com", "username": "alice", "password": "...", "id": "rec-1",
 "notes": "...", "urls": ["https://example.com"]}
{"ok": true, "id": "rec-1"}
```

`delete` (requires `delete`): `{"op": "delete", "domain", "username", "id"}` → `{"ok": true}`.

`rename` (requires `rename`) changes the username of an existing record:
`{"op": "rename", "domain", "username", "id", "new_username"}` → `{"ok": true}`.

PassRelay re-reads after every write and treats a mismatch as a failure, so a bridge that
returns `ok` without saving is detected.

Version 1 bridges from the prototype (`get`/`put` only, no `hello`) are not supported. Add a
`hello` reply that lists `{"write": true}`.
