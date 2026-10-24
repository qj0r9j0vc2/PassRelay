# pass entry format

PassRelay reads and writes ordinary `pass` entries. Nothing about the GPG storage changes, and
any entry you write by hand with `pass insert -m` or `pass edit` works.

```
correct horse battery staple        <- line 1: the password (required, single line)
username: alice@example.com         <- login name
url: https://example.com/login      <- website; repeat the line for more websites
url: https://login.example.net
title: Example (personal)
note: first line of a note          <- one `note:` line per note line
note:
note: third line
otpauth://totp/...                  <- kept as-is, never synced
pin: 1234                           <- anything else is kept as-is, never synced
```

| Key (case-insensitive) | Field | Notes |
| --- | --- | --- |
| `username`, `user`, `login` | username | First occurrence wins. Part of the item's identity. |
| `url`, `website`, `site` | websites | All occurrences, in order. The first one's host is part of the identity. |
| `title` | title | Copied from Apple into new pass entries; not synced back. |
| `note`, `notes` | notes | Synced only when the Apple backend can read notes (not with APW). |

Rules PassRelay follows when it rewrites an entry:

- Only the lines of fields that actually changed are replaced, in place, keeping your spelling of
  the key (`Login:` stays `Login:`).
- All other lines (custom fields, OTP URIs, free text) are kept in their position.
- A field the other side cannot provide (for example notes from APW) is never removed.
- A missing `username:`/`url:` is filled in from Apple when Apple has it.
- The trailing newline of the original entry is preserved.

## Identity

An item's identity is **website host + username** (plus a record ID when the Apple backend has
them). The pass path is only a name. When an entry has no `username:`/`url:` lines PassRelay
infers them from a path ending in `HOST/USERNAME` (for example `web/github.com/alice`); disable
with `"infer_from_path": false`. Entries with neither appear in `passrelay queue` as
`missing-info`; `passrelay queue info ID --site HOST --username NAME` writes the two lines into the
entry once.

## Websites

Websites compare by host, so `https://example.com/login` and `example.com` are the same. With
APW, Apple Passwords stores one website per saved login through the interface PassRelay can use:
the first `url:` line is synced, additional `url:` lines stay in pass and are reported as
"extra pass URLs kept in pass" in `passrelay items`.

## New entries created from Apple Passwords

They go to `new_pass_path` (default `apple/{domain}/{username}`), with `username:` and `url:`
lines, and `-2`, `-3`, ... appended if that path already exists.
