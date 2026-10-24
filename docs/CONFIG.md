# Configuration

`~/Library/Application Support/PassRelay/config.json` (override with `--config` or
`PASSRELAY_CONFIG`). It holds no secrets. Change it with `passrelay config set KEY VALUE` or
by editing the file; the running daemon reloads it within one poll interval. An invalid edit is
rejected and the previous configuration stays in effect.

| Key | Default | Meaning |
| --- | --- | --- |
| `pass_binary` | `pass` | The pass executable. |
| `pass_store` | `$PASSWORD_STORE_DIR` or `~/.password-store` | Store root. |
| `gpg_interactive` | `false` | Let the daemon show pinentry. When off, a locked key is reported as `auth.gpg`. |
| `apple_backend` | `apw` | `apw` or `bridge`. |
| `apw_socket` | `~/.apw/apw.sock` | APW daemon socket. |
| `apw_binary` | `apw` | Used by `doctor`. |
| `apw_save_url_prefix` | `""` | Prefix for the website when saving through APW (bare host, as `apw pw save` uses). |
| `bridge_command` | `[]` | argv array for a bridge ([BRIDGE.md](BRIDGE.md)). |
| `state_dir` | `~/Library/Application Support/PassRelay` | State, history, status, and log. |
| `key_store` | `keychain` | `keychain`, or `file` (tests/non-macOS only). |
| `pass_include` / `pass_exclude` | `["*"]` / `[]` | Globs over pass paths (no `.gpg`). Entries outside are never read or changed. |
| `apple_include` / `apple_exclude` | `["*"]` / `[]` | Globs over website hosts. |
| `include_shared` | `false` | Sync logins from shared groups (only for backends that report groups). |
| `watch_domains` | `[]` | Extra websites to look up in Apple Passwords. |
| `new_items` | `auto` | `auto` links and creates new items; `review` queues them for confirmation. |
| `new_pass_path` | `apple/{domain}/{username}` | Path template for logins coming from Apple. |
| `infer_from_path` | `true` | Read `HOST/USERNAME` from the path when metadata lines are missing. |
| `deletion_policy` | `ask` | `ask`, `propagate`, or `keep` (see ARCHITECTURE.md). |
| `bulk_threshold` | `10` | Deletions and overwrites per cycle above which a plan needs approval. |
| `history_retention_days` | `30` | How long encrypted change history is kept. |
| `pass_poll_seconds` | `5` | How often the store is checked for changes (stat only). |
| `apple_poll_seconds` | `20` | How often Apple Passwords is polled. |
| `apple_budget` | `400` | Website lookups per regular cycle with non-enumerating backends. |
| `apple_cycle_seconds` | `8` | Time limit for the rotating Apple lookups and password reads in one regular cycle (`sync` allows 4×). Items with pass changes are always read. With APW a password read takes about 1–5 s. |
| `apple_confirm_seconds` | `120` | How long to wait after an Apple write for the user to confirm macOS's "Save password?" prompt. |
| `notifications` | `true` | macOS notifications for conflicts, approvals, and authentication. |
