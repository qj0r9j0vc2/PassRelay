# Benchmarks

Measured on an Apple Silicon Mac (arm64), macOS 26.6.2, Python 3.14.6, pass 1.7.4, GnuPG with
an ed25519/cv25519 key and no passphrase. Reproduce with `bench/bench.py` (see its docstring).
Half of the items start in pass and half in Apple Passwords, so the initial sync both links and
creates items.

The tables use a simulated Apple side: no delay (engine cost alone), and a 20 ms delay per
request. Measurements against the real APW (v1.1.1, macOS 26.6.2) taken afterwards show the
model is too optimistic for password reads:

| Real APW operation | Measured |
| --- | --- |
| List the logins of a website (no passwords) | 2–5 ms |
| Read one password | 1.0–5.0 s (first read slowest) |
| Save | returns at once, but only takes effect after the user clicks **Save** in the macOS prompt |

PassRelay therefore bounds password reads per cycle (`apple_cycle_seconds`, 8 s, about 2–8
reads), reads changed items first, and rotates through the rest by least-recent read. It waits up to
`apple_confirm_seconds` (120 s) for a save to be confirmed. With real APW, Apple-to-pass
latency for an item nobody changed in pass is roughly `items / reads per cycle × cycle period`:
minutes for tens of items, around an hour for about 1,000.

## 1. Real pass + GPG, simulated APW socket (no delay)

`bench/bench.py real`. Each step runs the actual CLI (`passrelay setup`, `setup --apply`,
`sync`) in-process against a throwaway store.

| Items | First scan (decrypt all) | Initial apply | Idle `sync` | One change, `sync` | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 6.8 s | 6.5 s | 0.03 s | 0.22 s | 31 MB |
| 1,000 | 65 s | 66 s | 0.40 s | 0.53 s | 49 MB |
| 10,000 | 663 s | 855 s | 16.2 s* | 15.5 s* | 174 MB |

- The one-time cost is GPG: each `pass show` takes about 66 ms (one gpg process per entry),
  and each `pass insert` about 130 ms. The first scan of 10,000 entries takes about 11 minutes,
  and the initial apply (5,000 new pass entries plus 5,000 Apple creations) about 14 minutes. The
  daemon keeps fingerprints, so entries are never decrypted again unless their file changes.
- \* This harness set `apple_budget` to the item count, so every `sync` re-reads all 10,000
  websites, and the simulated APW server runs in the same process, so its CPU is included. That
  is a worst case, not the daemon's behaviour. The daemon defaults to 400 lookups and 8 seconds
  per regular cycle, and runs a quick cycle limited to the changed websites when pass changes
  (tables 2 and 3).

## 2. Engine only, no Apple delay

`bench/bench.py engine`. In-memory pass and Apple backends with APW's capabilities (no
enumeration, no change stamps); default `apple_budget` 400.

| Items | Initial discovery + sync | Idle cycle (CPU) | pass → Apple, one change | Apple → pass, worst case | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 0.05 s (1 cycle) | 0.005 s | 0.009 s | 1 cycle | 32 MB |
| 1,000 | 0.68 s (4 cycles) | 0.056 s | 0.058 s | 3 cycles | 36 MB |
| 10,000 | 24.9 s (26 cycles) | 0.42 s | 0.48 s | 24 cycles | 77 MB |

## 3. Engine with a modelled 20 ms per Apple request

`bench/bench.py engine --apple-latency-ms 20`. pass → Apple uses the daemon's quick cycle.

| Items | Initial discovery + sync | Idle regular cycle | pass → Apple, one change | Apple → pass, worst case |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 8.1 s | 4.5 s | 0.12 s | 4.6 s (1 cycle) |
| 1,000 | 106 s | 15.9 s | 0.13 s | 32 s of cycling (2 cycles) |
| 10,000 | 1,102 s (32 cycles) | 16.4 s | 0.27 s | 521 s of cycling (32 cycles) |

"Worst case" is how long the cycles themselves take until a change on the website checked last
reaches pass. In the daemon, regular cycles start `apple_poll_seconds` (20 s) after the previous
one ends, so with ~16 s cycles the wall-clock worst case is about 36 s per cycle: about 1 minute at
1,000 websites and about 19 minutes at 10,000, under the 20 ms assumption.

## What this means for the 30-second target

- **pass → Apple:** the daemon notices a change within `pass_poll_seconds` (5 s, stat only),
  then runs a quick cycle on just that website. The daemon test (`tests/test_daemon.py`) measured
  about 1 s end to end. The quick cycle stays under 0.3 s up to 10,000 items in table 3, so the
  bound is roughly `pass_poll_seconds` + 1 s at every size.
- **Apple → pass:** Apple Passwords sends no change notifications, and APW cannot list the vault
  or report modification times, so PassRelay polls. A change reaches pass within one
  `apple_poll_seconds` (20 s) plus a cycle, as long as all websites fit in one rotation. At the
  modelled 20 ms per request that is roughly 200 websites per 8-second cycle, so the 30-second
  target holds for small vaults only. Larger vaults need several rotations, and the
  worst case grows linearly. `passrelay status` shows the websites still waiting. This limit comes
  from the APW backend: a bridge with enumeration or change stamps ([BRIDGE.md](BRIDGE.md))
  avoids most of the re-reading.
- **Idle cost:** the pass check is a stat walk (no decryption). The Apple poll is bounded by
  `apple_cycle_seconds`. With 1,000 items, a regular cycle used 0.06 s of CPU without Apple delay
  and 0.14 s with the 20 ms model (most of that cycle is spent waiting). That is under 1 % of one
  core at one cycle per 20–36 s.
