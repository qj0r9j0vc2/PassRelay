"""PassRelay benchmarks (results are published in docs/BENCHMARKS.md).

Two modes:

  engine  In-memory pass store and Apple backend. Measures the engine itself: initial discovery
          and sync, one change in each direction, an idle cycle, CPU time, and peak memory.
          ``--apple-latency-ms`` adds a fixed delay per Apple request to model APW round trips.

  real    Real `pass` + `gpg` with a throwaway key in a temporary GNUPGHOME, and the fake APW
          socket server from the test suite. Measures what GPG and process spawning really cost.

    python3 bench/bench.py engine --sizes 100 1000 10000
    python3 bench/bench.py real --sizes 100 1000
"""
import argparse
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from passrelay.apple.base import Capabilities  # noqa: E402
from passrelay.apple.memory import MemoryApple  # noqa: E402
from tests.fakes import FakePass, make_engine  # noqa: E402


class SlowApple(MemoryApple):
    def __init__(self, caps, latency):
        super().__init__(caps)
        self.latency = latency

    def _guard(self, domain=None):
        if self.latency:
            time.sleep(self.latency)
        super()._guard(domain)


def cpu():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def peak_mb():
    # ru_maxrss is bytes on macOS, kilobytes on Linux.
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / (1024 * 1024 if sys.platform == 'darwin' else 1024)


def timed(fn):
    t, c = time.perf_counter(), cpu()
    result = fn()
    return result, time.perf_counter() - t, cpu() - c


def engine_bench(n, latency_ms, budget):
    caps = Capabilities(write=True)  # APW-equivalent: no enumeration, no change stamps
    apple = SlowApple(caps, latency_ms / 1000)
    p = FakePass()
    half = n // 2
    for i in range(half):
        p.put(f'web/site{i}.com/user', f'pw{i}\nusername: user\nurl: https://site{i}.com\n')
    for i in range(half, n):
        apple.add(f'site{i}.com', 'user', f'pw{i}')
    e = make_engine(apple, p, apple_budget=budget, bulk_threshold=10 ** 9)
    e.state['watch_domains'] = [f'site{i}.com' for i in range(half, n)]
    rounds = 0

    def initial():
        nonlocal rounds
        while True:
            rounds += 1
            e.cycle()
            if len(e.state['links']) == n and not e.report['apple_progress'].get('domains_pending'):
                return

    _, t_init, c_init = timed(initial)
    assert len(e.state['links']) == n, len(e.state['links'])
    _, t_idle, c_idle = timed(e.cycle)
    p.put('web/site0.com/user', 'changed\nusername: user\nurl: https://site0.com\n')
    report, t_p2a, c_p2a = timed(lambda: e.cycle(quick=True))  # what the daemon runs on a pass change
    assert apple.records[apple.find('site0.com', 'user')]['password'] == 'changed'
    # Apple-side change: worst case is waiting for the domain rotation to reach it.
    apple.set_password(f'site{n - 1}.com', 'user', 'changed-in-apple')
    cycles, t_a2p = 0, 0.0
    while p.password(f'apple/site{n - 1}.com/user') != 'changed-in-apple':
        _, t, _ = timed(e.cycle)
        cycles += 1
        t_a2p += t
    return {'items': n, 'initial_s': round(t_init, 2), 'initial_cycles': rounds, 'initial_cpu_s': round(c_init, 2),
            'idle_cycle_s': round(t_idle, 3), 'idle_cycle_cpu_s': round(c_idle, 3),
            'pass_to_apple_cycle_s': round(t_p2a, 3), 'apple_to_pass_worst_s': round(t_a2p, 2),
            'apple_to_pass_cycles': cycles, 'peak_rss_mb': round(peak_mb(), 1)}


def real_bench(n, tmp):
    from tests.test_integration import FakeApw
    from passrelay import cli
    gnupg = Path(tmp, 'g')
    gnupg.mkdir(mode=0o700)
    store = Path(tmp, 'store')
    env = dict(os.environ, GNUPGHOME=str(gnupg), PASSWORD_STORE_DIR=str(store))
    os.environ.update(GNUPGHOME=str(gnupg), PASSWORD_STORE_DIR=str(store))
    subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-gen-key',
                    'Bench <bench@example.invalid>', 'default', 'default', 'never'], check=True,
                   capture_output=True, env=env)
    subprocess.run(['pass', 'init', 'bench@example.invalid'], check=True, capture_output=True, env=env)
    # Encrypt directly with gpg: same file format as `pass insert`, much faster to build.
    t0 = time.perf_counter()
    for i in range(n):
        d = store / 'web' / f'site{i}.com'
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run(['gpg', '--batch', '--yes', '-e', '-r', 'bench@example.invalid', '-o', str(d / 'user.gpg')],
                       input=f'pw{i}\nusername: user\nurl: https://site{i}.com\n'.encode(), check=True, env=env,
                       capture_output=True)
    build = time.perf_counter() - t0
    apw = FakeApw(os.path.join(tmp, 's'))
    for i in range(0, n, 2):
        apw.records[(f'site{i}.com', 'user')] = f'pw{i}'
    config = os.path.join(tmp, 'config.json')
    state = os.path.join(tmp, 'state')

    def run(*argv):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(['--config', config, '--json', *argv])
        return code, json.loads(buf.getvalue())

    Path(config).write_text(json.dumps({'pass_store': str(store), 'key_store': 'file', 'state_dir': state,
                                        'apw_socket': apw.path, 'apple_budget': max(400, n),
                                        'bulk_threshold': 10 ** 9}))
    # First plan: decrypts every entry once (the dominant one-time cost); later runs reuse fingerprints.
    _, t_decrypt, c_decrypt = timed(lambda: run('setup'))
    (_, out), t_plan, c_plan = timed(lambda: run('setup'))
    (_, out), t_apply, c_apply = timed(lambda: run('setup', '--apply'))
    assert out['report']['counts']['linked'] == n, out['report']['counts']
    (_, out), t_idle, c_idle = timed(lambda: run('sync'))
    subprocess.run(['pass', 'insert', '-m', '-f', 'web/site1.com/user'], check=True, capture_output=True, env=env,
                   input=b'changed\nusername: user\nurl: https://site1.com\n')
    (_, out), t_one, c_one = timed(lambda: run('sync'))
    assert apw.records[('site1.com', 'user')] == 'changed'
    apw.close()
    subprocess.run(['gpgconf', '--kill', 'gpg-agent'], env=env, capture_output=True)
    return {'items': n, 'build_store_s': round(build, 1), 'first_scan_decrypt_s': round(t_decrypt, 1),
            'first_scan_cpu_s': round(c_decrypt, 2), 'initial_plan_s': round(t_plan, 2),
            'initial_apply_s': round(t_apply, 2), 'initial_cpu_s': round(c_plan + c_apply, 2),
            'idle_cycle_s': round(t_idle, 3), 'idle_cycle_cpu_s': round(c_idle, 3),
            'single_change_cycle_s': round(t_one, 3), 'peak_rss_mb': round(peak_mb(), 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['engine', 'real'])
    ap.add_argument('--sizes', type=int, nargs='+', default=[100, 1000, 10000])
    ap.add_argument('--apple-latency-ms', type=float, default=0)
    ap.add_argument('--apple-budget', type=int, default=400)
    args = ap.parse_args()
    meta = {'mode': args.mode, 'python': platform.python_version(), 'machine': platform.machine(),
            'macos': platform.mac_ver()[0], 'apple_latency_ms': args.apple_latency_ms,
            'apple_budget': args.apple_budget}
    print(json.dumps(meta), flush=True)
    for n in args.sizes:
        if args.mode == 'engine':
            row = engine_bench(n, args.apple_latency_ms, args.apple_budget)
        else:
            if not (shutil.which('pass') and shutil.which('gpg')):
                sys.exit('pass and gpg are required for real mode')
            tmp = tempfile.mkdtemp(prefix='prb-')
            try:
                row = real_bench(n, tmp)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        print(json.dumps(row), flush=True)


if __name__ == '__main__':
    main()
