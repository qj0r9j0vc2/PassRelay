"""Environment diagnostics. Reports problems; never prints secrets or item names."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

from . import app, service
from .errors import AuthRequired, PassRelayError


def _check(name, fn):
    try:
        status, detail = fn()
    except AuthRequired as e:
        status, detail = 'warn', e.hint
    except PassRelayError as e:
        status, detail = 'fail', str(e)
    except (OSError, subprocess.SubprocessError) as e:
        status, detail = 'fail', type(e).__name__
    return {'name': name, 'status': status, 'detail': detail}


def run(cfg):
    checks = []
    add = lambda name, fn: checks.append(_check(name, fn))  # noqa: E731

    add('python', lambda: ('ok' if sys.version_info >= (3, 10) else 'fail',
                           f'{sys.version_info.major}.{sys.version_info.minor}'))
    add('macOS', lambda: ('ok' if sys.platform == 'darwin' else 'fail', sys.platform))

    def binary(name, path):
        found = shutil.which(path)
        return ('ok', found) if found else ('fail', f'{name} not found; install it or set the path in config')
    add('pass binary', lambda: binary('pass', cfg.pass_binary))
    add('gpg binary', lambda: binary('gpg', 'gpg'))
    add('git (optional)', lambda: ('ok', shutil.which('git')) if shutil.which('git')
        else ('warn', 'git not found; `pass git` integration unavailable'))

    def store():
        root = Path(cfg.pass_store).expanduser()
        if not root.is_dir():
            return 'fail', 'pass store directory missing; run `pass init`'
        if not (root / '.gpg-id').exists():
            return 'fail', '.gpg-id missing; run `pass init GPG-ID`'
        n = sum(1 for _ in app.make_pass(cfg).scan())
        return 'ok', f'{n} entries'
    add('pass store', store)

    def gpg_unlocked():
        ps = app.make_pass(cfg, interactive=False)
        files = ps.scan()
        if not files:
            return 'ok', 'no entries to test'
        ps.read(sorted(files)[0])
        return 'ok', 'gpg-agent can decrypt without prompting'
    add('gpg agent', gpg_unlocked)

    if cfg.apple_backend == 'apw':
        add('apw binary', lambda: binary('apw', cfg.apw_binary))

        def apw():
            backend = app.make_apple(cfg)
            backend.check()
            return 'ok', 'APW running and authenticated'
        add('apple passwords (APW)', apw)
    elif cfg.apple_backend == 'bridge':
        def bridge():
            backend = app.make_apple(cfg)
            backend.check()
            caps = [k for k, v in backend.capabilities.as_dict().items() if v]
            return 'ok', 'capabilities: ' + ', '.join(caps)
        add('apple passwords (bridge)', bridge)

    def keychain():
        app.open_store(cfg)
        return 'ok', f'key readable from {cfg.key_store}'
    add('state key', keychain)

    def state():
        store, _ = app.open_store(cfg)
        s = store.load()
        mode = os.stat(store.dir).st_mode & 0o777
        if mode & 0o077:
            return 'fail', f'state directory permissions {oct(mode)}'
        return 'ok', f'{len(s["links"])} links, setup {"done" if s["setup_done"] else "pending"}'
    add('state', state)

    def launch_agent():
        st = service.status()
        if not st['installed']:
            return 'warn', 'not installed; run `passrelay service install` to sync in the background'
        return ('ok', 'loaded') if st['loaded'] else ('warn', 'installed but not loaded')
    add('LaunchAgent', launch_agent)
    return checks
