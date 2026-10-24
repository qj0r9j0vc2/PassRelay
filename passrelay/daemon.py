"""Background loop run by the LaunchAgent.

Pass changes are noticed by a cheap stat scan every ``pass_poll_seconds`` (ciphertext is only
re-hashed for files whose mtime/size/inode changed, nothing is decrypted). Apple Passwords has no
change notifications, so it is polled every ``apple_poll_seconds``. Sleep is detected by the wall
clock jumping ahead of the monotonic clock, which triggers an immediate full cycle after wake.
"""
import hashlib
import os
import signal
import sys
import threading
import time

from . import app, status as status_mod
from .config import load
from .errors import AuthRequired, Busy, ConfigError, PassRelayError
from .notify import Notifier

MAX_BACKOFF = 300


def log(message):
    # Operational messages only. Never pass item names, sites, or values here.
    print(time.strftime('%Y-%m-%dT%H:%M:%S'), message, file=sys.stderr, flush=True)


class Daemon:
    def __init__(self, config_path=None):
        self.cfg = load(config_path)
        self.config_mtime = self._config_mtime()
        self.wake = threading.Event()
        self.stop = False
        self.pass_store = app.make_pass(self.cfg)
        self.apple = app.make_apple(self.cfg)
        self.notifier = Notifier(self.cfg.notifications)
        self.backoff = 0
        self.last_pass_digest = None

    def _config_mtime(self):
        try:
            return self.cfg.path.stat().st_mtime_ns
        except OSError:
            return None

    def _reload_config(self):
        """Apply `passrelay config set` without a restart. A broken edit keeps the old config."""
        mtime = self._config_mtime()
        if mtime == self.config_mtime:
            return
        self.config_mtime = mtime
        try:
            cfg = load(self.cfg.path)
        except ConfigError:
            log('configuration change rejected: invalid; keeping the previous configuration')
            return
        backend_keys = ('pass_store', 'pass_binary', 'gpg_interactive', 'apple_backend', 'apw_socket',
                        'apw_save_url_prefix', 'bridge_command')
        if any(getattr(cfg, k) != getattr(self.cfg, k) for k in backend_keys):
            self.pass_store = app.make_pass(cfg)
            self.apple = app.make_apple(cfg)
        self.notifier.enabled = cfg.notifications
        self.cfg = cfg
        log('configuration reloaded')

    def _signals(self):
        def stop(*_):
            self.stop = True
            self.wake.set()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGUSR1, lambda *_: self.wake.set())

    def _pass_digest(self):
        try:
            files = self.pass_store.scan()
        except PassRelayError:
            return None
        h = hashlib.sha256()
        for path in sorted(files):
            h.update(path.encode() + b'\0' + files[path].token.encode() + b'\n')
        return h.hexdigest()

    def cycle(self, quick=False):
        store, fp = app.open_store(self.cfg)
        try:
            with store.lock(timeout=5):
                state = store.load()
                engine = app.Engine(self.cfg, self.pass_store, self.apple, store, state, fp)
                engine.read_budget = self.cfg.apple_cycle_seconds
                previous = store.read_status() or {}
                store.write_status({**previous, 'syncing': True, 'updated': time.time()})
                report = engine.cycle(apply=True, quick=quick)
                store.save(engine.state)
                status = status_mod.publish(store, engine, report)
        except Busy:
            log('state is locked by another PassRelay command; retrying')
            return 'busy'
        self.notifier.update(status)
        if report['auth']:
            log('authentication required: ' + ', '.join(sorted(report['auth'])))
            return 'auth'
        if report['errors']:
            log(f'cycle finished with {len(report["errors"])} item error(s)')
        return 'ok'

    def run(self):
        self._signals()
        store, _ = app.open_store(self.cfg)
        pid_file = store.dir / 'daemon.pid'
        pid_file.write_text(str(os.getpid()))
        log('daemon started')
        last_apple = 0.0
        last_wall, last_mono = time.time(), time.monotonic()
        try:
            while not self.stop:
                woke_signal = self.wake.is_set()
                self.wake.clear()
                self._reload_config()
                wall, mono = time.time(), time.monotonic()
                slept = (wall - last_wall) - (mono - last_mono) > 30
                last_wall, last_mono = wall, mono
                if store.control().get('paused'):
                    self.wake.wait(self.cfg.pass_poll_seconds * 6)
                    continue
                digest = self._pass_digest()
                pass_changed = digest != self.last_pass_digest
                apple_due = mono - last_apple >= self.cfg.apple_poll_seconds * (2 ** self.backoff)
                if slept:
                    log('wake from sleep detected')
                if woke_signal or slept or pass_changed or apple_due:
                    if os.environ.get('PASSRELAY_DEBUG'):
                        log(f'cycle: signal={woke_signal} slept={slept} pass={pass_changed} apple={apple_due}')
                    try:
                        # Only pass changed: check just those websites now; full polls stay on schedule.
                        quick = pass_changed and not (woke_signal or slept or apple_due)
                        result = self.cycle(quick=quick)
                    except AuthRequired as e:
                        status_mod.publish_auth_failure(store, e.backend, e.hint)
                        self.notifier.update(store.read_status() or {})
                        result = 'auth'
                    except (ConfigError, PassRelayError, OSError) as e:
                        log(f'cycle failed: {type(e).__name__}')
                        result = 'error'
                    if result == 'ok':
                        self.backoff = 0
                        self.last_pass_digest = digest
                        if not quick:
                            last_apple = time.monotonic()
                    elif result in ('auth', 'error'):
                        # Do not hammer a locked backend; keep checking the pass side cheaply.
                        self.backoff = min(self.backoff + 1, 4)
                        self.last_pass_digest = digest
                        last_apple = time.monotonic()
                self.wake.wait(self.cfg.pass_poll_seconds)
        finally:
            pid_file.unlink(missing_ok=True)
            log('daemon stopped')
        return 0


def notify_daemon(store):
    pid = status_mod.daemon_pid(store)
    if pid:
        os.kill(pid, signal.SIGUSR1)
    return pid
