"""Encrypted sync state, encrypted change history, and the non-secret status/control files."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

from . import crypto
from .errors import Busy, ConfigError

STATE_VERSION = 1


def new_state():
    return {
        'version': STATE_VERSION,
        'setup_done': False,
        'links': {},            # link id -> link (see engine.py)
        'tombstones': {},       # identity -> {time, reason}; prevents re-creating deleted items
        'conflicts': {},        # conflict id -> conflict
        'deletions': {},        # deletion id -> pending deletion awaiting approval
        'queue': {},            # queue id -> item needing link confirmation or missing info
        'plans': {},            # plan id -> bulk change plan awaiting approval
        'approved': [],         # action keys approved through plans
        'excluded': {'pass': [], 'apple': []},
        'pass_meta': {},        # pass path -> {token, domain, username, unsupported}
        'apple_seen': {},       # identity -> {modified, title, group}
        'domain_cursor': 0,
        'history': [],          # [{id, time, action, link, side}] — record bodies live in history/
        'last_success': None,
        'last_cycle': None,
    }


def _atomic_write(path, data, mode=0o600):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def secure_dir(directory):
    directory = Path(directory).expanduser()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid():
        raise ConfigError('unsafe state directory')
    os.chmod(directory, 0o700)
    return directory


class StateStore:
    def __init__(self, directory, key):
        self.dir = secure_dir(directory)
        self.key = key
        self.history_dir = self.dir / 'history'
        self.state_path = self.dir / 'state.enc'
        self.status_path = self.dir / 'status.json'
        self.control_path = self.dir / 'control.json'

    @contextlib.contextmanager
    def lock(self, timeout=30.0):
        fd = os.open(self.dir / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Busy('another PassRelay process is synchronizing') from None
                    time.sleep(0.1)
            yield
        finally:
            os.close(fd)

    def load(self):
        if self.state_path.is_symlink():
            raise ConfigError('unsafe state file')
        if not self.state_path.exists():
            return new_state()
        try:
            state = json.loads(crypto.open_(self.key, self.state_path.read_bytes(), b'state'))
        except ValueError:
            raise ConfigError('state cannot be decrypted with the stored key') from None
        if not isinstance(state, dict) or state.get('version') != STATE_VERSION:
            raise ConfigError('unsupported state version')
        base = new_state()
        base.update(state)
        return base

    def save(self, state):
        data = json.dumps(state, separators=(',', ':')).encode()
        _atomic_write(self.state_path, crypto.seal(self.key, data, b'state'))

    # history ---------------------------------------------------------------
    def history_add(self, state, record):
        """Store an encrypted pre-change snapshot. Called before every write."""
        self.history_dir.mkdir(mode=0o700, exist_ok=True)
        hid = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
        record = dict(record, id=hid, time=time.time())
        blob = crypto.seal(self.key, json.dumps(record).encode(), b'history:' + hid.encode())
        _atomic_write(self.history_dir / (hid + '.enc'), blob)
        state['history'].append({k: record.get(k) for k in ('id', 'time', 'action', 'link', 'side')})
        return hid

    def history_get(self, hid):
        if not isinstance(hid, str) or '/' in hid or hid.startswith('.'):
            raise ConfigError('invalid history id')
        path = self.history_dir / (hid + '.enc')
        if not path.exists():
            raise ConfigError('unknown history id')
        return json.loads(crypto.open_(self.key, path.read_bytes(), b'history:' + hid.encode()))

    def history_prune(self, state, retention_days, now=None):
        cutoff = (now or time.time()) - retention_days * 86400
        keep = []
        for entry in state['history']:
            if entry['time'] < cutoff:
                (self.history_dir / (entry['id'] + '.enc')).unlink(missing_ok=True)
            else:
                keep.append(entry)
        state['history'] = keep

    # plaintext, non-secret files ------------------------------------------------
    def write_status(self, status):
        _atomic_write(self.status_path, json.dumps(status, indent=2).encode())

    def read_status(self):
        try:
            return json.loads(self.status_path.read_text())
        except (OSError, ValueError):
            return None

    def control(self):
        try:
            value = json.loads(self.control_path.read_text())
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def set_control(self, **changes):
        value = self.control()
        value.update(changes)
        _atomic_write(self.control_path, json.dumps(value).encode())
        return value
