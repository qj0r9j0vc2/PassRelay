import os
import tempfile
import uuid

from passrelay.config import Config
from passrelay.engine import Engine
from passrelay.model import Fingerprinter
from passrelay.passstore import FileInfo, validate_path
from passrelay.state import StateStore


class FakePass:
    """In-memory pass store. Tokens behave like ciphertext hashes: new on every write, kept on mv."""

    def __init__(self):
        self.entries = {}   # path -> (token, payload)
        self.writes = 0
        self.locked = False
        self.reads = 0

    def put(self, path, payload):
        self.entries[path] = (uuid.uuid4().hex, payload)

    def mv(self, old, new):
        self.entries[new] = self.entries.pop(old)

    def cp(self, old, new):
        self.entries[new] = self.entries[old]

    def scan(self):
        return {p: FileInfo(t, 0, 0, 0) for p, (t, _) in self.entries.items()}

    def _check(self):
        if self.locked:
            from passrelay.errors import AuthRequired
            raise AuthRequired('gpg', 'locked')

    def read(self, path):
        self._check()
        self.reads += 1
        e = self.entries.get(validate_path(path))
        return e[1] if e else None

    def token(self, path):
        e = self.entries.get(path)
        return e[0] if e else None

    def write(self, path, payload):
        self._check()
        self.writes += 1
        self.put(validate_path(path), payload)

    def delete(self, path):
        self._check()
        self.entries.pop(path, None)

    def free_path(self, wanted):
        candidate, n = wanted, 2
        while candidate in self.entries:
            candidate, n = f'{wanted}-{n}', n + 1
        return candidate

    def password(self, path):
        return self.entries[path][1].split('\n', 1)[0]


def make_engine(apple, fake_pass=None, **cfg):
    d = tempfile.mkdtemp()
    os.chmod(d, 0o700)
    config = Config(state_dir=d, key_store='file', apple_backend='memory', **cfg)
    store = StateStore(d, os.urandom(32))
    state = store.load()
    state['setup_done'] = True
    return Engine(config, fake_pass or FakePass(), apple, store, state, Fingerprinter(os.urandom(32)))
