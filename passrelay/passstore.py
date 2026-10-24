"""Access to a standard pass store through the unmodified ``pass`` executable."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import subprocess

from .errors import AuthRequired, BackendError

TIMEOUT = 60
# Markers in gpg/pass stderr meaning the private key is locked and no pinentry may be shown.
_LOCKED = (b'pinentry', b'no secret key', b'operation cancelled', b'inappropriate ioctl',
           b'bad passphrase', b'no passphrase given')


@dataclass(frozen=True)
class FileInfo:
    token: str      # sha256 of the encrypted file; changes on every content change, survives `pass mv`
    mtime_ns: int
    size: int
    ino: int


def validate_path(path):
    if not isinstance(path, str) or not path:
        raise BackendError('invalid pass path')
    parts = path.split('/')
    if (PurePosixPath(path).is_absolute() or any(p in ('', '.', '..') for p in parts)
            or path.startswith('-') or any(c in path for c in '\\\n\r\x00')):
        raise BackendError('unsafe pass path')
    return path


class PassStore:
    def __init__(self, root, binary='pass', interactive=False, gpg_opts=''):
        self.root = Path(root).expanduser().resolve()
        self.binary = binary
        self.interactive = interactive
        self.gpg_opts = gpg_opts
        self._cache = {}

    def _env(self):
        env = dict(os.environ, PASSWORD_STORE_DIR=str(self.root))
        opts = [self.gpg_opts, os.environ.get('PASSWORD_STORE_GPG_OPTS', '')]
        if not self.interactive:
            # A background daemon must never pop up pinentry; report "auth required" instead.
            opts.append('--pinentry-mode error')
        env['PASSWORD_STORE_GPG_OPTS'] = ' '.join(o for o in opts if o).strip()
        # Clipboard/editor helpers are not used by PassRelay.
        env.pop('PASSWORD_STORE_CLIP_TIME', None)
        return env

    def _run(self, argv, data=None):
        try:
            p = subprocess.run([self.binary, *argv], input=data.encode() if data is not None else None,
                               capture_output=True, timeout=TIMEOUT, env=self._env())
        except (OSError, subprocess.TimeoutExpired):
            raise BackendError('pass unavailable or timed out') from None
        if p.returncode:
            # stderr is inspected for classification only; it is never logged or re-raised.
            err = p.stderr.lower()
            if any(m in err for m in _LOCKED):
                raise AuthRequired('gpg', 'unlock your GPG key with `passrelay auth gpg`')
            raise BackendError('pass command failed')
        return p.stdout

    def gpg_file(self, path):
        validate_path(path)
        p = self.root / (path + '.gpg')
        for parent in [p, *p.parents]:
            if parent == self.root:
                break
            if parent.is_symlink():
                raise BackendError('symlinked pass path refused')
        if not p.resolve().is_relative_to(self.root):
            raise BackendError('pass path escapes the store')
        return p

    def scan(self):
        """Return {path: FileInfo} for every entry. Only stats and hashes ciphertext; never decrypts."""
        if not (self.root / '.gpg-id').exists() and not any(self.root.rglob('.gpg-id')):
            raise BackendError('pass store is not initialized')
        result, cache = {}, {}
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith('.')
                                 and not os.path.islink(os.path.join(dirpath, d)))
            for name in filenames:
                if not name.endswith('.gpg') or name.startswith('.'):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except FileNotFoundError:
                    continue
                if not os.path.isfile(full) or os.path.islink(full):
                    continue
                rel = os.path.relpath(full, self.root)[:-4].replace(os.sep, '/')
                stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
                old = self._cache.get(rel)
                if old and (old.mtime_ns, old.size, old.ino) == stamp:
                    info = old
                else:
                    try:
                        with open(full, 'rb') as f:
                            token = hashlib.sha256(f.read()).hexdigest()
                    except FileNotFoundError:
                        continue
                    info = FileInfo(token, *stamp)
                result[rel] = cache[rel] = info
        self._cache = cache
        return result

    def read(self, path):
        """Return the decrypted payload, or None when the entry does not exist."""
        if not self.gpg_file(path).exists():
            return None
        payload = self._run(['show', '--', path]).decode('utf-8', 'strict')
        if not payload or '\x00' in payload:
            raise BackendError('invalid pass payload')
        return payload

    def token(self, path):
        p = self.gpg_file(path)
        try:
            with open(p, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError:
            return None

    def write(self, path, payload):
        self.gpg_file(path)
        self._run(['insert', '--multiline', '--force', '--', path], payload)

    def delete(self, path):
        self.gpg_file(path)
        self._run(['rm', '--force', '--', path])

    def unlock(self, path):
        """Interactive decrypt so gpg-agent caches the passphrase. Output is discarded."""
        self.gpg_file(path)
        env = dict(os.environ, PASSWORD_STORE_DIR=str(self.root))
        p = subprocess.run([self.binary, 'show', '--', path], stdout=subprocess.DEVNULL, env=env)
        return p.returncode == 0

    def free_path(self, wanted):
        """Pick a path that does not exist yet, appending -2, -3, ... when needed."""
        validate_path(wanted)
        candidate, n = wanted, 2
        while self.gpg_file(candidate).exists():
            candidate, n = f'{wanted}-{n}', n + 1
        return candidate
