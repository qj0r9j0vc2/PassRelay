"""Master key storage: macOS Keychain by default, a 0600 file only for tests and non-macOS hosts."""
import os
from pathlib import Path
import subprocess

from .errors import AuthRequired, ConfigError

SERVICE = 'PassRelay'


class KeychainKeyStore:
    def __init__(self, account='state-key', security='/usr/bin/security'):
        self.account = account
        self.security = security

    def _find(self):
        p = subprocess.run([self.security, 'find-generic-password', '-s', SERVICE, '-a', self.account,
                            '-w'], capture_output=True, timeout=30)
        if p.returncode == 44:  # errSecItemNotFound
            return None
        if p.returncode:
            raise AuthRequired('keychain', 'unlock the login keychain, then retry')
        value = p.stdout.decode().strip()
        try:
            key = bytes.fromhex(value)
        except ValueError:
            raise ConfigError('keychain item is not a PassRelay key') from None
        if len(key) != 32:
            raise ConfigError('keychain item is not a PassRelay key')
        return key

    def load(self, create=False):
        key = self._find()
        if key is None and create:
            key = os.urandom(32)
            # `security -i` reads the command from stdin, so the key never appears in argv.
            command = f'add-generic-password -U -s {SERVICE} -a {self.account} -w {key.hex()}\n'
            p = subprocess.run([self.security, '-i'], input=command.encode(), capture_output=True,
                               timeout=30)
            if p.returncode or self._find() != key:
                raise AuthRequired('keychain', 'allow PassRelay to store its key in the login keychain')
        if key is None:
            raise ConfigError('PassRelay key not found in Keychain; run `passrelay setup`')
        return key

    def delete(self):
        subprocess.run([self.security, 'delete-generic-password', '-s', SERVICE, '-a', self.account],
                       capture_output=True, timeout=30)


class FileKeyStore:
    def __init__(self, path):
        self.path = Path(path).expanduser()

    def load(self, create=False):
        if not self.path.exists():
            if not create:
                raise ConfigError('PassRelay key file missing; run `passrelay setup`')
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(os.urandom(32))
        if self.path.is_symlink() or self.path.stat().st_mode & 0o077:
            raise ConfigError('unsafe key file permissions')
        key = self.path.read_bytes()
        if len(key) != 32:
            raise ConfigError('invalid key file')
        return key

    def delete(self):
        self.path.unlink(missing_ok=True)


def keystore_for(config):
    if config.key_store == 'file':
        return FileKeyStore(Path(config.state_dir) / 'master.key')
    return KeychainKeyStore()
