"""Configuration file (JSON). Contains no secrets; see docs/CONFIG.md."""
from dataclasses import dataclass, field, fields, asdict
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import tempfile

from .errors import ConfigError

APP_DIR = Path('~/Library/Application Support/PassRelay').expanduser()


def default_config_path():
    return Path(os.environ.get('PASSRELAY_CONFIG') or APP_DIR / 'config.json').expanduser()


@dataclass
class Config:
    pass_binary: str = 'pass'
    pass_store: str = os.environ.get('PASSWORD_STORE_DIR', '~/.password-store')
    gpg_interactive: bool = False
    apple_backend: str = 'apw'                 # apw | bridge | memory (tests)
    apw_socket: str = '~/.apw/apw.sock'
    apw_binary: str = 'apw'
    apw_save_url_prefix: str = ''
    bridge_command: list = field(default_factory=list)
    state_dir: str = str(APP_DIR)
    key_store: str = 'keychain'                # keychain | file
    # Scope. Globs match pass paths (without .gpg) and Apple website hosts.
    pass_include: list = field(default_factory=lambda: ['*'])
    pass_exclude: list = field(default_factory=list)
    apple_include: list = field(default_factory=lambda: ['*'])
    apple_exclude: list = field(default_factory=list)
    include_shared: bool = False
    watch_domains: list = field(default_factory=list)
    new_items: str = 'auto'                    # auto | review
    new_pass_path: str = 'apple/{domain}/{username}'
    infer_from_path: bool = True
    deletion_policy: str = 'ask'               # ask | propagate | keep
    bulk_threshold: int = 10
    history_retention_days: int = 30
    pass_poll_seconds: float = 5
    apple_poll_seconds: float = 20
    apple_budget: int = 400
    apple_cycle_seconds: float = 8
    apple_confirm_seconds: float = 120
    notifications: bool = True

    def validate(self):
        if self.apple_backend not in ('apw', 'bridge', 'memory'):
            raise ConfigError('apple_backend must be apw or bridge')
        if self.apple_backend == 'bridge' and (not isinstance(self.bridge_command, list)
                                               or not self.bridge_command):
            raise ConfigError('bridge_command must be a non-empty argv array')
        if self.key_store not in ('keychain', 'file'):
            raise ConfigError('key_store must be keychain or file')
        if self.new_items not in ('auto', 'review'):
            raise ConfigError('new_items must be auto or review')
        if self.deletion_policy not in ('ask', 'propagate', 'keep'):
            raise ConfigError('deletion_policy must be ask, propagate, or keep')
        for name in ('pass_include', 'pass_exclude', 'apple_include', 'apple_exclude', 'watch_domains'):
            value = getattr(self, name)
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ConfigError(f'{name} must be a list of strings')
        if '{domain}' not in self.new_pass_path or '{username}' not in self.new_pass_path:
            raise ConfigError('new_pass_path must contain {domain} and {username}')
        if self.pass_poll_seconds < 1 or self.apple_poll_seconds < 5 or self.apple_cycle_seconds <= 0:
            raise ConfigError('poll intervals too small')
        if self.bulk_threshold < 1 or self.apple_budget < 1 or self.history_retention_days < 0:
            raise ConfigError('invalid numeric setting')
        return self

    def pass_in_scope(self, path):
        return (any(fnmatchcase(path, g) for g in self.pass_include)
                and not any(fnmatchcase(path, g) for g in self.pass_exclude))

    def apple_in_scope(self, domain, group=None):
        if group and not self.include_shared:
            return False
        return (any(fnmatchcase(domain, g) for g in self.apple_include)
                and not any(fnmatchcase(domain, g) for g in self.apple_exclude))

    def to_dict(self):
        return asdict(self)


def load(path=None):
    path = Path(path or default_config_path()).expanduser()
    if not path.exists():
        raise ConfigError('no configuration; run `passrelay setup`')
    try:
        raw = json.loads(path.read_text())
    except ValueError:
        raise ConfigError('configuration is not valid JSON') from None
    if not isinstance(raw, dict):
        raise ConfigError('configuration must be a JSON object')
    known = {f.name for f in fields(Config)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError('unknown configuration keys: ' + ', '.join(unknown))
    config = Config(**raw).validate()
    config.path = path
    return config


def save(config, path=None):
    path = Path(path or getattr(config, 'path', None) or default_config_path()).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.config-')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(config.to_dict(), f, indent=2)
            f.write('\n')
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    config.path = path
    return path
