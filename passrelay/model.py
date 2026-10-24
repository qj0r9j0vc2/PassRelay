"""Shared data model for login items on either side."""
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
from urllib.parse import urlsplit

# Fields that take part in the three-way merge. Order matters for reports.
FIELDS = ('password', 'username', 'urls', 'notes')


@dataclass(frozen=True)
class Login:
    password: str
    username: str | None = None
    urls: tuple = ()
    notes: str | None = None
    title: str | None = None
    # Fields present on this side that the other side cannot represent; reported, never synced.
    unsupported: tuple = ()

    @property
    def domain(self):
        return normalize_domain(self.urls[0]) if self.urls else None

    def get(self, name):
        return getattr(self, name)

    def with_fields(self, **kw):
        return replace(self, **kw)


@dataclass(frozen=True)
class AppleAccount:
    """An Apple Passwords account as returned by a listing (no password)."""
    domain: str
    username: str
    sites: tuple = ()
    title: str | None = None
    record_id: str | None = None
    modified: str | None = None
    group: str | None = None

    @property
    def key(self):
        return identity_key(self.domain, self.username)


def identity_key(domain, username):
    return json.dumps([domain, username], separators=(',', ':'))


def normalize_domain(value):
    """Reduce a URL or bare host to a lowercase host without scheme, port, path, or trailing dot."""
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if '://' not in value:
        value = 'https://' + value
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip('.').lower()
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    if not host or any(c.isspace() for c in host):
        return None
    return host


def looks_like_domain(value):
    host = normalize_domain(value)
    return bool(host) and '.' in host and host == value.lower().rstrip('.')


@dataclass
class Fingerprinter:
    """Keyed fingerprints so state never stores plaintext values."""
    key: bytes

    def __call__(self, value):
        if value is None:
            return None
        if isinstance(value, tuple):
            value = list(value)
        raw = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
        return hmac.new(self.key, raw, hashlib.sha256).hexdigest()

    def login(self, login):
        return {f: self(login.get(f)) for f in FIELDS}
