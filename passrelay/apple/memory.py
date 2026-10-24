"""In-memory Apple backend for tests and benchmarks. Capabilities are configurable."""
import itertools

from ..errors import AuthRequired, BackendError
from ..model import AppleAccount, Login
from .base import AppleBackend, Capabilities


class MemoryApple(AppleBackend):
    name = 'memory'

    def __init__(self, capabilities=None):
        self.capabilities = capabilities or Capabilities(write=True, change_tokens=True)
        self.records = {}       # id -> dict
        self.authenticated = True
        self.failing_domains = set()
        self.calls = 0
        self._ids = itertools.count(1)
        self._clock = itertools.count(1)

    # helpers for tests -------------------------------------------------
    def add(self, domain, username, password, notes=None, urls=None, group=None):
        rid = f'r{next(self._ids)}'
        self.records[rid] = {'domain': domain, 'username': username, 'password': password,
                             'notes': notes, 'urls': tuple(urls or (domain,)), 'group': group,
                             'modified': str(next(self._clock))}
        return rid

    def find(self, domain, username):
        found = [rid for rid, r in self.records.items()
                 if r['domain'] == domain and r['username'] == username]
        if len(found) > 1:
            raise BackendError('duplicate records')
        return found[0] if found else None

    def set_password(self, domain, username, password):
        r = self.records[self.find(domain, username)]
        r['password'] = password
        r['modified'] = str(next(self._clock))

    # backend API -------------------------------------------------------
    def _guard(self, domain=None):
        self.calls += 1
        if not self.authenticated:
            raise AuthRequired('apple', 'test backend locked')
        if domain in self.failing_domains:
            raise BackendError('injected failure')

    def _account(self, rid):
        r = self.records[rid]
        return AppleAccount(domain=r['domain'], username=r['username'], sites=r['urls'],
                            record_id=rid if self.capabilities.record_ids else None,
                            modified=r['modified'] if self.capabilities.change_tokens else None,
                            group=r['group'])

    def check(self):
        self._guard()

    def list_all(self):
        if not self.capabilities.enumerate:
            raise BackendError('enumeration unsupported')
        self._guard()
        return [self._account(rid) for rid in self.records]

    def list_domain(self, domain):
        self._guard(domain)
        return [self._account(rid) for rid, r in self.records.items() if r['domain'] == domain]

    def _rid(self, account):
        if self.capabilities.record_ids and account.record_id in self.records:
            return account.record_id
        return self.find(account.domain, account.username)

    def get(self, account):
        self._guard(account.domain)
        rid = self._rid(account)
        if rid is None:
            return None
        r = self.records[rid]
        return Login(password=r['password'], username=r['username'], urls=r['urls'],
                     notes=r['notes'] if self.capabilities.notes else None,
                     unsupported=() if self.capabilities.notes else ('notes',))

    def put(self, domain, username, login, record_id=None):
        self._guard(domain)
        if not self.capabilities.write:
            raise BackendError('read-only')
        rid = record_id if record_id in self.records else self.find(domain, username)
        if rid is None:
            rid = self.add(domain, username, login.password)
        r = self.records[rid]
        r.update(domain=domain, username=username, password=login.password,
                 modified=str(next(self._clock)))
        if self.capabilities.notes and login.notes is not None:
            r['notes'] = login.notes
        if self.capabilities.urls_write and login.urls:
            r['urls'] = tuple(login.urls)
        return rid if self.capabilities.record_ids else None

    def delete(self, account):
        self._guard(account.domain)
        if not self.capabilities.delete:
            raise BackendError('delete unsupported')
        rid = self._rid(account)
        if rid:
            del self.records[rid]

    def rename(self, account, new_username):
        self._guard(account.domain)
        if not self.capabilities.rename:
            raise BackendError('rename unsupported')
        r = self.records[self._rid(account)]
        r['username'] = new_username
        r['modified'] = str(next(self._clock))
