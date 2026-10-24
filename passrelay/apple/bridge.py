"""Apple Passwords through a user-supplied bridge executable (protocol in docs/BRIDGE.md).

Each request runs the bridge once: one JSON object on stdin, one JSON object on stdout. The bridge
declares what it can do in its ``hello`` response, so a richer bridge (enumeration, deletion,
record identifiers, notes) unlocks the matching engine features without code changes here.
"""
import json
import subprocess

from ..errors import AuthRequired, BackendError
from ..model import AppleAccount, Login, normalize_domain
from .base import AppleBackend, Capabilities

TIMEOUT = 30
VERSION = 2


class BridgeBackend(AppleBackend):
    name = 'bridge'

    def __init__(self, command):
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise BackendError('bridge_command must be an argv array')
        self.command = command
        self.capabilities = None

    def _call(self, request):
        request = {'version': VERSION, **request}
        try:
            p = subprocess.run(self.command, input=json.dumps(request).encode(), capture_output=True,
                               timeout=TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            raise BackendError('bridge unavailable or timed out') from None
        try:
            value = json.loads(p.stdout)
        except ValueError:
            value = None
        if isinstance(value, dict) and value.get('ok') is False and value.get('error') == 'auth':
            raise AuthRequired('apple', value.get('hint') if isinstance(value.get('hint'), str)
                               and len(value['hint']) < 200 else 'authenticate the bridge')
        if p.returncode or not isinstance(value, dict) or value.get('ok') is not True:
            raise BackendError('bridge rejected the request')
        return value

    def _hello(self):
        if self.capabilities is None:
            caps = self._call({'op': 'hello'}).get('capabilities', {})
            if not isinstance(caps, dict):
                raise BackendError('bridge returned invalid capabilities')
            known = Capabilities.__dataclass_fields__
            self.capabilities = Capabilities(**{k: v is True for k, v in caps.items() if k in known})
        return self.capabilities

    def check(self):
        self._hello()
        self._call({'op': 'check'})

    @staticmethod
    def _account(item):
        if not isinstance(item, dict) or not isinstance(item.get('username'), str):
            raise BackendError('bridge returned an invalid account')
        domain = normalize_domain(item.get('domain'))
        if not domain:
            raise BackendError('bridge returned an invalid domain')
        sites = item.get('urls') or [domain]
        if not isinstance(sites, list) or not all(isinstance(x, str) for x in sites):
            raise BackendError('bridge returned invalid urls')

        def opt(name):
            v = item.get(name)
            return v if isinstance(v, str) else None
        return AppleAccount(domain=domain, username=item['username'], sites=tuple(sites),
                            title=opt('title'), record_id=opt('id'), modified=opt('modified'),
                            group=opt('group'))

    def list_all(self):
        self._hello()
        items = self._call({'op': 'list'}).get('items')
        if not isinstance(items, list):
            raise BackendError('bridge returned an invalid listing')
        return [self._account(i) for i in items]

    def list_domain(self, domain):
        self._hello()
        items = self._call({'op': 'list', 'domain': domain}).get('items')
        if not isinstance(items, list):
            raise BackendError('bridge returned an invalid listing')
        return [a for a in map(self._account, items) if a.domain == domain]

    def get(self, account):
        caps = self._hello()
        value = self._call({'op': 'get', 'domain': account.domain, 'username': account.username,
                            'id': account.record_id})
        if type(value.get('found')) is not bool:
            raise BackendError('bridge omitted explicit found status')
        if not value['found']:
            return None
        item = value.get('item') or {'domain': account.domain, 'username': account.username,
                                     'password': value.get('password')}
        password = item.get('password')
        if not isinstance(password, str) or not password:
            raise BackendError('bridge omitted the password')
        acct = self._account(item)
        notes = item.get('notes') if caps.notes and isinstance(item.get('notes'), str) else None
        return Login(password=password, username=acct.username, urls=acct.sites, title=acct.title,
                     notes=notes, unsupported=() if caps.notes else ('notes',))

    def put(self, domain, username, login, record_id=None):
        caps = self._hello()
        if not caps.write:
            raise BackendError('bridge cannot write')
        request = {'op': 'put', 'domain': domain, 'username': username, 'password': login.password,
                   'id': record_id}
        if caps.notes and login.notes is not None:
            request['notes'] = login.notes
        if caps.urls_write and login.urls:
            request['urls'] = list(login.urls)
        value = self._call(request)
        return value.get('id') if isinstance(value.get('id'), str) else record_id

    def delete(self, account):
        if not self._hello().delete:
            raise BackendError('bridge cannot delete')
        self._call({'op': 'delete', 'domain': account.domain, 'username': account.username,
                    'id': account.record_id})

    def rename(self, account, new_username):
        if not self._hello().rename:
            raise BackendError('bridge cannot rename')
        self._call({'op': 'rename', 'domain': account.domain, 'username': account.username,
                    'id': account.record_id, 'new_username': new_username})
