"""Apple Passwords through the APW daemon (https://github.com/bendews/apw).

PassRelay speaks APW's local Unix-socket protocol directly instead of spawning the ``apw`` CLI:
it avoids one Deno process per item and the CLI's ``--stdin`` path, which trims whitespace from
passwords. The socket is created by ``apw start`` with mode 0600 and becomes usable after
``apw auth``. Message shapes mirror apw v1.1.x ``src/client.ts``.
"""
import json
import os
from pathlib import Path
import socket

from ..errors import AuthRequired, BackendError
from ..model import AppleAccount, Login, normalize_domain
from .base import AppleBackend, Capabilities

SUCCESS, NO_RESULTS, INVALID_SESSION = 0, 3, 9
CMD_LOGIN_NAMES, CMD_PASSWORD, CMD_SET = 4, 5, 6
ACT_SEARCH, ACT_MAYBE_ADD, ACT_GHOST_SEARCH = 2, 4, 5
TIMEOUT = 35
MAX_RESPONSE = 16 * 1024 * 1024
AUTH_HINT = 'run `passrelay auth apple` (starts APW and asks for the macOS PIN)'


class ApwBackend(AppleBackend):
    name = 'apw'

    def __init__(self, socket_path='~/.apw/apw.sock', save_url_prefix=''):
        self.socket_path = Path(socket_path).expanduser()
        self.save_url_prefix = save_url_prefix
        self.capabilities = Capabilities(write=True, change_tokens=False)

    def _request(self, message):
        if not self.socket_path.exists():
            raise AuthRequired('apple', AUTH_HINT)
        st = os.stat(self.socket_path)
        if st.st_uid != os.getuid():
            raise BackendError('APW socket is not owned by the current user')
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        try:
            try:
                s.connect(str(self.socket_path))
            except OSError:
                raise AuthRequired('apple', AUTH_HINT) from None
            s.sendall(json.dumps(message).encode() + b'\n')
            buf = bytearray()
            while b'\n' not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_RESPONSE:
                    raise BackendError('APW response too large')
        except socket.timeout:
            raise BackendError('APW timed out') from None
        except OSError:
            raise BackendError('APW connection failed') from None
        finally:
            s.close()
        try:
            response = json.loads(bytes(buf).split(b'\n', 1)[0])
        except ValueError:
            raise BackendError('APW returned invalid JSON') from None
        if not isinstance(response, dict):
            raise BackendError('APW returned an unexpected response')
        if 'data' not in response:
            status = response.get('status')
            if status == INVALID_SESSION:
                raise AuthRequired('apple', AUTH_HINT)
            if status != SUCCESS:
                raise BackendError(f'APW error status {status!r}')
        return response

    @staticmethod
    def _entries(response):
        data = response.get('data')
        if not isinstance(data, dict) or not isinstance(data.get('STATUS'), int):
            raise BackendError('APW returned an unexpected payload')
        if data['STATUS'] == NO_RESULTS:
            return []
        if data['STATUS'] == INVALID_SESSION:
            raise AuthRequired('apple', AUTH_HINT)
        if data['STATUS'] != SUCCESS:
            raise BackendError(f'APW error status {data["STATUS"]}')
        if isinstance(data.get('Entries'), list):
            entries = data['Entries']
        else:
            keys = sorted((k for k in data if k.startswith('Entry_')), key=lambda k: int(k[6:] or 0))
            entries = [data[k] for k in keys]
        out = []
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get('USR'), str):
                raise BackendError('APW entry without username')
            sites = e.get('sites')
            if not isinstance(sites, list) or not sites or not all(isinstance(x, str) for x in sites):
                raise BackendError('APW entry without sites')
            out.append(e)
        return out

    def _account(self, e):
        domain = normalize_domain(e['sites'][0])
        if not domain:
            raise BackendError('APW entry with invalid site')
        modified = e.get('ModDate') if isinstance(e.get('ModDate'), str) else None
        if modified:
            self.capabilities = Capabilities(write=True, change_tokens=True)
        title = e.get('customTitle') if isinstance(e.get('customTitle'), str) else None
        return AppleAccount(domain=domain, username=e['USR'], sites=tuple(e['sites']), title=title,
                            modified=modified)

    def request_challenge(self):
        """Ask APW to show the macOS PIN prompt (same as `apw auth request`)."""
        self._request({'cmd': 2})

    def verify_challenge(self, pin):
        """Answer the PIN prompt over the socket, so the PIN never appears in a process argv."""
        if not (isinstance(pin, str) and len(pin) == 6 and pin.isdigit()):
            raise BackendError('PIN must be six digits')
        self._request({'cmd': 2, 'pin': pin})

    def check(self):
        if not self.socket_path.exists():
            raise AuthRequired('apple', AUTH_HINT)
        # A harmless lookup proves the extension session is authenticated.
        self.list_domain('passrelay-healthcheck.invalid')

    def list_domain(self, domain):
        message = {'cmd': CMD_LOGIN_NAMES, 'qid': 'CmdGetLoginNames4URL', 'tabId': 1, 'frameId': 1,
                   'url': domain, 'body': {'ACT': ACT_GHOST_SEARCH, 'URL': domain}}
        # A lookup returns every login of the site family (e.g. google.com also returns
        # accounts.google.com and mail.google.com). All of them are real accounts; each one's identity
        # is its first site. The engine de-duplicates accounts seen from several lookups.
        return [self._account(e) for e in self._entries(self._request(message))]

    def get(self, account):
        message = {'cmd': CMD_PASSWORD, 'qid': 'CmdGetPassword4LoginName', 'tabId': 0, 'frameId': 0,
                   'url': account.domain,
                   'body': {'ACT': ACT_SEARCH, 'URL': account.domain, 'USR': account.username}}
        matches = [e for e in self._entries(self._request(message))
                   if e['USR'] == account.username and normalize_domain(e['sites'][0]) == account.domain]
        if not matches:
            return None
        if len(matches) > 1:
            raise BackendError('APW returned several records for one account')
        e = matches[0]
        password = e.get('PWD')
        if not isinstance(password, str) or password == 'Not Included' or not password:
            raise BackendError('APW did not include the password')
        acct = self._account(e)
        return Login(password=password, username=e['USR'], urls=acct.sites, title=acct.title,
                     unsupported=('notes',))

    def put(self, domain, username, login, record_id=None):
        message = {'cmd': CMD_SET, 'qid': 'CmdSetPassword4LoginName_URL', 'tabId': 0, 'frameId': 0,
                   'body': {'ACT': ACT_MAYBE_ADD, 'URL': '', 'USR': '', 'PWD': '',
                            'NURL': self.save_url_prefix + domain, 'NUSR': username,
                            'NPWD': login.password}}
        response = self._request(message)
        data = response.get('data')
        if isinstance(data, dict) and data.get('STATUS') not in (None, SUCCESS):
            if data.get('STATUS') == INVALID_SESSION:
                raise AuthRequired('apple', AUTH_HINT)
            raise BackendError(f'APW save failed with status {data.get("STATUS")}')
        return None
