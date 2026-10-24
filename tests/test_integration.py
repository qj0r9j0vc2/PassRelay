"""End-to-end tests with the real `pass` and `gpg` binaries and a fake APW daemon socket.

Everything runs in temporary directories with a throwaway GPG key; the user's store, keyring, and
Apple Passwords are never touched. Skipped when pass or gpg is not installed.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest

from passrelay import cli
from passrelay.apple.apw import ApwBackend
from passrelay.errors import AuthRequired
from passrelay.model import AppleAccount, Login
from passrelay.passstore import PassStore

HAVE_TOOLS = shutil.which('pass') and shutil.which('gpg')


class FakeApw:
    """Speaks APW's daemon socket protocol (apw v1.1 src/client.ts + ext/bridge.js)."""

    def __init__(self, path):
        self.path = path
        self.records = {}          # (site, user) -> password
        self.paired = True
        self.pin_requested = False
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(16)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        self.server.close()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                buf = b''
                while b'\n' not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                reply = self.handle(json.loads(buf.split(b'\n')[0]))
                conn.sendall(json.dumps(reply).encode() + b'\n')

    def handle(self, m):
        if m['cmd'] == 2:
            if 'pin' in m:
                self.paired = m['pin'] == '123456'
            else:
                self.pin_requested = True
            return {'id': '1', 'status': 0}
        if not self.paired:
            return {'id': '1', 'status': 9, 'error': 'unpaired'}
        body = m['body']
        if m['cmd'] == 4:
            entries = [{'USR': u, 'sites': [s], 'PWD': 'Not Included'}
                       for (s, u) in self.records if s == body['URL']]
        elif m['cmd'] == 5:
            entries = [{'USR': u, 'sites': [s], 'PWD': p} for (s, u), p in self.records.items()
                       if s == body['URL'] and (not body['USR'] or u == body['USR'])]
        elif m['cmd'] == 6:
            site = body['NURL'].split('://', 1)[-1]
            self.records[(site, body['NUSR'])] = body['NPWD']
            return {'id': '1', 'data': {'STATUS': 0}}
        else:
            return {'id': '1', 'status': 8}
        if not entries:
            return {'id': '1', 'data': {'STATUS': 3}}
        return {'id': '1', 'data': {'STATUS': 0, 'Entries': entries}}


@unittest.skipUnless(HAVE_TOOLS, 'pass and gpg required')
class RealPassCase(unittest.TestCase):
    """Temporary GPG key, pass store, fake APW socket, and CLI helpers. Holds no tests itself."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='pr-')
        cls.env_backup = {k: os.environ.get(k) for k in ('GNUPGHOME', 'PASSWORD_STORE_DIR', 'PASSRELAY_CONFIG')}
        gnupg = Path(cls.tmp, 'g')
        gnupg.mkdir(mode=0o700)
        os.environ['GNUPGHOME'] = str(gnupg)
        subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                        '--quick-gen-key', 'PassRelay Test <test@example.invalid>', 'default', 'default',
                        'never'], check=True, capture_output=True)
        cls.store_dir = Path(cls.tmp, 'store')
        os.environ['PASSWORD_STORE_DIR'] = str(cls.store_dir)
        subprocess.run(['pass', 'init', 'test@example.invalid'], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['gpgconf', '--kill', 'gpg-agent'], capture_output=True)
        for k, v in cls.env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        for child in self.store_dir.iterdir():
            if not child.name.startswith('.'):
                shutil.rmtree(child) if child.is_dir() else child.unlink()
        self.case = tempfile.mkdtemp(prefix='c-', dir=self.tmp)
        self.apw = FakeApw(os.path.join(self.case, 's'))
        self.state_dir = os.path.join(self.case, 'state')
        self.config = os.path.join(self.case, 'config.json')

    def tearDown(self):
        self.apw.close()

    def insert(self, path, payload):
        subprocess.run(['pass', 'insert', '-m', '-f', path], input=payload.encode(), check=True,
                       capture_output=True)

    def show(self, path):
        return subprocess.run(['pass', 'show', path], check=True, capture_output=True).stdout.decode()

    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(['--config', self.config, '--json', *argv])
        return code, json.loads(buf.getvalue())

    def setup_cli(self, *extra):
        return self.run_cli('setup', '--pass-store', str(self.store_dir), '--key-store', 'file',
                            '--state-dir', self.state_dir, *extra)



class RealPass(RealPassCase):
    # ----------------------------------------------------------------- PassStore
    def test_passstore_roundtrip_scan_and_mv_token(self):
        ps = PassStore(self.store_dir)
        self.insert('web/example.com', 'pw\nusername: a\n')
        files = ps.scan()
        self.assertEqual(list(files), ['web/example.com'])
        self.assertEqual(ps.read('web/example.com'), 'pw\nusername: a\n')
        ps.write('web/example.com', '  spaced pw  \nusername: a\n')
        self.assertEqual(ps.read('web/example.com'), '  spaced pw  \nusername: a\n')
        subprocess.run(['pass', 'mv', 'web/example.com', 'moved/example.com'], check=True, capture_output=True)
        self.assertEqual(list(ps.scan()), ['moved/example.com'])
        self.assertIsNone(ps.read('web/example.com'))
        with self.assertRaises(Exception):
            ps.read('../escape')

    def test_locked_key_reports_auth_not_missing(self):
        ps = PassStore(self.store_dir)
        self.insert('x', 'pw\n')
        ps.binary = str(Path(self.case, 'fakepass'))
        Path(ps.binary).write_text('#!/bin/sh\necho "gpg: public key decryption failed: No pinentry" >&2\nexit 2\n')
        os.chmod(ps.binary, 0o700)
        with self.assertRaises(AuthRequired):
            ps.read('x')

    # ----------------------------------------------------------------- APW socket
    def test_apw_socket_client(self):
        apple = ApwBackend(self.apw.path)
        self.apw.records[('example.com', 'alice')] = ' secret with spaces '
        (acct,) = apple.list_domain('example.com')
        self.assertEqual(apple.get(acct).password, ' secret with spaces ')
        self.assertIsNone(apple.get(AppleAccount('example.com', 'nobody')))
        self.assertEqual(apple.list_domain('none.example'), [])
        apple.put('new.com', 'bob', Login(password='p'))
        self.assertEqual(self.apw.records[('new.com', 'bob')], 'p')
        self.apw.paired = False
        with self.assertRaises(AuthRequired):
            apple.list_domain('example.com')
        apple.request_challenge()
        apple.verify_challenge('123456')
        self.assertTrue(self.apw.paired)
        with self.assertRaises(AuthRequired):
            ApwBackend(os.path.join(self.case, 'missing.sock')).list_domain('x.com')

    # ----------------------------------------------------------------- CLI end to end
    def test_cli_end_to_end(self):
        self.insert('web/example.com/alice', 'same-pw\nusername: alice\nurl: https://example.com\nnote: x\n')
        self.insert('web/pass-only.com/bob', 'bob-pw\n')
        self.apw.records[('example.com', 'alice')] = 'same-pw'
        self.apw.records[('apple-only.com', 'carol')] = 'carol-pw'

        cfg_path = Path(self.config)
        code, out = self.setup_cli('--watch-domain', 'apple-only.com')
        self.assertEqual(code, 0, out)
        cfg = json.loads(cfg_path.read_text())
        cfg['apw_socket'] = self.apw.path
        cfg_path.write_text(json.dumps(cfg))
        code, out = self.run_cli('setup')
        kinds = sorted(a['kind'] for a in out['report']['actions'])
        self.assertEqual(kinds, ['create-apple', 'create-pass', 'link'])
        self.assertEqual(self.apw.records.get(('pass-only.com', 'bob')), None)

        code, out = self.run_cli('setup', '--apply')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.apw.records[('pass-only.com', 'bob')], 'bob-pw')
        self.assertTrue(self.show('apple/apple-only.com/carol').startswith('carol-pw\n'))

        # pass edit -> Apple; Apple edit -> pass (metadata preserved)
        self.insert('web/example.com/alice', 'new-pw\nusername: alice\nurl: https://example.com\nnote: x\n')
        code, out = self.run_cli('sync')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.apw.records[('example.com', 'alice')], 'new-pw')
        self.apw.records[('example.com', 'alice')] = 'from-iphone'
        self.run_cli('sync')
        self.assertEqual(self.show('web/example.com/alice'),
                         'from-iphone\nusername: alice\nurl: https://example.com\nnote: x\n')

        # Conflict -> resolve via CLI
        self.insert('web/example.com/alice', 'L\nusername: alice\nurl: https://example.com\nnote: x\n')
        self.apw.records[('example.com', 'alice')] = 'R'
        code, out = self.run_cli('sync')
        self.assertEqual(code, 3)
        code, out = self.run_cli('conflicts')
        (c,) = out['conflicts']
        self.assertNotIn('L', json.dumps(out))
        code, out = self.run_cli('conflicts', 'show', c['id'], '--reveal')
        self.assertEqual(out['values']['apple']['password'], 'R')
        code, out = self.run_cli('resolve', c['id'], '--keep', 'pass')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.apw.records[('example.com', 'alice')], 'L')

        # History + restore
        code, out = self.run_cli('history')
        latest = next(h for h in out['history'] if h['side'] == 'apple' and h['action'] == 'update')
        code, out = self.run_cli('restore', latest['id'])
        self.assertEqual(code, 0, out)
        self.assertEqual(self.apw.records[('example.com', 'alice')], 'R')

        # Auth failure: no deletion, status reports auth.
        self.apw.paired = False
        code, out = self.run_cli('sync')
        self.assertEqual(code, 4)
        code, out = self.run_cli('status')
        self.assertEqual(out['state'], 'auth')
        code, out = self.run_cli('deletions')
        self.assertEqual(out['deletions'], [])
        self.apw.paired = True

        # pass rm -> pending deletion -> restore
        subprocess.run(['pass', 'rm', '-f', 'web/pass-only.com/bob'], check=True, capture_output=True)
        code, out = self.run_cli('sync')
        self.assertEqual(code, 3)
        code, out = self.run_cli('deletions')
        (d,) = out['deletions']
        code, out = self.run_cli('deletions', 'restore', d['id'])
        self.assertEqual(code, 0, out)
        self.assertTrue(self.show('web/pass-only.com/bob').startswith('bob-pw\n'))

        # Missing info queue -> info -> created in Apple
        self.insert('misc/router', 'router-pw\n')
        code, out = self.run_cli('sync')
        q = next(q for q in self.run_cli('queue')[1]['queue'] if q['kind'] == 'missing-info')
        code, out = self.run_cli('queue', 'info', q['id'], '--site', 'router.lan', '--username', 'admin')
        self.assertEqual(code, 0, out)
        self.run_cli('sync')
        self.assertEqual(self.apw.records[('router.lan', 'admin')], 'router-pw')
        self.assertIn('username: admin', self.show('misc/router'))

        # pass mv keeps the link (pass may re-encrypt on mv, so this goes by identity).
        subprocess.run(['pass', 'mv', 'web/pass-only.com/bob', 'archive/pass-only.com/bob'], check=True,
                       capture_output=True)
        code, out = self.run_cli('sync')
        self.assertIn('pass-renamed', [a['kind'] for a in out['report']['actions']])
        self.assertEqual(self.run_cli('deletions')[1]['deletions'], [])

        # Items listing masks names by default.
        code, out = self.run_cli('items')
        self.assertTrue(all('*' in i['site'] for i in out['items']))

        # Nothing on disk under the state directory contains plaintext passwords or sites.
        blob = b''.join(p.read_bytes() for p in Path(self.state_dir).rglob('*') if p.is_file())
        for secret in (b'bob-pw', b'carol-pw', b'router-pw', b'from-iphone', b'example.com'):
            self.assertNotIn(secret, blob)

    def test_doctor_runs(self):
        self.setup_cli()
        code, out = self.run_cli('doctor')
        names = {c['name']: c['status'] for c in out['checks']}
        self.assertEqual(names['pass store'], 'ok')
        self.assertEqual(names['gpg agent'], 'ok')
        self.assertEqual(names['state'], 'ok')


if __name__ == '__main__':
    unittest.main()
