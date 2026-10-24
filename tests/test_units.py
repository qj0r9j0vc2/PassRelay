import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from passrelay import cli, crypto, passfmt
from passrelay.apple.apw import ApwBackend
from passrelay.apple.bridge import BridgeBackend
from passrelay.config import Config
from passrelay.errors import AuthRequired, BackendError, Busy, ConfigError
from passrelay.model import AppleAccount, Login, normalize_domain
from passrelay.passstore import validate_path
from passrelay.state import StateStore


class Format(unittest.TestCase):
    def test_parse_fields_aliases_and_unsupported(self):
        login = passfmt.parse('pw\nLogin: alice\nurl: https://a.com/x\nwebsite: b.com\nnote: one\n'
                              'note:\nnote: three\notpauth://totp/x\ncustom: kept\n')
        self.assertEqual(login.username, 'alice')
        self.assertEqual(login.urls, ('https://a.com/x', 'b.com'))
        self.assertEqual(login.notes, 'one\n\nthree')
        self.assertEqual(login.unsupported, ('otp',))
        self.assertEqual(login.domain, 'a.com')

    def test_render_replaces_in_place_and_preserves_everything_else(self):
        payload = 'old\ncustom: 1\nLogin: alice\nurl: a.com\nurl: b.com\notpauth://x\n'
        new = Login(password='new', username='bob', urls=('https://c.com',))
        out = passfmt.render(payload, new, {'password', 'username', 'urls'})
        self.assertEqual(out, 'new\ncustom: 1\nLogin: bob\nurl: https://c.com\notpauth://x\n')

    def test_render_none_never_erases(self):
        payload = 'pw\nnote: keep\n'
        out = passfmt.render(payload, Login(password='pw2', notes=None), {'password', 'notes'})
        self.assertEqual(out, 'pw2\nnote: keep\n')

    def test_render_new_entry_and_rejects_multiline(self):
        out = passfmt.render(None, Login(password='p', username='u', urls=('https://x.com',), notes='a\nb'),
                             {'password', 'username', 'urls', 'notes'})
        self.assertEqual(out, 'p\nusername: u\nurl: https://x.com\nnote: a\nnote: b\n')
        with self.assertRaises(ValueError):
            passfmt.render(None, Login(password='p\nq'), {'password'})
        with self.assertRaises(ValueError):
            passfmt.render(None, Login(password='p', username='a\nb'), {'password', 'username'})

    def test_trailing_newline_preserved(self):
        self.assertEqual(passfmt.render('a\nx: 1', Login(password='b'), {'password'}), 'b\nx: 1')

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain('HTTPS://Login.Example.com:8443/path?q'), 'login.example.com')
        self.assertEqual(normalize_domain('bücher.de'), 'xn--bcher-kva.de')
        self.assertIsNone(normalize_domain(''))

    def test_validate_path(self):
        for bad in ('../a', '/a', '-a', 'a//b', 'a/./b', 'a\nb'):
            with self.assertRaises(BackendError):
                validate_path(bad)
        self.assertEqual(validate_path('web/a.com'), 'web/a.com')


class Storage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = StateStore(self.dir, os.urandom(32))

    def test_state_roundtrip_encrypted_and_wrong_key_rejected(self):
        state = self.store.load()
        state['links']['l1'] = {'domain': 'secret-site.com'}
        self.store.save(state)
        self.assertNotIn(b'secret-site', self.store.state_path.read_bytes())
        self.assertEqual(self.store.load()['links']['l1']['domain'], 'secret-site.com')
        with self.assertRaises(ConfigError):
            StateStore(self.dir, os.urandom(32)).load()
        self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.store.state_path).st_mode & 0o777, 0o600)

    def test_history_prune(self):
        state = self.store.load()
        hid = self.store.history_add(state, {'action': 'update', 'side': 'pass', 'before': 'x'})
        self.store.history_prune(state, 30, now=state['history'][0]['time'] + 31 * 86400)
        self.assertEqual(state['history'], [])
        with self.assertRaises(ConfigError):
            self.store.history_get(hid)

    def test_lock_excludes_second_process(self):
        with self.store.lock():
            with self.assertRaises(Busy):
                with StateStore(self.dir, os.urandom(32)).lock(timeout=0.2):
                    pass

    def test_crypto_tamper_detected(self):
        key = os.urandom(32)
        blob = crypto.seal(key, b'data', b'a')
        with self.assertRaises(ValueError):
            crypto.open_(key, blob, b'b')


class ConfigTests(unittest.TestCase):
    def test_validation_and_scope(self):
        c = Config(pass_exclude=['private/*'], apple_exclude=['*.bank.com'])
        c.validate()
        self.assertFalse(c.pass_in_scope('private/x'))
        self.assertTrue(c.pass_in_scope('web/x'))
        self.assertFalse(c.apple_in_scope('my.bank.com'))
        self.assertFalse(c.apple_in_scope('team.com', group='Family'))
        for bad in (dict(apple_backend='x'), dict(deletion_policy='never'), dict(new_pass_path='x/{domain}'),
                    dict(apple_poll_seconds=1), dict(apple_backend='bridge')):
            with self.assertRaises(ConfigError):
                Config(**bad).validate()

    def test_unknown_keys_rejected(self):
        path = Path(tempfile.mkdtemp(), 'c.json')
        path.write_text(json.dumps({'nope': 1}))
        from passrelay.config import load
        with self.assertRaises(ConfigError):
            load(path)


class ApwParsing(unittest.TestCase):
    def setUp(self):
        self.apw = ApwBackend('/nonexistent')

    def respond(self, value):
        return patch.object(ApwBackend, '_request', return_value=value)

    def test_entry_n_format_and_filtering(self):
        data = {'data': {'STATUS': 0, 'Entry_1': {'USR': 'b', 'sites': ['other.com']},
                         'Entry_0': {'USR': 'a', 'sites': ['https://Example.com'], 'ModDate': '5'}}}
        with self.respond(data):
            accounts = self.apw.list_domain('example.com')
        self.assertEqual([(a.domain, a.username, a.modified) for a in accounts],
                         [('example.com', 'a', '5'), ('other.com', 'b', None)])
        self.assertTrue(self.apw.capabilities.change_tokens)

    def test_no_results_vs_errors(self):
        with self.respond({'data': {'STATUS': 3}}):
            self.assertEqual(self.apw.list_domain('x.com'), [])
        with self.respond({'data': {'STATUS': 9}}):
            with self.assertRaises(AuthRequired):
                self.apw.list_domain('x.com')
        for bad in ({'data': {'STATUS': 0, 'Entries': [{'sites': ['x.com']}]}},
                    {'data': {'STATUS': 0, 'Entries': [{'USR': 'a'}]}},
                    {'data': {'STATUS': 1}}, {'data': 'x'}):
            with self.respond(bad):
                with self.assertRaises(BackendError):
                    self.apw.list_domain('x.com')

    def test_get_requires_password(self):
        acct = AppleAccount('x.com', 'a')
        with self.respond({'data': {'STATUS': 0, 'Entries': [{'USR': 'a', 'sites': ['x.com'],
                                                               'PWD': 'Not Included'}]}}):
            with self.assertRaises(BackendError):
                self.apw.get(acct)
        two = [{'USR': 'a', 'sites': ['x.com'], 'PWD': 'p'}] * 2
        with self.respond({'data': {'STATUS': 0, 'Entries': two}}):
            with self.assertRaises(BackendError):
                self.apw.get(acct)

    def test_pin_validation(self):
        with self.assertRaises(BackendError):
            self.apw.verify_challenge('12ab56')


BRIDGE = r'''
import json, sys
req = json.load(sys.stdin)
db_path = sys.argv[1]
db = json.load(open(db_path))
op = req['op']
def out(v): print(json.dumps(v)); sys.exit(0)
if op == 'hello': out({'ok': True, 'capabilities': {'enumerate': True, 'write': True, 'delete': True,
                                                  'notes': True, 'record_ids': True}})
if op == 'check': out({'ok': not db.get('locked'), **({'error': 'auth', 'hint': 'unlock'} if db.get('locked') else {})})
if op == 'list': out({'ok': True, 'items': [{k: v for k, v in i.items() if k != 'password'} for i in db['items']]})
if op == 'get':
    m = [i for i in db['items'] if i['id'] == req.get('id') or (i['domain'], i['username']) == (req['domain'], req['username'])]
    out({'ok': True, 'found': bool(m), **({'item': m[0]} if m else {})})
if op == 'put':
    db['items'].append({'id': 'n1', 'domain': req['domain'], 'username': req['username'], 'password': req['password'], 'notes': req.get('notes')})
    json.dump(db, open(db_path, 'w')); out({'ok': True, 'id': 'n1'})
out({'ok': False})
'''


class Bridge(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.script = Path(d, 'bridge.py')
        self.script.write_text(BRIDGE)
        self.db = Path(d, 'db.json')
        self.db.write_text(json.dumps({'items': [{'id': 'r1', 'domain': 'a.com', 'username': 'u',
                                                  'password': 'p', 'notes': 'n'}]}))
        self.b = BridgeBackend([sys.executable, str(self.script), str(self.db)])

    def test_capabilities_list_get_put(self):
        (acct,) = self.b.list_all()
        self.assertEqual(acct.record_id, 'r1')
        self.assertTrue(self.b.capabilities.record_ids and self.b.capabilities.notes)
        self.assertEqual(self.b.get(acct).notes, 'n')
        self.assertIsNone(self.b.get(AppleAccount('b.com', 'x')))
        self.assertEqual(self.b.put('b.com', 'x', Login(password='q', notes='hi')), 'n1')

    def test_auth_error_mapped(self):
        self.db.write_text(json.dumps({'items': [], 'locked': True}))
        with self.assertRaises(AuthRequired):
            self.b.check()


class Masking(unittest.TestCase):
    def test_masks(self):
        self.assertEqual(cli.mask('example.com'), 'ex*****.com')
        self.assertEqual(cli.mask('alice'), 'al***')
        self.assertEqual(cli.mask_path('web/example.com/alice'), 'web/ex*****.com/al***')

    def test_apple_export_reads_only_urls(self):
        f = Path(tempfile.mkdtemp(), 'export.csv')
        f.write_text('Title,URL,Username,Password,Notes,OTPAuth\nX,https://a.com/login,u,secret,,\n'
                     'Y,,v,secret2,,\n')
        self.assertEqual(cli.read_apple_export(f), {'a.com'})


if __name__ == '__main__':
    unittest.main()
