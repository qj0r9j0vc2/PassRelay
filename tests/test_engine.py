import json
import unittest

from passrelay.apple.base import Capabilities
from passrelay.apple.memory import MemoryApple
from passrelay.errors import Stale
from tests.fakes import FakePass, make_engine

APW = Capabilities(write=True)                       # what APW offers
FULL = Capabilities(enumerate=True, write=True, delete=True, rename=True, notes=True,
                    urls_write=True, record_ids=True, change_tokens=True)


def entry(password, username='alice', url='https://example.com', extra=''):
    return f'{password}\nusername: {username}\nurl: {url}\n{extra}'


class Base(unittest.TestCase):
    caps = APW
    config = {}

    def setUp(self):
        self.apple = MemoryApple(self.caps)
        self.p = FakePass()
        self.e = make_engine(self.apple, self.p, **self.config)

    def sync(self, apply=True):
        return self.e.cycle(apply)

    def kinds(self, report):
        return [a['kind'] for a in report['actions']]

    def link(self):
        (link,) = self.e.state['links'].values()
        return link


class InitialSync(Base):
    def test_setup_plan_writes_nothing_then_apply_links_and_creates(self):
        self.e.state['setup_done'] = False
        self.p.put('web/example.com', entry('same'))
        self.apple.add('example.com', 'alice', 'same')
        self.p.put('web/new-in-pass', entry('p1', url='https://pass-only.com'))
        self.apple.add('apple-only.com', 'bob', 'a1')
        self.e.config = self.e.cfg
        self.e.cfg.watch_domains = ['apple-only.com']
        report = self.sync()
        self.assertTrue(report['dry_run'])
        self.assertEqual(sorted(self.kinds(report)), ['create-apple', 'create-pass', 'link'])
        self.assertEqual(self.e.state['links'], {})
        self.assertEqual(self.p.writes, 0)
        self.e.state['setup_done'] = True
        report = self.sync()
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(self.e.state['links']), 3)
        self.assertEqual(self.apple.records[self.apple.find('pass-only.com', 'alice')]['password'], 'p1')
        self.assertEqual(self.p.password('apple/apple-only.com/bob'), 'a1')
        self.assertIn('username: bob', self.p.entries['apple/apple-only.com/bob'][1])
        # Steady state: nothing more to do.
        self.assertEqual([k for k in self.kinds(self.sync()) if k != 'queued'], [])

    def test_initial_difference_is_a_conflict_not_an_overwrite(self):
        self.p.put('example.com/alice', entry('left'))
        self.apple.add('example.com', 'alice', 'right')
        self.sync()
        self.assertEqual(len(self.e.state['conflicts']), 1)
        self.assertEqual(self.p.password('example.com/alice'), 'left')
        self.assertEqual(self.apple.records['r1']['password'], 'right')

    def test_same_password_on_different_items_is_never_merged(self):
        self.p.put('a', entry('shared', username='one'))
        self.apple.add('example.com', 'two', 'shared')
        self.sync()
        identities = sorted((l['domain'], l['username']) for l in self.e.state['links'].values())
        self.assertEqual(identities, [('example.com', 'one'), ('example.com', 'two')])

    def test_path_inference_and_missing_info_queue(self):
        self.p.put('sites/example.com/alice', 'pw\n')
        self.p.put('notes/random', 'pw\nsome note\n')
        self.sync()
        self.assertEqual(self.link()['pass_path'], 'sites/example.com/alice')
        (q,) = self.e.state['queue'].values()
        self.assertEqual((q['kind'], q['path']), ('missing-info', 'notes/random'))


class Changes(Base):
    def setUp(self):
        super().setUp()
        self.p.put('example.com/alice', entry('v1', extra='notes: keep me\ncustom: field\n'))
        self.apple.add('example.com', 'alice', 'v1')
        self.sync()

    def test_pass_change_reaches_apple_and_back(self):
        self.p.put('example.com/alice', entry('v2', extra='notes: keep me\ncustom: field\n'))
        self.assertIn('update', self.kinds(self.sync()))
        self.assertEqual(self.apple.records['r1']['password'], 'v2')
        self.apple.set_password('example.com', 'alice', 'v3')
        self.sync()
        payload = self.p.entries['example.com/alice'][1]
        self.assertTrue(payload.startswith('v3\n'))
        self.assertIn('notes: keep me', payload)
        self.assertIn('custom: field', payload)
        self.assertEqual([k for k in self.kinds(self.sync())], [])

    def test_both_changed_same_value_needs_no_write(self):
        self.p.put('example.com/alice', entry('same'))
        self.apple.set_password('example.com', 'alice', 'same')
        writes = self.p.writes
        self.sync()
        self.assertEqual(self.p.writes, writes)
        self.assertEqual(self.e.state['conflicts'], {})

    def test_conflict_preserves_both_and_does_not_block_others(self):
        self.p.put('other.com/bob', entry('o1', username='bob', url='other.com'))
        self.apple.add('other.com', 'bob', 'o1')
        self.sync()
        self.p.put('example.com/alice', entry('left'))
        self.apple.set_password('example.com', 'alice', 'right')
        self.p.put('other.com/bob', entry('o2', username='bob', url='other.com'))
        self.sync()
        self.assertEqual(len(self.e.state['conflicts']), 1)
        self.assertEqual(self.apple.records[self.apple.find('other.com', 'bob')]['password'], 'o2')
        self.assertEqual(self.p.password('example.com/alice'), 'left')
        (cid,) = self.e.state['conflicts']
        self.e.resolve_conflict(cid, 'apple')
        self.assertEqual(self.p.password('example.com/alice'), 'right')
        self.assertEqual(self.e.state['conflicts'], {})
        self.assertNotIn('update', self.kinds(self.sync()))

    def test_resolve_refuses_when_values_moved_on(self):
        self.p.put('example.com/alice', entry('left'))
        self.apple.set_password('example.com', 'alice', 'right')
        self.sync()
        (cid,) = self.e.state['conflicts']
        self.apple.set_password('example.com', 'alice', 'newer')
        with self.assertRaises(Stale):
            self.e.resolve_conflict(cid, 'pass')
        self.assertEqual(self.apple.records['r1']['password'], 'newer')

    def test_auth_failure_is_not_a_deletion(self):
        self.apple.authenticated = False
        report = self.sync()
        self.assertIn('apple', report['auth'])
        self.assertEqual(self.e.state['deletions'], {})
        self.assertEqual(self.link()['status'], 'ok')

    def test_lookup_failure_is_not_a_deletion(self):
        self.apple.failing_domains.add('example.com')
        self.sync()
        self.assertEqual(self.e.state['deletions'], {})
        self.assertIn('example.com/alice', self.p.entries)

    def test_gpg_locked_reports_auth(self):
        self.p.put('example.com/alice', entry('v2'))
        self.p.locked = True
        report = self.sync()
        self.assertIn('gpg', report['auth'])
        self.assertEqual(self.apple.records['r1']['password'], 'v1')

    def test_pass_mv_keeps_link(self):
        self.p.mv('example.com/alice', 'renamed/example.com/alice')
        report = self.sync()
        self.assertIn('pass-renamed', self.kinds(report))
        self.assertEqual(self.link()['pass_path'], 'renamed/example.com/alice')
        self.assertEqual(len(self.apple.records), 1)

    def test_pass_cp_is_queued_as_duplicate(self):
        self.p.cp('example.com/alice', 'copy/example.com/alice')
        self.sync()
        kinds = [q['kind'] for q in self.e.state['queue'].values()]
        self.assertEqual(kinds, ['duplicate-identity'])
        self.assertEqual(len(self.apple.records), 1)

    def test_race_between_plan_and_write_aborts(self):
        self.p.put('example.com/alice', entry('v2'))
        original = self.apple.get

        def racing(account):
            login = original(account)
            self.apple.records['r1']['password'] = 'raced'
            return login
        self.apple.get = racing
        report = self.sync()
        self.apple.get = original
        self.assertTrue(report['errors'])
        self.assertEqual(self.apple.records['r1']['password'], 'raced')

    def test_dry_run_changes_nothing(self):
        self.p.put('example.com/alice', entry('v2'))
        decisions = ('links', 'conflicts', 'deletions', 'queue', 'plans', 'tombstones', 'history')
        before = json.dumps({k: self.e.state[k] for k in decisions}, sort_keys=True)
        report = self.sync(apply=False)
        self.assertIn('update', self.kinds(report))
        self.assertEqual(self.apple.records['r1']['password'], 'v1')
        self.assertEqual(json.dumps({k: self.e.state[k] for k in decisions}, sort_keys=True), before)
        self.assertIn('update', self.kinds(self.sync()))

    def test_history_is_encrypted_and_records_preimage(self):
        self.p.put('example.com/alice', entry('v2'))
        self.sync()
        (h,) = self.e.state['history']
        raw = (self.e.store.history_dir / (h['id'] + '.enc')).read_bytes()
        self.assertNotIn(b'v1', raw)
        self.assertEqual(self.e.store.history_get(h['id'])['before']['password'], 'v1')
        state_raw = self.e.store.state_path
        self.e.store.save(self.e.state)
        self.assertNotIn(b'example.com', state_raw.read_bytes())


class Deletions(Base):
    def setUp(self):
        super().setUp()
        self.p.put('example.com/alice', entry('v1'))
        self.apple.add('example.com', 'alice', 'v1')
        self.sync()

    def test_ask_policy_waits_then_restores(self):
        del self.p.entries['example.com/alice']
        self.sync()
        (did,) = self.e.state['deletions']
        self.assertEqual(len(self.apple.records), 1)
        self.sync()  # still waiting, still not deleted
        self.assertEqual(len(self.apple.records), 1)
        self.e.resolve_deletion(did, approve=False)
        self.assertEqual(self.p.password('example.com/alice'), 'v1')
        self.assertEqual(self.link()['status'], 'ok')

    def test_ask_policy_approve_without_apple_delete_queues_manual_step(self):
        del self.p.entries['example.com/alice']
        self.sync()
        (did,) = self.e.state['deletions']
        self.e.resolve_deletion(did, approve=True)
        self.assertEqual(self.e.state['links'], {})
        self.assertEqual([q['kind'] for q in self.e.state['queue'].values()], ['apple-delete-manual'])
        # The Apple item still exists but must not be re-imported into pass.
        self.sync()
        self.assertNotIn('apple/example.com/alice', self.p.entries)

    def test_deleted_from_apple_then_pass_deleted_on_approval(self):
        self.apple.records.clear()
        self.sync()
        (did,) = self.e.state['deletions']
        self.e.resolve_deletion(did, approve=True)
        self.assertNotIn('example.com/alice', self.p.entries)
        self.sync()
        self.assertEqual(self.apple.records, {})

    def test_keep_policy_unlinks_without_recreating(self):
        self.e.cfg.deletion_policy = 'keep'
        self.apple.records.clear()
        self.sync()
        self.assertEqual(self.e.state['links'], {})
        self.sync()
        self.assertEqual(self.apple.records, {})
        # New content at the same path is a new item and syncs again.
        self.p.put('example.com/alice', entry('fresh'))
        self.sync()
        self.assertEqual(self.apple.records[self.apple.find('example.com', 'alice')]['password'], 'fresh')

    def test_propagate_policy_with_capability(self):
        self.e.cfg.deletion_policy = 'propagate'
        self.apple.capabilities = Capabilities(write=True, delete=True)
        del self.p.entries['example.com/alice']
        self.sync()
        self.assertEqual(self.apple.records, {})

    def test_leaving_scope_unlinks_instead_of_deleting(self):
        self.e.cfg.deletion_policy = 'propagate'
        self.apple.capabilities = Capabilities(write=True, delete=True)
        self.e.cfg.pass_exclude = ['example.com/*']
        report = self.sync()
        self.assertIn('unlinked-out-of-scope', self.kinds(report))
        self.assertEqual(len(self.apple.records), 1)
        self.assertEqual(self.e.state['deletions'], {})
        self.e.cfg.pass_exclude = []
        self.e.cfg.apple_exclude = ['example.com']
        self.sync()
        self.assertIn('example.com/alice', self.p.entries)

    def test_propagate_never_deletes_a_modified_survivor(self):
        self.e.cfg.deletion_policy = 'propagate'
        self.apple.capabilities = Capabilities(write=True, delete=True)
        del self.p.entries['example.com/alice']
        self.apple.set_password('example.com', 'alice', 'changed')
        self.sync()
        self.assertEqual(len(self.apple.records), 1)
        self.assertEqual(len(self.e.state['deletions']), 1)


class ReviewRegressions(Base):
    """Scenarios from the adversarial engine review; each once lost data or touched the wrong item."""
    caps = Capabilities(write=True, delete=True, record_ids=True, notes=True)

    def setUp(self):
        super().setUp()
        self.p.put('example.com/alice', entry('v1', extra='otpauth://totp/x\n'))
        self.apple.add('example.com', 'alice', 'v1')
        self.sync()
        self.e.cfg.deletion_policy = 'propagate'

    def test_mv_out_of_scope_unlinks_instead_of_deleting(self):
        self.e.cfg.pass_exclude = ['archive/*']
        self.sync()  # records the current outside-of-scope paths
        self.p.mv('example.com/alice', 'archive/example.com/alice')
        self.assertIn('unlinked-out-of-scope', self.kinds(self.sync()))
        self.assertEqual(len(self.apple.records), 1)

    def test_reencrypting_mv_out_of_scope_is_never_auto_deleted(self):
        self.e.cfg.pass_exclude = ['archive/*']
        self.sync()
        self.p.mv('example.com/alice', 'archive/example.com/alice')
        self.p.put('archive/example.com/alice', self.p.entries['archive/example.com/alice'][1])  # new token
        self.sync()
        self.assertEqual(len(self.apple.records), 1)
        self.assertEqual(len(self.e.state['deletions']), 1)

    def test_propagate_keeps_survivor_with_new_notes(self):
        del self.p.entries['example.com/alice']
        self.apple.records['r1']['notes'] = 'recovery codes'
        self.sync()
        self.assertEqual(len(self.apple.records), 1)
        self.assertEqual(len(self.e.state['deletions']), 1)

    def test_record_moved_to_other_website_is_followed_not_deleted(self):
        self.apple.records['r1'].update(domain='login.example.com', urls=('login.example.com',))
        self.sync()
        self.assertIn('example.com/alice', self.p.entries)
        self.assertIn('url: https://login.example.com', self.p.entries['example.com/alice'][1])
        self.assertIn('otpauth://', self.p.entries['example.com/alice'][1])

    def test_deletion_withdrawn_when_copy_returns(self):
        self.e.cfg.deletion_policy = 'ask'
        saved = self.apple.records.pop('r1')
        self.sync()
        (did,) = self.e.state['deletions']
        self.apple.records['r1'] = dict(saved, password='new')
        self.sync()
        self.assertEqual(self.e.state['deletions'], {})
        self.assertEqual(self.p.password('example.com/alice'), 'new')


class SiteFamilies(Base):
    def test_login_returned_by_several_lookups_is_not_a_duplicate(self):
        rid = self.apple.add('accounts.google.com', 'me', 'g1', urls=('accounts.google.com', 'google.com'))
        original = self.apple.list_domain
        # Like APW: a lookup of any site in the family returns the whole family.
        self.apple.list_domain = lambda d: [self.apple._account(rid)] if d.endswith('google.com') else original(d)
        self.e.state['watch_domains'] = ['google.com', 'accounts.google.com']
        self.sync()
        self.assertEqual([q['kind'] for q in self.e.state['queue'].values()], [])
        self.assertEqual(self.p.password('apple/accounts.google.com/me'), 'g1')


class ReadBudget(Base):
    def test_reads_rotate_under_budget_and_changed_items_are_always_read(self):
        for i in range(6):
            self.p.put(f'site{i}.com/u', entry('v1', username='u', url=f'site{i}.com'))
            self.apple.add(f'site{i}.com', 'u', 'v1')
        self.sync()
        self.e.read_budget = 1e-9   # exhausted after the first read
        self.apple.set_password('site5.com', 'u', 'apple-new')
        self.p.put('site2.com/u', entry('pass-new', username='u', url='site2.com'))
        report = self.sync()
        self.assertEqual(self.apple.records[self.apple.find('site2.com', 'u')]['password'], 'pass-new')
        self.assertGreater(report['apple_progress']['reads_deferred'], 0)
        for _ in range(8):
            self.sync()
        self.assertEqual(self.p.password('site5.com/u'), 'apple-new')

    def test_apple_write_waits_for_save_confirmation(self):
        self.p.put('example.com/alice', entry('v1'))
        self.apple.add('example.com', 'alice', 'v1')
        self.sync()
        put, calls = self.apple.put, []

        def delayed_put(domain, username, login, record_id=None):
            calls.append(login)   # the user has not pressed "Save" yet
        get = self.apple.get

        def get_then_confirm(account):
            if calls:
                put(account.domain, account.username, calls.pop())
            return get(account)
        self.apple.put, self.apple.get = delayed_put, get_then_confirm
        self.e.cfg.apple_confirm_seconds = 5
        self.p.put('example.com/alice', entry('v2'))
        report = self.sync()
        self.assertEqual(report['errors'], [])
        self.assertEqual(self.apple.records['r1']['password'], 'v2')


class StaleApproval(Base):
    config = {'bulk_threshold': 2}

    def test_approval_does_not_cover_a_different_change(self):
        for i in range(4):
            self.p.put(f'site{i}.com/u', entry('v1', username='u', url=f'site{i}.com'))
            self.apple.add(f'site{i}.com', 'u', 'v1')
        self.sync()
        for i in range(4):
            self.apple.set_password(f'site{i}.com', 'u', 'v2')
        self.sync()
        (pid,) = self.e.state['plans']
        self.e.approve_plan(pid)
        for i in range(4):  # the situation changes before the approved plan runs
            self.apple.set_password(f'site{i}.com', 'u', 'v1')
            self.p.put(f'site{i}.com/u', entry('CLOBBER', username='u', url=f'site{i}.com'))
        self.assertIn('plan-pending', self.kinds(self.sync()))
        self.assertTrue(all(r['password'] == 'v1' for r in self.apple.records.values()))


class Polling(Base):
    def test_quick_cycle_checks_only_changed_websites(self):
        for i in range(5):
            self.p.put(f'site{i}.com/u', entry('v1', username='u', url=f'site{i}.com'))
            self.apple.add(f'site{i}.com', 'u', 'v1')
        self.sync()
        self.p.put('site3.com/u', entry('v2', username='u', url='site3.com'))
        self.apple.calls = 0
        self.e.cycle(quick=True)
        self.assertEqual(self.apple.records[self.apple.find('site3.com', 'u')]['password'], 'v2')
        self.assertLess(self.apple.calls, 6)

    def test_rotation_is_time_bounded_and_progress_reported(self):
        self.e.cfg.apple_cycle_seconds = 1e-9
        for i in range(5):
            self.apple.add(f'site{i}.com', 'u', 'v1')
        self.e.state['watch_domains'] = [f'site{i}.com' for i in range(5)]
        report = self.sync()
        self.assertEqual(report['apple_progress']['domains_pending'], 4)
        for _ in range(5):
            self.sync()
        self.assertEqual(len(self.e.state['links']), 5)


class Bulk(Base):
    config = {'bulk_threshold': 2}

    def test_bulk_overwrites_need_plan_approval(self):
        for i in range(4):
            self.p.put(f'site{i}.com/u', entry('v1', username='u', url=f'site{i}.com'))
            self.apple.add(f'site{i}.com', 'u', 'v1')
        self.sync()
        for i in range(4):
            self.apple.set_password(f'site{i}.com', 'u', 'v2')
        report = self.sync()
        self.assertIn('plan-pending', self.kinds(report))
        self.assertTrue(all(self.p.password(f'site{i}.com/u') == 'v1' for i in range(4)))
        (pid,) = self.e.state['plans']
        self.e.approve_plan(pid)
        self.sync()
        self.assertTrue(all(self.p.password(f'site{i}.com/u') == 'v2' for i in range(4)))
        self.assertEqual(self.e.state['approved'], [])


class Identity(Base):
    def setUp(self):
        super().setUp()
        self.p.put('example.com/alice', entry('v1'))
        self.apple.add('example.com', 'alice', 'v1')
        self.sync()

    def test_pass_username_change_with_apw_creates_new_and_asks_cleanup(self):
        self.p.put('example.com/alice', entry('v1', username='alice2'))
        self.sync()
        self.assertEqual((self.link()['username']), 'alice2')
        self.assertIsNotNone(self.apple.find('example.com', 'alice2'))
        self.assertEqual([q['kind'] for q in self.e.state['queue'].values()], ['apple-delete-manual'])
        self.sync()
        self.assertNotIn('apple/example.com/alice', self.p.entries)

    def test_apple_username_change_without_record_ids_suggests_relink(self):
        self.apple.records['r1']['username'] = 'renamed'
        self.sync()
        (q,) = self.e.state['queue'].values()
        self.assertEqual(q['kind'], 'relink-suggested')
        self.assertEqual(len(self.p.entries), 1)
        self.e.accept_queue(q['id'])
        self.sync()
        self.assertIn('username: renamed', self.p.entries['example.com/alice'][1])
        self.assertEqual(self.e.state['deletions'], {})

    def test_extra_pass_urls_do_not_conflict_with_single_website_backend(self):
        self.p.put('example.com/alice', entry('v1') + 'url: https://login.example.net\n')
        self.sync()
        self.assertEqual(self.e.state['conflicts'], {})
        self.assertIn('login.example.net', self.p.entries['example.com/alice'][1])


class FullBackend(Base):
    caps = FULL

    def test_record_ids_follow_apple_username_change_and_sync_notes(self):
        self.p.put('example.com/alice', entry('v1'))
        self.apple.add('example.com', 'alice', 'v1', notes='apple note')
        self.sync()
        self.assertIn('note: apple note', self.p.entries['example.com/alice'][1])
        self.apple.records['r1']['username'] = 'alice.new'
        self.apple.records['r1']['modified'] = '99'
        self.sync()
        self.assertIn('username: alice.new', self.p.entries['example.com/alice'][1])
        self.assertEqual(self.link()['username'], 'alice.new')
        self.assertEqual(self.e.state['queue'], {})

    def test_enumeration_discovers_without_watch_list(self):
        self.apple.add('unknown-site.org', 'zed', 'z1')
        self.sync()
        self.assertEqual(self.p.password('apple/unknown-site.org/zed'), 'z1')

    def test_shared_group_items_skipped_unless_enabled(self):
        self.apple.add('team.com', 'ops', 's1', group='Family')
        self.sync()
        self.assertEqual(self.p.entries, {})
        self.e.cfg.include_shared = True
        self.sync()
        self.assertIn('apple/team.com/ops', self.p.entries)


if __name__ == '__main__':
    unittest.main()
