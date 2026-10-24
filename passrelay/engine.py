"""The synchronization engine.

One ``cycle`` scans both sides, links matching logins, merges changes field by field against the
last agreed baseline, and applies the result with re-checks before and verification after every
write. The engine never treats a failed or unauthenticated lookup as a deletion, never merges two
items because their passwords match, and never lets a problem with one item block the others.

State vocabulary (everything lives in the encrypted state, see state.py):

link        a pass path tied to an Apple identity (domain, username[, record id]) with per-field
            baseline fingerprints from the last successful sync
conflict    both sides changed a field differently (or differed when first linked)
deletion    one side disappeared; waits for approval unless the policy says otherwise
queue       items that need a human: missing username/website, duplicates, ambiguous renames
plan        a bulk set of deletions/overwrites above ``bulk_threshold`` waiting for approval
tombstone   a pass path or Apple identity whose current content must not be re-created or re-linked
"""
import copy
import json
import time
import uuid

from . import passfmt
from .errors import AuthRequired, BackendError, ConfigError, Deferred, PassRelayError, Stale
from .model import AppleAccount, FIELDS, identity_key, looks_like_domain, normalize_domain


def _id(prefix):
    return prefix + uuid.uuid4().hex[:10]


def split_key(key):
    try:
        domain, username = json.loads(key)
        return domain, username
    except (ValueError, TypeError):
        return None, None


def infer_identity(path):
    """`site.com/user` (optionally under folders) -> (site.com, user)."""
    parts = path.split('/')
    if len(parts) >= 2 and looks_like_domain(parts[-2]):
        return parts[-2].lower(), parts[-1]
    return None, None


def with_scheme(urls):
    return tuple(u if '://' in u else 'https://' + u for u in urls)


def login_dict(login):
    return {'password': login.password, 'username': login.username, 'urls': list(login.urls),
            'notes': login.notes, 'title': login.title}


class Engine:
    quick = False

    def __init__(self, config, pass_store, apple, store, state, fingerprint, now=time.time):
        self.cfg = config
        self.pass_store = pass_store
        self.apple = apple
        self.store = store
        self.state = state
        self.fp = fingerprint
        self.now = now
        self.apply = True
        self._apple_logins = {}
        # Seconds of Apple password reads per cycle (None = unlimited). With APW a read costs about
        # 1-5 s while a listing costs milliseconds, so the daemon bounds reads and rotates them.
        self.read_budget = None
        self._read_deadline = None
        self._reads = self._deferred = 0
        self.report = self._new_report()

    def _new_report(self):
        return {'started': self.now(), 'dry_run': not self.apply, 'setup_done': self.state['setup_done'],
                'actions': [], 'errors': [], 'auth': {}, 'apple_progress': {}}

    # ------------------------------------------------------------------ helpers
    def comparable(self, login):
        """Values compared across sides. Websites compare by host; when the backend can only store
        one website, only the first one takes part and extra pass URLs stay pass-only."""
        urls = tuple(dict.fromkeys(normalize_domain(u) or u for u in login.urls))
        if urls and not self.apple.capabilities.urls_write:
            urls = urls[:1]
        return {'password': login.password, 'username': login.username, 'urls': urls or None,
                'notes': login.notes}

    def fps(self, login):
        return {f: self.fp(v) for f, v in self.comparable(login).items()}

    def _event(self, kind, link=None, **extra):
        entry = {'kind': kind, **({'link': link} if link else {}), **extra}
        if not self.apply:
            entry['dry_run'] = True
        self.report['actions'].append(entry)
        return entry

    def _error(self, side, reason, link=None):
        self.report['errors'].append({'side': side, 'reason': reason, **({'link': link} if link else {})})

    def _queue(self, kind, key, **data):
        """Add a needs-attention item once; ``key`` makes it idempotent across cycles."""
        for q in self.state['queue'].values():
            if q['key'] == key:
                return q['id']
        qid = _id('q')
        self.state['queue'][qid] = {'id': qid, 'kind': kind, 'key': key, 'time': self.now(), **data}
        self._event('queued', reason=kind, item=qid)
        return qid

    def _tombstone_pass(self, path, token, reason):
        if path and token:
            self.state['tombstones']['path:' + path] = {'time': self.now(), 'token': token, 'reason': reason}

    def _tombstone_apple(self, key, password_fp, reason):
        if key and password_fp:
            self.state['tombstones'][key] = {'time': self.now(), 'fp': password_fp, 'reason': reason}

    def _pass_tombstoned(self, path, token):
        t = self.state['tombstones'].get('path:' + path)
        if t and t.get('token') != token:
            # The path now holds different content: a new item, not the one that was removed.
            del self.state['tombstones']['path:' + path]
            return False
        return t is not None

    def _apple_tombstoned(self, account):
        t = self.state['tombstones'].get(account.key)
        if t is None:
            return False
        _, fps = self._apple_current(account, required=False)
        if fps and fps['password'] != t.get('fp'):
            del self.state['tombstones'][account.key]
            return False
        return True

    def account_of(self, link):
        return AppleAccount(domain=link['domain'], username=link['username'],
                            record_id=link.get('record_id'))

    def support(self, pass_login=None):
        caps = self.apple.capabilities
        support = {'password': 'synced', 'username': 'synced',
                   'urls': 'synced' if caps.urls_write else 'first website synced; extra pass URLs kept in pass',
                   'notes': 'synced' if caps.notes else 'Apple backend cannot read notes; pass notes kept'}
        if pass_login is not None and 'otp' in pass_login.unsupported:
            support['otp'] = 'kept in pass, not synced'
        return support

    # ------------------------------------------------------------------ pass side
    def pass_login(self, path):
        """(token, payload, login) with the token taken before decrypting, for compare-before-write."""
        token = self.pass_store.token(path)
        payload = self.pass_store.read(path)
        if payload is None:
            return None, None, None
        return token, payload, passfmt.parse(payload)

    def pass_identity(self, path, login):
        domain, username = login.domain, login.username
        inferred = False
        if (not domain or username is None) and self.cfg.infer_from_path:
            d, u = infer_identity(path)
            if not domain and d:
                domain, inferred = d, True
            if username is None and u is not None and d == domain:
                username, inferred = u, True
        return domain, username, inferred

    def _meta_for(self, path, login, token):
        domain, username, inferred = self.pass_identity(path, login)
        return {'token': token, 'domain': domain, 'username': username, 'inferred': inferred,
                'fps': self.fps(login), 'unsupported': list(login.unsupported)}

    def _scan_pass(self):
        excluded = set(self.state['excluded']['pass'])
        everything = self.pass_store.scan()
        self.all_pass_paths = set(everything)
        files = {p: i for p, i in everything.items() if self.cfg.pass_in_scope(p) and p not in excluded}
        # Paths outside the scope are never decrypted; only their names and ciphertext hashes are
        # used, to recognise a linked entry moved out of scope (`pass mv` into an excluded folder).
        self.outside = {p: i for p, i in everything.items() if p not in files}
        previous_outside = set(self.state.get('outside_paths', []))
        self.new_outside = set(self.outside) - previous_outside if 'outside_paths' in self.state else set()
        self.state['outside_paths'] = sorted(self.outside)
        meta = self.state['pass_meta']
        self.prev_meta = dict(meta)
        changed = self._changed = set()
        for path, info in files.items():
            m = meta.get(path)
            if m and m['token'] == info.token and ('fps' in m or 'error' in m):
                continue
            changed.add(path)
            try:
                token, _, login = self.pass_login(path)
                if login is None:
                    continue
                meta[path] = self._meta_for(path, login, token)
            except AuthRequired:
                raise
            except (BackendError, ValueError, UnicodeError):
                meta[path] = {'token': info.token, 'error': 'unreadable'}
                self._error('pass', 'entry unreadable or not a login')
        for path in list(meta):
            if path not in files:
                del meta[path]
        return files, changed

    # ------------------------------------------------------------------ Apple side
    def _poll_apple(self, files, changed):
        """Return ({domain: [accounts]}, failed_domains). Domains absent from both were not checked."""
        listed, failed = {}, set()
        if self.apple.capabilities.enumerate:
            for a in self.apple.list_all():
                listed.setdefault(a.domain, []).append(a)
            for l in self.state['links'].values():
                listed.setdefault(l['domain'], [])
            self.report['apple_progress'] = {'domains_checked': len(listed), 'domains_total': len(listed),
                                             'domains_pending': 0, 'rotation_cycles': 1}
            return listed, failed
        meta = self.state['pass_meta']
        domains = set(self.cfg.watch_domains) | set(self.state.get('watch_domains', []))
        domains |= {l['domain'] for l in self.state['links'].values()}
        domains |= {m['domain'] for p, m in meta.items() if p in files and m.get('domain')}
        domains |= {split_key(k)[0] for k in self.state['apple_seen']}
        domains = sorted(d for d in domains if d)
        # Websites with fresh pass changes or pending work are checked in every cycle.
        priority = {meta[p]['domain'] for p in changed if meta.get(p, {}).get('domain')}
        priority |= set(self.priority_domains)
        waiting = self._waiting_links()
        for l in self.state['links'].values():
            m = meta.get(l['pass_path'])
            if l['id'] not in waiting and (m is None or m.get('token') != l.get('pass_token')):
                priority.add(l['domain'])
        first = [d for d in domains if d in priority]
        rest = [d for d in domains if d not in priority]
        # Quick cycles (triggered by a pass change) only look at the websites that changed, so pass
        # edits reach Apple in seconds regardless of vault size. Regular cycles also rotate through
        # the rest, bounded by `apple_budget` lookups and `apple_cycle_seconds`.
        room = 0 if self.quick else max(1, self.cfg.apple_budget - len(first))
        cursor = self.state['domain_cursor'] % len(rest) if rest else 0
        rotation = (rest[cursor:] + rest[:cursor])[:room]
        deadline = time.monotonic() + self.cfg.apple_cycle_seconds
        checked = self.state.setdefault('checked_domains', {})
        rotated = 0
        for d in first + rotation:
            if d not in priority:
                # At least one rotating lookup per regular cycle, so the rotation never starves.
                if rotated and time.monotonic() > deadline:
                    break
                rotated += 1
            try:
                listed[d] = self.apple.list_domain(d)
                checked[d] = self.now()
            except AuthRequired:
                raise
            except BackendError:
                failed.add(d)
                self._error('apple', 'website lookup failed')
        if rest:
            self.state['domain_cursor'] = (cursor + rotated) % len(rest)
        domain_set = set(domains)
        for d in [d for d in checked if d not in domain_set]:
            del checked[d]
        # "pending" = websites never checked yet (initial discovery progress); a full rotation over
        # all websites takes `rotation_cycles` cycles when there are more than `apple_budget`.
        self.report['apple_progress'] = {
            'domains_checked': len(listed), 'domains_total': len(domains),
            'domains_pending': sum(1 for d in domains if d not in checked),
            'rotation_cycles': 1 + (len(rest) - 1) // max(rotated, 1) if rest else 1}
        return listed, failed

    def _apple_current(self, account, required=True):
        """(login or None, fps or None). Reuses cached fingerprints when the change stamp matches.

        ``required=False`` reads may be deferred (raise Deferred) once the cycle's read budget is
        spent; at least one read always happens per cycle so the rotation keeps moving."""
        seen = self.state['apple_seen'].get(account.key)
        if account.modified and seen and seen.get('modified') == account.modified and 'fps' in seen:
            return None, seen['fps']
        if (not required and self._read_deadline is not None and self._reads
                and time.monotonic() > self._read_deadline):
            self._deferred += 1
            raise Deferred('read budget used up')
        self._reads += 1
        login = self.apple.get(account)
        if login is None:
            return None, None
        fps = self.fps(login)
        self.state['apple_seen'][account.key] = {'modified': account.modified, 'fps': fps,
                                                 'read_at': self.now()}
        self._apple_logins[account.key] = login
        return login, fps

    def _apple_login(self, account):
        login = self._apple_logins.get(account.key) or self.apple.get(account)
        if login is None:
            raise Stale('Apple item disappeared')
        return login

    # ------------------------------------------------------------------ cycle
    def cycle(self, apply=True, priority_domains=(), quick=False):
        original = self.state
        self.quick = quick
        self.apply = apply and original['setup_done']
        if not self.apply:
            # Dry runs work on a throwaway copy so nothing they discover is persisted.
            self.state = copy.deepcopy(original)
        try:
            return self._cycle(priority_domains)
        finally:
            if self.state is not original:
                # Keep only the fingerprint caches from a dry run, so a following real run does
                # not have to decrypt every entry again. Entries the dry run saw change keep their
                # old cache, so the next real (or quick) cycle still treats them as changed.
                changed = getattr(self, '_changed', set())
                meta = {p: m for p, m in self.state['pass_meta'].items() if p not in changed}
                meta.update({p: m for p, m in original['pass_meta'].items() if p in changed})
                original['pass_meta'] = meta
                original['apple_seen'] = self.state['apple_seen']
            self.state = original

    def _cycle(self, priority_domains):
        self.priority_domains = tuple(priority_domains)
        self._apple_logins = {}
        self._actions = []
        self.report = self._new_report()
        try:
            files, changed = self._scan_pass()
            listed, failed = self._poll_apple(files, changed)
            self._process(files, listed, failed)
            self._execute()
        except AuthRequired as e:
            self.report['auth'][e.backend] = e.hint
        finally:
            self._apple_logins = {}
        self.report['finished'] = self.now()
        ok = not self.report['auth'] and not self.report['errors']
        if self.apply:
            self.state['last_cycle'] = {'time': self.report['finished'], 'ok': ok}
            if ok:
                self.state['last_success'] = self.report['finished']
            self.store.history_prune(self.state, self.cfg.history_retention_days, self.now())
        self.report['counts'] = self.counts()
        return self.report

    def counts(self):
        s = self.state
        statuses = {}
        for l in s['links'].values():
            statuses[l['status']] = statuses.get(l['status'], 0) + 1
        return {'linked': len(s['links']), 'by_status': statuses, 'conflicts': len(s['conflicts']),
                'deletions_pending': len(s['deletions']), 'queue': len(s['queue']),
                'plans_pending': len(s['plans'])}

    # ------------------------------------------------------------------ planning
    def _process(self, files, listed, failed):
        s = self.state
        links = s['links']
        by_path = {l['pass_path']: l for l in links.values()}
        by_identity = {identity_key(l['domain'], l['username']): l for l in links.values()}
        excluded_apple = set(s['excluded']['apple'])
        apple_accounts, seen = {}, set()
        for accounts in listed.values():
            for a in accounts:
                # The same login can come back from lookups of several related websites.
                if (a.key, a.sites, a.record_id) in seen:
                    continue
                seen.add((a.key, a.sites, a.record_id))
                if self.cfg.apple_in_scope(a.domain, a.group) and a.key not in excluded_apple:
                    apple_accounts.setdefault(a.key, []).append(a)

        # `pass mv`: a linked path vanished and exactly one new path holds the same ciphertext or,
        # because `pass mv` may re-encrypt, claims the same website and username.
        new_paths = [p for p in files if p not in by_path]
        meta = s['pass_meta']
        for link in list(links.values()):
            if link['pass_path'] in files:
                continue
            old = (self.prev_meta.get(link['pass_path']) or {}).get('token') or link.get('pass_token')
            candidates = [p for p in new_paths if files[p].token == old]
            if not candidates:
                ident = (link['domain'], link['username'])
                candidates = [p for p in new_paths
                              if (meta.get(p, {}).get('domain'), meta.get(p, {}).get('username')) == ident]
            if not candidates:
                moved_out = [p for p, i in self.outside.items() if i.token == old and p in self.new_outside]
                if len(moved_out) == 1:
                    self._event('unlinked-out-of-scope', link['id'])
                    if self.apply:
                        del links[link['id']]
                        del by_path[link['pass_path']]
                    continue
            if len(candidates) == 1:
                self._event('pass-renamed', link['id'])
                if self.apply:
                    del by_path[link['pass_path']]
                    link['pass_path'] = candidates[0]
                    by_path[candidates[0]] = link
                new_paths.remove(candidates[0])
            elif len(candidates) > 1:
                self._queue('ambiguous-rename', 'rename:' + link['id'], link=link['id'], paths=candidates)
                new_paths = [p for p in new_paths if p not in candidates]

        claimed = set()
        by_record = {a.record_id: a for accts in apple_accounts.values() for a in accts if a.record_id}
        self._read_deadline = time.monotonic() + self.read_budget if self.read_budget else None
        self._reads = self._deferred = 0
        seen = s['apple_seen']

        def urgent(l):
            m = meta.get(l['pass_path'])
            return (m is None or m.get('token') != l.get('pass_token') or l['status'] != 'ok'
                    or l['domain'] in self.priority_domains)
        # Links with pass-side changes first (always read), then the least recently read ones.
        ordered = sorted(links.values(), key=lambda l: (
            not urgent(l), seen.get(identity_key(l['domain'], l['username']), {}).get('read_at', 0)))
        for link in ordered:
            try:
                self._process_link(link, files, listed, failed, apple_accounts, by_record, claimed,
                                   required=urgent(link))
            except Deferred:
                continue
            except AuthRequired:
                raise
            except (BackendError, Stale, ValueError):
                link['status'] = 'error'
                self._error('link', 'lookup failed; baseline retained', link['id'])

        # Discovery of unlinked items on both sides.
        meta = s['pass_meta']
        queued_paths = {q.get('path') for q in s['queue'].values()}
        pass_by_identity, apple_by_identity = {}, {}
        for path in new_paths:
            m = meta.get(path)
            if not m or 'error' in m or path in queued_paths or self._pass_tombstoned(path, m['token']):
                continue
            if not m.get('domain') or m.get('username') is None:
                self._queue('missing-info', 'info:' + path, path=path)
                continue
            if self.cfg.apple_in_scope(m['domain']):
                pass_by_identity.setdefault(identity_key(m['domain'], m['username']), []).append(path)
        linked_records = {l['record_id'] for l in links.values() if l.get('record_id')}
        for key, accounts in apple_accounts.items():
            if key in by_identity or key in claimed:
                continue
            if any(a.record_id in linked_records for a in accounts if a.record_id):
                continue
            try:
                if any(self._apple_tombstoned(a) for a in accounts):
                    if key not in pass_by_identity:
                        continue
                    # The user re-created this login in pass: link it instead of re-creating Apple's.
                    s['tombstones'].pop(key, None)
            except (BackendError, Deferred):
                continue
            apple_by_identity[key] = accounts

        for key in sorted(set(pass_by_identity) | set(apple_by_identity)):
            paths = pass_by_identity.get(key, [])
            accounts = apple_by_identity.get(key, [])
            if key in by_identity:
                # A second pass entry claims an identity that is already linked (`pass cp`).
                for p in paths:
                    self._queue('duplicate-identity', 'dup:' + p, path=p, link=by_identity[key]['id'])
                continue
            if len(paths) > 1 or len(accounts) > 1:
                self._queue('duplicate-identity', 'dup:' + key, paths=paths, identity=key,
                            apple_records=len(accounts))
                continue
            try:
                self._discover(key, paths[0] if paths else None, accounts[0] if accounts else None,
                               listed, failed)
            except Deferred:
                continue
            except AuthRequired:
                raise
            except (BackendError, Stale, ValueError):
                self._error('discovery', 'lookup failed; will retry')
        self.report['apple_progress']['reads_deferred'] = self._deferred

    def _needs_review(self, key):
        return (self.cfg.new_items == 'review' and self.state['setup_done']
                and key not in self.state.get('accepted', []))

    def _discover(self, key, path, account, listed, failed):
        s = self.state
        if path and account:
            if self._needs_review('link:' + key):
                self._queue('confirm-link', 'link:' + key, path=path, identity=key)
                return
            _, apple_fps = self._apple_current(account, required=False)
            if apple_fps is None:
                return
            link = self.new_link(path, account, s['pass_meta'][path]['token'])
            self._plan('link', link, pass_fps=s['pass_meta'][path]['fps'], apple_fps=apple_fps)
            return
        if path:
            m = s['pass_meta'][path]
            if m['domain'] not in listed or m['domain'] in failed:
                return  # Website not checked yet; never create blindly.
            if not self.apple.capabilities.write:
                self._queue('apple-write-unavailable', 'nowrite:' + path, path=path)
                return
            if self._needs_review('create:' + path):
                self._queue('confirm-create', 'create:' + path, path=path, target='apple')
                return
            self._plan('create-apple', None, path=path, identity=(m['domain'], m['username']))
            return
        if self._needs_review('create:' + key):
            self._queue('confirm-create', 'create:' + key, identity=key, target='pass')
            return
        target = self.cfg.new_pass_path.format(domain=account.domain,
                                               username=account.username.replace('/', '_') or '_')
        if not self.cfg.pass_in_scope(target):
            self._queue('outside-pass-scope', 'scope:' + key, identity=key)
            return
        self._plan('create-pass', None, account=account, path=target)

    def new_link(self, path, account, pass_token):
        return {'id': _id('l'), 'pass_path': path, 'domain': account.domain,
                'username': account.username, 'record_id': account.record_id,
                'base': {f: None for f in FIELDS}, 'pass_token': pass_token, 'status': 'pending',
                'support': self.support(), 'notice': None, 'created': self.now()}

    def _waiting_links(self):
        s = self.state
        return ({c['link'] for c in s['conflicts'].values()} | {d['link'] for d in s['deletions'].values()})

    def _waiting(self, link):
        return link['id'] in self._waiting_links()

    def changed_since_base(self, fps, link):
        """True when any comparable field differs from the last synced value (not just the password)."""
        for f in FIELDS:
            if f == 'notes' and not self.apple.capabilities.notes:
                continue
            if fps.get(f) is not None and fps.get(f) != link['base'].get(f):
                return True
        return False

    def _out_of_scope(self, link, files):
        """A linked item that still exists but left the configured scope is unlinked, never deleted."""
        s = self.state
        key = identity_key(link['domain'], link['username'])
        pass_gone_from_scope = link['pass_path'] not in files and link['pass_path'] in self.all_pass_paths
        apple_gone_from_scope = not self.cfg.apple_in_scope(link['domain']) or key in s['excluded']['apple']
        if not (pass_gone_from_scope or apple_gone_from_scope):
            return False
        self._event('unlinked-out-of-scope', link['id'])
        if self.apply:
            del s['links'][link['id']]
        return True

    def _process_link(self, link, files, listed, failed, apple_accounts, by_record, claimed, required=True):
        key = identity_key(link['domain'], link['username'])
        if self._out_of_scope(link, files):
            return
        account = by_record.get(link['record_id']) if link.get('record_id') else None
        checked = (link['domain'] in listed and link['domain'] not in failed) or (
            self.apple.capabilities.enumerate and link['domain'] not in failed)
        if account is None and checked:
            account = next(iter(apple_accounts.get(key, [])), None)
        if account is None and checked and link.get('record_id') and not self.apple.capabilities.enumerate:
            # The record may have moved to another website; ask for it by id before calling it deleted.
            login = self.apple.get(self.account_of(link))
            if login is not None:
                domain = normalize_domain(login.urls[0]) if login.urls else link['domain']
                account = AppleAccount(domain=domain, username=login.username or '', record_id=link['record_id'])
                self._apple_logins[account.key] = login
        if account is not None:
            claimed.add(account.key)
        pending = [d for d in self.state['deletions'].values() if d['link'] == link['id']]
        for d in pending:
            back = link['pass_path'] in files if d['deleted_in'] == 'pass' else account is not None
            if back:
                # The "deleted" copy is there again: the deletion request no longer applies.
                del self.state['deletions'][d['id']]
                link['status'] = 'pending'
                self._event('deletion-withdrawn', link['id'])
        if self._waiting(link):
            return  # Waiting for the user; neither side is touched meanwhile.
        if link['domain'] in failed or (account is None and not checked):
            return  # Apple not checked this cycle; never read that as a deletion.
        pass_present = link['pass_path'] in files
        meta = self.state['pass_meta'].get(link['pass_path']) if pass_present else None
        if meta is not None and 'error' in meta:
            link['status'] = 'error'
            return
        if not pass_present and account is None:
            self._event('removed-both', link['id'])
            if self.apply:
                del self.state['links'][link['id']]
            return
        if not pass_present or account is None:
            self._deleted(link, 'pass' if not pass_present else 'apple', meta, account,
                          apple_accounts, claimed)
            return
        _, apple_fps = self._apple_current(account, required)
        if apple_fps is None:
            return  # Raced with a deletion; the next cycle decides.
        self._plan('sync', link, pass_fps=meta['fps'], apple_fps=apple_fps, account=account)

    def _deleted(self, link, side, meta, account, apple_accounts, claimed):
        s = self.state
        if side == 'apple' and not self.apple.capabilities.record_ids:
            # Without record ids an Apple username edit looks like delete + create. Suggest a relink
            # (never apply one) when exactly one unclaimed account on that website has the last
            # synced password.
            linked = {identity_key(l['domain'], l['username']) for l in s['links'].values()}
            matching = []
            for k, accts in apple_accounts.items():
                for a in accts:
                    if a.domain == link['domain'] and k not in linked and k not in claimed:
                        _, fps = self._apple_current(a, required=False)
                        if fps and fps['password'] == link['base'].get('password'):
                            matching.append(a)
            if len(matching) == 1:
                claimed.add(matching[0].key)
                self._queue('relink-suggested', 'relink:' + link['id'], link=link['id'],
                            identity=matching[0].key)
                link['status'] = 'needs-review'
                return
        if side == 'pass':
            _, other = self._apple_current(account)
        else:
            other = meta['fps']
        modified = other is not None and self.changed_since_base(other, link)
        policy = self.cfg.deletion_policy
        if side == 'pass' and self.new_outside and policy != 'keep':
            # Something appeared outside the scope in the same cycle; this may be a `pass mv` out of
            # scope that re-encrypted the file. Never delete automatically in that case.
            policy = 'ask'
        if policy == 'keep':
            self._event('unlinked-after-delete', link['id'], side=side)
            if self.apply:
                self._tombstone_pass(link['pass_path'], meta and meta['token'], 'deleted in Apple; kept')
                self._tombstone_apple(identity_key(link['domain'], link['username']),
                                      other and other['password'] if side == 'pass' else None,
                                      'deleted in pass; kept')
                del s['links'][link['id']]
            return
        if policy == 'ask' or modified:
            if any(d['link'] == link['id'] for d in s['deletions'].values()):
                return
            did = _id('d')
            s['deletions'][did] = {'id': did, 'link': link['id'], 'deleted_in': side,
                                   'other_modified': modified, 'time': self.now()}
            link['status'] = 'deletion-pending'
            self._event('deletion-pending', link['id'], side=side, deletion=did)
            return
        self._plan('delete-' + ('apple' if side == 'pass' else 'pass'), link)

    def _plan(self, kind, link, **data):
        self._actions.append({'kind': kind, 'link': link, **data})

    # ------------------------------------------------------------------ merge
    def merge(self, link, pass_fps, apple_fps):
        """Three-way merge on fingerprints. Returns (to_pass, to_apple, conflicts, new_base)."""
        caps = self.apple.capabilities
        to_pass, to_apple, conflicts, base = [], [], [], dict(link['base'])
        for f in FIELDS:
            p, a, b = pass_fps.get(f), apple_fps.get(f), link['base'].get(f)
            if f == 'notes' and not caps.notes:
                continue
            if p is None or a is None:
                # One side cannot represent the field. Never erase; fill pass metadata from Apple.
                if p is None and a is not None and f in ('urls', 'notes'):
                    to_pass.append(f)
                continue
            if p == a:
                base[f] = p
            elif b is not None and p == b:
                to_pass.append(f)
            elif b is not None and a == b:
                to_apple.append(f)
            else:
                conflicts.append(f)
        return to_pass, to_apple, conflicts, base

    # ------------------------------------------------------------------ execution
    def action_key(self, action):
        """Identifies one specific change: kind, target, direction, and the values involved, so an
        approval can never authorise a different change to the same item later."""
        link = action.get('link')
        parts = [action['kind'], action.get('path') or (link and link['id'])]
        if action['kind'] == 'sync':
            to_pass, to_apple, _ = action['merge']
            parts += [','.join(to_pass), ','.join(to_apple),
                      self.fp([action['pass_fps'], action['apple_fps'], link['base']])]
        elif link is not None:
            parts.append(self.fp(link['base']))
        return ':'.join(str(p) for p in parts)

    def _execute(self):
        s = self.state
        destructive = []
        for action in self._actions:
            if action['kind'].startswith('delete-'):
                destructive.append(action)
            elif action['kind'] == 'sync':
                to_pass, to_apple, conflicts, _ = self.merge(action['link'], action['pass_fps'],
                                                             action['apple_fps'])
                action['merge'] = (to_pass, to_apple, conflicts)
                if (to_pass or to_apple) and not conflicts:
                    destructive.append(action)
        approved = set(s['approved'])  # single-use keys; see action_key
        guarded = [a for a in destructive if self.action_key(a) not in approved]
        held = set()
        if len(guarded) > self.cfg.bulk_threshold:
            keys = sorted(self.action_key(a) for a in guarded)
            if self.apply and not any(p['keys'] == keys for p in s['plans'].values()):
                pid = _id('p')
                s['plans'][pid] = {'id': pid, 'keys': keys, 'time': self.now(), 'summary': summarize(guarded)}
                self._event('plan-pending', plan=pid, size=len(keys))
            held = {id(a) for a in guarded}
        for action in self._actions:
            if id(action) in held:
                self._event('held-for-approval', action['link'] and action['link']['id'])
                continue
            key = self.action_key(action)
            link = action.get('link')
            try:
                getattr(self, '_do_' + action['kind'].replace('-', '_'))(action)
                if key in approved and self.apply:
                    s['approved'].remove(key)
            except AuthRequired:
                raise
            except (Stale, BackendError, ValueError, PassRelayError) as e:
                if link is not None and link['id'] in s['links']:
                    link['status'] = 'error'
                self._error('apply', 'changed during sync; retrying next cycle' if isinstance(e, Stale)
                            else 'write failed; baseline retained', link and link['id'])

    def _do_link(self, action):
        link, pf, af = action['link'], action['pass_fps'], action['apple_fps']
        self._event('link', link['id'])
        if not self.apply:
            _, _, conflicts, _ = self.merge(link, pf, af)
            if conflicts:
                self._event('conflict', link['id'], fields=conflicts)
            return
        self.state['links'][link['id']] = link
        to_pass, to_apple, conflicts, base = self.merge(link, pf, af)
        link['base'] = base
        if conflicts:
            self.add_conflict(link, 'initial', conflicts, pf, af)
        elif to_pass or to_apple:
            self._do_sync({'link': link, 'pass_fps': pf, 'apple_fps': af, 'account': self.account_of(link),
                           'merge': (to_pass, to_apple, conflicts)})
        else:
            link['status'] = 'ok'

    def add_conflict(self, link, kind, fields, pass_fps, apple_fps):
        for c in self.state['conflicts'].values():
            if c['link'] == link['id']:
                c.update(fields=fields, pass_fps=pass_fps, apple_fps=apple_fps)
                return c['id']
        cid = _id('c')
        self.state['conflicts'][cid] = {'id': cid, 'link': link['id'], 'kind': kind, 'fields': fields,
                                        'pass_fps': pass_fps, 'apple_fps': apple_fps, 'time': self.now()}
        link['status'] = 'conflict'
        self._event('conflict', link['id'], fields=fields, conflict=cid)
        return cid

    def _do_sync(self, action):
        link, account = action['link'], action['account']
        to_pass, to_apple, conflicts = action['merge']
        if conflicts:
            if self.apply:
                self.add_conflict(link, 'both-changed', conflicts, action['pass_fps'], action['apple_fps'])
            else:
                self._event('conflict', link['id'], fields=conflicts)
            return
        if not to_pass and not to_apple:
            if self.apply:
                link['base'] = self.merge(link, action['pass_fps'], action['apple_fps'])[3]
                link['pass_token'] = self.state['pass_meta'][link['pass_path']]['token']
                link['status'] = 'manual-action' if link.get('notice') else 'ok'
            return
        self._event('update', link['id'], to_pass=to_pass, to_apple=to_apple)
        if not self.apply:
            return
        token, payload, pass_login = self.pass_login(link['pass_path'])
        if payload is None or self.fps(pass_login) != action['pass_fps']:
            raise Stale('pass entry changed')
        # Fresh read, never the copy cached during planning: this is the compare-before-write.
        apple_login = self.apple.get(account)
        if apple_login is None or self.fps(apple_login) != action['apple_fps']:
            raise Stale('Apple item changed')
        if to_apple:
            target = apple_login.with_fields(**{f: pass_login.get(f) for f in to_apple})
            self.store.history_add(self.state, {'action': 'update', 'link': link['id'], 'side': 'apple',
                                                'domain': link['domain'], 'username': link['username'],
                                                'before': login_dict(apple_login)})
            new_domain = normalize_domain(target.urls[0]) if target.urls else link['domain']
            if (new_domain, target.username) != (link['domain'], link['username']):
                self._change_apple_identity(link, account, target, (new_domain, target.username))
            else:
                rid = self.apple.put(link['domain'], link['username'], target, link.get('record_id'))
                link['record_id'] = rid or link.get('record_id')
        if to_pass:
            updates = {f: apple_login.get(f) for f in to_pass}
            if 'urls' in updates:
                urls = with_scheme(apple_login.urls)
                if not self.apple.capabilities.urls_write:
                    # Replace only the first website; keep extra pass URLs.
                    urls = urls[:1] + tuple(u for u in pass_login.urls[1:] if u not in urls[:1])
                updates['urls'] = urls
            new_payload = passfmt.render(payload, pass_login.with_fields(**updates), set(to_pass))
            self.write_pass(link, link['pass_path'], new_payload, payload, token, 'update')
            if 'username' in to_pass or 'urls' in to_pass:
                link['username'] = apple_login.username
                link['domain'] = normalize_domain(apple_login.urls[0]) if apple_login.urls else link['domain']
        self._finish_link(link, set(to_pass) | set(to_apple), apple_written=bool(to_apple))

    def _finish_link(self, link, fields, apple_written=False):
        """Re-read both sides, verify the written fields agree, then advance the baseline.

        Apple Passwords asks the user to confirm a save ("Save password?"), so after an Apple write
        the result is re-read until it appears or ``apple_confirm_seconds`` pass."""
        token, _, pass_login = self.pass_login(link['pass_path'])
        if pass_login is None:
            raise BackendError('item missing after write')
        pf = self.fps(pass_login)
        deadline = time.monotonic() + (self.cfg.apple_confirm_seconds if apple_written else 0)

        def agrees(af):
            # A field one side cannot hold (None) is not compared, e.g. a username inferred from the path.
            return all(pf[f] == af[f] for f in fields if pf[f] is not None and af[f] is not None)
        while True:
            apple_login = self.apple.get(self.account_of(link))
            af = self.fps(apple_login) if apple_login is not None else None
            if af is not None and agrees(af):
                break
            if time.monotonic() >= deadline:
                if apple_written:
                    raise BackendError('Apple Passwords did not show the saved value; was "Save" confirmed?')
                raise BackendError('write verification failed')
            time.sleep(2)
        _, _, _, link['base'] = self.merge(link, pf, af)
        link['pass_token'] = token
        link['support'] = self.support(pass_login)
        link['status'] = 'manual-action' if link.get('notice') else 'ok'
        self.state['pass_meta'][link['pass_path']] = self._meta_for(link['pass_path'], pass_login, token)
        self.state['apple_seen'].pop(identity_key(link['domain'], link['username']), None)

    def _change_apple_identity(self, link, account, target, new_identity):
        caps = self.apple.capabilities
        new_domain, new_username = new_identity
        new_key = identity_key(new_domain, new_username)
        if any(identity_key(l['domain'], l['username']) == new_key for l in self.state['links'].values()):
            self._queue('identity-collision', 'collide:' + link['id'], link=link['id'], identity=new_key)
            raise Stale('target identity already linked')
        if caps.rename and new_domain == link['domain']:
            self.apple.rename(account, new_username)
            if target.password != self.apple.get(AppleAccount(new_domain, new_username,
                                                              record_id=link.get('record_id'))).password:
                self.apple.put(new_domain, new_username, target, link.get('record_id'))
        else:
            if self.apple.get(AppleAccount(domain=new_domain, username=new_username)) is not None:
                self._queue('identity-collision', 'collide:' + link['id'], link=link['id'], identity=new_key)
                raise Stale('target identity exists in Apple Passwords')
            link['record_id'] = self.apple.put(new_domain, new_username, target)
            old_key = identity_key(link['domain'], link['username'])
            if caps.delete:
                self.apple.delete(account)
            else:
                link['notice'] = 'old Apple login kept after rename; delete it in the Passwords app'
                self._queue('apple-delete-manual', 'manual:' + old_key, identity=old_key, link=link['id'])
            self._tombstone_apple(old_key, link['base'].get('password'), 'renamed in pass')
        self._event('apple-identity-changed', link['id'])
        link['domain'], link['username'] = new_domain, new_username

    def write_pass(self, link, path, new_payload, old_payload, expected_token, action):
        if self.pass_store.token(path) != expected_token:
            raise Stale('pass entry changed')
        self.store.history_add(self.state, {'action': action, 'link': link and link['id'], 'side': 'pass',
                                            'path': path, 'before': old_payload})
        self.pass_store.write(path, new_payload)
        if self.pass_store.read(path) != new_payload:
            raise BackendError('pass write verification failed')

    def _do_create_apple(self, action):
        path = action['path']
        domain, username = action['identity']
        self._event('create-apple', path=path)
        if not self.apply:
            return
        token, payload, login = self.pass_login(path)
        if login is None or token != self.state['pass_meta'][path]['token']:
            raise Stale('pass entry changed')
        account = AppleAccount(domain=domain, username=username)
        if self.apple.get(account) is not None:
            raise Stale('Apple login appeared meanwhile')
        self.store.history_add(self.state, {'action': 'create', 'side': 'apple', 'path': path,
                                            'domain': domain, 'username': username, 'before': None})
        rid = self.apple.put(domain, username, login.with_fields(username=username))
        link = self.new_link(path, AppleAccount(domain=domain, username=username, record_id=rid), token)
        self.state['links'][link['id']] = link
        try:
            self._finish_link(link, {'password', 'username'}, apple_written=True)
        except BackendError:
            # Not confirmed in Apple Passwords: no link, so this is never mistaken for a deletion.
            # If the save is confirmed later, discovery links both copies.
            del self.state['links'][link['id']]
            raise

    def _do_create_pass(self, action):
        account = action['account']
        self._event('create-pass', path=action['path'])
        if not self.apply:
            return
        login = self._apple_login(account)
        path = self.pass_store.free_path(action['path'])
        pass_login = login.with_fields(urls=with_scheme(login.urls or (account.domain,)),
                                       username=account.username, unsupported=())
        payload = passfmt.render(None, pass_login, {'password', 'username', 'urls', 'title', 'notes'})
        link = self.new_link(path, account, None)
        self.write_pass(link, path, payload, None, None, 'create')
        self.state['links'][link['id']] = link
        self._finish_link(link, {'password', 'username'})

    def _do_delete_apple(self, action):
        self._event('delete-apple', action['link']['id'])
        if self.apply:
            self.delete_side(action['link'], 'apple')

    def _do_delete_pass(self, action):
        self._event('delete-pass', action['link']['id'])
        if self.apply:
            self.delete_side(action['link'], 'pass')

    def delete_side(self, link, side):
        """Delete one side of a link after re-checking it still matches the baseline."""
        s = self.state
        key = identity_key(link['domain'], link['username'])
        if side == 'apple':
            account = self.account_of(link)
            current = self.apple.get(account)
            if current is not None:
                if self.changed_since_base(self.fps(current), link):
                    raise Stale('Apple item changed since last sync; not deleting')
                self.store.history_add(s, {'action': 'delete', 'link': link['id'], 'side': 'apple',
                                           'domain': link['domain'], 'username': link['username'],
                                           'before': login_dict(current)})
                if self.apple.capabilities.delete:
                    self.apple.delete(account)
                    if self.apple.get(account) is not None:
                        raise BackendError('Apple delete verification failed')
                else:
                    self._tombstone_apple(key, link['base'].get('password'), 'delete in Passwords app')
                    self._queue('apple-delete-manual', 'manual:' + key, identity=key)
        else:
            token, payload, login = self.pass_login(link['pass_path'])
            if payload is not None:
                if self.changed_since_base(self.fps(login), link):
                    raise Stale('pass entry changed since last sync; not deleting')
                self.store.history_add(s, {'action': 'delete', 'link': link['id'], 'side': 'pass',
                                           'path': link['pass_path'], 'before': payload})
                self.pass_store.delete(link['pass_path'])
                if self.pass_store.token(link['pass_path']) is not None:
                    raise BackendError('pass delete verification failed')
        s['links'].pop(link['id'], None)
        s['pass_meta'].pop(link['pass_path'], None)
        self._event('deleted', link['id'], side=side)

    # ------------------------------------------------------------------ user decisions
    def _find(self, table, ref):
        item = self.state[table].get(ref)
        if item is None:
            raise ConfigError(f'unknown {table[:-1]} id')
        return item

    def resolve_conflict(self, cid, keep):
        """Keep one side's values for the conflicting fields and write them to the other side."""
        if keep not in ('pass', 'apple'):
            raise ConfigError('keep must be pass or apple')
        c = self._find('conflicts', cid)
        link = self.state['links'][c['link']]
        token, payload, pass_login = self.pass_login(link['pass_path'])
        apple_login = self.apple.get(self.account_of(link))
        if pass_login is None or apple_login is None:
            raise Stale('an item disappeared; run sync again')
        pf, af = self.fps(pass_login), self.fps(apple_login)
        if pf != c['pass_fps'] or af != c['apple_fps']:
            # Values moved on since the conflict was recorded; refuse rather than overwrite them.
            del self.state['conflicts'][cid]
            link['status'] = 'pending'
            raise Stale('values changed since the conflict was recorded; run sync to re-evaluate')
        loser = af if keep == 'pass' else pf
        for f in c['fields']:
            link['base'][f] = loser[f]
        del self.state['conflicts'][cid]
        self.apply = True
        self._apple_logins = {self.account_of(link).key: apple_login}
        to_pass, to_apple, conflicts, _ = self.merge(link, pf, af)
        self._do_sync({'link': link, 'account': self.account_of(link), 'pass_fps': pf, 'apple_fps': af,
                       'merge': (to_pass, to_apple, conflicts)})
        return link['id']

    def resolve_deletion(self, did, approve):
        """approve=True deletes the surviving side; False restores the deleted side from it."""
        d = self._find('deletions', did)
        link = self.state['links'][d['link']]
        self.apply = True
        if d['deleted_in'] == 'pass':
            back = self.pass_store.token(link['pass_path']) is not None
        else:
            back = self.apple.get(self.account_of(link)) is not None
        if back:
            del self.state['deletions'][did]
            link['status'] = 'pending'
            raise Stale('the deleted copy exists again; nothing to approve. Run sync to re-evaluate')
        if approve:
            self.delete_side(link, 'apple' if d['deleted_in'] == 'pass' else 'pass')
        elif d['deleted_in'] == 'pass':
            login = self.apple.get(self.account_of(link))
            if login is None:
                raise Stale('Apple item is gone too')
            pass_login = login.with_fields(urls=with_scheme(login.urls), unsupported=())
            payload = passfmt.render(None, pass_login, {'password', 'username', 'urls', 'title', 'notes'})
            self.write_pass(link, link['pass_path'], payload, None, None, 'restore')
            self._finish_link(link, {'password'})
        else:
            _, _, login = self.pass_login(link['pass_path'])
            if login is None:
                raise Stale('pass entry is gone too')
            self.store.history_add(self.state, {'action': 'restore', 'link': link['id'], 'side': 'apple',
                                                'domain': link['domain'], 'username': link['username'],
                                                'before': None})
            link['record_id'] = self.apple.put(link['domain'], link['username'],
                                               login.with_fields(username=link['username']))
            self._finish_link(link, {'password'}, apple_written=True)
        del self.state['deletions'][did]
        return link['id']

    def approve_plan(self, pid):
        plan = self._find('plans', pid)
        self.state['approved'] = sorted(set(self.state['approved']) | set(plan['keys']))
        del self.state['plans'][pid]

    def reject_plan(self, pid):
        self._find('plans', pid)
        del self.state['plans'][pid]

    def accept_queue(self, qid, path=None):
        q = self._find('queue', qid)
        s = self.state
        kind = q['kind']
        if kind in ('confirm-link', 'confirm-create'):
            s.setdefault('accepted', []).append(q['key'])
        elif kind == 'relink-suggested':
            link = s['links'][q['link']]
            domain, username = split_key(q['identity'])
            link['domain'], link['username'], link['status'] = domain, username, 'pending'
            # Pass still holds the old username; with the baseline at the old value the next merge
            # copies the Apple username into pass instead of reporting a conflict.
        elif kind == 'ambiguous-rename':
            if path not in q['paths']:
                raise ConfigError('choose one of the candidate paths with --path')
            s['links'][q['link']]['pass_path'] = path
        elif kind in ('apple-delete-manual', 'apple-write-unavailable', 'outside-pass-scope',
                      'identity-collision', 'duplicate-identity', 'missing-info'):
            pass  # Acknowledge; the underlying condition is re-detected if it persists.
        else:
            raise ConfigError('unknown queue item kind')
        del s['queue'][qid]

    def link_manually(self, path, domain, username):
        """Explicitly link a pass entry to an Apple identity; the next cycle merges them."""
        s = self.state
        domain = normalize_domain(domain)
        if not domain:
            raise ConfigError('invalid website')
        key = identity_key(domain, username)
        if any(l['pass_path'] == path or identity_key(l['domain'], l['username']) == key
               for l in s['links'].values()):
            raise ConfigError('path or identity already linked')
        token = self.pass_store.token(path)
        if token is None:
            raise ConfigError('no such pass entry')
        link = self.new_link(path, AppleAccount(domain=domain, username=username), token)
        s['links'][link['id']] = link
        s['tombstones'].pop(key, None)
        s['tombstones'].pop('path:' + path, None)
        for qid in [k for k, q in s['queue'].items() if q.get('path') == path]:
            del s['queue'][qid]
        return link['id']

    def unlink(self, link_id, exclude=False):
        s = self.state
        link = self._find('links', link_id)
        if exclude:
            s['excluded']['pass'] = sorted(set(s['excluded']['pass']) | {link['pass_path']})
            s['excluded']['apple'] = sorted(set(s['excluded']['apple'])
                                            | {identity_key(link['domain'], link['username'])})
        else:
            token = self.pass_store.token(link['pass_path']) or link.get('pass_token')
            try:
                current = self.apple.get(self.account_of(link))
                apple_fp = self.fps(current)['password'] if current else None
            except PassRelayError:
                apple_fp = None
            self._tombstone_pass(link['pass_path'], token, 'unlinked')
            self._tombstone_apple(identity_key(link['domain'], link['username']),
                                  apple_fp or link['base'].get('password'), 'unlinked')
        for table in ('conflicts', 'deletions'):
            for k in [k for k, v in s[table].items() if v['link'] == link_id]:
                del s[table][k]
        del s['links'][link_id]


def summarize(actions):
    out = {}
    for a in actions:
        kind = a['kind']
        if kind == 'sync':
            to_pass, to_apple, _ = a['merge']
            kind = 'overwrite-pass' if to_pass else 'overwrite-apple'
        out[kind] = out.get(kind, 0) + 1
    return out
