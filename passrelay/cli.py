"""`passrelay` command line. The JSON contract is documented in docs/CLI.md."""
import argparse
import csv
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from . import __version__, app, config as config_mod, daemon as daemon_mod, doctor, passfmt, service
from . import status as status_mod
from .apple.apw import ApwBackend
from .errors import (EXIT_ATTENTION, EXIT_ERROR, EXIT_OK, EXIT_USAGE, AuthRequired, ConfigError,
                     PassRelayError, Stale)
from .keystore import keystore_for
from .model import Login, normalize_domain
from .engine import split_key, login_dict
from .state import secure_dir


# ---------------------------------------------------------------------- output helpers
class Out:
    def __init__(self, as_json):
        self.json = as_json

    def emit(self, obj, human=None, code=EXIT_OK):
        if self.json:
            print(json.dumps({'ok': True, **obj}, indent=None, sort_keys=False))
        elif human is not None:
            text = human(obj) if callable(human) else human
            if text:
                print(text)
        return code


def mask(value, keep=2):
    if value is None:
        return None
    if '.' in value and normalize_domain(value) == value:
        head, _, tld = value.rpartition('.')
        return head[:keep] + '*' * max(0, len(head) - keep) + '.' + tld
    return value[:keep] + '*' * max(0, len(value) - keep)


def mask_path(path):
    parts = path.split('/')
    return '/'.join([parts[0]] + [mask(p) for p in parts[1:]]) if len(parts) > 1 else mask(path)


def names(link, reveal):
    if not link:
        return {}
    if reveal:
        return {'pass_path': link['pass_path'], 'site': link['domain'], 'username': link['username']}
    return {'pass_path': mask_path(link['pass_path']), 'site': mask(link['domain']),
            'username': mask(link['username'])}


def ago(ts):
    if not ts:
        return 'never'
    s = int(time.time() - ts)
    for unit, size in (('d', 86400), ('h', 3600), ('m', 60)):
        if s >= size:
            return f'{s // size}{unit} ago'
    return f'{s}s ago'


def table(rows, columns):
    if not rows:
        return '(none)'
    widths = [max(len(c), *(len(str(r.get(c, '') or '')) for r in rows)) for c in columns]
    lines = ['  '.join(c.upper().ljust(w) for c, w in zip(columns, widths))]
    for r in rows:
        lines.append('  '.join(str(r.get(c, '') or '').ljust(w) for c, w in zip(columns, widths)))
    return '\n'.join(lines)


def report_text(report):
    lines = []
    if report.get('dry_run'):
        lines.append('Plan only; nothing was written.' if report.get('setup_done')
                     else 'Initial plan (run `passrelay setup --apply` to perform it):')
    kinds = {}
    for a in report['actions']:
        kinds[a['kind']] = kinds.get(a['kind'], 0) + 1
    for k, n in sorted(kinds.items()):
        lines.append(f'  {k}: {n}')
    if not kinds:
        lines.append('  no changes')
    for backend, hint in report.get('auth', {}).items():
        lines.append(f'! {backend}: {hint}')
    if report.get('errors'):
        lines.append(f'! {len(report["errors"])} item(s) failed and will be retried')
    progress = report.get('apple_progress') or {}
    if progress.get('domains_pending'):
        lines.append(f'  {progress["domains_pending"]} website(s) still to check in later cycles')
    c = report.get('counts') or {}
    attention = sum(c.get(k, 0) for k in ('conflicts', 'deletions_pending', 'queue', 'plans_pending'))
    if attention:
        lines.append(f'  {attention} item(s) need attention: see `passrelay conflicts`, `deletions`, '
                     '`queue`, `plans`')
    return '\n'.join(lines)


def report_code(report):
    if report.get('auth'):
        return 4
    c = report.get('counts') or {}
    if any(c.get(k) for k in ('conflicts', 'deletions_pending', 'queue', 'plans_pending')):
        return EXIT_ATTENTION
    return EXIT_ERROR if report.get('errors') else EXIT_OK


# ---------------------------------------------------------------------- commands
def cmd_setup(args, out):
    path = Path(args.config or config_mod.default_config_path()).expanduser()
    try:
        cfg = config_mod.load(path)
    except ConfigError:
        cfg = config_mod.Config()
    if args.pass_store:
        cfg.pass_store = args.pass_store
    if args.apple_backend:
        cfg.apple_backend = args.apple_backend
    if args.bridge_command:
        try:
            cfg.bridge_command = json.loads(args.bridge_command)
        except ValueError:
            raise ConfigError('--bridge-command must be a JSON array') from None
    if args.include:
        cfg.pass_include = args.include
    if args.exclude:
        cfg.pass_exclude = args.exclude
    if args.watch_domain:
        cfg.watch_domains = sorted(set(cfg.watch_domains) | {normalize_domain(d) for d in args.watch_domain
                                                              if normalize_domain(d)})
    for name in ('new_items', 'deletion_policy', 'key_store', 'state_dir'):
        if getattr(args, name, None):
            setattr(cfg, name, getattr(args, name))
    cfg.validate()
    secure_dir(cfg.state_dir)
    config_mod.save(cfg, path)
    keystore_for(cfg).load(create=True)
    imported = 0
    with app.session(cfg) as engine:
        if args.import_apple_csv:
            domains = read_apple_export(args.import_apple_csv)
            engine.state['watch_domains'] = sorted(set(engine.state.get('watch_domains', [])) | domains)
            imported = len(domains)
        if args.apply:
            engine.state['setup_done'] = True
        report = engine.cycle(apply=bool(args.apply))
        status_mod.publish(engine.store, engine, report)
    daemon_mod.notify_daemon(engine.store)

    def human(o):
        head = f'Configuration: {path}'
        if imported:
            head += f'\nLearned {imported} website(s) from the Apple export. Delete that file now.'
        return head + '\n' + report_text(report)
    return out.emit({'config': str(path), 'applied': bool(args.apply), 'imported_websites': imported,
                     'report': report}, human, report_code(report) if args.apply else EXIT_OK)


def read_apple_export(path):
    """Read only the URL column of a Passwords export. Password cells are never stored."""
    domains = set()
    with open(Path(path).expanduser(), newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or not any(h.lower() == 'url' for h in reader.fieldnames):
            raise ConfigError('not a Passwords export: URL column missing')
        url_col = next(h for h in reader.fieldnames if h.lower() == 'url')
        for row in reader:
            host = normalize_domain(row.get(url_col) or '')
            if host:
                domains.add(host)
            row.clear()
    return domains


def cmd_status(args, out):
    try:
        cfg = config_mod.load(args.config)
    except ConfigError as e:
        result = {'setup_done': False, 'paused': False, 'daemon': {'running': False, 'pid': None},
                  'service': {'installed': False}, 'last_success': None, 'last_cycle': None,
                  'auth': {'apple': None, 'gpg': None, 'keychain': None}, 'counts': {},
                  'apple_progress': {}, 'attention': 1, 'state': 'not-setup', 'updated': None,
                  'message': str(e)}
        return out.emit(result, f'State: not-setup ({e})', EXIT_ATTENTION)
    store = status_store(cfg)
    result, code = status_mod.summarize(store, service.status()['installed'] if sys.platform == 'darwin'
                                        else False)

    def human(o):
        lines = [f'State: {o["state"]}', f'Last successful sync: {ago(o["last_success"])}',
                 f'Daemon: {"running" if o["daemon"]["running"] else "not running"}'
                 + (' (paused)' if o['paused'] else '')]
        c = o['counts']
        if c:
            lines.append(f'Linked: {c.get("linked", 0)}  conflicts: {c.get("conflicts", 0)}  '
                         f'deletions: {c.get("deletions_pending", 0)}  queue: {c.get("queue", 0)}  '
                         f'plans: {c.get("plans_pending", 0)}')
        p = o['apple_progress']
        if p.get('domains_pending'):
            lines.append(f'Apple: {p["domains_pending"]} website(s) waiting to be checked')
        for k, v in o['auth'].items():
            if v:
                lines.append(f'! {k}: {v}')
        return '\n'.join(lines)
    return out.emit(result, human, code)


def status_store(cfg):
    """A StateStore usable without the key, for reading the plaintext status/control files."""
    from .state import StateStore
    return StateStore(cfg.state_dir, None)


def cmd_sync(args, out):
    with app.session(config_path=args.config, save=not args.dry_run) as engine:
        # A manual sync may read for longer than a background cycle, but stays bounded.
        engine.read_budget = engine.cfg.apple_cycle_seconds * 4
        report = engine.cycle(apply=not args.dry_run)
        if not args.dry_run:
            status_mod.publish(engine.store, engine, report)
    return out.emit({'report': report}, report_text(report), report_code(report))


def cmd_pause(args, out, paused):
    cfg = config_mod.load(args.config)
    store = status_store(cfg)
    store.set_control(paused=paused)
    daemon_mod.notify_daemon(store)
    return out.emit({'paused': paused}, 'Paused.' if paused else 'Resumed.')


def cmd_items(args, out):
    with app.session(config_path=args.config, save=args.action is not None) as engine:
        s = engine.state
        if args.action == 'exclude':
            engine.unlink(args.id, exclude=True)
            return out.emit({'excluded': args.id}, 'Excluded; both copies are kept.')
        if args.action == 'unlink':
            engine.unlink(args.id)
            return out.emit({'unlinked': args.id}, 'Unlinked; both copies are kept.')
        if args.action == 'include':
            if not args.path:
                raise ConfigError('--path is required')
            s['excluded']['pass'] = [p for p in s['excluded']['pass'] if p != args.path]
            return out.emit({'included': args.path}, 'Included again.')
        if args.action == 'link':
            if not (args.path and args.site and args.username is not None):
                raise ConfigError('--path, --site, and --username are required')
            lid = engine.link_manually(args.path, args.site, args.username)
            return out.emit({'link': lid}, f'Linked as {lid}; the next sync merges both sides.')
        items = []
        for l in s['links'].values():
            if args.status and l['status'] != args.status:
                continue
            items.append({'id': l['id'], **names(l, args.names), 'status': l['status'],
                          'notice': l.get('notice'), 'support': l.get('support') or engine.support()})
        result = {'items': items, 'excluded': {k: len(v) for k, v in s['excluded'].items()}}
    return out.emit(result, lambda o: table(o['items'], ['id', 'pass_path', 'site', 'username', 'status']))


def _with_link(engine, entry, reveal):
    return {**entry, **names(engine.state['links'].get(entry.get('link')), reveal)}


def cmd_conflicts(args, out):
    with app.session(config_path=args.config, save=False) as engine:
        s = engine.state
        if args.action == 'show':
            c = s['conflicts'].get(args.id)
            if c is None:
                raise ConfigError('unknown conflict id')
            result = {'conflict': _with_link(engine, c, args.reveal or args.names)}
            result['conflict'].pop('pass_fps', None)
            result['conflict'].pop('apple_fps', None)
            if args.reveal:
                link = s['links'][c['link']]
                _, _, pass_login = engine.pass_login(link['pass_path'])
                apple_login = engine.apple.get(engine.account_of(link))
                result['values'] = {
                    'pass': login_dict(pass_login) if pass_login else None,
                    'apple': login_dict(apple_login) if apple_login else None}
            return out.emit(result, lambda o: json.dumps(o, indent=2))
        rows = []
        for c in s['conflicts'].values():
            row = _with_link(engine, c, args.names)
            row.pop('pass_fps', None)
            row.pop('apple_fps', None)
            rows.append(row)
    return out.emit({'conflicts': rows}, lambda o: table(o['conflicts'], ['id', 'kind', 'fields', 'pass_path',
                                                                         'site', 'username']),
                    EXIT_ATTENTION if rows else EXIT_OK)


def cmd_resolve(args, out):
    with app.session(config_path=args.config) as engine:
        lid = engine.resolve_conflict(args.id, args.keep)
        status_mod.publish(engine.store, engine, {'auth': {}})
    return out.emit({'link': lid}, f'Resolved; kept the {args.keep} values.')


def cmd_deletions(args, out):
    with app.session(config_path=args.config, save=args.action is not None) as engine:
        if args.action in ('approve', 'restore'):
            lid = engine.resolve_deletion(args.id, approve=args.action == 'approve')
            status_mod.publish(engine.store, engine, {'auth': {}})
            return out.emit({'link': lid, 'action': args.action},
                            'Deleted the remaining copy.' if args.action == 'approve' else 'Restored.')
        rows = [_with_link(engine, d, args.names) for d in engine.state['deletions'].values()]
    return out.emit({'deletions': rows}, lambda o: table(o['deletions'], ['id', 'deleted_in', 'other_modified',
                                                                         'pass_path', 'site']),
                    EXIT_ATTENTION if rows else EXIT_OK)


def cmd_plans(args, out):
    with app.session(config_path=args.config, save=args.action is not None) as engine:
        if args.action == 'approve':
            engine.approve_plan(args.id)
            daemon_mod.notify_daemon(engine.store)
            return out.emit({'approved': args.id}, 'Approved; the next sync applies it.')
        if args.action == 'reject':
            engine.reject_plan(args.id)
            return out.emit({'rejected': args.id}, 'Rejected.')
        rows = [{'id': p['id'], 'time': p['time'], 'size': len(p['keys']), 'summary': p['summary']}
                for p in engine.state['plans'].values()]
    return out.emit({'plans': rows}, lambda o: table(o['plans'], ['id', 'size', 'summary']),
                    EXIT_ATTENTION if rows else EXIT_OK)


def cmd_queue(args, out):
    with app.session(config_path=args.config, save=args.action is not None) as engine:
        s = engine.state
        if args.action == 'accept':
            engine.accept_queue(args.id, path=args.path)
            daemon_mod.notify_daemon(engine.store)
            return out.emit({'accepted': args.id}, 'Accepted.')
        if args.action == 'info':
            q = s['queue'].get(args.id)
            if q is None or q['kind'] != 'missing-info':
                raise ConfigError('not a missing-info queue item')
            site = normalize_domain(args.site or '')
            if not site or args.username is None:
                raise ConfigError('--site and --username are required')
            token, payload, login = engine.pass_login(q['path'])
            if login is None:
                raise Stale('pass entry is gone')
            # The given website becomes the first URL; other url: lines are kept.
            urls = ('https://' + site,) + tuple(u for u in login.urls if normalize_domain(u) != site)
            updated = passfmt.render(payload, login.with_fields(username=args.username, urls=urls),
                                     {'username', 'urls'})
            engine.write_pass(None, q['path'], updated, payload, token, 'metadata')
            del s['queue'][args.id]
            s['pass_meta'].pop(q['path'], None)
            daemon_mod.notify_daemon(engine.store)
            return out.emit({'updated': args.id}, 'Saved username and website into the pass entry.')
        rows = []
        for q in s['queue'].values():
            row = {'id': q['id'], 'kind': q['kind'], 'time': q['time']}
            if q.get('path'):
                row['pass_path'] = q['path'] if args.names else mask_path(q['path'])
            if q.get('paths'):
                row['paths'] = q['paths'] if args.names else [mask_path(p) for p in q['paths']]
            if q.get('identity'):
                d, u = split_key(q['identity'])
                row['site'], row['username'] = (d, u) if args.names else (mask(d), mask(u))
            if q.get('link'):
                row['link'] = q['link']
            rows.append(row)
    return out.emit({'queue': rows}, lambda o: table(o['queue'], ['id', 'kind', 'pass_path', 'site', 'username']),
                    EXIT_ATTENTION if rows else EXIT_OK)


def cmd_auth(args, out):
    cfg = config_mod.load(args.config)
    result = {}
    targets = [args.target] if args.target else ['keychain', 'gpg', 'apple']
    store = status_store(cfg)
    for target in targets:
        try:
            if target == 'keychain':
                app.open_store(cfg)
            elif target == 'gpg':
                auth_gpg(cfg, interactive=not out.json)
            elif target == 'apple':
                auth_apple(cfg, args, interactive=not out.json)
            result[target] = None
        except AuthRequired as e:
            result[target] = e.hint
    status = store.read_status() or {}
    status['auth'] = {**(status.get('auth') or {}), **{k: v for k, v in result.items()}}
    store.write_status(status)
    daemon_mod.notify_daemon(store)
    code = 4 if any(result.values()) else EXIT_OK
    return out.emit({'auth': result}, lambda o: '\n'.join(f'{k}: {v or "ok"}' for k, v in o['auth'].items()),
                    code)


def auth_gpg(cfg, interactive):
    ps = app.make_pass(cfg, interactive=False)
    files = sorted(ps.scan())
    if not files:
        return
    try:
        ps.read(files[0])
        return
    except AuthRequired:
        if not interactive and not os.environ.get('DISPLAY') and sys.platform != 'darwin':
            raise
    # pinentry (pinentry-mac or the terminal) asks for the passphrase; gpg-agent caches it.
    if not app.make_pass(cfg, interactive=True).unlock(files[0]):
        raise AuthRequired('gpg', 'GPG unlock was cancelled')
    ps.read(files[0])


def auth_apple(cfg, args, interactive):
    if cfg.apple_backend != 'apw':
        app.make_apple(cfg).check()
        return
    backend = ApwBackend(cfg.apw_socket, cfg.apw_save_url_prefix)
    if not backend.socket_path.exists():
        start_apw(cfg)
    if args.request:
        backend.request_challenge()
        raise AuthRequired('apple', 'enter the PIN shown by macOS with `passrelay auth apple --pin-stdin`')
    if args.pin_stdin:
        backend.verify_challenge(sys.stdin.readline().strip())
        backend.check()
        return
    try:
        backend.check()
        return
    except AuthRequired:
        if not interactive:
            raise
    backend.request_challenge()
    pin = getpass.getpass('Enter the 6-digit PIN macOS is showing: ').strip()
    backend.verify_challenge(pin)
    backend.check()


def start_apw(cfg):
    """Start the APW daemon the supported way (Homebrew service) and wait for its socket."""
    brew = shutil.which('brew')
    if brew:
        subprocess.run([brew, 'services', 'start', 'apw'], capture_output=True, timeout=60)
    sock = Path(cfg.apw_socket).expanduser()
    for _ in range(30):
        if sock.exists():
            return
        time.sleep(0.5)
    raise AuthRequired('apple', 'APW is not running; start it with `brew services start apw` '
                       '(or `apw start`), then run `passrelay auth apple`')


def cmd_history(args, out):
    with app.session(config_path=args.config, save=False) as engine:
        rows = []
        for h in reversed(engine.state['history'][-args.limit:]):
            row = dict(h)
            link = engine.state['links'].get(h.get('link'))
            if link:
                row.update(names(link, args.names))
            rows.append(row)
    return out.emit({'history': rows}, lambda o: '\n'.join(
        f'{r["id"]}  {time.strftime("%Y-%m-%d %H:%M", time.localtime(r["time"]))}  {r["action"]:<8} '
        f'{r["side"]:<5} {r.get("pass_path") or ""}' for r in o['history']) or '(none)')


def cmd_restore(args, out):
    with app.session(config_path=args.config) as engine:
        s = engine.state
        rec = engine.store.history_get(args.id)
        if rec.get('before') is None:
            raise ConfigError('that change created the item; nothing earlier to restore')
        later = [h for h in s['history'] if h['time'] > rec['time'] and h.get('link') == rec.get('link')
                 and h.get('side') == rec['side'] and h['id'] != rec['id']]
        if later and not args.force:
            raise Stale('the item changed again after this snapshot; use --force to restore anyway')
        if rec['side'] == 'pass':
            path = rec['path']
            token, payload, _ = engine.pass_login(path)
            engine.write_pass(None, path, rec['before'], payload, token, 'restore')
            s['tombstones'].pop('path:' + path, None)
        else:
            before = rec['before']
            login = Login(password=before['password'], username=before.get('username'),
                          urls=tuple(before.get('urls') or ()), notes=before.get('notes'))
            current = engine.apple.get(engine.account_of({'domain': rec['domain'],
                                                          'username': rec['username']}))
            engine.store.history_add(s, {'action': 'restore', 'link': rec.get('link'), 'side': 'apple',
                                         'domain': rec['domain'], 'username': rec['username'],
                                         'before': login_dict(current) if current else None})
            engine.apple.put(rec['domain'], rec['username'], login)
            s['tombstones'].pop(json.dumps([rec['domain'], rec['username']], separators=(',', ':')), None)
        daemon_mod.notify_daemon(engine.store)
    return out.emit({'restored': args.id}, 'Restored; the next sync carries it to the other side.')


def cmd_service(args, out):
    cfg = config_mod.load(args.config)
    actions = {'install': lambda: service.install(cfg.path, cfg.state_dir, args.menubar),
               'uninstall': service.uninstall, 'start': service.start, 'stop': service.stop,
               'restart': service.restart, 'status': service.status}
    st = actions[args.action]()
    return out.emit({'service': st}, lambda o: '\n'.join(f'{k}: {v}' for k, v in o['service'].items()))


def cmd_config(args, out):
    path = args.config or config_mod.default_config_path()
    cfg = config_mod.load(path)
    if args.action == 'set':
        known = cfg.to_dict()
        if args.key not in known:
            raise ConfigError('unknown configuration key')
        try:
            value = json.loads(args.value)
        except ValueError:
            value = args.value
        setattr(cfg, args.key, value)
        cfg.validate()
        config_mod.save(cfg, path)
        daemon_mod.notify_daemon(status_store(cfg))
        return out.emit({'key': args.key, 'value': value}, f'{args.key} = {json.dumps(value)}')
    if args.key:
        value = cfg.to_dict().get(args.key)
        return out.emit({'key': args.key, 'value': value}, json.dumps(value))
    return out.emit({'config': cfg.to_dict()}, lambda o: json.dumps(o['config'], indent=2))


def cmd_doctor(args, out):
    cfg = config_mod.load(args.config)
    checks = doctor.run(cfg)
    failed = any(c['status'] == 'fail' for c in checks)
    marks = {'ok': '✓', 'warn': '!', 'fail': '✗'}
    return out.emit({'checks': checks}, lambda o: '\n'.join(
        f'{marks[c["status"]]} {c["name"]}: {c["detail"]}' for c in o['checks']),
        EXIT_ERROR if failed else EXIT_OK)


def cmd_uninstall(args, out):
    cfg = config_mod.load(args.config)
    st = service.uninstall() if sys.platform == 'darwin' else {}
    purged = False
    if args.purge:
        keystore_for(cfg).delete()
        shutil.rmtree(Path(cfg.state_dir).expanduser(), ignore_errors=True)
        purged = True
    return out.emit({'service': st, 'purged': purged},
                    'Removed the background service.' + (' Deleted state, history, and key.' if purged else '')
                    + ' Your passwords in pass and Apple Passwords are untouched.')


def cmd_daemon(args, out):
    return daemon_mod.Daemon(args.config).run()


# ---------------------------------------------------------------------- parser
def build_parser():
    p = argparse.ArgumentParser(prog='passrelay', description='Sync Apple Passwords with pass.')
    p.add_argument('--config', help='configuration file (default: ~/Library/Application Support/PassRelay/config.json)')
    p.add_argument('--json', action='store_true', help='machine-readable output')
    p.add_argument('--version', action='version', version=f'passrelay {__version__}')
    sub = p.add_subparsers(dest='command', required=True)

    s = sub.add_parser('setup', help='initial connection and scope')
    s.add_argument('--pass-store')
    s.add_argument('--apple-backend', choices=['apw', 'bridge'])
    s.add_argument('--bridge-command')
    s.add_argument('--include', action='append')
    s.add_argument('--exclude', action='append')
    s.add_argument('--watch-domain', action='append')
    s.add_argument('--import-apple-csv')
    s.add_argument('--new-items', choices=['auto', 'review'])
    s.add_argument('--deletion-policy', choices=['ask', 'propagate', 'keep'])
    s.add_argument('--key-store', choices=['keychain', 'file'])
    s.add_argument('--state-dir', help=argparse.SUPPRESS)
    s.add_argument('--apply', action='store_true')

    sub.add_parser('status')
    s = sub.add_parser('sync')
    s.add_argument('--dry-run', action='store_true')
    sub.add_parser('pause')
    sub.add_parser('resume')

    s = sub.add_parser('items')
    s.add_argument('action', nargs='?', choices=['exclude', 'include', 'link', 'unlink'])
    s.add_argument('id', nargs='?')
    s.add_argument('--names', action='store_true')
    s.add_argument('--status')
    s.add_argument('--path')
    s.add_argument('--site')
    s.add_argument('--username')

    s = sub.add_parser('conflicts')
    s.add_argument('action', nargs='?', choices=['show'])
    s.add_argument('id', nargs='?')
    s.add_argument('--names', action='store_true')
    s.add_argument('--reveal', action='store_true')

    s = sub.add_parser('resolve')
    s.add_argument('id')
    s.add_argument('--keep', choices=['pass', 'apple'], required=True)

    s = sub.add_parser('deletions')
    s.add_argument('action', nargs='?', choices=['approve', 'restore'])
    s.add_argument('id', nargs='?')
    s.add_argument('--names', action='store_true')

    s = sub.add_parser('plans')
    s.add_argument('action', nargs='?', choices=['approve', 'reject'])
    s.add_argument('id', nargs='?')

    s = sub.add_parser('queue')
    s.add_argument('action', nargs='?', choices=['accept', 'info'])
    s.add_argument('id', nargs='?')
    s.add_argument('--names', action='store_true')
    s.add_argument('--path')
    s.add_argument('--site')
    s.add_argument('--username')

    s = sub.add_parser('auth')
    s.add_argument('target', nargs='?', choices=['apple', 'gpg', 'keychain'])
    s.add_argument('--request', action='store_true')
    s.add_argument('--pin-stdin', action='store_true')

    s = sub.add_parser('history')
    s.add_argument('--names', action='store_true')
    s.add_argument('--limit', type=int, default=50)
    s = sub.add_parser('restore')
    s.add_argument('id')
    s.add_argument('--force', action='store_true')

    s = sub.add_parser('service')
    s.add_argument('action', choices=['install', 'uninstall', 'start', 'stop', 'restart', 'status'])
    s.add_argument('--menubar', help='path to PassRelay.app to start at login as well')

    s = sub.add_parser('config')
    s.add_argument('action', nargs='?', choices=['get', 'set'], default='get')
    s.add_argument('key', nargs='?')
    s.add_argument('value', nargs='?')

    sub.add_parser('doctor')
    s = sub.add_parser('uninstall')
    s.add_argument('--purge', action='store_true')
    sub.add_parser('daemon')
    return p


NEEDS_ID = {('items', 'exclude'), ('items', 'unlink'), ('conflicts', 'show'), ('deletions', 'approve'),
            ('deletions', 'restore'), ('plans', 'approve'), ('plans', 'reject'), ('queue', 'accept'),
            ('queue', 'info')}


def main(argv=None):
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Out(args.json)
    if (args.command, getattr(args, 'action', None)) in NEEDS_ID and not args.id:
        parser.error(f'{args.command} {args.action} needs an ID')
    if args.command == 'config' and args.action == 'set' and (args.key is None or args.value is None):
        parser.error('config set needs KEY and VALUE')
    handlers = {
        'setup': cmd_setup, 'status': cmd_status, 'sync': cmd_sync,
        'pause': lambda a, o: cmd_pause(a, o, True), 'resume': lambda a, o: cmd_pause(a, o, False),
        'items': cmd_items, 'conflicts': cmd_conflicts, 'resolve': cmd_resolve,
        'deletions': cmd_deletions, 'plans': cmd_plans, 'queue': cmd_queue, 'auth': cmd_auth,
        'history': cmd_history, 'restore': cmd_restore, 'service': cmd_service,
        'config': cmd_config, 'doctor': cmd_doctor, 'uninstall': cmd_uninstall, 'daemon': cmd_daemon,
    }
    try:
        return handlers[args.command](args, out)
    except PassRelayError as e:
        return fail(out, e.kind, str(e), e.exit_code)
    except OSError as e:
        return fail(out, 'os', f'{type(e).__name__}: {e.strerror or "I/O error"}', EXIT_ERROR)
    except KeyboardInterrupt:
        return fail(out, 'interrupted', 'interrupted', EXIT_USAGE)


def fail(out, kind, message, code):
    if out.json:
        print(json.dumps({'ok': False, 'error': {'kind': kind, 'message': message}}))
    else:
        print(f'passrelay: {message}', file=sys.stderr)
    return code
