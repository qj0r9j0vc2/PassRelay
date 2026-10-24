"""Non-secret status: what the menu bar app and `passrelay status` read without any key."""
import os
import time

from .errors import EXIT_ATTENTION, EXIT_AUTH, EXIT_OK


def publish(store, engine, report, syncing=False):
    """Write status.json after a cycle. Counts and timestamps only: no sites, names, or values."""
    s = engine.state
    previous = store.read_status() or {}
    status = {
        'updated': time.time(),
        'setup_done': s['setup_done'],
        'syncing': syncing,
        'last_success': s.get('last_success'),
        'last_cycle': s.get('last_cycle'),
        'auth': {k: report.get('auth', {}).get(k) for k in ('apple', 'gpg', 'keychain')},
        'counts': engine.counts(),
        'apple_progress': report.get('apple_progress') or previous.get('apple_progress') or {},
        'errors': len(report.get('errors', [])),
    }
    store.write_status(status)
    return status


def publish_auth_failure(store, backend, hint):
    status = store.read_status() or {}
    status.setdefault('auth', {})[backend] = hint
    status['updated'] = time.time()
    status['syncing'] = False
    store.write_status(status)


def daemon_pid(store):
    try:
        pid = int((store.dir / 'daemon.pid').read_text())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def summarize(store, service_installed=False):
    """Combine status.json, control.json, and the daemon pid into the `status` contract."""
    status = store.read_status() or {}
    control = store.control()
    pid = daemon_pid(store)
    counts = status.get('counts') or {}
    auth = {k: (status.get('auth') or {}).get(k) for k in ('apple', 'gpg', 'keychain')}
    attention = (counts.get('conflicts', 0) + counts.get('deletions_pending', 0)
                 + counts.get('queue', 0) + counts.get('plans_pending', 0))
    if not status.get('setup_done'):
        state = 'not-setup'
    elif control.get('paused'):
        state = 'paused'
    elif any(auth.values()):
        state = 'auth'
    elif status.get('syncing'):
        state = 'syncing'
    elif attention:
        state = 'attention'
    elif status.get('last_cycle') and not status['last_cycle'].get('ok'):
        state = 'error'
    elif pid is None:
        state = 'stopped'
    else:
        state = 'ok'
    out = {'setup_done': bool(status.get('setup_done')), 'paused': bool(control.get('paused')),
           'daemon': {'running': pid is not None, 'pid': pid}, 'service': {'installed': service_installed},
           'last_success': status.get('last_success'), 'last_cycle': status.get('last_cycle'),
           'auth': auth, 'counts': counts, 'apple_progress': status.get('apple_progress') or {},
           'attention': attention, 'state': state, 'updated': status.get('updated')}
    code = EXIT_AUTH if any(auth.values()) else EXIT_ATTENTION if attention else EXIT_OK
    return out, code
