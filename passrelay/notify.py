"""macOS user notifications for things that need the user. Normal syncs stay silent."""
import subprocess
import sys

SCRIPT = ['-e', 'on run argv', '-e', 'display notification (item 2 of argv) with title (item 1 of argv)',
          '-e', 'end run']


def send(title, message):
    if sys.platform != 'darwin':
        return
    # Text goes in as argv to the AppleScript, never interpolated into the script source.
    subprocess.run(['/usr/bin/osascript', *SCRIPT, title, message], capture_output=True, timeout=10)


class Notifier:
    """Notify on transitions only: new attention items, new auth problems, persistent errors."""

    def __init__(self, enabled=True, sender=send):
        self.enabled = enabled
        self.sender = sender
        self.last = {'attention': 0, 'auth': set(), 'error_streak': 0}

    def update(self, status):
        if not self.enabled:
            return []
        messages = []
        counts = status.get('counts') or {}
        attention = sum(counts.get(k, 0) for k in ('conflicts', 'deletions_pending', 'queue', 'plans_pending'))
        if attention > self.last['attention']:
            messages.append(f'{attention} item(s) need your decision. Open PassRelay to review.')
        self.last['attention'] = attention
        auth = {k for k, v in (status.get('auth') or {}).items() if v}
        for backend in sorted(auth - self.last['auth']):
            label = {'apple': 'Apple Passwords', 'gpg': 'GPG', 'keychain': 'Keychain'}.get(backend, backend)
            messages.append(f'{label} needs authentication. Sync is paused until you sign in.')
        self.last['auth'] = auth
        cycle_ok = (status.get('last_cycle') or {}).get('ok', True)
        self.last['error_streak'] = 0 if cycle_ok else self.last['error_streak'] + 1
        if self.last['error_streak'] == 5:
            messages.append('Some items keep failing to sync. Run `passrelay doctor` for details.')
        for m in messages:
            try:
                self.sender('PassRelay', m)
            except (OSError, subprocess.SubprocessError):
                pass
        return messages
