"""LaunchAgent management for the daemon and the menu bar app."""
import os
from pathlib import Path
import plistlib
import subprocess
import sys

from .errors import ConfigError

DAEMON_LABEL = 'io.passrelay.daemon'
MENUBAR_LABEL = 'io.passrelay.menubar'
AGENTS = Path('~/Library/LaunchAgents').expanduser()


def plist_path(label):
    return AGENTS / f'{label}.plist'


def _domain():
    return f'gui/{os.getuid()}'


def _launchctl(*args):
    return subprocess.run(['/bin/launchctl', *args], capture_output=True, text=True, timeout=30)


def daemon_plist(config_path, state_dir):
    package_root = str(Path(__file__).resolve().parent.parent)
    return {
        'Label': DAEMON_LABEL,
        'ProgramArguments': [str(Path(sys.executable).resolve()), '-m', 'passrelay',
                             '--config', str(Path(config_path).resolve()), 'daemon'],
        'EnvironmentVariables': {
            'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
            'PYTHONPATH': package_root,
        },
        'RunAtLoad': True,
        'KeepAlive': True,
        'ThrottleInterval': 30,
        'ProcessType': 'Background',
        'LowPriorityIO': True,
        'LimitLoadToSessionType': 'Aqua',
        # Only non-secret operational messages are ever written here.
        'StandardErrorPath': str(Path(state_dir).expanduser() / 'daemon.log'),
        'StandardOutPath': '/dev/null',
    }


def menubar_plist(app_path):
    binary = Path(app_path).expanduser().resolve() / 'Contents/MacOS/PassRelayMenu'
    if not binary.exists():
        raise ConfigError('menu bar app not found at that path')
    return {'Label': MENUBAR_LABEL, 'ProgramArguments': [str(binary)], 'RunAtLoad': True,
            'KeepAlive': {'SuccessfulExit': False}, 'LimitLoadToSessionType': 'Aqua',
            'ProcessType': 'Interactive'}


def _write(label, data):
    AGENTS.mkdir(parents=True, exist_ok=True)
    path = plist_path(label)
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'wb') as f:
        plistlib.dump(data, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return path


def loaded(label):
    return _launchctl('print', f'{_domain()}/{label}').returncode == 0


def install(config_path, state_dir, menubar=None):
    if sys.platform != 'darwin':
        raise ConfigError('LaunchAgents require macOS')
    for label, data in [(DAEMON_LABEL, daemon_plist(config_path, state_dir))] + (
            [(MENUBAR_LABEL, menubar_plist(menubar))] if menubar else []):
        if loaded(label):
            _launchctl('bootout', f'{_domain()}/{label}')
        path = _write(label, data)
        result = _launchctl('bootstrap', _domain(), str(path))
        if result.returncode and not loaded(label):
            raise ConfigError(f'launchctl could not load {label}')
    return status()


def uninstall():
    for label in (DAEMON_LABEL, MENUBAR_LABEL):
        if loaded(label):
            _launchctl('bootout', f'{_domain()}/{label}')
        plist_path(label).unlink(missing_ok=True)
    return status()


def start():
    if not plist_path(DAEMON_LABEL).exists():
        raise ConfigError('service not installed; run `passrelay service install`')
    if not loaded(DAEMON_LABEL):
        _launchctl('bootstrap', _domain(), str(plist_path(DAEMON_LABEL)))
    _launchctl('kickstart', f'{_domain()}/{DAEMON_LABEL}')
    return status()


def stop():
    if loaded(DAEMON_LABEL):
        _launchctl('bootout', f'{_domain()}/{DAEMON_LABEL}')
    return status()


def restart():
    stop()
    return start()


def status():
    return {'installed': plist_path(DAEMON_LABEL).exists(), 'loaded': loaded(DAEMON_LABEL),
            'plist': str(plist_path(DAEMON_LABEL)),
            'menubar_installed': plist_path(MENUBAR_LABEL).exists()}
