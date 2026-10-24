"""Error types. Messages must never contain secrets, domains, or usernames."""

# Exit codes are part of the public CLI contract (docs/CLI.md).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_ATTENTION = 3
EXIT_AUTH = 4
EXIT_BUSY = 5


class PassRelayError(Exception):
    exit_code = EXIT_ERROR
    kind = 'error'


class ConfigError(PassRelayError):
    exit_code = EXIT_USAGE
    kind = 'config'


class BackendError(PassRelayError):
    kind = 'backend'


class AuthRequired(PassRelayError):
    """A backend needs the user to authenticate. Never interpret as missing data."""
    exit_code = EXIT_AUTH
    kind = 'auth'

    def __init__(self, backend, hint):
        super().__init__(f'{backend} authentication required: {hint}')
        self.backend = backend
        self.hint = hint


class Busy(PassRelayError):
    exit_code = EXIT_BUSY
    kind = 'busy'


class Unsupported(PassRelayError):
    kind = 'unsupported'


class Deferred(PassRelayError):
    """This cycle's Apple read budget is used up; the item is checked in a later cycle."""
    kind = 'deferred'


class Stale(PassRelayError):
    """A value changed between planning and writing; the action is retried next cycle."""
    kind = 'stale'
