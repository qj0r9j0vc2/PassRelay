"""Apple Passwords backend interface.

Backends differ a lot in what they can do. APW can look up accounts per website and create or
update a password, but cannot enumerate the whole vault, delete, rename, or read notes. The engine
consults ``capabilities`` and turns anything a backend cannot do into a visible user action
instead of silently skipping it.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Capabilities:
    enumerate: bool = False      # list every login without knowing domains in advance
    write: bool = False          # create or update a password
    delete: bool = False
    rename: bool = False         # change the username of an existing record in place
    notes: bool = False          # read and write notes
    urls_write: bool = False     # write additional website URLs
    record_ids: bool = False     # stable identifiers that survive username/website edits
    change_tokens: bool = False  # listings carry a modification stamp

    def as_dict(self):
        return dict(self.__dict__)


class AppleBackend:
    name = 'apple'
    capabilities = Capabilities()

    def check(self):
        """Raise AuthRequired when the backend is not usable right now."""
        raise NotImplementedError

    def list_all(self):
        """All accounts (only when capabilities.enumerate)."""
        raise NotImplementedError

    def list_domain(self, domain):
        """Accounts for one website. An empty list means the backend positively found none."""
        raise NotImplementedError

    def get(self, account):
        """Return a Login for the account, or None when the backend positively reports it missing."""
        raise NotImplementedError

    def put(self, domain, username, login, record_id=None):
        """Create or update; return the record id when the backend has them."""
        raise NotImplementedError

    def delete(self, account):
        raise NotImplementedError

    def rename(self, account, new_username):
        raise NotImplementedError
