"""The pass entry metadata format (documented in docs/FORMAT.md).

Line 1 is the password. Later lines of the form ``key: value`` map to login fields:

    username | user | login      -> username (first one wins)
    url | website | site         -> urls (every line, in order)
    title                        -> title
    note | notes                 -> notes (one line each, joined with newlines)

``otpauth://`` lines are preserved and reported as unsupported. Every other line is preserved
verbatim and in place when PassRelay rewrites an entry.
"""
from .model import Login

KEYS = {
    'username': 'username', 'user': 'username', 'login': 'username',
    'url': 'urls', 'website': 'urls', 'site': 'urls',
    'title': 'title',
    'note': 'notes', 'notes': 'notes',
}
CANONICAL = {'username': 'username', 'urls': 'url', 'title': 'title', 'notes': 'note'}


def _split(payload):
    if payload is None:
        return [], True
    trailing = payload.endswith('\n')
    body = payload[:-1] if trailing else payload
    return body.split('\n'), trailing


def _key(line):
    name, sep, value = line.partition(':')
    if not sep:
        return None, None, None
    field = KEYS.get(name.strip().lower())
    if field is None:
        return None, None, None
    return field, name, value[1:] if value.startswith(' ') else value


def parse(payload):
    lines, _ = _split(payload)
    if not lines:
        raise ValueError('empty pass entry')
    password = lines[0]
    username, title = None, None
    urls, notes, unsupported = [], [], []
    for line in lines[1:]:
        if line.lower().startswith('otpauth://'):
            unsupported.append('otp')
            continue
        field, _, value = _key(line)
        if field == 'username' and username is None:
            username = value.strip()
        elif field == 'urls' and value.strip():
            urls.append(value.strip())
        elif field == 'title' and title is None:
            title = value.strip()
        elif field == 'notes':
            notes.append(value)
    return Login(password=password, username=username, urls=tuple(urls),
                 notes='\n'.join(notes) if notes else None, title=title,
                 unsupported=tuple(sorted(set(unsupported))))


def _format(field, value, key):
    if field == 'urls':
        return [f'{key}: {u}' for u in value]
    if field == 'notes':
        return [f'{key}: {n}' if n else f'{key}:' for n in value.split('\n')]
    return [f'{key}: {value}']


def render(payload, login, fields):
    """Rewrite ``payload`` so the given fields take their values from ``login``.

    Fields whose new value is None are left untouched; that is how one side avoids erasing data
    the other side cannot represent. Lines PassRelay does not understand are kept in place.
    """
    for name in ('username', 'title'):
        value = login.get(name)
        if value is not None and ('\n' in value or '\r' in value):
            raise ValueError('multiline metadata')
    if any('\n' in u or '\r' in u for u in login.urls):
        raise ValueError('multiline metadata')
    lines, trailing = _split(payload)
    head = login.password if ('password' in fields or not lines) else lines[0]
    if not head or '\n' in head or '\r' in head:
        raise ValueError('empty or multiline password')
    rest = lines[1:]
    for field in ('username', 'urls', 'title', 'notes'):
        if field not in fields:
            continue
        value = login.get(field)
        if value is None or (field == 'urls' and not value):
            continue
        positions = [i for i, line in enumerate(rest) if _key(line)[0] == field]
        key = _key(rest[positions[0]])[1].strip() if positions else CANONICAL[field]
        new = _format(field, value, key)
        if positions:
            at = positions[0]
            rest = [line for i, line in enumerate(rest) if i not in positions]
        else:
            mapped = [i for i, line in enumerate(rest) if _key(line)[0]]
            at = mapped[-1] + 1 if mapped else 0
        rest[at:at] = new
    return '\n'.join([head, *rest]) + ('\n' if trailing else '')
