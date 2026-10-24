"""Wiring: config -> backends -> state -> engine. Shared by the CLI and the daemon."""
import contextlib

from . import config as config_mod
from .apple.apw import ApwBackend
from .apple.bridge import BridgeBackend
from .crypto import hkdf
from .engine import Engine
from .keystore import keystore_for
from .model import Fingerprinter
from .passstore import PassStore
from .state import StateStore


def make_apple(cfg):
    if cfg.apple_backend == 'apw':
        return ApwBackend(cfg.apw_socket, cfg.apw_save_url_prefix)
    if cfg.apple_backend == 'bridge':
        return BridgeBackend(cfg.bridge_command)
    from .apple.memory import MemoryApple
    return MemoryApple()


def make_pass(cfg, interactive=None):
    return PassStore(cfg.pass_store, cfg.pass_binary,
                     interactive=cfg.gpg_interactive if interactive is None else interactive)


def open_store(cfg, create=False):
    key = keystore_for(cfg).load(create=create)
    return StateStore(cfg.state_dir, hkdf(key, b'state')), Fingerprinter(hkdf(key, b'fingerprint'))


@contextlib.contextmanager
def session(cfg=None, config_path=None, timeout=30.0, apple=None, pass_store=None, save=True):
    """Lock the state, yield an Engine, and persist the state on success."""
    cfg = cfg or config_mod.load(config_path)
    store, fp = open_store(cfg)
    with store.lock(timeout):
        state = store.load()
        engine = Engine(cfg, pass_store or make_pass(cfg), apple or make_apple(cfg), store, state, fp)
        yield engine
        if save:
            store.save(engine.state)
