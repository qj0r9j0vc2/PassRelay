"""Runs the real daemon process against real pass/gpg and the fake APW socket."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

from passrelay.notify import Notifier
from tests.test_integration import HAVE_TOOLS, RealPassCase

ROOT = Path(__file__).resolve().parent.parent


class NotifierTests(unittest.TestCase):
    def test_only_transitions_notify(self):
        sent = []
        n = Notifier(sender=lambda t, m: sent.append(m))
        ok = {'counts': {'conflicts': 0}, 'auth': {}, 'last_cycle': {'ok': True}}
        n.update(ok)
        n.update(ok)
        self.assertEqual(sent, [])
        n.update({**ok, 'counts': {'conflicts': 1}})
        n.update({**ok, 'counts': {'conflicts': 1}})
        n.update({**ok, 'auth': {'apple': 'x'}})
        n.update({**ok, 'auth': {'apple': 'x'}})
        self.assertEqual(len(sent), 2)
        self.assertNotIn('example', ' '.join(sent))


@unittest.skipUnless(HAVE_TOOLS, 'pass and gpg required')
class DaemonProcess(RealPassCase):
    def wait_for(self, predicate, timeout):
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if predicate():
                return time.monotonic() - start
            time.sleep(0.2)
        self.fail('condition not reached in time')

    def test_daemon_propagates_both_ways_within_target(self):
        self.insert('web/example.com/alice', 'v1\nusername: alice\nurl: https://example.com\n')
        self.apw.records[('example.com', 'alice')] = 'v1'
        self.setup_cli()
        cfg = json.loads(Path(self.config).read_text())
        cfg.update(apw_socket=self.apw.path, pass_poll_seconds=1, apple_poll_seconds=5, notifications=False)
        Path(self.config).write_text(json.dumps(cfg))
        code, out = self.run_cli('setup', '--apply')
        self.assertEqual(code, 0, out)
        env = dict(os.environ, PYTHONPATH=str(ROOT), PASSRELAY_DEBUG='1')
        proc = subprocess.Popen([sys.executable, '-X', 'faulthandler', '-m', 'passrelay', '--config',
                                 self.config, 'daemon'],
                                env=env, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
        try:
            self.wait_for(lambda: Path(self.state_dir, 'daemon.pid').exists(), 10)
            self.insert('web/example.com/alice', 'v2\nusername: alice\nurl: https://example.com\n')
            pass_to_apple = self.wait_for(lambda: self.apw.records[('example.com', 'alice')] == 'v2', 30)
            # Let the daemon finish verifying that write. Changing Apple in the middle of it is a
            # real race, which PassRelay reports as a conflict instead of picking a winner.
            self.wait_for(lambda: not json.loads(Path(self.state_dir, 'status.json').read_text())['syncing'], 10)
            self.apw.records[('example.com', 'alice')] = 'v3'
            apple_to_pass = self.wait_for(lambda: self.show('web/example.com/alice').startswith('v3\n'), 30)
            code, out = self.run_cli('status')
            self.assertTrue(out['daemon']['running'])
            # Pause stops propagation; resume restarts it.
            self.run_cli('pause')
            time.sleep(1.5)
            self.insert('web/example.com/alice', 'v4\nusername: alice\nurl: https://example.com\n')
            time.sleep(3)
            self.assertEqual(self.apw.records[('example.com', 'alice')], 'v3')
            self.run_cli('resume')
            self.wait_for(lambda: self.apw.records[('example.com', 'alice')] == 'v4', 30)
        except AssertionError:
            proc.send_signal(signal.SIGABRT)  # faulthandler dumps every thread's stack
            print(proc.communicate(timeout=20)[1].decode(), file=sys.stderr)
            raise
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                _, err = proc.communicate(timeout=20)
        log = err.decode()
        self.assertIn('daemon started', log)
        self.assertNotIn('v2', log)
        self.assertNotIn('example.com', log)
        self.assertLess(pass_to_apple, 30)
        self.assertLess(apple_to_pass, 30)
        print(f'\n  latency pass->apple {pass_to_apple:.1f}s, apple->pass {apple_to_pass:.1f}s', file=sys.stderr)


if __name__ == '__main__':
    unittest.main()
