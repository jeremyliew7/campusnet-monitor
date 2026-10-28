import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import campusnet_core as c


class SafetyTests(unittest.TestCase):
    def test_host_validation_rejects_injection_credentials_and_ip(self):
        for value in ("example.com\n1.1.1.1 bad.com", "https://u:p@example.com", "127.0.0.1", "https://example.com/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.normalize_host(value)
        self.assertEqual(c.normalize_host("https://Example.COM/"), "example.com")

    def test_public_ipv4_rejects_private_fake_and_invalid(self):
        for value in ("127.0.0.1", "192.168.1.1", "198.18.0.1", "::1", "bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.public_ipv4(value)

    def test_add_and_remove_preserve_other_tools_block(self):
        original = b"127.0.0.1 localhost\r\n# >>> other >>>\r\n1.1.1.1 other.example\r\n# <<< other <<<\r\n"
        added, _ = c.render_hosts(original, "example.com", "8.8.8.8")
        self.assertTrue(added.startswith(original))
        self.assertEqual(c.host_state(added, "example.com")["own"], "8.8.8.8")
        restored, _ = c.render_hosts(added, "example.com", None)
        self.assertEqual(restored, original)

    def test_refuses_overwriting_other_tool_and_bad_markers(self):
        foreign = b"# >>> foreign >>>\r\n1.1.1.1 example.com\r\n# <<< foreign <<<\r\n"
        with self.assertRaises(ValueError):
            c.render_hosts(foreign, "example.com", "8.8.8.8")
        with self.assertRaises(ValueError):
            c.render_hosts(c.BEGIN + b"\n", "example.com", "8.8.8.8")

    def test_authentication_domains_are_not_pinned(self):
        for domain in ("auth.openai.com", "challenges.cloudflare.com", "accounts.google.com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                c.render_hosts(b"", domain, "8.8.8.8")

    def test_elevated_operation_rechecks_hash_and_preserves_other_records(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "hosts"
            before = b"127.0.0.1 localhost\r\n1.1.1.1 keep.example\r\n"
            path.write_bytes(before)
            good_probe = {"exit": 0, "http": 200}
            class RunResult:
                returncode = 0
            with patch.object(c, "hosts_path", return_value=path), patch.object(c, "probe", return_value=good_probe), patch.object(c.subprocess, "run", return_value=RunResult()):
                with self.assertRaises(ValueError):
                    c.apply_hosts("example.com", "8.8.8.8", "0" * 64, int(time.time()))
                self.assertEqual(path.read_bytes(), before)
                c.apply_hosts("example.com", "8.8.8.8", c.sha256(before), int(time.time()))
                modified = path.read_bytes()
                self.assertTrue(modified.startswith(before))
                c.apply_hosts("example.com", None, c.sha256(modified), int(time.time()))
                self.assertEqual(path.read_bytes(), before)

    def test_candidate_must_pass_fresh_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "hosts"
            before = b"127.0.0.1 localhost\r\n"
            path.write_bytes(before)
            failed_probe = {"exit": 28, "http": 0}
            with patch.object(c, "hosts_path", return_value=path), patch.object(c, "probe", return_value=failed_probe):
                with self.assertRaises(ValueError):
                    c.apply_hosts("example.com", "8.8.8.8", c.sha256(before), int(time.time()))
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
