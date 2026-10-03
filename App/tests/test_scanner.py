import os
import tempfile
import unittest
from pathlib import Path

from reconspace.duplicates import find_duplicate_groups
from reconspace.scanner import ScanConfig, scan_filesystem, _norm


class ScannerTests(unittest.TestCase):
    def test_directory_accounting_and_top_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "root.bin").write_bytes(b"x" * 5)
            (root / "a" / "one.bin").write_bytes(b"a" * 10)
            (root / "b" / "two.bin").write_bytes(b"b" * 20)

            inv = scan_filesystem(ScanConfig(root=td, duplicate_min_bytes=1, top_files=10, top_directories=10))
            self.assertEqual(inv.stats.files_seen, 3)
            self.assertEqual(inv.stats.bytes_seen, 35)
            self.assertEqual(inv.directory_sizes[_norm(td)], 35)
            self.assertEqual(inv.top_files[0].size_bytes, 20)

    def test_exact_duplicate_verification(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = (b"same-content" * 1000)
            (root / "a.bin").write_bytes(payload)
            (root / "b.bin").write_bytes(payload)
            (root / "c.bin").write_bytes(b"different" * 1000)

            inv = scan_filesystem(ScanConfig(root=td, duplicate_min_bytes=1, top_files=10, top_directories=10))
            groups, errors = find_duplicate_groups(inv.duplicate_candidates)
            self.assertFalse(errors)
            self.assertEqual(len(groups), 1)
            self.assertEqual(len(groups[0].paths), 2)
            self.assertGreaterEqual(groups[0].reclaimable_bytes, len(payload))
            self.assertLessEqual(groups[0].reclaimable_bytes - len(payload), 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
