import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build_release_zip
import update_release_manifest
from reconspace import __version__
from reconspace import engine
from reconspace.cli import MAX_DUPLICATE_MB, _duplicate_mb, _port
from reconspace.compare import load_report
from reconspace.models import CollectorResult
from reconspace.scanner import ScanCancelled


class CancellationTests(unittest.TestCase):
    def test_audit_cancels_between_scan_phases_before_collector_starts(self):
        cancelled = False

        def progress(payload):
            nonlocal cancelled
            if payload.get("phase") == "applications":
                cancelled = True

        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            engine, "collect_installed_applications"
        ) as applications:
            with self.assertRaises(ScanCancelled):
                engine.run_audit(
                    engine.AuditConfig(root=td, profile="quick"),
                    progress=progress,
                    cancel=lambda: cancelled,
                )
        applications.assert_not_called()

    def test_optional_inventory_stops_between_collectors(self):
        from reconspace import windows_collectors as wc

        checks = iter((False, True))
        with mock.patch.object(wc, "IS_WINDOWS", True), mock.patch.object(
            wc, "_powershell_json", return_value=CollectorResult("one", True, {})
        ) as powershell:
            rows = wc.collect_optional_system_inventory(cancel=lambda: next(checks, True))
        self.assertEqual(len(rows), 1)
        powershell.assert_called_once()


class ReportBoundaryTests(unittest.TestCase):
    def test_report_loader_rejects_oversized_file_before_parsing(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "large.json"
            path.write_bytes(b"{" + b" " * 10)
            with self.assertRaisesRegex(ValueError, "too large"):
                load_report(str(path), max_bytes=10)

    def test_report_loader_rejects_non_finite_numbers(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nan.json"
            path.write_text('{"stats":{"bytes_seen":NaN}}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-finite"):
                load_report(str(path))

    def test_report_loader_rejects_non_object_rows(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text(json.dumps({"stats": {}, "findings": ["bad"]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "entries must be objects"):
                load_report(str(path))


class CliBoundaryTests(unittest.TestCase):
    def test_duplicate_threshold_is_bounded(self):
        self.assertEqual(_duplicate_mb("1"), 1)
        self.assertEqual(_duplicate_mb(str(MAX_DUPLICATE_MB)), MAX_DUPLICATE_MB)
        for value in ("0", "-1", str(MAX_DUPLICATE_MB + 1), "1.5"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                _duplicate_mb(value)

    def test_port_is_bounded(self):
        self.assertEqual(_port("8765"), 8765)
        for value in ("0", "65536", "abc"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                _port(value)


class ReleaseScopeTests(unittest.TestCase):
    def test_unlisted_release_file_is_rejected(self):
        listed = [build_release_zip.ROOT / "README.md"]
        discovered = {listed[0], build_release_zip.ROOT / "unexpected.txt"}
        with self.assertRaisesRegex(RuntimeError, "unexpected.txt"):
            build_release_zip.verify_manifest_scope(listed, discovered)

    def test_rendered_manifest_is_sorted_and_contains_current_version(self):
        rendered = update_release_manifest.render_manifest()
        self.assertTrue(rendered.startswith(f"ReconSpace {__version__} release source manifest\n"))
        paths = [
            line.split("  ", 2)[2]
            for line in rendered.splitlines()
            if len(line.split("  ", 2)) == 3 and len(line.split("  ", 1)[0]) == 64
        ]
        self.assertEqual(paths, sorted(paths, key=str.casefold))
        self.assertIn("update_release_manifest.py", paths)


class DashboardImportTests(unittest.TestCase):
    def test_compare_import_is_labeled_bounded_and_structurally_validated(self):
        from reconspace.webapp import _html

        html = _html()
        self.assertIn('label for="priorFile"', html)
        self.assertIn("MAX_IMPORTED_REPORT_BYTES=64*1024*1024", html)
        self.assertIn("validateImportedReport", html)
        self.assertIn("MAX_IMPORTED_SECTION_ROWS", html)


class OwnershipPerformanceAndCorrectnessTests(unittest.TestCase):
    def test_build_application_footprints_large_scale_is_fast_and_accurate(self):
        import os
        import time
        from reconspace.models import ApplicationRecord
        from reconspace.ownership import build_application_footprints

        data_root = os.environ.get("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
        apps = [
            ApplicationRecord(name=f"AppVendor{i}", install_location=rf"C:\Program Files\AppVendor{i}")
            for i in range(100)
        ]
        # Simulate 10,000 directories across Windows, Program Files, and AppData
        dirs = {rf"C:\Windows\System32\lib_{i}": 1024 for i in range(4000)}
        dirs.update({rf"C:\Program Files\Common\sub_{i}": 2048 for i in range(4000)})
        dirs.update({rf"{data_root}\AppVendor{i}\Cache": 8192 for i in range(50)})
        dirs.update({rf"{data_root}\OtherVendor\Data_{i}": 4096 for i in range(1950)})

        t0 = time.time()
        footprints = build_application_footprints(apps, dirs)
        elapsed = time.time() - t0

        self.assertLess(elapsed, 1.0, f"Ownership evaluation took {elapsed:.2f}s, expected < 1.0s")
        self.assertEqual(len(footprints), 100)
        matched = [f for f in footprints if f.related_paths]
        self.assertEqual(len(matched), 50)
        for f in matched:
            self.assertEqual(f.related_data_bytes, 8192)


class LiveSubphaseProgressTests(unittest.TestCase):
    def test_find_duplicate_groups_emits_stage_progress(self):
        from reconspace.duplicates import find_duplicate_groups

        events = []
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "a.bin"
            p2 = Path(td) / "b.bin"
            content = b"duplicate content" * 100
            p1.write_bytes(content)
            p2.write_bytes(content)

            groups, errors = find_duplicate_groups(
                {len(content): [str(p1), str(p2)]},
                progress=lambda p: events.append(dict(p)),
            )

        self.assertEqual(len(groups), 1)
        stages = [e.get("stage") for e in events if e.get("phase") == "duplicate_hashing"]
        self.assertIn("quick_fingerprint", stages)
        self.assertIn("sha256", stages)

    def test_optional_system_inventory_emits_subphase_progress(self):
        from reconspace import windows_collectors as wc

        events = []
        with mock.patch.object(wc, "IS_WINDOWS", True), mock.patch.object(
            wc, "_powershell_json", return_value=CollectorResult("test", True, {})
        ):
            wc.collect_optional_system_inventory(
                profile="quick",
                cancel=lambda: len(events) >= 3,
                progress=lambda p: events.append(dict(p)),
            )

        self.assertGreaterEqual(len(events), 3)
        for e in events:
            self.assertEqual(e.get("phase"), "windows_deep_inventory")
            self.assertIn("item", e)
            self.assertIn("done", e)
            self.assertIn("total", e)

    def test_binary_trust_and_path_security_skip_offline_drives_without_hanging(self):
        from reconspace import windows_collectors as wc

        offline_path = r"X:\NonExistentDrive\service.exe"
        records, results = wc.collect_binary_trust([offline_path])
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0].exists)
        self.assertEqual(records[0].signature_status, "Missing")

        sec_records, sec_results = wc.collect_path_security([offline_path])
        self.assertEqual(len(sec_records), 1)
        self.assertIn("offline", sec_records[0].error.lower())


class PathNormalizationRobustnessTests(unittest.TestCase):
    def test_scanner_and_engine_norm_handles_quotes_and_bare_drives(self):
        from reconspace.doctor import doctor
        from reconspace.engine import _norm as engine_norm
        from reconspace.scanner import _norm as scanner_norm
        from reconspace.webapp import _request_path

        for raw in ['"C:\\"', "'C:\\'", "C:", '"C:"', '  "C:\\"  ']:
            with self.subTest(raw=raw):
                sn = scanner_norm(raw)
                en = engine_norm(raw)
                rp = _request_path(raw, "test")
                self.assertTrue(sn.startswith("c:\\"), f"scanner_norm failed for {raw}: {sn}")
                self.assertTrue(en.startswith("c:\\"), f"engine_norm failed for {raw}: {en}")
                self.assertTrue(rp.casefold().startswith("c:\\"), f"_request_path failed for {raw}: {rp}")

        doc = doctor('"C:\\"')
        self.assertTrue(doc["root_exists"])


if __name__ == "__main__":
    unittest.main()


