import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from reconspace.classify import classify_applications, classify_services_and_tasks
from reconspace.commandline import extract_windows_executable, has_unquoted_service_path_risk
from reconspace.compare import compare_reports
from reconspace.doctor import doctor
from reconspace.duplicates import FileChangedDuringHash, _stable_hash, find_duplicate_groups
from reconspace.exporter import export_csv_bundle
from reconspace.models import ApplicationRecord, CollectorResult, Finding, ScheduledTaskRecord, ServiceRecord
from reconspace.reclaim import build_reclaim_summary
from reconspace.scanner import (
    FILE_ATTRIBUTE_OFFLINE,
    ScanCancelled,
    ScanConfig,
    STATEFUL_HASH_EXTENSIONS,
    _hash_eligible,
    scan_filesystem,
)
from reconspace.system_insights import build_system_findings

MB = 1024 * 1024


class V03Tests(unittest.TestCase):
    def test_flat_directory_scan_cancels_cooperatively(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for idx in range(1300):
                (root / f"f{idx:04d}.txt").write_text("x", encoding="utf-8")
            calls = {"n": 0}
            def cancel():
                calls["n"] += 1
                return calls["n"] >= 3
            with self.assertRaises(ScanCancelled):
                scan_filesystem(ScanConfig(root=td, duplicate_min_bytes=99*MB), cancel=cancel)
            self.assertGreaterEqual(calls["n"], 3)

    def test_interesting_retention_keeps_largest_not_first(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for idx, mb in enumerate([1, 2, 3, 4, 5]):
                with open(root / f"a{idx}.zip", "wb") as f:
                    f.truncate(mb * MB)
            inv = scan_filesystem(ScanConfig(root=td, interesting_file_min_bytes=1, max_interesting_files=2, duplicate_min_bytes=99*MB))
            self.assertEqual([x.size_bytes for x in inv.interesting_files], [5*MB, 4*MB])

    def test_stateful_duplicate_hashing_is_opt_in(self):
        ext = next(iter(STATEFUL_HASH_EXTENSIONS))
        self.assertFalse(_hash_eligible(0, ext, 100, ScanConfig()))
        self.assertTrue(_hash_eligible(0, ext, 100, ScanConfig(hash_stateful_files=True)))
        self.assertFalse(_hash_eligible(FILE_ATTRIBUTE_OFFLINE, ".zip", 100, ScanConfig(hash_stateful_files=True)))

    def test_hash_rejects_file_changed_during_read(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.bin"
            p.write_bytes(b"a" * 1024)
            real_stat = __import__("reconspace.duplicates", fromlist=["_stat_signature"])._stat_signature
            sig = real_stat(str(p))
            with mock.patch("reconspace.duplicates._stat_signature", side_effect=[sig, (sig[0], sig[1]+1, sig[2], sig[3])]):
                with self.assertRaises(FileChangedDuringHash):
                    _stable_hash(str(p), 1024, full=False)

    def test_hardlink_only_group_not_duplicate_reclaim(self):
        if not hasattr(os, "link"):
            self.skipTest("hard links unsupported")
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a.bin"; b = Path(td) / "b.bin"
            a.write_bytes(b"z" * 2048)
            try:
                os.link(a, b)
            except OSError:
                self.skipTest("filesystem hard links unavailable")
            groups, errors = find_duplicate_groups({2048: [str(a), str(b)]})
            self.assertFalse(errors)
            self.assertEqual(groups, [])

    def test_application_token_boundary_avoids_logitech_as_git(self):
        apps = [ApplicationRecord(name="Logitech Options+", publisher="Logitech"), ApplicationRecord(name="Git", publisher="Git")]
        classify_applications(apps)
        self.assertFalse(apps[0].classification.startswith("Likely intentional"))
        self.assertTrue(apps[1].classification.startswith("Likely intentional"))

    def test_persistence_review_service_and_hidden_task(self):
        svc = ServiceRecord(name="x", display_name="X", state="Running", start_mode="Auto", path_name=r"C:\Program Files\Vendor App\service.exe -k")
        task = ScheduledTaskRecord(task_name="X", task_path="\\", state="Ready", hidden=True, actions=[r"powershell.exe -EncodedCommand AAAA"])
        classify_services_and_tasks([svc], [task])
        self.assertEqual(svc.risk_hint, "review")
        self.assertIn("unquoted", svc.reason)
        self.assertEqual(task.risk_hint, "review")
        self.assertIn("Hidden", task.reason)

    def test_commandline_extracts_quoted_executable(self):
        self.assertEqual(extract_windows_executable(r'"C:\Program Files\A\a.exe" --flag'), r"C:\Program Files\A\a.exe")
        self.assertTrue(has_unquoted_service_path_risk(r"C:\Program Files\A\a.exe -s"))
        self.assertFalse(has_unquoted_service_path_risk(r'"C:\Program Files\A\a.exe" -s'))

    def test_reclaim_summary_suppresses_child_but_separates_alternatives(self):
        parent = Finding("P", r"C:\A", 1000, "Cache", "probably_safe_cleanup", "low", "high", "", "", "", estimated_reclaimable_bytes=1000, evidence={"scope_type":"folder"})
        child = Finding("C", r"C:\A\x.zip", 500, "Archive", "manual_review", "medium", "high", "", "", "", estimated_reclaimable_bytes=500, evidence={"scope_type":"file"})
        dup = Finding("D", "duplicate", 500, "Duplicates", "manual_review", "low", "high", "", "", "", estimated_reclaimable_bytes=500, evidence={"scope_type":"duplicate_group"})
        app = Finding("A", "app", 700, "Installed applications", "manual_review", "medium", "medium", "", "", "", estimated_reclaimable_bytes=700, evidence={"scope_type":"application"})
        platform = Finding("Docker", "Docker", 300, "Docker storage", "manual_review", "low", "high", "", "", "", estimated_reclaimable_bytes=300, evidence={"scope_type":"platform"})
        summary = build_reclaim_summary([parent, child, dup, app, platform])
        self.assertEqual(summary["path_candidates_nonoverlap_bytes"], 1000)
        self.assertEqual(summary["suppressed_overlapping_path_findings"], 1)
        self.assertEqual(summary["duplicate_potential_bytes_separate"], 500)
        self.assertEqual(summary["application_potential_bytes_separate"], 700)
        self.assertEqual(summary["platform_potential_bytes_separate"], 300)

    def test_compare_warns_different_volumes_and_does_not_emit_free_delta(self):
        old = {"stats":{"root":"C:\\", "filesystem_free_bytes":1000}, "profile":"deep", "findings":[], "top_files":[], "top_directories":[], "applications":[]}
        new = {"stats":{"root":"D:\\", "filesystem_free_bytes":500}, "profile":"standard", "findings":[], "top_files":[], "top_directories":[], "applications":[]}
        diff = compare_reports(old,new)
        self.assertIsNone(diff["free_space_delta_bytes"])
        self.assertFalse(diff["same_volume"])
        self.assertTrue(diff["warnings"])

    def test_system_insights_docker_wsl_vss_and_pagefile(self):
        collectors = [
            CollectorResult("wsl_registry", True, [{"name":"Ubuntu", "version":2, "vhdx":r"C:\x\ext4.vhdx", "vhdx_logical_bytes":1000, "vhdx_allocated_bytes":700}]),
            CollectorResult("docker_system_df", True, [{"Type":"Build Cache", "Size":"10GB", "Reclaimable":"4GB (40%)"}]),
            CollectorResult("shadow_storage", True, [{"UsedSpace":2000,"AllocatedSpace":3000,"MaxSpace":9000}]),
            CollectorResult("pagefile_usage", True, [{"Name":r"C:\pagefile.sys","AllocatedBaseSize":256}]),
        ]
        findings = build_system_findings(collectors)
        titles = {f.title for f in findings}
        self.assertTrue(any("WSL" in x for x in titles))
        self.assertTrue(any("Docker" in x for x in titles))
        self.assertIn("Volume Shadow Copy / restore storage", titles)
        self.assertIn("Windows pagefile allocation", titles)
        docker = next(f for f in findings if "Docker" in f.title)
        self.assertGreater(docker.estimated_reclaimable_bytes, 0)

    def test_doctor_never_executes_subprocess(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("must not execute")):
            result = doctor(root=tempfile.gettempdir())
        self.assertEqual(result["safety"], "READ_ONLY_DIAGNOSTIC_NO_EXTERNAL_COMMAND_EXECUTION")
        self.assertTrue(result["platform"])

    def test_csv_export_explicit_bundle(self):
        report = {"findings":[{"title":"X","evidence":{"a":1}}], "duplicates":[], "top_files":[], "top_directories":[], "applications":[], "startup":[], "services":[], "scheduled_tasks":[], "project_artifacts":[], "extension_summary":[], "age_summary":[]}
        with tempfile.TemporaryDirectory() as td:
            paths = export_csv_bundle(report, td)
            self.assertEqual(len(paths), 11)
            self.assertTrue((Path(td)/"findings.csv").exists())


if __name__ == "__main__":
    unittest.main()

class PrivacyValidationTests(unittest.TestCase):
    def test_report_redaction_returns_copy(self):
        from reconspace.privacy import redact_report
        original = {"stats": {"root": r"C:\Users\Alice"}, "findings": [{"path": r"C:\Users\Alice\secret.txt"}]}
        redacted = redact_report(original, [(r"C:\Users\Alice", "%USERPROFILE%")])
        self.assertEqual(original["stats"]["root"], r"C:\Users\Alice")
        self.assertEqual(redacted["stats"]["root"], "%USERPROFILE%")
        self.assertTrue(redacted["privacy_redacted"])

    def test_report_validation_catches_invalid_disposition(self):
        from reconspace.validation import validate_report
        report = {"schema_version": 3, "stats": {"root": "C:\\", "files_seen": 1, "directories_seen": 1, "bytes_seen": 1},
                  "findings": [{"title":"x","path":"p","category":"c","disposition":"delete_it","risk":"low","confidence":"high","size_bytes":1,"estimated_reclaimable_bytes":1}],
                  "top_files":[],"top_directories":[],"duplicates":[],"applications":[],"collectors":[]}
        result = validate_report(report)
        self.assertFalse(result["ok"])
        self.assertTrue(any("disposition" in e for e in result["errors"]))
