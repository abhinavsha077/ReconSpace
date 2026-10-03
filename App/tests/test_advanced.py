import json
import os
import tempfile
import unittest
from pathlib import Path

from reconspace.compare import compare_reports
from reconspace.duplicates import find_duplicate_groups
from reconspace.insights import discover_project_artifacts
from reconspace.plan import build_plan
from reconspace.scanner import ScanConfig, scan_filesystem, _norm


class AdvancedTests(unittest.TestCase):
    def test_hardlinks_do_not_inflate_reclaimable_duplicate_space(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = b"x" * (1024 * 1024)
            a = root / "a.bin"
            b = root / "b-hardlink.bin"
            c = root / "c-copy.bin"
            a.write_bytes(payload)
            try:
                os.link(a, b)
            except (OSError, NotImplementedError):
                self.skipTest("hard links unavailable on this filesystem")
            c.write_bytes(payload)

            inv = scan_filesystem(ScanConfig(root=td, duplicate_min_bytes=1, top_files=10, top_directories=10))
            groups, errors = find_duplicate_groups(inv.duplicate_candidates)
            self.assertFalse(errors)
            self.assertEqual(len(groups), 1)
            g = groups[0]
            self.assertEqual(g.distinct_file_instances, 2)
            self.assertGreaterEqual(g.reclaimable_bytes, len(payload))
            self.assertLessEqual(g.reclaimable_bytes - len(payload), 1024 * 1024)
            self.assertTrue(g.hardlink_sets)

    def test_project_context_finds_node_modules_and_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "app"
            nm = project / "node_modules"
            nm.mkdir(parents=True)
            (project / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
            with open(nm / "payload.bin", "wb") as f:
                f.truncate(3 * 1024 * 1024)
            inv = scan_filesystem(ScanConfig(root=td, duplicate_min_bytes=99 * 1024 * 1024))
            artifacts = discover_project_artifacts(inv, min_size_bytes=1)
            hit = next(x for x in artifacts if x.path == _norm(str(nm)))
            self.assertEqual(hit.artifact_type, "Node.js dependencies")
            self.assertEqual(hit.project_root, _norm(str(project)))
            self.assertIn("package.json", hit.project_markers)
            self.assertTrue(hit.rebuildable)

    def test_plan_excludes_do_not_touch_and_intentional_tooling(self):
        report = {
            "version": "0.2.0", "profile": "deep", "stats": {"root": "C:\\"},
            "findings": [
                {"title": "Cache", "path": "C:\\Cache", "category": "cache", "disposition": "probably_safe_cleanup", "risk": "low", "confidence": "high", "priority_score": 90, "size_bytes": 1000, "estimated_reclaimable_bytes": 900, "why_it_exists": "cache", "recommendation": "review", "removal_risk": "rebuild", "related_to": [], "evidence": {}},
                {"title": "VM", "path": "C:\\vm.vhdx", "category": "vm", "disposition": "intentional_tooling", "risk": "high", "confidence": "high", "priority_score": 10, "size_bytes": 5000, "estimated_reclaimable_bytes": 0, "why_it_exists": "vm", "recommendation": "keep", "removal_risk": "loss", "related_to": [], "evidence": {}},
                {"title": "WinSxS", "path": "C:\\Windows\\WinSxS", "category": "system", "disposition": "do_not_touch", "risk": "critical", "confidence": "high", "priority_score": 0, "size_bytes": 9999, "estimated_reclaimable_bytes": 0, "why_it_exists": "system", "recommendation": "do not touch", "removal_risk": "damage", "related_to": [], "evidence": {}},
            ],
        }
        plan = build_plan(report)
        self.assertEqual(len(plan["items"]), 1)
        self.assertEqual(plan["items"][0]["approval_status"], "PENDING_REVIEW")
        self.assertEqual(plan["items"][0]["execution"], "NONE - PLAN ONLY")

    def test_report_compare_tracks_free_space_and_hotspot_growth(self):
        old = {
            "version": "0.2.0",
            "stats": {"finished_at": "old", "filesystem_free_bytes": 1000, "bytes_seen": 5000},
            "top_directories": [{"path": "C:\\A", "size_bytes": 100}],
            "top_files": [],
            "findings": [],
            "applications": [],
        }
        new = {
            "version": "0.2.0",
            "stats": {"finished_at": "new", "filesystem_free_bytes": 700, "bytes_seen": 5300},
            "top_directories": [{"path": "C:\\A", "size_bytes": 400}],
            "top_files": [],
            "findings": [{"title": "New", "path": "C:\\A", "size_bytes": 400}],
            "applications": [],
        }
        diff = compare_reports(old, new)
        self.assertEqual(diff["free_space_delta_bytes"], -300)
        self.assertEqual(diff["directory_deltas"][0]["delta_bytes"], 300)
        self.assertEqual(len(diff["added_findings"]), 1)


if __name__ == "__main__":
    unittest.main()
