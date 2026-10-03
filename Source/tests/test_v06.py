import unittest

from reconspace.audit_health import build_audit_health
from reconspace.models import CollectorResult, ScanStats
from reconspace.report import report_markdown
from reconspace.webapp import _html


class DecisionGuidanceTests(unittest.TestCase):
    def test_non_file_task_actions_do_not_become_project_relative_trust_targets(self):
        from reconspace.engine import _trust_targets
        from reconspace.models import ScheduledTaskRecord

        tasks = [ScheduledTaskRecord(
            task_name="Handler",
            task_path="\\Vendor\\",
            state="Ready",
            actions=["COM:{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}", "cmd /c echo ok"],
            target_paths=["COM:{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}", "cmd"],
        )]
        targets, sources = _trust_targets([], [], tasks, [], include_processes=False)
        self.assertEqual(targets, [])
        self.assertEqual(sources, {})

    def test_builtin_microsoft_hidden_task_is_inventory_not_review_noise(self):
        from reconspace.classify import classify_services_and_tasks
        from reconspace.models import ScheduledTaskRecord

        task = ScheduledTaskRecord(
            task_name="Maintenance",
            task_path="\\Microsoft\\Windows\\Servicing\\",
            state="Ready",
            hidden=True,
            actions=["rundll32.exe system.dll,Entry"],
        )
        classify_services_and_tasks([], [task])
        self.assertEqual(task.risk_hint, "")
        self.assertEqual(task.reason, "")

        suspicious = ScheduledTaskRecord(
            task_name="Unexpected",
            task_path="\\Microsoft\\Windows\\Servicing\\",
            state="Ready",
            actions=[r"C:\Users\Public\tool.exe"],
        )
        classify_services_and_tasks([], [suspicious])
        self.assertEqual(suspicious.risk_hint, "review")
        self.assertIn("user-writable", suspicious.reason)

    def test_process_owner_collection_uses_batched_tasklist_index(self):
        from pathlib import Path

        source = Path("reconspace/windows_collectors.py").read_text(encoding="utf-8")
        self.assertIn("tasklist.exe /V /FO CSV /NH", source)
        self.assertNotIn("Invoke-CimMethod -InputObject $_ -MethodName GetOwner", source)

    def test_depth_ledger_groups_success_partial_and_unavailable_evidence(self):
        stats = ScanStats(root="C:\\", started_at="x", directories_seen=1)
        health = build_audit_health(
            stats,
            [
                CollectorResult("logical_disks", True),
                CollectorResult("wsl_list", True),
                CollectorResult("docker_images", False, error="Docker stopped"),
                CollectorResult("hyperv_vms", False, error="Feature unavailable", applicable=False),
                CollectorResult("binary_trust_batch_1", True),
                CollectorResult("path_security_batch_1", False, error="Access denied"),
            ],
            profile="deep",
            duplicate_scan_enabled=True,
        )
        domains = {row["id"]: row for row in health["depth_domains"]}
        self.assertEqual(domains["storage_map"]["status"], "complete")
        self.assertEqual(domains["virtualization"]["status"], "partial")
        self.assertEqual(domains["trust_permissions"]["status"], "partial")
        self.assertIn("docker_images", domains["virtualization"]["limitations"])

    def test_markdown_explains_scope_depth_and_next_step_without_console_unsafe_icons(self):
        report = {
            "version": "0.6.0",
            "profile": "deep",
            "stats": {
                "root": "C:\\Users\\Example",
                "filesystem_total_bytes": 1000,
                "filesystem_used_bytes": 950,
                "filesystem_free_bytes": 50,
            },
            "findings": [{
                "title": "Cache",
                "path": "C:\\Users\\Example\\cache",
                "size_bytes": 100,
                "estimated_reclaimable_bytes": 80,
                "category": "cache",
                "disposition": "probably_safe_cleanup",
                "risk": "low",
                "confidence": "high",
                "why_it_exists": "Speeds up work.",
                "recommendation": "Use the owning tool.",
                "removal_risk": "Must be rebuilt.",
            }],
            "reclaim_summary": {"probably_safe_path_bytes": 80, "path_candidates_nonoverlap_bytes": 80},
            "audit_health": {
                "coverage_grade": "high",
                "coverage_score": 90,
                "depth_domains": [{"title": "Storage map", "status": "complete", "checks_succeeded": 2, "checks_requested": 2}],
            },
        }
        text = report_markdown(report)
        self.assertIn("## What This Audit Means", text)
        self.assertIn("## Audit Depth and Limitations", text)
        self.assertIn("wider host", text)
        self.assertIn("Recommended next move", text)
        text.encode("cp1252")

    def test_dashboard_has_decision_brief_action_plan_scope_and_depth_views(self):
        html = _html()
        self.assertIn('data-view="plan"', html)
        self.assertIn("function decisionBrief()", html)
        self.assertIn("function actionPlan()", html)
        self.assertIn("function depthMatrix()", html)
        self.assertIn("Two scopes, kept separate", html)
        self.assertIn("What ReconSpace actually inspected", html)

    def test_cli_configures_replacement_for_limited_windows_console_encodings(self):
        from pathlib import Path

        source = Path("reconspace/cli.py").read_text(encoding="utf-8")
        self.assertIn('reconfigure(encoding="utf-8", errors="replace")', source)

    def test_edge_and_webview_are_not_counted_as_cleanup_opportunities(self):
        import tempfile
        from reconspace.classify import build_findings, classify_applications
        from reconspace.models import ApplicationRecord
        from reconspace.scanner import ScanConfig, scan_filesystem

        apps = [
            ApplicationRecord(name="Microsoft Edge", publisher="Microsoft Corporation", estimated_size_bytes=2 * 1024**3),
            ApplicationRecord(name="Microsoft Edge WebView2 Runtime", publisher="Microsoft Corporation", estimated_size_bytes=2 * 1024**3),
        ]
        classify_applications(apps)
        with tempfile.TemporaryDirectory() as root:
            inventory = scan_filesystem(ScanConfig(root=root, duplicate_min_bytes=1024**3))
            findings = build_findings(inventory, [], apps)
        app_findings = [row for row in findings if row.title.startswith("Large installed application:")]
        self.assertEqual(len(app_findings), 2)
        self.assertTrue(all(row.disposition == "do_not_touch" for row in app_findings))
        self.assertTrue(all(row.estimated_reclaimable_bytes == 0 for row in app_findings))


if __name__ == "__main__":
    unittest.main()
