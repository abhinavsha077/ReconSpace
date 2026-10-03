import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from reconspace.audit_health import build_audit_health
from reconspace.models import (
    ApplicationRecord,
    CollectorResult,
    Finding,
    ProcessRecord,
    ScanStats,
    StartupRecord,
)
from reconspace.ownership import build_application_footprints, protect_active_process_paths
from reconspace.query import parse_query, query_report, query_to_csv, query_to_table
from reconspace.rules import apply_keep_policy, evaluate_rule_packs, load_rule_packs, validate_rule_pack
from reconspace.scanner import ScanConfig, scan_filesystem, _norm
from reconspace.security_insights import build_binary_and_acl_findings, build_storage_health_findings
from reconspace.trend import analyze_trend


class RuleEngineTests(unittest.TestCase):
    def _pack(self):
        return {
            "schema_version": 1,
            "name": "test pack",
            "version": "1",
            "rules": [{
                "id": "cache",
                "title": "Test cache",
                "scope": "directory",
                "match": {"segments_any": ["cache"]},
                "min_size_bytes": 1024,
                "category": "Test",
                "disposition": "probably_safe_cleanup",
                "risk": "low",
                "confidence": "high",
                "why_it_exists": "Generated test data.",
                "recommendation": "Review it.",
                "removal_risk": "Regeneration may be needed.",
                "related_to": ["tests"],
                "reclaim_fraction": 1.0,
            }],
        }

    def test_custom_rule_matches_metadata_and_executes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "cache"
            cache.mkdir()
            (cache / "large.bin").write_bytes(b"x" * 4096)
            inventory = scan_filesystem(ScanConfig(root=td, interesting_file_min_bytes=1))
            pack = validate_rule_pack(self._pack(), "test")
            findings, info = evaluate_rule_packs(inventory, [pack])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].estimated_reclaimable_bytes, 4096)
            self.assertFalse(info["custom_code_execution"])
            self.assertEqual(findings[0].evidence["rule_id"], "cache")

    def test_rule_pack_rejects_execution_fields(self):
        data = self._pack()
        data["rules"][0]["command"] = "anything"
        with self.assertRaises(ValueError):
            validate_rule_pack(data)

    def test_rule_pack_file_size_and_json_loading(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rules.json"
            path.write_text(json.dumps(self._pack()), encoding="utf-8")
            packs = load_rule_packs([str(path)], include_builtin=False)
            self.assertEqual(packs[0].name, "test pack")

    def test_keep_policy_zeroes_reclaim_and_downgrades_safe_label(self):
        finding = Finding(
            "Cache", r"C:\Work\Keep\cache", 1000, "cache", "probably_safe_cleanup", "low", "high",
            "generated", "review", "rebuild", estimated_reclaimable_bytes=1000,
        )
        result = apply_keep_policy([finding], [r"C:\Work\Keep"])
        self.assertEqual(finding.estimated_reclaimable_bytes, 0)
        self.assertEqual(finding.disposition, "manual_review")
        self.assertEqual(result["affected_findings"], 1)


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "findings": [
                {"title": "Old node cache", "path": r"C:\p\node_modules", "size_bytes": 3 * 1024**3, "age_days": 120, "risk": "low", "disposition": "manual_review", "related_to": ["Node.js"]},
                {"title": "VM", "path": r"C:\vm\kali.vhdx", "size_bytes": 20 * 1024**3, "age_days": 5, "risk": "high", "disposition": "intentional_tooling", "related_to": ["VMs"]},
            ]
        }

    def test_query_units_aliases_and_free_text(self):
        result = query_report(self.report, "findings", 'size>1GiB age>90d node', limit=10)
        self.assertEqual(result["matched"], 1)
        self.assertIn("node", result["rows"][0]["title"].lower())

    def test_query_or_and_regex(self):
        result = query_report(self.report, "findings", r"path~node_modules OR risk=high", limit=10)
        self.assertEqual(result["matched"], 2)

    def test_query_renderers(self):
        result = query_report(self.report, "findings", "size>1GiB")
        self.assertIn("matched", query_to_table(result))
        self.assertIn("title", query_to_csv(result))
        self.assertTrue(parse_query("risk:high").groups)


class TrendTests(unittest.TestCase):
    def _report(self, day, used, folder):
        ts = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)).isoformat()
        return {
            "version": "0.4.0", "profile": "deep",
            "stats": {"root": "C:\\", "started_at": ts, "finished_at": ts, "filesystem_total_bytes": 1000, "filesystem_used_bytes": used, "filesystem_free_bytes": 1000-used, "bytes_seen": folder, "files_seen": 1},
            "top_directories": [{"path": r"C:\Data", "size_bytes": folder}],
            "top_files": [], "findings": [], "applications": [],
            "reclaim_summary": {"path_candidates_nonoverlap_bytes": 0},
        }

    def test_trend_forecast_and_growth(self):
        result = analyze_trend([self._report(0, 400, 100), self._report(30, 500, 180), self._report(60, 600, 260)])
        self.assertTrue(result["same_volume"])
        self.assertTrue(result["capacity_forecast"]["available"])
        self.assertGreater(result["capacity_forecast"]["growth_bytes_per_day"], 0)
        self.assertEqual(result["directory_growth"][0]["delta_bytes"], 160)

    def test_trend_disables_capacity_across_volumes(self):
        one = self._report(0, 400, 100)
        two = self._report(30, 500, 150)
        two["stats"]["root"] = "D:\\"
        result = analyze_trend([one, two])
        self.assertFalse(result["same_volume"])
        self.assertFalse(result["capacity_forecast"]["available"])


class OwnershipHealthTests(unittest.TestCase):
    def test_application_footprint_links_active_process_and_data(self):
        with tempfile.TemporaryDirectory() as td:
            local = Path(td) / "Local"
            install = Path(td) / "Programs" / "ExampleTool"
            data = local / "ExampleTool"
            install.mkdir(parents=True)
            data.mkdir(parents=True)
            app = ApplicationRecord("Example Tool", publisher="Example Corp", install_location=str(install), estimated_size_bytes=100)
            proc = ProcessRecord(42, "example.exe", executable_path=str(install / "example.exe"), working_set_bytes=50)
            dirs = {str(data): 500, str(install): 100}
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local), "APPDATA": "", "PROGRAMDATA": ""}, clear=False):
                rows = build_application_footprints([app], dirs, processes=[proc])
            self.assertEqual(rows[0].ownership_confidence, "high")
            self.assertTrue(rows[0].active_processes)
            self.assertEqual(rows[0].related_data_bytes, 500)

    def test_active_process_protection_zeroes_candidate(self):
        finding = Finding("App folder", "/opt/example", 100, "app", "manual_review", "low", "medium", "", "", "", estimated_reclaimable_bytes=100)
        process = ProcessRecord(1, "example", executable_path="/opt/example/bin/tool")
        result = protect_active_process_paths([finding], [process])
        self.assertEqual(finding.estimated_reclaimable_bytes, 0)
        self.assertEqual(result["affected_findings"], 1)

    def test_audit_health_is_coverage_not_security_score(self):
        stats = ScanStats(root="C:\\", started_at="x", files_seen=10, directories_seen=5)
        health = build_audit_health(stats, [CollectorResult("x", True)], profile="deep", duplicate_scan_enabled=True, process_count=2)
        self.assertIn("coverage", health["interpretation"].lower())
        self.assertIn("not a system health", health["interpretation"].lower())
        self.assertGreaterEqual(health["coverage_score"], 0)


class WindowsEvidenceParserTests(unittest.TestCase):
    def test_binary_trust_parser_and_source_signal(self):
        from reconspace import windows_collectors as wc
        payload = [{"Path": r"C:\Users\A\tool.exe", "Exists": True, "SignatureStatus": "NotSigned", "SignerSubject": "", "SignerIssuer": "", "CertificateThumbprint": "", "Sha256": "ABC", "SizeBytes": 99, "ModifiedTime": "x"}]
        with mock.patch.object(wc, "IS_WINDOWS", True), mock.patch.object(wc, "_powershell_json", return_value=CollectorResult("x", True, payload)):
            rows, results = wc.collect_binary_trust([r"C:\Users\A\tool.exe"], include_hashes=True)
        self.assertTrue(results[0].ok)
        self.assertEqual(rows[0].signature_status, "NotSigned")
        self.assertEqual(rows[0].sha256, "ABC")

    def test_acl_parser(self):
        from reconspace import windows_collectors as wc
        payload = [{"Path": r"C:\Data", "Owner": "SYSTEM", "AccessRuleCount": 5, "ExplicitRuleCount": 1, "DenyRuleCount": 0, "BroadWrite": ["Users: Modify"], "ProtectedAcl": False, "Error": ""}]
        with mock.patch.object(wc, "IS_WINDOWS", True), mock.patch.object(wc, "_powershell_json", return_value=CollectorResult("x", True, payload)):
            rows, _ = wc.collect_path_security([r"C:\Data"])
        self.assertTrue(rows[0].broad_write_detected)
        findings = build_binary_and_acl_findings([], rows)
        self.assertEqual(findings[0].estimated_reclaimable_bytes, 0)

    def test_storage_reliability_finding_is_not_cleanup(self):
        collectors = [CollectorResult("physical_disk_reliability", True, [{"FriendlyName": "Disk", "HealthStatus": "Warning", "OperationalStatus": ["Degraded"], "Size": 1000}])]
        findings = build_storage_health_findings(collectors)
        self.assertEqual(findings[0].risk, "critical")
        self.assertEqual(findings[0].estimated_reclaimable_bytes, 0)


if __name__ == "__main__":
    unittest.main()

class CrossMachinePrivacyTests(unittest.TestCase):
    def test_redaction_uses_report_content_not_only_local_environment(self):
        from reconspace.privacy import redact_report

        report = {
            "stats": {"root": r"D:\Cases\Client-A", "started_at": "", "finished_at": ""},
            "top_files": [{"path": r"D:\Cases\Client-A\Users\Alice\Desktop\secret.txt"}],
            "collectors": [{"name": "platform_info", "ok": True, "data": {"node": "LAB-PC-77", "username": "Alice"}}],
        }
        redacted = redact_report(report)
        rendered = json.dumps(redacted)
        self.assertNotIn("Client-A", rendered)
        self.assertNotIn("LAB-PC-77", rendered)
        self.assertNotIn("Alice", rendered)
        self.assertEqual(redacted["stats"]["root"], "<SCAN_ROOT>")
        self.assertIn("<SCAN_ROOT>", redacted["top_files"][0]["path"])
        self.assertFalse(redacted["privacy_redaction_summary"]["formal_anonymization_guarantee"])

    def test_volume_root_is_preserved_but_user_profile_is_redacted(self):
        from reconspace.privacy import redact_report

        report = {
            "stats": {"root": "C:\\"},
            "top_files": [{"path": r"C:\Users\ExternalUser\Downloads\case.zip"}],
        }
        redacted = redact_report(report)
        self.assertEqual(redacted["stats"]["root"], "C:\\")
        self.assertNotIn("ExternalUser", redacted["top_files"][0]["path"])

class TrendMetricQualityTests(unittest.TestCase):
    def test_impossible_capacity_counters_disable_forecast(self):
        from reconspace.trend import analyze_trend

        reports = []
        gib = 1024 ** 3
        for day, used, free in [(1, 70 * gib, 20 * gib), (15, 80 * gib, 10 * gib), (30, 120 * gib, 0)]:
            reports.append({
                "version": "0.4.0",
                "profile": "deep",
                "stats": {
                    "root": "C:\\",
                    "finished_at": f"2026-01-{day:02d}T00:00:00+00:00",
                    "filesystem_total_bytes": 100 * gib,
                    "filesystem_used_bytes": used,
                    "filesystem_free_bytes": free,
                },
                "top_directories": [], "top_files": [], "applications": [], "findings": [],
            })
        result = analyze_trend(reports)
        self.assertFalse(result["capacity_forecast"]["available"])
        self.assertTrue(any("inconsistent" in x.lower() or "greater than total" in x.lower() for x in result["warnings"]))


class PhysicalReclaimBasisTests(unittest.TestCase):
    def test_allocated_size_is_preferred_over_logical_size(self):
        from reconspace.models import FileRecord
        from reconspace.storage_basis import file_reclaim_basis

        record = FileRecord(path=r"C:\\Data\\sparse.bin", size_bytes=10 * 1024 ** 3, allocated_bytes=64 * 1024 ** 2)
        reclaim, evidence = file_reclaim_basis(record)
        self.assertEqual(reclaim, 64 * 1024 ** 2)
        self.assertEqual(evidence["reclaim_basis"], "allocated_size_on_disk")

    def test_single_hardlink_path_has_no_guaranteed_reclaim(self):
        from reconspace.models import FileRecord
        from reconspace.storage_basis import file_reclaim_basis

        record = FileRecord(path=r"C:\\Data\\alias.bin", size_bytes=1024, allocated_bytes=4096, link_count=2)
        reclaim, evidence = file_reclaim_basis(record)
        self.assertEqual(reclaim, 0)
        self.assertIn("hardlink", evidence["reclaim_basis"])

class CollectorApplicabilityTests(unittest.TestCase):
    def test_not_applicable_optional_collector_does_not_reduce_coverage(self):
        from reconspace.audit_health import build_audit_health
        from reconspace.models import ScanStats, CollectorResult

        stats = ScanStats(root="C:\\", started_at="x", directories_seen=10)
        health = build_audit_health(
            stats,
            [
                CollectorResult("required", True),
                CollectorResult("optional_missing", False, error="not installed", applicable=False),
            ],
            profile="standard",
        )
        self.assertEqual(health["collectors_requested"], 1)
        self.assertEqual(health["collectors_succeeded"], 1)
        self.assertEqual(health["collectors_failed"], 0)
        self.assertEqual(health["collectors_not_applicable"], 1)
        self.assertEqual(health["collector_success_rate"], 1.0)

class SystemFileBasisRegressionTests(unittest.TestCase):
    def test_memory_dump_uses_its_own_reclaim_basis_without_interesting_file_state(self):
        from reconspace.classify import build_findings

        with tempfile.TemporaryDirectory() as td:
            windows = Path(td) / "Windows"
            windows.mkdir()
            dump = windows / "MEMORY.DMP"
            dump.write_bytes(b"x" * 4096)
            inventory = scan_filesystem(ScanConfig(
                root=td,
                top_files=20,
                interesting_file_min_bytes=1024 * 1024,
                duplicate_min_bytes=1024 * 1024,
            ))
            self.assertFalse(inventory.interesting_files)
            with mock.patch.dict(os.environ, {"SystemDrive": td, "SystemRoot": str(windows)}, clear=False):
                findings = build_findings(inventory, [], [])
            row = next(item for item in findings if item.title == "Windows kernel memory dump")
            self.assertEqual(row.estimated_reclaimable_bytes, row.evidence["allocated_size_bytes"])
            self.assertEqual(row.evidence["reclaim_basis"], "allocated_size_on_disk")

class RequestedEvidenceCoverageTests(unittest.TestCase):
    def test_non_applicable_deep_evidence_does_not_reduce_coverage(self):
        stats = ScanStats(root="C:\\", started_at="x", directories_seen=10)
        health = build_audit_health(
            stats,
            [CollectorResult("active_processes", False, error="Windows-only", applicable=False)],
            profile="deep",
            duplicate_scan_enabled=True,
            process_requested=True,
            process_applicable=False,
            signature_requested=True,
            signature_applicable=False,
            acl_requested=True,
            acl_applicable=False,
        )
        self.assertEqual(health["coverage_score"], 100.0)
        self.assertEqual(health["collectors_failed"], 0)
        self.assertTrue(any("not applicable" in row["message"].lower() for row in health["issues"]))

    def test_applicable_empty_process_collector_is_reported(self):
        stats = ScanStats(root="C:\\", started_at="x", directories_seen=10)
        health = build_audit_health(
            stats,
            [CollectorResult("active_processes", True, data=[])],
            profile="deep",
            duplicate_scan_enabled=True,
            process_requested=True,
            process_applicable=True,
        )
        self.assertEqual(health["coverage_score"], 97.0)
        self.assertTrue(any("returned no process" in row["message"].lower() for row in health["issues"]))

class OptionalCommandApplicabilityTests(unittest.TestCase):
    def test_missing_optional_command_is_not_applicable(self):
        from reconspace import windows_collectors as wc

        with mock.patch.object(wc.subprocess, "run", side_effect=FileNotFoundError("missing")):
            result = wc._run_read_only(["missing-tool.exe", "--version"])
        self.assertFalse(result.ok)
        self.assertFalse(result.applicable)
        self.assertIn("not installed", result.error.lower())

class RuleOptimizationSemanticsTests(unittest.TestCase):
    def test_validation_does_not_mutate_input_and_all_mode_requires_all_predicates(self):
        data = {
            "schema_version": 1,
            "name": "all-mode",
            "version": "1",
            "rules": [{
                "id": "both",
                "title": "Both predicates",
                "scope": "file",
                "match_mode": "all",
                "match": {"extensions": [".tmp"], "path_contains_any": ["downloads"]},
                "min_size_bytes": 1,
                "category": "test",
                "disposition": "manual_review",
                "risk": "low",
                "confidence": "high",
                "why_it_exists": "test",
                "recommendation": "review",
                "removal_risk": "test",
                "reclaim_fraction": 1.0,
            }],
        }
        original = json.loads(json.dumps(data))
        pack = validate_rule_pack(data)
        self.assertEqual(data, original)
        with tempfile.TemporaryDirectory() as td:
            downloads = Path(td) / "downloads"
            other = Path(td) / "other"
            downloads.mkdir(); other.mkdir()
            (downloads / "yes.tmp").write_bytes(b"x" * 64)
            (downloads / "wrong.bin").write_bytes(b"x" * 64)
            (other / "wrong.tmp").write_bytes(b"x" * 64)
            inv = scan_filesystem(ScanConfig(root=td, interesting_file_min_bytes=1, duplicate_min_bytes=999999))
            findings, info = evaluate_rule_packs(inv, [pack])
        self.assertEqual([Path(row.path).name for row in findings], ["yes.tmp"])
        self.assertGreater(info["candidate_indexing"]["file_candidates"], 0)

class QueryWindowsPathAndSortTests(unittest.TestCase):
    def test_unquoted_windows_backslashes_are_preserved(self):
        report = {"top_files": [{"path": r"C:\Users\Alice\Downloads\x.zip", "size_bytes": 1}]}
        result = query_report(report, "files", r"path:C:\Users\Alice")
        self.assertEqual(result["matched"], 1)

    def test_mixed_type_sort_is_deterministic_and_missing_values_are_last(self):
        report = {"collectors": [
            {"name": "numeric", "data": 10},
            {"name": "text", "data": "abc"},
            {"name": "missing"},
        ]}
        result = query_report(report, "collectors", sort="data")
        self.assertEqual(result["rows"][-1]["name"], "missing")

class PrivacySecretScrubbingTests(unittest.TestCase):
    def test_redaction_scrubs_common_cli_and_url_secret_forms(self):
        from reconspace.privacy import redact_report

        report = {
            "stats": {"root": "C:\\"},
            "processes": [{
                "command_line": "tool --api-key=ABC123 --password hunter2 --token:ZXCV https://user:pass@example.test/ Authorization: Bearer deadbeef"
            }],
        }
        rendered = json.dumps(redact_report(report))
        for secret in ("ABC123", "hunter2", "ZXCV", "pass@example", "deadbeef"):
            self.assertNotIn(secret, rendered)
        self.assertIn("REDACTED_SECRET", rendered)

class PortableHtmlExportTests(unittest.TestCase):
    def test_static_html_export_is_escaped_and_non_executable(self):
        from reconspace.exporter import export_html_report

        report = {
            "version": "0.4.0",
            "profile": "deep",
            "stats": {"root": r"C:\\Audit", "files_seen": 1, "bytes_seen": 1024},
            "findings": [{
                "title": "<script>alert(1)</script>",
                "path": r"C:\\Audit\\x.tmp",
                "disposition": "manual_review",
                "risk": "low",
                "estimated_reclaimable_bytes": 1024,
                "recommendation": "Review only",
                "removal_risk": "Unknown",
            }],
            "notes": ["READ-ONLY"],
            "audit_health": {"coverage_score": 90, "coverage_grade": "high"},
            "reclaim_summary": {},
        }
        with tempfile.TemporaryDirectory() as td:
            path = export_html_report(report, str(Path(td) / "report.html"))
            text = path.read_text(encoding="utf-8")
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertNotIn("<script", text.casefold())
        self.assertIn("READ-ONLY / NO EXECUTION", text)
        self.assertIn("Content-Security-Policy", text)

class RuleReclaimAccountingTests(unittest.TestCase):
    def test_rule_findings_participate_in_conservative_path_summary(self):
        from reconspace.reclaim import build_reclaim_summary

        data = {
            "schema_version": 1,
            "name": "reclaim-test",
            "version": "1",
            "rules": [{
                "id": "tmp-file",
                "title": "Temporary file",
                "scope": "file",
                "match": {"extensions": [".tmp"]},
                "min_size_bytes": 1,
                "category": "test",
                "disposition": "manual_review",
                "risk": "low",
                "confidence": "high",
                "why_it_exists": "test",
                "recommendation": "review",
                "removal_risk": "test",
                "reclaim_fraction": 1.0,
            }],
        }
        pack = validate_rule_pack(data)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "candidate.tmp"
            path.write_bytes(b"x" * 4096)
            inv = scan_filesystem(ScanConfig(root=td, interesting_file_min_bytes=1, duplicate_min_bytes=999999))
            findings, _info = evaluate_rule_packs(inv, [pack])
        self.assertEqual(findings[0].evidence["scope_type"], "file")
        summary = build_reclaim_summary(findings)
        self.assertGreater(summary["path_candidates_nonoverlap_bytes"], 0)

class ArbitraryFileRuleReachabilityTests(unittest.TestCase):
    def test_large_file_rule_is_not_limited_to_hard_coded_extensions(self):
        data = {
            "schema_version": 1,
            "name": "extension-reachability",
            "version": "1",
            "rules": [{
                "id": "partial",
                "title": "Partial download",
                "scope": "file",
                "match": {"extensions": [".crdownload"]},
                "min_size_bytes": 1,
                "category": "test",
                "disposition": "manual_review",
                "risk": "low",
                "confidence": "high",
                "why_it_exists": "test",
                "recommendation": "review",
                "removal_risk": "test",
                "reclaim_fraction": 1.0,
            }],
        }
        pack = validate_rule_pack(data)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "download.crdownload"
            path.write_bytes(b"x" * 4096)
            inv = scan_filesystem(ScanConfig(
                root=td,
                interesting_file_min_bytes=1,
                duplicate_min_bytes=999999,
            ))
            findings, _ = evaluate_rule_packs(inv, [pack])
        self.assertEqual([row.path for row in findings], [_norm(str(path))])
        self.assertEqual(inv.stats.metadata_candidate_files_seen, 1)
        self.assertEqual(inv.stats.metadata_candidate_files_retained, 1)
        self.assertEqual(inv.stats.metadata_candidate_files_omitted, 0)

class EngineRuleRetentionPlanningTests(unittest.TestCase):
    def test_engine_uses_validated_file_rules_to_lower_candidate_threshold_safely(self):
        from reconspace.engine import AuditConfig, run_audit

        pack = {
            "schema_version": 1,
            "name": "engine-retention",
            "version": "1",
            "rules": [{
                "id": "custom-large-file",
                "title": "Custom large file",
                "scope": "file",
                "match": {"extensions": [".customcache"]},
                "min_size_bytes": 1,
                "category": "test",
                "disposition": "manual_review",
                "risk": "low",
                "confidence": "high",
                "why_it_exists": "test",
                "recommendation": "review",
                "removal_risk": "test",
                "reclaim_fraction": 1.0,
            }],
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            root.mkdir()
            candidate = root / "data.customcache"
            candidate.write_bytes(b"x" * (2 * 1024 * 1024))
            pack_path = Path(td) / "rules.json"
            pack_path.write_text(json.dumps(pack), encoding="utf-8")
            report = run_audit(AuditConfig(
                root=str(root),
                profile="quick",
                scan_duplicates=False,
                deep_windows_inventory=False,
                collect_processes=False,
                verify_signatures=False,
                collect_path_security=False,
                collect_prefetch=False,
                use_builtin_rules=False,
                rule_pack_paths=(str(pack_path),),
            ))
        self.assertTrue(any(row.title == "Custom large file" for row in report.findings))
        retention = report.rule_pack_info["file_candidate_retention"]
        self.assertEqual(retention["effective_min_bytes"], 1024 * 1024)
        self.assertTrue(retention["floor_applied"])
        self.assertGreaterEqual(retention["files_retained"], 1)
