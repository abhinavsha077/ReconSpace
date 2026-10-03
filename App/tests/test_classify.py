import tempfile
import unittest
from pathlib import Path

from reconspace.classify import build_findings
from reconspace.scanner import ScanConfig, scan_filesystem, _norm


class ClassificationTests(unittest.TestCase):
    def test_node_modules_is_intentional_tooling(self):
        with tempfile.TemporaryDirectory() as td:
            nm = Path(td) / "project" / "node_modules"
            nm.mkdir(parents=True)
            with open(nm / "large.pkg", "wb") as f:
                f.truncate(110 * 1024 * 1024)
            inv = scan_filesystem(ScanConfig(root=td, duplicate_min_bytes=200 * 1024 * 1024))
            findings = build_findings(inv, [], [])
            hits = [f for f in findings if f.path == _norm(str(nm))]
            self.assertTrue(hits)
            self.assertEqual(hits[0].disposition, "intentional_tooling")
            self.assertIn("Node.js", hits[0].related_to)


    def test_category_group_resolution(self):
        from reconspace.classify import CATEGORY_GROUPS, resolve_category_group
        
        self.assertIn("system_temp", CATEGORY_GROUPS)
        self.assertIn("dev_build", CATEGORY_GROUPS)
        self.assertIn("ai_ml", CATEGORY_GROUPS)
        self.assertIn("browser_app", CATEGORY_GROUPS)
        self.assertIn("apps_installers", CATEGORY_GROUPS)
        self.assertIn("virtualization", CATEGORY_GROUPS)
        self.assertIn("diagnostics", CATEGORY_GROUPS)

        self.assertEqual(resolve_category_group("temp"), "system_temp")
        self.assertEqual(resolve_category_group("cache"), "system_temp")
        self.assertEqual(resolve_category_group("pip_cache"), "dev_build")
        self.assertEqual(resolve_category_group("npm_cache"), "dev_build")
        self.assertEqual(resolve_category_group("node_modules"), "dev_build")
        self.assertEqual(resolve_category_group("huggingface_cache"), "ai_ml")
        self.assertEqual(resolve_category_group("ollama_models"), "ai_ml")
        self.assertEqual(resolve_category_group("browser_cache"), "browser_app")
        self.assertEqual(resolve_category_group("downloads"), "apps_installers")
        self.assertEqual(resolve_category_group("docker_data"), "virtualization")
        self.assertEqual(resolve_category_group("memory_dump"), "system_temp")
        self.assertEqual(resolve_category_group("security_finding"), "diagnostics")
        self.assertEqual(resolve_category_group("unknown_cat_xyz"), "diagnostics")

    def test_normalize_findings_sets_category_group(self):
        from reconspace.classify import normalize_findings
        from reconspace.models import Finding

        f = Finding(
            title="NPM Cache",
            path=r"C:\npm",
            size_bytes=5000,
            category="npm_cache",
            disposition="probably_safe_cleanup",
            risk="low",
            confidence="high",
            why_it_exists="Cache",
            recommendation="Purge",
            removal_risk="Re-downloads",
            estimated_reclaimable_bytes=5000,
        )
        normalized = normalize_findings([f])
        self.assertEqual(normalized[0].category_group, "dev_build")

    def test_report_markdown_renders_categories_and_explanative_pillars(self):
        from dataclasses import asdict
        from reconspace.report import report_markdown
        from reconspace.models import Finding

        f = Finding(
            title="Windows Temp Files",
            path=r"C:\Windows\Temp",
            size_bytes=1024 * 1024 * 50,
            category="temp",
            disposition="probably_safe_cleanup",
            risk="low",
            confidence="high",
            why_it_exists="Scratch files created during operations",
            recommendation="Clean using Windows Storage Sense",
            removal_risk="Active installers may fail if running",
            estimated_reclaimable_bytes=1024 * 1024 * 50,
        )
        report = {
            "version": "0.4.2",
            "profile": "deep",
            "stats": {"root": r"C:\\", "files_seen": 100, "bytes_seen": 1024 * 1024 * 100},
            "findings": [asdict(f)],
            "reclaim_summary": {},
            "audit_health": {"coverage_score": 95, "coverage_grade": "A"},
        }
        md = report_markdown(report)
        self.assertIn("System & Temporary Files", md)
        self.assertIn("Why it exists", md)
        self.assertIn("Recommended action", md)
        self.assertIn("Risk if removed", md)
        self.assertIn("Safe Cleanup", md)

    def test_static_html_report_renders_categories_and_modern_styling(self):
        from reconspace.exporter import render_html_report

        report = {
            "version": "0.4.2",
            "profile": "deep",
            "stats": {"root": r"C:\\", "files_seen": 100, "bytes_seen": 1024 * 1024 * 100},
            "findings": [{
                "title": "HuggingFace Model Weights",
                "path": r"C:\Users\test\.cache\huggingface",
                "size_bytes": 1024 * 1024 * 500,
                "category": "huggingface_cache",
                "disposition": "manual_review",
                "risk": "medium",
                "confidence": "high",
                "why_it_exists": "Downloaded transformer models",
                "recommendation": "Use huggingface-cli delete-cache",
                "removal_risk": "Models will re-download when queried",
                "estimated_reclaimable_bytes": 1024 * 1024 * 500,
            }],
            "notes": ["Test notes"],
            "audit_health": {"coverage_score": 90, "coverage_grade": "A"},
            "reclaim_summary": {},
        }
        html_out = render_html_report(report)
        self.assertIn("Storage by category", html_out)
        self.assertIn("AI &amp; Machine Learning Models", html_out)
        self.assertIn("cat-grid", html_out)
        self.assertIn("cat-card", html_out)
        self.assertIn("Why it exists", html_out)
        self.assertIn("Recommendation", html_out)
        self.assertIn("Removal risk", html_out)

    def test_webapp_dashboard_contains_modern_categorized_elements(self):
        from reconspace.webapp import _html

        html_text = _html()
        self.assertIn("CATEGORY_META", html_text)
        self.assertIn("cat-bar", html_text)
        self.assertIn("cat-pill", html_text)
        self.assertIn("explain-grid", html_text)
        self.assertIn("explain-card", html_text)
        self.assertIn("copy-btn", html_text)
        self.assertIn("switchCategory", html_text)
        self.assertIn("overview-cats", html_text)


if __name__ == "__main__":
    unittest.main()

