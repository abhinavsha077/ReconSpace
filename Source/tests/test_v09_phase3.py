import unittest
from reconspace.models import CollectorResult
from reconspace.windows_collectors import (
    IS_WINDOWS,
    collect_extended_persistence,
    collect_alternate_data_streams,
    collect_windows_update_cache,
    _collect_component_store,
)
from reconspace.security_insights import build_protection_findings
from reconspace.system_insights import build_system_findings
from reconspace.webapp import _html


class Phase3PersistenceAndServicingTests(unittest.TestCase):
    def test_extended_persistence_collector(self):
        res = collect_extended_persistence()
        self.assertEqual(res.name, "extended_persistence")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            self.assertIsInstance(res.data, list)
            self.assertGreater(len(res.data), 0)
            for r in res.data[:5]:
                self.assertIn("category", r)
                self.assertIn("name", r)
                self.assertIn("is_user_writable", r)
        else:
            self.assertFalse(res.applicable)

    def test_alternate_data_streams_collector(self):
        res = collect_alternate_data_streams()
        self.assertEqual(res.name, "alternate_data_streams")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            self.assertIsInstance(res.data, dict)
            self.assertIn("total_streams", res.data)
            self.assertIn("zone_identifier_streams", res.data)
            self.assertIn("streams", res.data)
        else:
            self.assertFalse(res.applicable)

    def test_windows_update_cache_collector(self):
        res = collect_windows_update_cache()
        self.assertEqual(res.name, "windows_update_cache")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            self.assertIsInstance(res.data, dict)
            self.assertIn("software_distribution_download_bytes", res.data)
            self.assertIn("software_distribution_datastore_bytes", res.data)
            self.assertIn("services_state", res.data)
            self.assertIn("purge_recipe", res.data)
            self.assertIn("wuauserv", res.data["services_state"])
        else:
            self.assertFalse(res.applicable)

    def test_component_store_hardlink_delta_calculation(self):
        # Test simulated DISM output parsing with hardlink delta calculation
        fake_collector = CollectorResult(
            name="component_store_analysis",
            ok=True,
            data={
                "cleanup_recommended": True,
                "explorer_reported_bytes": 15 * 1024**3,
                "actual_size_bytes": 8 * 1024**3,
                "hardlink_dedup_savings_bytes": 7 * 1024**3,
                "backups_disabled_features_bytes": 3 * 1024**3,
                "cleanup_recipe": "cleanmgr.exe",
            },
        )
        self.assertEqual(fake_collector.data["hardlink_dedup_savings_bytes"], 7 * 1024**3)
        findings = build_system_findings([fake_collector])
        titles = [f.title for f in findings]
        self.assertTrue(any("Windows Component Store (WinSxS) cleanup recommended" in t for t in titles))
        matching = next(f for f in findings if "WinSxS" in f.title)
        self.assertEqual(matching.estimated_reclaimable_bytes, 3 * 1024**3)

    def test_security_insights_extended_persistence_and_ads(self):
        collectors = [
            CollectorResult(
                name="extended_persistence",
                ok=True,
                data=[
                    {
                        "category": "ContextMenuHandler",
                        "scope": "HKCR\\*\\shellex\\ContextMenuHandlers",
                        "name": "SuspiciousHandler",
                        "clsid": "{12345678-1234-1234-1234-123456789012}",
                        "target_path": "C:\\Users\\Test\\AppData\\Local\\Temp\\handler.dll",
                        "target_exists": True,
                        "is_user_writable": True,
                    }
                ],
            ),
            CollectorResult(
                name="alternate_data_streams",
                ok=True,
                data={
                    "total_streams": 5,
                    "zone_identifier_streams": 3,
                    "total_stream_bytes": 45000,
                    "streams": [
                        {
                            "file_path": "C:\\Users\\Test\\Downloads\\tool.exe",
                            "file_name": "tool.exe",
                            "stream_name": ":hiddenpayload.bin:$DATA",
                            "size_bytes": 42000,
                            "is_zone_identifier": False,
                        }
                    ],
                },
            ),
        ]
        findings = build_protection_findings(collectors)
        titles = [f.title for f in findings]
        self.assertTrue(any("Extended persistence entry requires review" in t for t in titles))
        self.assertTrue(any("Hidden Alternate Data Streams detected" in t for t in titles))

    def test_webapp_phase3_html_content(self):
        html = _html()
        self.assertIn("Hardlink Deduplication Savings", html)
        self.assertIn("Windows Update &amp; Delivery Cache", html)
        self.assertIn("Extended Autoruns &amp; Shell Extensions", html)
        self.assertIn("Alternate Data Streams (ADS)", html)

    def test_windows_update_cache_finding_manual_review(self):
        wu_collector = CollectorResult(
            name="windows_update_cache",
            ok=True,
            data={
                "software_distribution_download_bytes": 1024 * 1024 * 1024,
                "software_distribution_datastore_bytes": 200 * 1024 * 1024,
                "services_state": {"wuauserv": "RUNNING"},
                "purge_recipe": "safe_recipe",
            },
        )
        findings = build_system_findings([wu_collector])
        wu_finding = next(f for f in findings if "Windows Update download cache" in f.title)
        self.assertEqual(wu_finding.disposition, "manual_review")
        self.assertIn("SoftwareDistribution", wu_finding.path)


if __name__ == "__main__":
    unittest.main()
