import unittest
from reconspace.models import CollectorResult, ApplicationRecord
from reconspace.ntfs import inspect_ntfs_volume_metadata, collect_ntfs_mft_status, IS_WINDOWS
from reconspace.windows_collectors import (
    collect_winget_catalog_correlation,
    collect_browser_extensions,
)
from reconspace.security_insights import build_protection_findings
from reconspace.webapp import _html


class Phase2AcceleratedAndCatalogTests(unittest.TestCase):
    def test_ntfs_volume_metadata(self):
        meta = inspect_ntfs_volume_metadata("C:\\")
        if IS_WINDOWS:
            self.assertTrue(meta.get("is_ntfs"))
            self.assertIn("bytes_per_cluster", meta)
            self.assertIn("bytes_per_file_record", meta)
            self.assertEqual(meta["bytes_per_file_record"], 1024)
            self.assertGreater(meta["mft_valid_bytes"], 0)
            self.assertGreater(meta["estimated_mft_records"], 0)
        else:
            self.assertFalse(meta.get("supported"))

    def test_ntfs_mft_status_collector(self):
        res = collect_ntfs_mft_status("C:\\")
        self.assertEqual(res.name, "ntfs_mft_status")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            self.assertIsInstance(res.data, dict)
            self.assertTrue(res.data.get("can_query_ntfs_data"))
        else:
            self.assertFalse(res.applicable)

    def test_winget_catalog_correlation(self):
        res = collect_winget_catalog_correlation()
        self.assertEqual(res.name, "winget_catalog_correlation")
        if IS_WINDOWS and res.ok:
            data = res.data
            self.assertIsInstance(data, dict)
            self.assertIn("total_tracked", data)
            self.assertIn("upgrades_available_count", data)
            self.assertIn("upgrades", data)
            for upg in data["upgrades"]:
                self.assertIn("id", upg)
                self.assertIn("upgrade_command", upg)
                self.assertTrue(upg["has_update"])

    def test_browser_extensions_collector(self):
        res = collect_browser_extensions()
        self.assertEqual(res.name, "browser_extensions")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            self.assertIsInstance(res.data, list)
            for ext in res.data[:10]:
                self.assertIn("browser", ext)
                self.assertIn("name", ext)
                self.assertIn("permissions", ext)
                self.assertIn(ext["risk_level"], ("high", "medium", "low"))
        else:
            self.assertFalse(res.applicable)

    def test_browser_extension_protection_findings(self):
        fake_ext_collector = CollectorResult(
            name="browser_extensions",
            ok=True,
            data=[
                {
                    "browser": "Google Chrome",
                    "profile": "Default",
                    "id": "mock_broad_ext",
                    "name": "Network Interceptor",
                    "version": "1.0",
                    "description": "Mock extension",
                    "permissions": ["<all_urls>", "webRequest"],
                    "risk_level": "high",
                    "has_broad_web": True,
                    "has_native_messaging": False,
                }
            ],
        )
        findings = build_protection_findings([fake_ext_collector])
        titles = [f.title for f in findings]
        self.assertTrue(any("Browser extensions with elevated web permissions" in t for t in titles))

    def test_empty_working_set_recipe_in_html(self):
        html = _html()
        self.assertIn("EmptyWorkingSet", html)
        self.assertIn("Trim Process Working Sets", html)
        self.assertIn("[System.GC]::Collect()", html)
        self.assertIn("winget upgrade --id", html)


if __name__ == "__main__":
    unittest.main()
