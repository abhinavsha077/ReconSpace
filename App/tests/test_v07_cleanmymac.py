import unittest
import sys
from reconspace.classify import CATEGORY_GROUPS, resolve_category_group
from reconspace.models import CollectorResult, ApplicationRecord
from reconspace.windows_collectors import (
    IS_WINDOWS,
    collect_system_memory_status,
    collect_privacy_consent_store,
    collect_browser_privacy_footprints,
    collect_orphaned_app_data,
)
from reconspace.security_insights import build_protection_findings
from reconspace.system_insights import build_system_findings
from reconspace.webapp import _html


class CleanMyMacForPCTests(unittest.TestCase):
    def test_category_groups_registered(self):
        self.assertIn("app_leftovers", CATEGORY_GROUPS)
        self.assertIn("privacy_permissions", CATEGORY_GROUPS)
        self.assertIn("system_maintenance", CATEGORY_GROUPS)
        self.assertEqual(resolve_category_group("Application leftovers"), "app_leftovers")
        self.assertEqual(resolve_category_group("Privacy and permissions"), "privacy_permissions")
        self.assertEqual(resolve_category_group("System maintenance"), "system_maintenance")

    def test_memory_status_collector(self):
        res = collect_system_memory_status()
        self.assertEqual(res.name, "system_memory_status")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            data = res.data
            self.assertIsInstance(data, dict)
            self.assertIn("memory_load_pct", data)
            self.assertGreaterEqual(data["memory_load_pct"], 0)
            self.assertLessEqual(data["memory_load_pct"], 100)
            self.assertGreater(data["total_physical_bytes"], 0)
            self.assertGreater(data["available_physical_bytes"], 0)
            self.assertGreater(data["used_physical_bytes"], 0)
        else:
            self.assertFalse(res.applicable)

    def test_privacy_consent_store_collector(self):
        res = collect_privacy_consent_store()
        self.assertEqual(res.name, "privacy_consent_store")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            data = res.data
            self.assertIsInstance(data, dict)
            for cap in ("webcam", "microphone", "location", "userNotificationListener"):
                self.assertIn(cap, data)
                self.assertIsInstance(data[cap], list)
        else:
            self.assertFalse(res.applicable)

    def test_browser_privacy_footprints_collector(self):
        res = collect_browser_privacy_footprints()
        self.assertEqual(res.name, "browser_privacy_footprints")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            self.assertIsInstance(res.data, list)
        else:
            self.assertFalse(res.applicable)

    def test_orphaned_app_data_collector(self):
        fake_apps = [
            ApplicationRecord(name="Visual Studio Code", publisher="Microsoft", version="1.90.0", install_location="C:\\VSCode"),
            ApplicationRecord(name="Google Chrome", publisher="Google LLC", version="125.0.0", install_location="C:\\Chrome"),
        ]
        res = collect_orphaned_app_data(installed_apps=fake_apps)
        self.assertEqual(res.name, "orphaned_app_data")
        if IS_WINDOWS:
            self.assertTrue(res.ok)
            self.assertIsInstance(res.data, list)
        else:
            self.assertFalse(res.applicable)

    def test_protection_findings_defender_and_consent(self):
        collectors = [
            CollectorResult(
                name="defender_status",
                ok=True,
                data={
                    "Status": {
                        "RealTimeProtectionEnabled": False,
                        "AntivirusSignatureAge": 12,
                        "ProductVersion": "4.18.24050.7",
                    },
                    "Threats": [
                        {
                            "ThreatID": 1001,
                            "ThreatName": "Trojan:Win32/TestGeneric",
                            "SeverityID": 5,
                            "InitialDetectionTime": "2026-09-01",
                        }
                    ],
                },
            ),
            CollectorResult(
                name="privacy_consent_store",
                ok=True,
                data={
                    "webcam": [{"name": "CameraApp", "type": "packaged", "scope": "user", "capability": "webcam"}],
                    "microphone": [{"name": "VoiceRecorder", "type": "packaged", "scope": "user", "capability": "microphone"}],
                    "location": [],
                    "userNotificationListener": [],
                },
            ),
        ]
        findings = build_protection_findings(collectors)
        titles = [f.title for f in findings]
        self.assertTrue(any("Real-Time Protection is disabled" in t for t in titles))
        self.assertTrue(any("signatures are outdated" in t for t in titles))
        self.assertTrue(any("Trojan:Win32/TestGeneric" in t for t in titles))
        self.assertTrue(any("Hardware privacy permissions active" in t for t in titles))

    def test_system_insights_orphaned_and_memory(self):
        collectors = [
            CollectorResult(
                name="orphaned_app_data",
                ok=True,
                data=[
                    {
                        "name": "LegacyTool",
                        "path": "C:\\Users\\Test\\AppData\\Local\\LegacyTool",
                        "location_env": "LocalAppData",
                        "size_bytes": 50 * 1024 * 1024,
                    }
                ],
            ),
            CollectorResult(
                name="system_memory_status",
                ok=True,
                data={
                    "memory_load_pct": 92,
                    "total_physical_bytes": 16 * 1024**3,
                    "used_physical_bytes": 15 * 1024**3,
                    "available_physical_bytes": 1 * 1024**3,
                },
            ),
        ]
        findings = build_system_findings(collectors)
        titles = [f.title for f in findings]
        self.assertTrue(any("LegacyTool" in t for t in titles))
        self.assertTrue(any("High system memory load (92%" in t for t in titles))

    def test_webapp_html_structure_and_hubs(self):
        html = _html()
        # Verify Hub Tabs exist
        for hub in ("cleanup_hub", "protection_hub", "performance_hub", "applications_hub", "clutter_hub"):
            self.assertIn(f'data-view="{hub}"', html)

        # Verify Hub functions exist in JS
        for func in ("cleanupHub", "protectionHub", "performanceHub", "applicationsHub", "clutterHub", "getPreScanHub", "setClutterFilter"):
            self.assertIn(f"function {func}", html)

        # Verify CleanMyMac CSS classes
        for css in (".hub-hero", ".hub-orb", ".hub-card-grid", ".recipe-box", ".perm-badge", ".lens-tree", ".pillar-grid", ".pillar-card"):
            self.assertIn(css, html)

        # Verify Care Pillars in Overview
        self.assertIn('class="pillar-grid"', html)
        self.assertIn('class="pillar-card cleanup-pillar"', html)
        self.assertIn('class="pillar-card protection-pillar"', html)
        self.assertIn('class="pillar-card performance-pillar"', html)
        self.assertIn('class="pillar-card applications-pillar"', html)

        # Verify pages route to hubs
        self.assertIn("views:['cleanup_hub'", html)
        self.assertIn("views:['protection_hub'", html)
        self.assertIn("views:['performance_hub'", html)
        self.assertIn("views:['applications_hub'", html)
        self.assertIn("views:['clutter_hub'", html)

    def test_informational_disposition_in_webapp(self):
        html = _html()
        self.assertIn("'informational'", html)

    def test_memory_zero_safety(self):
        collectors = [
            CollectorResult(
                name="system_memory_status",
                ok=True,
                data={
                    "memory_load_pct": 90,
                    "total_physical_bytes": 0,
                    "used_physical_bytes": 0,
                    "available_physical_bytes": 0,
                },
            ),
        ]
        # Must not raise ZeroDivisionError
        findings = build_system_findings(collectors)
        self.assertEqual(len(findings), 0)

    def test_orphaned_app_data_token_matching(self):
        apps = [
            ApplicationRecord(name="OBS Studio", publisher="OBS Project", version="30.0", install_location="C:\\Program Files\\obs-studio"),
            ApplicationRecord(name="Git", publisher="The Git Development Community", version="2.45", install_location="C:\\Program Files\\Git"),
        ]
        res = collect_orphaned_app_data(installed_apps=apps)
        self.assertTrue(res.ok)


if __name__ == "__main__":
    unittest.main()
