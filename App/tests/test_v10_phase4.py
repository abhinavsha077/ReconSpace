import json
import os
import tempfile
import unittest
from pathlib import Path
from reconspace.plan import build_plan, compute_manifest_hash, verify_plan_manifest
from reconspace.runner import (
    is_system_protected_path,
    safe_recycle_path,
    execute_approved_plan,
)
from reconspace.models import ScanReport, ScanStats, Finding


class Phase4ProductionRunnerAndManifestTests(unittest.TestCase):
    def test_manifest_hashing_and_verification(self):
        fake_report = {
            "version": "1.0.0",
            "profile": "standard",
            "stats": {"root": "C:\\", "finished_at": "2026-10-02T12:00:00Z"},
            "findings": [
                {
                    "title": "Old cache files",
                    "path": "C:\\Users\\Test\\AppData\\Local\\Temp\\cache",
                    "disposition": "probably_safe_cleanup",
                    "estimated_reclaimable_bytes": 1048576,
                    "size_bytes": 1048576,
                    "priority_score": 10.0,
                },
                {
                    "title": "Review folder",
                    "path": "C:\\Users\\Test\\Downloads\\unverified",
                    "disposition": "manual_review",
                    "estimated_reclaimable_bytes": 5242880,
                    "size_bytes": 5242880,
                    "priority_score": 5.0,
                },
            ],
        }
        plan = build_plan(fake_report)
        self.assertIn("manifest_sha256", plan)
        self.assertIn("manifest_signature", plan)
        self.assertTrue(plan["manifest_signature"].startswith("sha256:"))

        # Verification succeeds on untouched plan
        valid, msg = verify_plan_manifest(plan)
        self.assertTrue(valid)

        # Verification fails if an item is tampered with
        plan["items"][0]["path"] = "C:\\Windows\\System32\\cmd.exe"
        valid_tampered, msg_tampered = verify_plan_manifest(plan)
        self.assertFalse(valid_tampered)
        self.assertIn("integrity failure", msg_tampered)

    def test_is_system_protected_path(self):
        sys_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/")
        sys_root = os.environ.get("SystemRoot", "C:\\Windows")
        user_prof = os.environ.get("USERPROFILE", "")

        # System roots and directories must be protected
        self.assertTrue(is_system_protected_path(f"{sys_drive}\\"))
        self.assertTrue(is_system_protected_path(sys_root))
        self.assertTrue(is_system_protected_path(os.path.join(sys_root, "System32")))
        self.assertTrue(is_system_protected_path(os.path.join(sys_root, "System32", "drivers")))
        self.assertTrue(is_system_protected_path(os.path.join(sys_root, "explorer.exe")))
        self.assertTrue(is_system_protected_path(os.path.join(sys_root, "notepad.exe")))
        self.assertTrue(is_system_protected_path(os.path.join(sys_root, "Fonts")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Program Files")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Program Files", "7-Zip")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Program Files", "7-Zip", "7z.exe")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Program Files (x86)", "App")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "ProgramData", "Microsoft")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Boot", "BCD")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Recovery", "OEM")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "System Volume Information", "idx")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "$Recycle.Bin", "S-1-5-21")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Users")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Users", "Default")))
        self.assertTrue(is_system_protected_path(os.path.join(f"{sys_drive}\\", "Users", "Public")))
        self.assertTrue(is_system_protected_path("\\\\server\\share"))
        if user_prof:
            self.assertTrue(is_system_protected_path(user_prof))
            self.assertTrue(is_system_protected_path(os.path.join(user_prof, "Desktop")))
            self.assertTrue(is_system_protected_path(os.path.join(user_prof, "Desktop", "important.docx")))
            self.assertTrue(is_system_protected_path(os.path.join(user_prof, "Documents", "financials.xlsx")))

        # Safe custom temp file must NOT be marked protected
        with tempfile.NamedTemporaryFile() as tmp:
            self.assertFalse(is_system_protected_path(tmp.name))

    def test_safe_recycle_path_network_drive_rejection(self):
        # UNC network shares must be rejected to prevent permanent data deletion
        ok, msg = safe_recycle_path("\\\\remote_server\\share\\disposable.tmp")
        self.assertFalse(ok)

    def test_safe_recycle_path_locked_file_handling(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"exclusive lock test data")
            tf.flush()
            temp_path = tf.name
            try:
                # File is currently held open by tf handle on Windows
                ok, msg = safe_recycle_path(temp_path)
                self.assertFalse(ok)
                self.assertIn("32", msg)  # Win32 ERROR_SHARING_VIOLATION
                self.assertTrue(os.path.exists(temp_path))
            finally:
                tf.close()
                if os.path.exists(temp_path):
                    safe_recycle_path(temp_path)

    def test_runner_dry_run_and_execution(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "disposable_cache.tmp"
            test_file.write_text("temporary cache content", encoding="utf-8")

            fake_report = {
                "version": "1.0.0",
                "profile": "standard",
                "stats": {"root": tmp_dir, "finished_at": "2026-10-02T12:00:00Z"},
                "findings": [
                    {
                        "title": "Disposable cache",
                        "path": str(test_file),
                        "disposition": "probably_safe_cleanup",
                        "estimated_reclaimable_bytes": 23,
                        "size_bytes": 23,
                        "priority_score": 10.0,
                    }
                ],
            }
            plan = build_plan(fake_report)

            # 1. Dry run simulation
            res_dry = execute_approved_plan(
                plan,
                dry_run=True,
                confirm=False,
                approved_ids=["RS-0001"],
            )
            self.assertTrue(res_dry["success"])
            self.assertTrue(res_dry["dry_run"])
            self.assertEqual(len(res_dry["actions"]), 1)
            self.assertEqual(res_dry["actions"][0]["status"], "SIMULATED_RECYCLE")
            self.assertTrue(test_file.exists())  # Must NOT be modified during dry run

            # 2. Rejection without confirmation
            res_no_confirm = execute_approved_plan(
                plan,
                dry_run=False,
                confirm=False,
                approved_ids=["RS-0001"],
            )
            self.assertTrue(res_no_confirm["success"])
            self.assertEqual(res_no_confirm["actions"][0]["status"], "REJECTED_NO_CONFIRMATION")
            self.assertTrue(test_file.exists())

            # 3. Execution with confirmation
            res_exec = execute_approved_plan(
                plan,
                dry_run=False,
                confirm=True,
                approved_ids=["RS-0001"],
            )
            self.assertTrue(res_exec["success"])
            self.assertFalse(res_exec["dry_run"])
            self.assertIn("RECYCLED", res_exec["actions"][0]["status"])

    def test_runner_rejects_unsafe_disposition(self):
        fake_report = {
            "version": "1.0.0",
            "profile": "standard",
            "stats": {"root": "C:\\", "finished_at": "2026-10-02T12:00:00Z"},
            "findings": [
                {
                    "title": "Manual review tool",
                    "path": "C:\\Users\\Test\\AppData\\Local\\Tool",
                    "disposition": "manual_review",
                    "estimated_reclaimable_bytes": 1024,
                    "size_bytes": 1024,
                    "priority_score": 5.0,
                }
            ],
        }
        plan = build_plan(fake_report)
        res = execute_approved_plan(
            plan,
            dry_run=False,
            confirm=True,
            approved_ids=["RS-0001"],
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["actions"][0]["status"], "REJECTED_UNSAFE_DISPOSITION")

    def test_runner_rejects_unknown_id(self):
        fake_report = {
            "version": "1.0.0",
            "profile": "standard",
            "stats": {"root": "C:\\", "finished_at": "2026-10-02T12:00:00Z"},
            "findings": [],
        }
        plan = build_plan(fake_report)
        res = execute_approved_plan(
            plan,
            dry_run=True,
            confirm=False,
            approved_ids=["RS-9999"],
        )
        self.assertTrue(res["success"])
        self.assertEqual(len(res["actions"]), 1)
        self.assertEqual(res["actions"][0]["status"], "REJECTED_UNKNOWN_ID")

    def test_manifest_validation_non_dict(self):
        valid, msg = verify_plan_manifest("not_a_dict")  # type: ignore
        self.assertFalse(valid)
        self.assertIn("dictionary object", msg)

        res = execute_approved_plan("not_a_dict")  # type: ignore
        self.assertFalse(res["success"])
        self.assertIn("dictionary object", res["error"])


if __name__ == "__main__":
    unittest.main()
