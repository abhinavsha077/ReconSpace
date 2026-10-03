import re
import unittest
from pathlib import Path


class SafetyRegressionTests(unittest.TestCase):
    def test_no_destructive_apis_in_scanner_package(self):
        root = Path(__file__).resolve().parents[1] / "reconspace"
        source = "\n".join(p.read_text(encoding="utf-8") for p in root.glob("*.py"))
        banned_patterns = {
            r"\bos\.remove\s*\(": "os.remove",
            r"\bos\.unlink\s*\(": "os.unlink",
            r"\bos\.rmdir\s*\(": "os.rmdir",
            r"\bshutil\.rmtree\s*\(": "shutil.rmtree",
            r"\.unlink\s*\(": "Path.unlink",
            r"\.rmdir\s*\(": "Path.rmdir",
            r"\bwinreg\.SetValue": "registry write",
            r"\bwinreg\.Delete": "registry delete",
            r"\bos\.chmod\s*\(": "permission mutation",
            r"\bos\.chown\s*\(": "ownership mutation",
            r"\bMove-Item\b": "PowerShell move",
            r"\bRemove-Item\b": "PowerShell remove",
            r"\bStop-Service\b": "service stop",
            r"\bSet-Service\b": "service change",
            r"\bUnregister-ScheduledTask\b": "task deletion",
            r"\bwsl(?:\.exe)?\s+--unregister\b": "WSL distro deletion",
            r"\bdocker(?:\.exe)?\s+system\s+prune\b": "Docker prune",
        }
        for pattern, label in banned_patterns.items():
            self.assertIsNone(re.search(pattern, source, flags=re.IGNORECASE), f"Destructive API introduced: {label}")

    def test_windows_collectors_only_contain_inventory_forms(self):
        source = (Path(__file__).resolve().parents[1] / "reconspace" / "windows_collectors.py").read_text(encoding="utf-8").lower()
        banned_patterns = [
            r"clear-recyclebin",
            r"uninstall-package",
            r"remove-appxpackage",
            r"remove-item",
            r"stop-service",
            r"set-service",
            r"unregister-scheduledtask",
            r"\[\"']vssadmin\.exe\[\"']\s*,\s*\[\"']delete",
            r"\[\"']wsl\.exe\[\"']\s*,\s*\[\"']--unregister",
            r"\[\"']docker\.exe\[\"']\s*,\s*\[\"']system\[\"']\s*,\s*\[\"']prune",
            r"/startcomponentcleanup",
            r"/resetbase",
            r"\[\"']powercfg\.exe\[\"']\s*,\s*\[\"']/h\[\"']\s*,\s*\[\"']off",
        ]
        for pattern in banned_patterns:
            self.assertIsNone(re.search(pattern, source), f"Destructive Windows command form introduced: {pattern}")
        self.assertIn('shell=false', source.replace(' ', ''))


if __name__ == "__main__":
    unittest.main()
