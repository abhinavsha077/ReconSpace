import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "reconspace"
CORE = [
    "engine.py", "scanner.py", "duplicates.py", "rules.py", "query.py", "trend.py",
    "ownership.py", "audit_health.py", "security_insights.py", "system_insights.py",
    "windows_collectors.py", "webapp.py", "classify.py", "models.py",
    "storage_basis.py", "privacy.py", "validation.py", "report.py", "exporter.py",
]
BANNED_CALLS = {
    "remove", "unlink", "rmdir", "removedirs", "rename", "truncate",
    "chmod", "chown", "rmtree", "move", "copytree", "DeleteKey", "DeleteValue",
    "SetValue", "SetValueEx", "CreateKey", "CreateKeyEx",
}
BANNED_COMMANDS = [
    "system prune", "image prune", "volume prune", "container prune", "--unregister",
    "remove-item", "clear-content", "remove-appxpackage", "uninstall-package",
    "/startcomponentcleanup", "/resetbase", "vssadmin delete", "schtasks /delete",
    "stop-service", "set-service", "disable-scheduledtask", "powercfg /hibernate off",
]


class SafetyV04Tests(unittest.TestCase):
    def test_new_intelligence_core_has_no_destructive_calls(self):
        hits = []
        for name in CORE:
            tree = ast.parse((ROOT / name).read_text(encoding="utf-8"), filename=name)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                call = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                if call in BANNED_CALLS:
                    hits.append(f"{name}:{node.lineno}:{call}")
        self.assertEqual(hits, [])

    def test_new_windows_commands_are_inventory_only(self):
        text = (ROOT / "windows_collectors.py").read_text(encoding="utf-8").casefold()
        for fragment in BANNED_COMMANDS:
            self.assertNotIn(fragment, text)
        for expected in ("get-authenticodesignature", "get-acl", "get-storagereliabilitycounter", '"buildx", "du"', '"ps", "-a", "--size"'):
            self.assertIn(expected, text)

    def test_rule_engine_has_no_dynamic_execution_primitive(self):
        path = ROOT / "rules.py"
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.append(node.func.id)
        self.assertNotIn("eval", calls)
        self.assertNotIn("exec", calls)
        self.assertNotIn("compile", calls)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("powershell", text.casefold())

    def test_dashboard_has_no_mutating_route(self):
        text = (ROOT / "webapp.py").read_text(encoding="utf-8").casefold()
        routes = re.findall(r'parsed\.path\s*[!=]=\s*["\']([^"\']+)', text)
        for route in routes:
            self.assertFalse(any(word in route for word in ("delete", "cleanup", "uninstall", "prune", "remove", "execute")))


if __name__ == "__main__":
    unittest.main()
