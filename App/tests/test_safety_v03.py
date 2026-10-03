import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "reconspace"
CORE = [
    "scanner.py", "duplicates.py", "engine.py", "classify.py", "insights.py",
    "system_insights.py", "windows_collectors.py", "commandline.py", "doctor.py",
    "webapp.py", "models.py", "reclaim.py", "compare.py",
]

# These APIs would be strong evidence of destructive behavior in the audit engine.
BANNED_CALL_SUFFIXES = {
    "remove", "unlink", "rmdir", "removedirs", "rename", "truncate",
    "chmod", "chown", "rmtree", "move", "copytree", "makedirs",
    "DeleteKey", "DeleteValue", "SetValue", "SetValueEx", "CreateKey", "CreateKeyEx",
}

# Query commands containing words like Cleanup-Image are permitted only in the
# explicitly allowlisted query forms below. Mutating command fragments are banned.
BANNED_COMMAND_FRAGMENTS = [
    "docker system prune", "docker image prune", "docker volume prune", "docker container prune",
    "wsl --unregister", "remove-item", "clear-content", "del /", "rd /", "rmdir /",
    "uninstall-package", "remove-appxpackage", "disable-windowsoptionalfeature",
    "/startcomponentcleanup", "/resetbase", "vssadmin delete", "wmic shadowcopy delete",
    "schtasks /delete", "sc.exe delete", "stop-service", "set-service", "disable-scheduledtask",
    "powercfg /hibernate off", "compact /c", "diskpart",
]


class SafetyTests(unittest.TestCase):
    def test_core_has_no_destructive_python_calls(self):
        hits = []
        for name in CORE:
            path = ROOT / name
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name):
                        call = fn.id
                    elif isinstance(fn, ast.Attribute):
                        call = fn.attr
                    else:
                        continue
                    if call in BANNED_CALL_SUFFIXES:
                        hits.append(f"{name}:{getattr(node,'lineno','?')}:{call}")
        self.assertEqual(hits, [], "destructive-looking Python calls found: " + ", ".join(hits))

    def test_no_banned_mutating_command_fragments(self):
        hits = []
        for name in CORE:
            text = (ROOT / name).read_text(encoding="utf-8").casefold()
            for fragment in BANNED_COMMAND_FRAGMENTS:
                if fragment.casefold() in text:
                    hits.append(f"{name}:{fragment}")
        self.assertEqual(hits, [], "mutating command fragments found: " + ", ".join(hits))

    def test_subprocess_is_centralized_and_shell_false(self):
        subprocess_users = []
        for path in ROOT.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "subprocess.run" in text:
                subprocess_users.append(path.name)
        self.assertEqual(subprocess_users, ["windows_collectors.py"])
        text = (ROOT / "windows_collectors.py").read_text(encoding="utf-8")
        self.assertIn("shell=False", text)

    def test_webapp_exposes_no_cleanup_delete_uninstall_endpoint(self):
        text = (ROOT / "webapp.py").read_text(encoding="utf-8").casefold()
        route_literals = re.findall(r'parsed\.path\s*==\s*["\']([^"\']+)', text)
        route_literals += re.findall(r'parsed\.path\s*!=\s*["\']([^"\']+)', text)
        for route in route_literals:
            self.assertFalse(any(word in route for word in ("delete", "cleanup", "uninstall", "prune", "remove", "execute")), route)

    def test_windows_inventory_command_allowlist_is_query_only(self):
        text = (ROOT / "windows_collectors.py").read_text(encoding="utf-8").casefold()
        # These query forms are deliberately present and should remain recognizable.
        self.assertIn('/analyzecomponentstore', text)
        self.assertIn('"system", "df"', text)
        self.assertIn('"usn", "queryjournal"', text)
        self.assertIn('"list", "shadowstorage"', text)
        self.assertNotIn('/startcomponentcleanup', text)
        self.assertNotIn('"system", "prune"', text)


if __name__ == "__main__":
    unittest.main()
