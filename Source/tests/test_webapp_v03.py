import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from reconspace.webapp import Handler, LocalThreadingHTTPServer, TOKEN


class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = LocalThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path, method="GET", body=None, token=True):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-ReconSpace-Token"] = TOKEN
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode()
            finally:
                e.close()

    def test_api_requires_session_token(self):
        status, _ = self.request("/api/status", token=False)
        self.assertEqual(status, 403)

    def test_root_has_security_headers(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/?token={TOKEN}")
        with urllib.request.urlopen(req, timeout=3) as r:
            self.assertEqual(r.status, 200)
            self.assertIn("default-src 'self'", r.headers.get("Content-Security-Policy", ""))
            self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
            self.assertEqual(r.headers.get("Cross-Origin-Resource-Policy"), "same-origin")

    def test_dashboard_controls_have_accessible_labels_and_status(self):
        source = (Path(__file__).resolve().parents[1] / "reconspace" / "webapp.py").read_text(encoding="utf-8")
        for control in ("root", "profile", "dupmin", "exclude", "keep", "rulePacks"):
            self.assertIn(f'<label for="{control}">', source)
        self.assertIn('id="status" role="status" aria-live="polite"', source)
        self.assertIn('role="tablist"', source)
        self.assertIn('role="tabpanel"', source)

    def test_scan_validation_rejects_non_string_paths(self):
        with tempfile.TemporaryDirectory() as td:
            status, text = self.request(f"/api/scan?token={TOKEN}", "POST", {"root": td, "profile": "quick", "keep_paths": [{"path": td}]})
            self.assertEqual(status, 400)
            self.assertIn("string path", text)

    def test_scan_validation_rejects_non_finite_numbers(self):
        with tempfile.TemporaryDirectory() as td:
            status, text = self.request(f"/api/scan?token={TOKEN}", "POST", {"root": td, "profile": "quick", "duplicate_min_mb": float("inf")})
            self.assertEqual(status, 400)
            self.assertIn("non-finite", text)
            status, text = self.request(f"/api/scan?token={TOKEN}", "POST", {"root": td, "profile": "quick", "duplicate_min_mb": True})
            self.assertEqual(status, 400)
            self.assertIn("integer", text)

    def test_dashboard_surfaces_connection_failures_and_empty_sections(self):
        source = (Path(__file__).resolve().parents[1] / "reconspace" / "webapp.py").read_text(encoding="utf-8")
        self.assertIn("Disconnected from local service", source)
        self.assertIn("clearError('connection')", source)
        self.assertIn("No records were returned for this section.", source)

    def test_scan_validation_rejects_nonboolean_stateful_hash(self):
        with tempfile.TemporaryDirectory() as td:
            status, text = self.request(f"/api/scan?token={TOKEN}", "POST", {"root": td, "profile": "quick", "hash_stateful_files": "false"})
            self.assertEqual(status, 400)
            self.assertIn("boolean", text)

    def test_scan_validation_rejects_exclusion_outside_root(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as other:
            status, text = self.request(f"/api/scan?token={TOKEN}", "POST", {"root": td, "profile": "quick", "excluded_paths": [other]})
            self.assertEqual(status, 400)
            self.assertIn("descendant", text)

    def test_browser_compare_suppresses_free_delta_for_different_roots(self):
        source = (Path(__file__).resolve().parents[1] / "reconspace" / "webapp.py").read_text(encoding="utf-8")
        self.assertIn("sameRoot=oldRoot&&oldRoot===newRoot", source)
        self.assertIn("sameRoot&&typeof os.filesystem_free_bytes", source)
        self.assertIn("Free-space delta is suppressed because the scan roots differ", source)

    def test_browser_removes_session_token_from_visible_url_and_uses_header(self):
        source = (Path(__file__).resolve().parents[1] / "reconspace" / "webapp.py").read_text(encoding="utf-8")
        self.assertIn("history.replaceState(null,'',location.pathname)", source)
        self.assertIn("fetch('/api/status',{cache:'no-store',credentials:'omit',headers:{'X-ReconSpace-Token':token}})", source)
        self.assertNotIn("fetch('/api/status?token='+encodeURIComponent(token)", source)


if __name__ == "__main__":
    unittest.main()
