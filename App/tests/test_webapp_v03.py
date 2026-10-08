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

    def test_busy_launch_port_falls_back_without_stopping_other_apps(self):
        import contextlib
        import errno
        import io
        from unittest.mock import Mock, patch
        from reconspace.webapp import serve
        for code in (errno.EADDRINUSE, errno.EACCES):
            with self.subTest(error_code=code):
                server = Mock()
                server.server_address = ("127.0.0.1", 49152)
                with patch("reconspace.webapp.LocalThreadingHTTPServer", side_effect=[OSError(code, "busy"), server]) as factory:
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        serve(port=8765, open_browser=False)
                self.assertEqual(factory.call_args_list[1].args[0], ("127.0.0.1", 0))
                self.assertIn("http://127.0.0.1:49152/", output.getvalue())
                server.server_close.assert_called_once()

    def test_landing_artwork_is_a_local_packaged_png(self):
        from importlib.resources import files
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/assets/care-desktop.png", timeout=3) as response:
            self.assertEqual(response.headers.get("Content-Type"), "image/png")
            self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(response.read(), files("reconspace").joinpath("assets/care-desktop.png").read_bytes())

    def test_asset_route_does_not_expose_other_local_files(self):
        status, _ = self.request("/assets/../webapp.py")
        self.assertEqual(status, 404)

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

    def test_ai_prompt_get_returns_preview_when_no_report(self):
        status, text = self.request("/api/ai-prompt")
        self.assertEqual(status, 200)
        data = json.loads(text)
        self.assertIn("prompt", data)
        self.assertIn("SYSTEM PROMPT", data["prompt"])

    def test_ai_prompt_post_accepts_custom_report(self):
        sample = {"version": "1.1", "root": "C:\\", "findings": [], "summary": {}}
        status, text = self.request("/api/ai-prompt", method="POST", body={"report": sample})
        self.assertEqual(status, 200)
        data = json.loads(text)
        self.assertIn("prompt", data)

    def test_ai_review_post_with_heuristic_provider(self):
        sample = {
            "version": "1.1",
            "root": "C:\\",
            "findings": [{"id": "t1", "category": "system_cache", "severity": "warn", "title": "Old cache", "reclaimable_bytes": 1000}],
            "summary": {"reclaimable_bytes": 1000},
        }
        status, text = self.request("/api/ai-review", method="POST", body={"report": sample, "provider": "heuristic"})
        self.assertEqual(status, 200)
        data = json.loads(text)
        self.assertTrue(data.get("ok"))
        self.assertIn("summary_verdict", data)


if __name__ == "__main__":
    unittest.main()
