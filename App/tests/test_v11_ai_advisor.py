import io
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from reconspace.ai_advisor import (
    AIProviderConfig,
    AIRecommendation,
    AIReviewResult,
    ai_review_to_json,
    build_advisor_prompt,
    build_condensed_audit_context,
    generate_heuristic_review,
    query_ai_advisor,
    render_ai_review_markdown,
)
from reconspace.cli import _main
from reconspace.windows_collectors import (
    collect_battery_power_health,
    collect_crash_dumps_inventory,
    collect_delivery_optimization_status,
    collect_hibernation_pagefile_intelligence,
    collect_network_adapters_telemetry,
    collect_recycle_bin_metrics,
)


def sample_report() -> dict:
    return {
        "version": "1.1.0",
        "profile": "deep",
        "stats": {
            "root": "C:\\",
            "filesystem_total_bytes": 512000000000,
            "filesystem_free_bytes": 45000000000,
            "filesystem_used_bytes": 467000000000,
        },
        "reclaim_summary": {
            "reclaim_candidates_total_bytes": 25000000000,
            "safe_cleanup_bytes": 18000000000,
            "manual_review_bytes": 7000000000,
            "duplicate_reclaim_bytes": 2000000000,
        },
        "findings": [
            {
                "title": "Windows Delivery Optimization Cache",
                "path": "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache",
                "size_bytes": 3200000000,
                "category": "system_cache",
                "disposition": "probably_safe_cleanup",
                "risk": "low",
                "why_it_exists": "Cached Windows Update peer distribution chunks.",
                "estimated_reclaimable_bytes": 3200000000,
            },
            {
                "title": "Python Virtualenv",
                "path": "C:\\Users\\Alice\\Projects\\WebApp\\.venv",
                "size_bytes": 850000000,
                "category": "dev_environment",
                "disposition": "intentional_tooling",
                "risk": "high",
                "why_it_exists": "Python virtual environment containing site-packages.",
                "estimated_reclaimable_bytes": 0,
            },
        ],
        "collectors": [
            {
                "name": "system_memory_status",
                "ok": True,
                "data": {
                    "memory_load_pct": 72,
                    "total_physical_bytes": 17179869184,
                    "available_physical_bytes": 4810362880,
                    "total_pagefile_bytes": 25769803776,
                },
            },
            {
                "name": "defender_status",
                "ok": True,
                "data": {
                    "Status": {
                        "RealTimeProtectionEnabled": True,
                        "AntivirusSignatureAge": 2,
                    },
                    "Threats": [],
                },
            },
            {
                "name": "hibernation_pagefile_intelligence",
                "ok": True,
                "data": {
                    "hiberfil_exists": True,
                    "hiberfil_bytes": 6598193152,
                    "hiber_file_type": "full",
                    "mode_description": "Full (100% RAM allocation)",
                    "potential_reduced_savings_bytes": 3299096576,
                    "pagefile_bytes": 16000000000,
                    "swapfile_bytes": 16777216,
                },
            },
            {
                "name": "delivery_optimization_status",
                "ok": True,
                "data": {
                    "cache_size_bytes": 3200000000,
                    "bytes_from_peers": 500000000,
                    "bytes_uploaded_to_peers": 1500000000,
                    "download_mode": "Default (LAN / Cloud peering)",
                },
            },
            {
                "name": "crash_dumps_inventory",
                "ok": True,
                "data": {
                    "total_dumps_count": 8,
                    "total_size_bytes": 750000000,
                    "dumps": [],
                },
            },
            {
                "name": "recycle_bin_metrics",
                "ok": True,
                "data": {
                    "drive": "C:",
                    "total_size_bytes": 600000000,
                    "item_count": 42,
                    "inspect_recipe": "Get-ChildItem -Path 'C:\\$Recycle.Bin' -Force -Recurse | Measure-Object -Property Length -Sum",
                },
            },
            {
                "name": "orphaned_app_data",
                "ok": True,
                "data": {
                    "orphaned_directories": [{"name": "OldTool", "path": "C:\\Users\\Alice\\AppData\\Local\\OldTool"}],
                    "total_reclaimable_bytes": 250000000,
                },
            },
            {
                "name": "network_adapters_telemetry",
                "ok": True,
                "data": {
                    "active_adapters_count": 1,
                    "total_adapters_count": 3,
                    "adapters": [
                        {"name": "Wi-Fi", "status": "Up", "link_speed": "144.4 Mbps", "is_up": True}
                    ],
                },
            },
            {
                "name": "battery_power_health",
                "ok": True,
                "data": {
                    "is_battery_present": True,
                    "device_name": "Primary Battery",
                    "charge_percent": 85,
                    "status": "AC connected (charging or full)",
                    "wear_level_percent": 5.2,
                },
            },
        ],
        "applications": [{"name": "VS Code", "version": "1.93.0"}],
        "startup": [
            {"name": "Discord", "command": "C:\\Users\\Alice\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe", "risk_hint": "user_writable", "reason": "Executes from user-writable AppData"}
        ],
        "processes": [{"pid": 1234, "name": "Code.exe", "working_set_bytes": 450000000}],
    }


class AIAdvisorCoreTests(unittest.TestCase):
    def test_ai_provider_config_resolution(self):
        cfg_openai = AIProviderConfig(provider="openai")
        self.assertEqual(cfg_openai.resolve_endpoint(), "https://api.openai.com/v1/chat/completions")
        self.assertEqual(cfg_openai.resolve_model(), "gpt-4o")

        cfg_anthropic = AIProviderConfig(provider="anthropic")
        self.assertEqual(cfg_anthropic.resolve_endpoint(), "https://api.anthropic.com/v1/messages")
        self.assertEqual(cfg_anthropic.resolve_model(), "claude-3-5-sonnet-20241022")

        cfg_gemini = AIProviderConfig(provider="gemini", model="gemini-1.5-pro")
        self.assertIn("gemini-1.5-pro", cfg_gemini.resolve_endpoint())
        self.assertEqual(cfg_gemini.resolve_model(), "gemini-1.5-pro")

        cfg_ollama = AIProviderConfig(provider="ollama")
        self.assertEqual(cfg_ollama.resolve_endpoint(), "http://localhost:11434/api/generate")
        self.assertEqual(cfg_ollama.resolve_model(), "llama3:latest")

        cfg_custom = AIProviderConfig(provider="openai", endpoint="http://localhost:8000/v1/chat/completions", model="custom-llama")
        self.assertEqual(cfg_custom.resolve_endpoint(), "http://localhost:8000/v1/chat/completions")
        self.assertEqual(cfg_custom.resolve_model(), "custom-llama")

    def test_build_condensed_audit_context(self):
        rep = sample_report()
        ctx = build_condensed_audit_context(rep)
        self.assertEqual(ctx["scan_root"], "C:\\")
        self.assertEqual(ctx["storage"]["total_bytes"], 512000000000)
        self.assertEqual(ctx["storage"]["safe_cleanup_bytes"], 18000000000)
        self.assertEqual(ctx["performance"]["ram_load_pct"], 72)
        self.assertTrue(ctx["protection"]["defender_realtime"])
        self.assertEqual(ctx["windows_internals"]["hibernation"]["mode"], "full")
        self.assertEqual(ctx["windows_internals"]["delivery_optimization"]["cache_size_bytes"], 3200000000)
        self.assertEqual(ctx["windows_internals"]["crash_dumps"]["count"], 8)
        self.assertEqual(ctx["windows_internals"]["recycle_bin"]["count"], 42)
        self.assertEqual(ctx["windows_internals"]["network"]["active_adapters"], 1)

    def test_build_advisor_prompt_sanitization(self):
        rep = sample_report()
        sys_prompt, user_prompt, sanitization = build_advisor_prompt(rep, redact=True)
        self.assertTrue(sanitization["redacted"])
        self.assertIn("ReconSpace AI Audit Advisor", sys_prompt)
        # Verify sensitive user 'Alice' in path was sanitized
        self.assertNotIn("C:\\Users\\Alice", user_prompt)
        self.assertIn("%USERPROFILE%", user_prompt)

    def test_generate_heuristic_review_deterministic(self):
        rep = sample_report()
        res = generate_heuristic_review(rep)
        self.assertTrue(res.ok)
        self.assertEqual(res.provider, "heuristic")
        self.assertGreater(res.overall_score, 0)
        self.assertLessEqual(res.overall_score, 100)

        # Check categories
        self.assertGreater(len(res.quick_wins), 0)
        self.assertGreater(len(res.safety_warnings), 0)
        self.assertGreater(len(res.explainers), 0)
        self.assertGreater(res.total_potential_reclaim_bytes, 0)

        # Check safety warning content
        titles = [w.title for w in res.safety_warnings]
        self.assertTrue(any("Developer Workspaces" in t for t in titles))
        self.assertTrue(any("WinSxS" in t for t in titles))

        # Check reduced hibernation quick win
        quick_titles = [q.title for q in res.quick_wins]
        self.assertTrue(any("Hibernation" in t for t in quick_titles))

    def test_render_ai_review_markdown_and_json(self):
        rep = sample_report()
        res = generate_heuristic_review(rep)
        md = render_ai_review_markdown(res)
        self.assertIn("# ReconSpace AI Audit Advisor - Executive Review", md)
        self.assertIn("**System Wellness Score:**", md)
        self.assertIn("[QUICK WIN]", md)
        self.assertIn("[SAFETY]", md)
        self.assertIn("[EXPLAINER]", md)

        data = ai_review_to_json(res)
        self.assertEqual(data["overall_score"], res.overall_score)
        self.assertEqual(len(data["recommendations"]), len(res.recommendations))

    @patch("urllib.request.urlopen")
    def test_query_ai_advisor_mock_openai(self, mock_urlopen):
        mock_response_data = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps({
                            "overall_score": 88,
                            "summary_verdict": "OpenAI audited system with 4.5 GB cleanable space.",
                            "critical_actions": [
                                {
                                    "id": "AIR-C01",
                                    "title": "Enable Defender Tamper Protection",
                                    "impact_reclaim_bytes": 0,
                                    "safety_rating": "high_safety",
                                    "summary": "Tamper protection guards security policies.",
                                    "technical_detail": "Details here.",
                                    "suggested_action": "Set-MpPreference -EnableControlledFolderAccess Enabled",
                                    "affected_paths": ["C:\\Windows\\System32"],
                                }
                            ],
                            "quick_wins": [
                                {
                                    "id": "AIR-Q01",
                                    "title": "Purge Delivery Optimization",
                                    "impact_reclaim_bytes": 3200000000,
                                    "safety_rating": "high_safety",
                                    "summary": "Clean cached DO chunks.",
                                    "suggested_action": "Delete-DeliveryOptimizationCache",
                                }
                            ],
                            "safety_warnings": [],
                            "explainers": [],
                        })
                    }
                }
            ],
            "usage": {"prompt_tokens": 1200, "completion_tokens": 400},
        }

        mock_cm = MagicMock()
        mock_cm.__enter__.return_value.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_urlopen.return_value = mock_cm

        rep = sample_report()
        cfg = AIProviderConfig(provider="openai", api_key="sk-test-mock-key")
        result = query_ai_advisor(rep, config=cfg)

        self.assertTrue(result.ok)
        self.assertEqual(result.provider, "openai")
        self.assertEqual(result.overall_score, 88)
        self.assertEqual(len(result.critical_actions), 1)
        self.assertEqual(result.critical_actions[0].title, "Enable Defender Tamper Protection")
        self.assertEqual(len(result.quick_wins), 1)
        self.assertEqual(result.total_potential_reclaim_bytes, 3200000000)

    @patch("urllib.request.urlopen")
    def test_query_ai_advisor_mock_anthropic(self, mock_urlopen):
        mock_response_data = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "overall_score": 92,
                        "summary_verdict": "Anthropic Claude review passed.",
                        "critical_actions": [],
                        "quick_wins": [],
                        "safety_warnings": [
                            {
                                "id": "AIR-S01",
                                "title": "Preserve WSL VHDX",
                                "safety_rating": "do_not_touch",
                                "summary": "Do not delete ext4.vhdx.",
                            }
                        ],
                        "explainers": [],
                    }),
                }
            ],
            "usage": {"input_tokens": 1100, "output_tokens": 350},
        }

        mock_cm = MagicMock()
        mock_cm.__enter__.return_value.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_urlopen.return_value = mock_cm

        rep = sample_report()
        cfg = AIProviderConfig(provider="anthropic", api_key="sk-ant-test-mock-key")
        result = query_ai_advisor(rep, config=cfg)

        self.assertTrue(result.ok)
        self.assertEqual(result.provider, "anthropic")
        self.assertEqual(result.overall_score, 92)
        self.assertEqual(len(result.safety_warnings), 1)

    @patch("urllib.request.urlopen")
    def test_query_ai_advisor_mock_gemini(self, mock_urlopen):
        mock_response_data = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps({
                                    "overall_score": 85,
                                    "summary_verdict": "Google Gemini audit completed.",
                                    "critical_actions": [],
                                    "quick_wins": [],
                                    "safety_warnings": [],
                                    "explainers": [
                                        {
                                            "id": "AIR-E01",
                                            "title": "Understanding WinSxS Hardlinks",
                                            "summary": "Hardlinks share clusters.",
                                        }
                                    ],
                                })
                            }
                        ]
                    }
                }
            ],
            "usageMetadata": {"promptTokenCount": 900, "candidatesTokenCount": 250},
        }

        mock_cm = MagicMock()
        mock_cm.__enter__.return_value.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_urlopen.return_value = mock_cm

        rep = sample_report()
        cfg = AIProviderConfig(provider="gemini", api_key="test-gemini-key")
        result = query_ai_advisor(rep, config=cfg)

        self.assertTrue(result.ok)
        self.assertEqual(result.provider, "gemini")
        self.assertEqual(result.overall_score, 85)
        self.assertEqual(len(result.explainers), 1)

    @patch("urllib.request.urlopen")
    def test_query_ai_advisor_mock_ollama(self, mock_urlopen):
        mock_response_data = {
            "response": json.dumps({
                "overall_score": 80,
                "summary_verdict": "Ollama Local LLM recommendation.",
                "critical_actions": [],
                "quick_wins": [],
                "safety_warnings": [],
                "explainers": [],
            }),
            "prompt_eval_count": 800,
            "eval_count": 200,
        }

        mock_cm = MagicMock()
        mock_cm.__enter__.return_value.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_urlopen.return_value = mock_cm

        rep = sample_report()
        cfg = AIProviderConfig(provider="ollama")
        result = query_ai_advisor(rep, config=cfg)

        self.assertTrue(result.ok)
        self.assertEqual(result.provider, "ollama")
        self.assertEqual(result.overall_score, 80)


class OpenSourceIntelligenceCollectorsTests(unittest.TestCase):
    def test_collect_hibernation_pagefile_intelligence(self):
        res = collect_hibernation_pagefile_intelligence("C:\\")
        self.assertTrue(res.ok)
        self.assertEqual(res.name, "hibernation_pagefile_intelligence")
        d = res.data
        self.assertIn("drive", d)
        self.assertIn("hiberfil_exists", d)
        self.assertIn("hiber_file_type", d)
        self.assertIn("recipes", d)

    def test_collect_delivery_optimization_status(self):
        res = collect_delivery_optimization_status()
        self.assertTrue(res.ok)
        self.assertEqual(res.name, "delivery_optimization_status")
        d = res.data
        self.assertIn("cache_size_bytes", d)
        self.assertIn("purge_recipe", d)

    def test_collect_battery_power_health(self):
        res = collect_battery_power_health()
        self.assertTrue(res.ok)
        self.assertEqual(res.name, "battery_power_health")
        d = res.data
        self.assertIn("is_battery_present", d)

    def test_collect_network_adapters_telemetry(self):
        res = collect_network_adapters_telemetry()
        self.assertTrue(res.ok)
        self.assertEqual(res.name, "network_adapters_telemetry")
        d = res.data
        self.assertIn("adapters", d)
        self.assertIn("active_adapters_count", d)

    def test_collect_crash_dumps_inventory(self):
        res = collect_crash_dumps_inventory()
        self.assertTrue(res.ok)
        self.assertEqual(res.name, "crash_dumps_inventory")
        d = res.data
        self.assertIn("total_dumps_count", d)
        self.assertIn("total_size_bytes", d)

    def test_collect_recycle_bin_metrics(self):
        res = collect_recycle_bin_metrics("C:\\")
        self.assertTrue(res.ok)
        self.assertEqual(res.name, "recycle_bin_metrics")
        d = res.data
        self.assertIn("total_size_bytes", d)
        self.assertIn("item_count", d)


class CLIAIReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.report_path = os.path.join(self.temp_dir.name, "test_report.json")
        with open(self.report_path, "w", encoding="utf-8") as f:
            json.dump(sample_report(), f)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_ai_review_prompt_only(self):
        with patch("sys.argv", ["reconspace", "ai-review", "--prompt-only", self.report_path]), patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            _main()
            out = mock_stdout.getvalue()
            self.assertIn("--- SYSTEM PROMPT ---", out)
            self.assertIn("--- USER PROMPT ---", out)

    def test_cli_ai_review_json_output(self):
        out_file = os.path.join(self.temp_dir.name, "ai_review.json")
        with patch("sys.argv", ["reconspace", "ai-review", "--provider", "heuristic", "--json", "--output", out_file, self.report_path]):
            _main()
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertTrue(data["ok"])
            self.assertIn("overall_score", data)
            self.assertIn("critical_actions", data)
            self.assertIn("quick_wins", data)

    def test_cli_ai_review_markdown_output(self):
        out_file = os.path.join(self.temp_dir.name, "ai_review.md")
        with patch("sys.argv", ["reconspace", "ai-review", "--provider", "heuristic", "--output", out_file, self.report_path]):
            _main()
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("# ReconSpace AI Audit Advisor - Executive Review", content)
            self.assertIn("System Wellness Score", content)


if __name__ == "__main__":
    unittest.main()
