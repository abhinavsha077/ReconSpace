from __future__ import annotations

import argparse
import json
import ntpath
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .duplicates import DuplicateScanCancelled
from .engine import AuditConfig, PROFILE_DEFAULTS, run_audit
from .scanner import ScanCancelled


def _scope_contains(root: str, candidate: str) -> bool:
    """Return True when candidate is a strict descendant of root.

    Use Windows path semantics for drive-letter/UNC paths even when tests run on a
    non-Windows host; otherwise use the host path implementation.
    """
    windowsish = bool(ntpath.splitdrive(root)[0] or ntpath.splitdrive(candidate)[0] or root.startswith("\\\\") or candidate.startswith("\\\\"))
    pathmod = ntpath if windowsish else os.path
    r = pathmod.normcase(pathmod.normpath(root))
    c = pathmod.normcase(pathmod.normpath(candidate))
    if c == r:
        return False
    try:
        return pathmod.commonpath([r, c]) == r
    except ValueError:
        return False


def _scope_equal_or_contains(root: str, candidate: str) -> bool:
    windowsish = bool(ntpath.splitdrive(root)[0] or ntpath.splitdrive(candidate)[0] or root.startswith("\\") or candidate.startswith("\\"))
    pathmod = ntpath if windowsish else os.path
    r = pathmod.normcase(pathmod.normpath(root))
    c = pathmod.normcase(pathmod.normpath(candidate))
    return c == r or _scope_contains(root, candidate)


class AuditState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.progress: dict = {"phase": "idle"}
        self.report: dict | None = None
        self.error: str = ""
        self.cancel_event = threading.Event()

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.running,
                "progress": dict(self.progress),
                "has_report": self.report is not None,
                "error": self.error,
            }


STATE = AuditState()
TOKEN = secrets.token_urlsafe(24)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _request_path(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string path")
    text = value.strip().strip('"').strip("'").strip()
    if not text:
        raise ValueError(f"{label} must not be empty")
    if len(text) > 32767 or "\x00" in text:
        raise ValueError(f"{label} is not a valid local path")
    if len(text) == 2 and text[0].isalpha() and text[1] == ":":
        text += "\\"
    return os.path.abspath(os.path.expandvars(os.path.expanduser(text)))


def _html() -> str:
    profiles = json.dumps({k: v for k, v in PROFILE_DEFAULTS.items()}, separators=(",", ":"))
    return r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ReconSpace — Windows Storage Intelligence</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='18' fill='%23111e35'/%3E%3Ccircle cx='32' cy='32' r='18' fill='none' stroke='%2368dce5' stroke-width='4'/%3E%3Ccircle cx='32' cy='32' r='5' fill='%23dfffff'/%3E%3C/svg%3E" />
<style>
:root{
  color-scheme:dark;
  --bg:#090d16;
  --surface:#121826;
  --surface-card:#162035;
  --surface-hover:#1c273e;
  --surface-subtle:#0d1320;
  --text:#f8fafc;
  --text-muted:#94a3b8;
  --text-dim:#64748b;
  --border:#232f45;
  --border-focus:#3b82f6;
  --primary:#3b82f6;
  --primary-hover:#2563eb;
  --good:#10b981;
  --good-bg:rgba(16,185,129,0.12);
  --warn:#f59e0b;
  --warn-bg:rgba(245,158,11,0.12);
  --risk:#ef4444;
  --risk-bg:rgba(239,68,68,0.12);
  --info:#06b6d4;
  --info-bg:rgba(6,182,212,0.12);
  --purple:#a855f7;
  --purple-bg:rgba(168,85,247,0.12);
  --accent:#3b82f6;
  --radius-sm:8px;
  --radius-md:12px;
  --radius-lg:16px;
}
*{box-sizing:border-box}
body{
  margin:0;
  background-color:var(--bg);
  background-image:radial-gradient(circle at 50% 0%,#162238 0%,transparent 45%);
  font:14px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  color:var(--text);
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
}
button,input,select,textarea{font:inherit}
.wrap{max-width:1540px;margin:0 auto;padding:28px 32px}
.hero{display:flex;gap:24px;align-items:center;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap}
.brand h1{font-size:28px;font-weight:800;letter-spacing:-.03em;margin:0 0 6px;display:flex;align-items:center;gap:12px}
.brand h1 .logo-icon{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#3b82f6,#06b6d4);display:inline-flex;align-items:center;justify-content:center;font-size:20px;color:#fff;box-shadow:0 4px 14px rgba(59,130,246,.3)}
.brand h1 .version-badge{font-size:11px;font-weight:700;background:rgba(59,130,246,.15);color:#93c5fd;border:1px solid rgba(59,130,246,.3);padding:3px 9px;border-radius:99px}
.brand p{color:var(--text-muted);margin:0;max-width:820px;font-size:13.5px;line-height:1.5}
.badges{display:flex;gap:8px;flex-wrap:wrap}
.badge{border:1px solid rgba(16,185,129,.35);background:var(--good-bg);color:var(--good);padding:6px 13px;border-radius:999px;font-weight:700;font-size:11.5px;display:inline-flex;align-items:center;gap:6px}
.badge.dim{border-color:var(--border);background:var(--surface);color:var(--text-muted)}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;box-shadow:0 8px 30px rgba(0,0,0,.25);margin:18px 0}
.controls{display:grid;grid-template-columns:2fr 1.1fr 1fr auto auto;gap:14px;align-items:end}
.field label{display:block;color:var(--text-muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin:0 0 6px}
.field input,.field select,.field textarea{width:100%;background:var(--surface-subtle);border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:10px;outline:none;transition:border-color .15s,box-shadow .15s}
.field textarea{min-height:70px;resize:vertical}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--border-focus);box-shadow:0 0 0 3px rgba(59,130,246,.2)}
.quick-chips{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
.chip{font-size:11px;color:var(--text-muted);background:rgba(255,255,255,.05);border:1px solid var(--border);padding:3px 9px;border-radius:6px;cursor:pointer;user-select:none;transition:all .15s}
.chip:hover{color:var(--text);background:rgba(59,130,246,.15);border-color:var(--primary)}
button{background:var(--primary);color:#fff;border:0;border-radius:10px;padding:10px 20px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 2px 10px rgba(37,99,235,.25);transition:all .15s;display:inline-flex;align-items:center;gap:8px;font-size:13.5px}
button:hover:not(:disabled){background:var(--primary-hover);transform:translateY(-1px);box-shadow:0 4px 14px rgba(37,99,235,.35)}
button:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}
button.secondary{background:var(--surface-card);color:var(--text);border:1px solid var(--border);box-shadow:none}
button.secondary:hover:not(:disabled){background:var(--surface-hover);border-color:#384865}
button.dangerish{background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.3);box-shadow:none}
button.dangerish:hover:not(:disabled){background:rgba(239,68,68,.22);border-color:var(--risk)}
.advanced{margin-top:16px;border-top:1px solid var(--border);padding-top:14px}
.advanced summary{cursor:pointer;color:var(--text-muted);font-size:12.5px;font-weight:600;user-select:none}
.advanced summary:hover{color:var(--text)}

/* Modern Reassuring Monitor Card */
.monitor-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:22px;margin:18px 0;box-shadow:0 8px 30px rgba(0,0,0,.25)}
.monitor-top{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;padding-bottom:16px;border-bottom:1px solid var(--border)}
.monitor-status{display:flex;align-items:center;gap:12px}
.status-pill{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border-radius:999px;font-size:12px;font-weight:750;letter-spacing:.03em}
.status-pill.idle{background:rgba(148,163,184,.1);color:var(--text-muted);border:1px solid var(--border)}
.status-pill.running{background:rgba(59,130,246,.15);color:#93c5fd;border:1px solid rgba(59,130,246,.4)}
.status-pill.done{background:var(--good-bg);color:var(--good);border:1px solid rgba(16,185,129,.4)}
.status-pill.cancelled{background:var(--warn-bg);color:var(--warn);border:1px solid rgba(245,158,11,.4)}
.status-pill.failed{background:var(--risk-bg);color:var(--risk);border:1px solid rgba(239,68,68,.4)}
.pulse-dot{width:8px;height:8px;border-radius:50%;background:currentColor;display:inline-block}
.status-pill.running .pulse-dot{animation:pulse 1.4s infinite ease-in-out}
@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.3);opacity:.4}}
.monitor-metrics{display:flex;align-items:center;gap:14px;color:var(--text-muted);font-size:12.5px}
.metric-box{display:flex;align-items:center;gap:6px;background:var(--surface-subtle);border:1px solid var(--border);padding:5px 12px;border-radius:8px}
.metric-box b{color:var(--text);font-variant-numeric:tabular-nums}
.pulse-heartbeat{width:7px;height:7px;border-radius:50%;background:var(--good);display:inline-block;opacity:.4;transition:opacity .2s}
.pulse-heartbeat.beat{opacity:1;transform:scale(1.2)}

/* 7-Stage Pipeline Stepper */
.stepper-wrap{margin:18px 0 14px}
.stepper-title{font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px}
.stepper{display:grid;grid-template-columns:repeat(7,1fr);gap:10px}
.step-node{background:var(--surface-subtle);border:1px solid var(--border);border-radius:10px;padding:10px 12px;display:flex;flex-direction:column;gap:3px;transition:all .2s}
.step-node.pending{opacity:.5}
.step-node.active{border-color:var(--primary);background:rgba(59,130,246,.08);box-shadow:0 0 14px rgba(59,130,246,.15)}
.step-node.completed{border-color:rgba(16,185,129,.4);background:rgba(16,185,129,.04)}
.step-header{display:flex;align-items:center;justify-content:space-between;font-size:11px;font-weight:700}
.step-header .step-idx{color:var(--text-dim)}
.step-header .step-badge{font-size:10px;font-weight:750;padding:1px 6px;border-radius:4px}
.step-node.completed .step-badge{background:var(--good-bg);color:var(--good)}
.step-node.active .step-badge{background:rgba(59,130,246,.2);color:#bfdbfe}
.step-node.pending .step-badge{background:rgba(255,255,255,.04);color:var(--text-dim)}
.step-name{font-size:12.5px;font-weight:700;color:var(--text);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.step-desc{font-size:10.5px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* Progress bar */
.progress-container{margin:16px 0 12px}
.progress-labels{display:flex;justify-content:space-between;align-items:center;font-size:12.5px;margin-bottom:7px}
.progress-detail{color:var(--text);font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:85%}
.progress-pct{font-weight:750;color:#38bdf8;font-variant-numeric:tabular-nums}
.progress{height:7px;background:var(--surface-subtle);border-radius:99px;overflow:hidden;position:relative;border:1px solid rgba(255,255,255,.05)}
.progress>i{display:block;height:100%;width:0;background:linear-gradient(90deg,#3b82f6,#06b6d4,#10b981);border-radius:99px;transition:width .35s ease}
.progress.indeterminate>i{width:30%;animation:slide 1.4s infinite ease-in-out}
@keyframes slide{0%{transform:translateX(-120%)}100%{transform:translateX(350%)}}

.reassurance-note{background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.25);border-radius:10px;padding:11px 15px;color:#a5f3fc;font-size:12.5px;display:flex;align-items:center;gap:10px;margin-top:12px}

/* Collapsible Activity Log */
.activity-card{margin-top:14px;background:var(--surface-subtle);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.activity-header{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;cursor:pointer;user-select:none;font-size:11px;color:var(--text-muted);font-weight:700;background:rgba(255,255,255,.02);border-bottom:1px solid var(--border)}
.activity-header:hover{color:var(--text)}
.activity-feed{height:110px;overflow-y:auto;padding:10px 14px;font:11.5px/1.6 Consolas,monospace;color:#94a3b8}
.activity-row{display:flex;gap:8px}
.activity-row .t{color:#38bdf8;flex:none}
.activity-row .m{color:#cbd5e1;word-break:break-all}
.activity-row.stage .m{color:#c084fc;font-weight:700}
.activity-row.success .m{color:#34d399;font-weight:700}

/* Executive Metrics */
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
.metric{background:var(--surface-subtle);border:1px solid var(--border);border-radius:14px;padding:16px 18px;min-width:0}
.metric b{display:block;font-size:22px;font-weight:800;letter-spacing:-.02em;margin:5px 0 2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-variant-numeric:tabular-nums}
.metric span{color:var(--text-muted);font-size:11.5px;display:block}
.metric.good b{color:var(--good)}
.metric.warn b{color:var(--warn)}
.metric.info b{color:var(--primary)}

/* Modern Tab Navigation */
.tabs{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:18px}
.tab{background:var(--surface-subtle);border:1px solid var(--border);color:var(--text-muted);padding:9px 14px;border-radius:9px;font-size:12.5px;font-weight:600;display:inline-flex;align-items:center;gap:7px;transition:all .15s}
.tab:hover{color:var(--text);background:var(--surface-card)}
.tab.active{color:#fff;background:var(--surface-hover);border-color:var(--primary);box-shadow:0 2px 8px rgba(0,0,0,.25)}
.tab-count{font-size:10px;font-weight:750;background:rgba(255,255,255,.08);color:var(--text-muted);padding:2px 7px;border-radius:99px}
.tab.active .tab-count{background:rgba(59,130,246,.25);color:#93c5fd}

.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 18px;align-items:center}
.toolbar input,.toolbar select{background:var(--surface-subtle);border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:9px}
.toolbar input{min-width:300px}
.small{color:var(--text-muted);font-size:12px}
.mono{font-family:Consolas,monospace}
.path{color:#cbd5e1;font-family:Consolas,monospace;font-size:12px;word-break:break-all}
.hidden{display:none!important}
.notice{border-left:3px solid var(--warn);padding:14px 16px;background:#241d0b;color:#fef3c7;border-radius:10px;font-size:13px}
.error{border-left-color:var(--risk);background:#2d1214;color:#fee2e2}
.success{border-left-color:var(--good);background:#0d261b;color:#d1fae5}

/* Categorized Findings System */
.cat-bar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 18px}
.cat-pill{background:var(--surface-subtle);border:1px solid var(--border);color:var(--text-muted);padding:8px 14px;border-radius:999px;cursor:pointer;font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:7px;transition:all .15s}
.cat-pill:hover{color:var(--text);border-color:var(--primary);background:var(--surface-card)}
.cat-pill.active{color:#fff;background:#1e3a8a;border-color:var(--primary);box-shadow:0 2px 8px rgba(59,130,246,.2)}
.cat-pill .sub{font-size:10.5px;opacity:.85}
.cat-section{background:var(--surface-subtle);border:1px solid var(--border);border-radius:16px;padding:22px;margin:18px 0 24px}
.cat-section-header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.cat-section-title{font-size:17px;font-weight:750;color:var(--text);display:flex;align-items:center;gap:10px;margin:0}
.cat-section-desc{color:var(--text-muted);font-size:12.5px;margin-top:4px;max-width:860px;line-height:1.5}
.cat-section-badge{display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border-radius:999px;font-size:11.5px;font-weight:700;background:rgba(59,130,246,.12);color:#93c5fd;border:1px solid rgba(59,130,246,.3)}

/* Modern Explanative Finding Card */
.finding-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin:12px 0;transition:border-color .15s,box-shadow .15s}
.finding-card:hover{border-color:#3b4d6b;box-shadow:0 4px 16px rgba(0,0,0,.2)}
.finding-top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.finding-title-box{flex:1;min-width:280px}
.finding-title{font-size:15px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px}
.finding-sizes{display:flex;align-items:center;gap:16px;text-align:right}
.finding-reclaim b{font-size:18px;font-weight:800;color:var(--good);font-variant-numeric:tabular-nums;display:block}
.finding-reclaim span{font-size:11px;color:var(--text-muted)}
.finding-path-bar{display:flex;align-items:center;justify-content:space-between;gap:10px;background:var(--surface-subtle);border:1px solid var(--border);border-radius:8px;padding:7px 12px;margin:8px 0 14px}
.finding-path-text{font-family:Consolas,monospace;font-size:12px;color:#cbd5e1;word-break:break-all}
.copy-btn{background:transparent;border:1px solid var(--border);color:var(--text-muted);padding:3px 8px;border-radius:6px;font-size:10.5px;cursor:pointer;box-shadow:none}
.copy-btn:hover{background:rgba(255,255,255,.06);color:var(--text);transform:none}
.explain-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px}
.explain-card{background:var(--surface-subtle);border:1px solid var(--border);border-radius:9px;padding:12px 14px}
.explain-card-lbl{font-size:11px;font-weight:750;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px;display:flex;align-items:center;gap:6px}
.explain-card-txt{font-size:12px;color:#e2e8f0;line-height:1.5;margin:0}
.finding-tech{margin-top:12px;border-top:1px dashed var(--border);padding-top:8px}
.finding-tech summary{cursor:pointer;font-size:11.5px;color:var(--text-muted);font-weight:600;user-select:none}
.finding-tech summary:hover{color:var(--text)}
.tech-pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.tech-pill{background:rgba(255,255,255,.03);border:1px solid var(--border);padding:3px 8px;border-radius:6px;font-size:11px;color:var(--text-muted)}
.tech-pill b{color:var(--text)}

/* Legacy finding fallback */
.finding{display:grid;grid-template-columns:minmax(240px,1.25fr) .55fr .6fr 2fr;gap:14px;border-top:1px solid var(--border);padding:14px 4px;align-items:start}
.finding:first-child{border-top:0}
.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:10.5px;font-weight:750;border:1px solid transparent;letter-spacing:.02em}
.safe,.pill.safe{background:var(--good-bg);color:var(--good);border-color:rgba(16,185,129,.35)}
.review,.pill.review{background:var(--warn-bg);color:var(--warn);border-color:rgba(245,158,11,.35)}
.tooling,.pill.tooling{background:rgba(59,130,246,.12);color:#93c5fd;border-color:rgba(59,130,246,.35)}
.dont,.pill.dont{background:var(--risk-bg);color:#fca5a5;border-color:rgba(239,68,68,.35)}
.info,.pill.info{background:var(--purple-bg);color:#d8b4fe;border-color:rgba(168,85,247,.35)}

/* Tables and Charts */
.tablewrap{overflow:auto;max-height:680px;border:1px solid var(--border);border-radius:12px;background:var(--surface-subtle)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;border-bottom:1px solid var(--border);padding:11px 14px;vertical-align:top}
th{position:sticky;top:0;background:#151e2e;color:var(--text-muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;z-index:1;font-weight:700}
td.pathcell{font-family:Consolas,monospace;font-size:12px;min-width:310px;word-break:break-all}
tr:last-child td{border-bottom:0}
tr:hover td{background:rgba(255,255,255,.02)}
.twocol{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.chart{background:var(--surface-subtle);border:1px solid var(--border);border-radius:14px;padding:18px}
.chart h3{margin:0 0 14px;font-size:15px;font-weight:700}
.barrow{display:grid;grid-template-columns:minmax(110px,1fr) 2fr 85px;gap:12px;align-items:center;margin:9px 0}
.barlabel{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#cbd5e1;font-size:12px}
.bar{height:8px;border-radius:99px;background:#1b2537;overflow:hidden}
.bar i{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,#3b82f6,#06b6d4)}
.barval{text-align:right;color:var(--text-muted);font-size:11.5px;font-variant-numeric:tabular-nums}
.diskbar{height:14px;background:#1b2537;border-radius:99px;overflow:hidden;margin:12px 0}
.diskbar i{display:block;height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6,#06b6d4)}
.dupcard{border:1px solid var(--border);background:var(--surface-subtle);border-radius:12px;padding:16px;margin:12px 0}
.dupcard .paths{margin-top:10px}
.dupcard .paths div{padding:6px 0;border-top:1px dashed var(--border)}
.score{font-variant-numeric:tabular-nums}
.score strong{font-size:18px}
.collector{border:1px solid var(--border);border-radius:10px;margin:10px 0;background:var(--surface-subtle)}
.collector summary{cursor:pointer;padding:12px 16px;font-weight:600}
.collector pre{white-space:pre-wrap;word-break:break-word;padding:0 16px 16px;color:#cbd5e1;font:12px/1.5 Consolas,monospace;max-height:440px;overflow:auto}
.comparebox{border:1px dashed #384865;border-radius:12px;padding:20px;background:var(--surface-subtle)}
.delta.plus{color:var(--risk)}
.delta.minus{color:var(--good)}

/* Overview Category Cards */
.overview-cats{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-top:16px}
.overview-cat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;display:flex;flex-direction:column;justify-content:space-between;gap:10px;cursor:pointer;transition:all .15s}
.overview-cat-card:hover{border-color:var(--primary);transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.25)}
.overview-cat-top{display:flex;align-items:center;justify-content:space-between;gap:10px}
.overview-cat-title{font-weight:750;font-size:14px;display:flex;align-items:center;gap:8px;color:var(--text)}
.overview-cat-size{font-size:18px;font-weight:800;color:var(--good);font-variant-numeric:tabular-nums}
.overview-cat-count{font-size:11.5px;color:var(--text-muted)}

@media(max-width:1200px){
  .stepper{grid-template-columns:repeat(4,1fr)}
  .grid{grid-template-columns:repeat(3,1fr)}
  .finding{grid-template-columns:1fr 1fr}
  .explain-grid{grid-template-columns:1fr}
}
@media(max-width:800px){
  .wrap{padding:16px}
  .controls{grid-template-columns:1fr 1fr}
  .stepper{grid-template-columns:repeat(2,1fr)}
  .grid,.finding{grid-template-columns:1fr}
  .twocol{grid-template-columns:1fr}
  .toolbar input{min-width:100%}
  .monitor-top{flex-direction:column;align-items:flex-start}
  .explain-grid{grid-template-columns:1fr}
}

/* ReconSpace Observatory — v0.5 visual system */
:root{
  color-scheme:dark;
  --bg:#060b14;
  --surface:#0d1728;
  --surface-card:#13213a;
  --surface-hover:#192b49;
  --surface-subtle:#09111f;
  --text:#f5f8ff;
  --text-muted:#a8b7ce;
  --muted:#a8b7ce;
  --text-dim:#70819c;
  --border:#273957;
  --border-focus:#73dfe6;
  --primary:#6f8fff;
  --primary-hover:#83a0ff;
  --good:#67dfa9;
  --good-bg:rgba(103,223,169,.11);
  --warn:#ffc76b;
  --warn-bg:rgba(255,199,107,.11);
  --risk:#ff8a7e;
  --risk-bg:rgba(255,138,126,.11);
  --info:#68dce5;
  --info-bg:rgba(104,220,229,.11);
  --purple:#ad91ff;
  --purple-bg:rgba(173,145,255,.11);
  --rail:#091220;
  --shadow:0 24px 70px rgba(0,0,0,.35);
}
html{scroll-behavior:smooth}
body{
  background:
    radial-gradient(ellipse 70% 45% at 76% -10%,rgba(69,112,203,.18),transparent 70%),
    linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px),
    var(--bg);
  background-size:auto,32px 32px,32px 32px,auto;
  font:15px/1.55 "Segoe UI Variable Text","Segoe UI",sans-serif;
  letter-spacing:.002em;
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;
  background:linear-gradient(115deg,transparent 20%,rgba(95,136,224,.035) 48%,transparent 70%);
}
button,input,select,textarea{font:inherit}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,summary:focus-visible,[tabindex]:focus-visible{
  outline:3px solid rgba(104,220,229,.6);outline-offset:3px;
}
.wrap{max-width:none;margin:0;padding:30px 34px 70px 304px}

/* Permanent navigation rail */
.hero{
  position:fixed;inset:18px auto 18px 18px;width:252px;margin:0;padding:26px 22px;
  display:flex;flex-direction:column;align-items:stretch;justify-content:flex-start;gap:24px;
  background:linear-gradient(180deg,rgba(17,31,53,.98),rgba(7,15,27,.98));
  border:1px solid rgba(119,150,196,.2);border-radius:26px;box-shadow:var(--shadow);z-index:20;overflow:hidden;
}
.hero::before{
  content:"";position:absolute;width:210px;height:210px;left:-80px;top:-95px;border-radius:50%;
  background:radial-gradient(circle,rgba(105,225,231,.19),transparent 67%);pointer-events:none;
}
.hero::after{
  content:"SYSTEM OBSERVATORY";margin-top:auto;padding-top:19px;border-top:1px solid var(--border);
  color:var(--text-dim);font:650 10px/1.4 "Cascadia Mono",Consolas,monospace;letter-spacing:.16em;
}
.brand{position:relative;z-index:1}
.brand h1{display:grid;grid-template-columns:44px 1fr;column-gap:11px;row-gap:1px;align-items:center;margin:0 0 20px;font:720 23px/1 "Bahnschrift","Segoe UI Variable Display",sans-serif;letter-spacing:-.025em}
.brand h1 .logo-icon{grid-row:1/3;width:44px;height:44px;border-radius:15px;background:radial-gradient(circle at 35% 30%,#a6fbff 0 5%,#57cdd9 18%,#416ac5 58%,#263a70 100%);font-size:0;box-shadow:0 0 0 1px rgba(138,236,242,.34),0 12px 30px rgba(52,111,198,.34)}
.brand h1 .logo-icon::before{content:"";width:17px;height:17px;border:2px solid #e9ffff;border-radius:50%;box-shadow:0 0 14px rgba(193,255,255,.9)}
.brand h1 .version-badge{grid-column:2;background:none;border:0;padding:0;color:#7f91ac;border-radius:0;font:600 10px/1.2 "Cascadia Mono",Consolas,monospace;letter-spacing:.12em}
.brand p{max-width:none;margin:0;color:#b7c6d9;font-size:13px;line-height:1.65}
.brand p b{color:#dffeff;font-weight:650}
.badges{display:grid;gap:9px;margin-top:4px}
.badge,.badge.dim{justify-content:flex-start;width:100%;padding:9px 11px;background:rgba(255,255,255,.025);border:1px solid rgba(125,151,188,.15);border-radius:11px;color:#b7c6da;font-size:10px;letter-spacing:.06em}
.badge:first-child{background:var(--good-bg);border-color:rgba(103,223,169,.24);color:#8ce9c0}

/* Scan composer */
.panel,.monitor-card{border:1px solid rgba(119,150,196,.2);box-shadow:var(--shadow)}
.hero + .panel{
  position:relative;margin:0 0 20px;padding:32px;border-radius:24px;
  background:linear-gradient(135deg,rgba(18,34,58,.98),rgba(10,19,34,.98));overflow:hidden;
}
.hero + .panel::after{
  content:"";position:absolute;right:-100px;top:-150px;width:330px;height:330px;border-radius:50%;pointer-events:none;
  background:radial-gradient(circle,rgba(112,143,255,.14),transparent 67%);
}
.controls{position:relative;z-index:1;grid-template-columns:minmax(260px,2fr) minmax(180px,1fr) minmax(165px,.9fr) auto auto;gap:14px}
.controls::before{
  content:"Map this PC";grid-column:1/-1;margin-bottom:7px;color:var(--text);
  font:700 clamp(25px,3vw,38px)/1.05 "Bahnschrift","Segoe UI Variable Display",sans-serif;letter-spacing:-.035em;
}
.field label{color:#8fa2bd;font-size:10px;letter-spacing:.12em}
.field input,.field select,.field textarea,.toolbar input,.toolbar select{
  min-height:45px;background:rgba(3,9,18,.72);border-color:#304362;border-radius:12px;color:var(--text);padding:11px 14px;
}
.field input:hover,.field select:hover,.field textarea:hover{border-color:#476383}
.small{color:var(--text-muted)}
.quick-chips{gap:7px;margin-top:9px}
.chip{padding:4px 9px;border-radius:8px;background:rgba(105,143,255,.06);border-color:#2a3d5c;color:#a9bdd8}
.chip:hover{background:rgba(104,220,229,.12);border-color:#4a8b9c;color:#ddfcff}
button{min-height:45px;padding:10px 19px;border-radius:12px;background:linear-gradient(135deg,#7696ff,#5777e7);font-weight:700;box-shadow:0 10px 26px rgba(73,103,208,.27)}
button:hover:not(:disabled){background:linear-gradient(135deg,#89a5ff,#6484ee);box-shadow:0 12px 30px rgba(73,103,208,.35)}
button.dangerish{background:rgba(255,138,126,.09);border-color:rgba(255,138,126,.3);color:#ffb1a9}
.advanced{margin-top:21px;padding-top:17px;border-color:#293c59}
.advanced summary{width:max-content;color:#b9c8db;font-size:13px}

/* Signature: storage radar */
.monitor-card{
  position:relative;min-height:292px;margin:20px 0;padding:28px 28px 24px 242px;border-radius:24px;overflow:hidden;
  background:linear-gradient(145deg,rgba(11,23,41,.98),rgba(8,16,29,.98));
}
.monitor-card::before{
  content:"";position:absolute;left:45px;top:47px;width:142px;height:142px;border-radius:50%;
  background:
    radial-gradient(circle at center,#86f5f2 0 3px,transparent 4px 22px,rgba(102,220,229,.22) 23px 24px,transparent 25px 45px,rgba(111,143,255,.24) 46px 47px,transparent 48px 64px,rgba(111,143,255,.13) 65px 66px,transparent 67px),
    conic-gradient(from 15deg,transparent 0 68%,rgba(104,220,229,.72) 82%,transparent 96%);
  border:1px solid rgba(109,223,230,.27);box-shadow:0 0 50px rgba(68,140,213,.18),inset 0 0 40px rgba(63,115,191,.09);
  animation:radarSweep 5s linear infinite;
}
.monitor-card::after{
  content:"SYSTEM MAP";position:absolute;left:73px;top:205px;color:#7f93ae;font:650 10px/1 "Cascadia Mono",Consolas,monospace;letter-spacing:.18em;
}
.monitor-card:has(.status-pill.running)::before{animation-duration:1.8s;box-shadow:0 0 70px rgba(84,202,221,.34),inset 0 0 42px rgba(73,143,214,.16)}
.monitor-card:has(.status-pill.done)::before{background:radial-gradient(circle at center,#baffdb 0 5px,transparent 6px 23px,rgba(103,223,169,.28) 24px 25px,transparent 26px 48px,rgba(103,223,169,.2) 49px 50px,transparent 51px);animation:none}
@keyframes radarSweep{to{transform:rotate(360deg)}}
.monitor-top{padding-bottom:15px;border-color:#283b58}
.monitor-status{align-items:center}
.status-pill{padding:7px 12px;font-size:10px;letter-spacing:.1em;text-transform:uppercase}
.status{font-size:14px;color:#d7e2f0}
.monitor-metrics{gap:8px}
.metric-box{background:#08111f;border-color:#2b3d5a;border-radius:9px;color:#91a4c0}
.stepper-wrap{margin:17px 0 12px}
.stepper-title{margin-bottom:9px;color:#778ba8;font:650 9px/1.4 "Cascadia Mono",Consolas,monospace;letter-spacing:.16em}
.stepper{grid-template-columns:repeat(7,minmax(105px,1fr));gap:7px;overflow-x:auto;padding-bottom:3px}
.step-node{min-width:105px;padding:9px 10px;border-radius:10px;background:#08111f;border-color:#233654}
.step-node.active{border-color:#58cbd4;background:rgba(78,181,198,.1);box-shadow:0 0 18px rgba(74,190,202,.12)}
.step-node.completed{border-color:rgba(103,223,169,.26);background:rgba(103,223,169,.045)}
.step-name{font-size:11px}.step-desc{font-size:9px}.step-header{font-size:9px}
.progress{height:9px;background:#07101d;border-color:#243654}
.progress>i{background:linear-gradient(90deg,#5878de,#6f8fff 48%,#68dce5)}
.progress-detail{font-size:12px;color:#c8d5e6}.progress-pct{color:#83e8ec;font-family:"Cascadia Mono",Consolas,monospace}
.reassurance-note{background:rgba(104,220,229,.06);border-color:rgba(104,220,229,.19);color:#c1f7fa}
.activity-card{background:#07101d;border-color:#233653}
.activity-header{background:rgba(255,255,255,.018);border-color:#233653;letter-spacing:.08em}
.activity-feed{color:#a9bad1}

/* Results command center */
#summary{margin-top:25px}
#summary > .grid{grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.metric{position:relative;min-height:116px;padding:18px 19px;border-color:#273b59;border-radius:16px;background:linear-gradient(145deg,#111e33,#0b1526);overflow:hidden}
.metric::after{content:"";position:absolute;right:-24px;bottom:-36px;width:90px;height:90px;border-radius:50%;background:radial-gradient(circle,rgba(111,143,255,.11),transparent 70%)}
.metric b{font:720 26px/1.2 "Bahnschrift","Segoe UI Variable Display",sans-serif;letter-spacing:-.025em;color:#f6f9ff}
.metric span:first-child{text-transform:uppercase;letter-spacing:.1em;font-size:9px;color:#8498b5}
#summary > .panel:first-of-type{padding:19px 22px;border-radius:18px;background:#0d182a}
#summary > .panel:last-of-type{display:grid;grid-template-columns:224px minmax(0,1fr);gap:0;padding:0;border-radius:22px;background:#0c1627;overflow:hidden}
.tabs{display:flex;flex-direction:column;align-items:stretch;gap:4px;margin:0;padding:19px 12px;background:#091321;border-right:1px solid #263954;max-height:calc(100vh - 38px);overflow-y:auto;position:sticky;top:18px;align-self:start}
.tabs::before{content:"AUDIT MAP";padding:2px 11px 10px;color:#7286a4;font:650 9px/1 "Cascadia Mono",Consolas,monospace;letter-spacing:.16em}
.tab{width:100%;min-height:38px;justify-content:flex-start;padding:8px 10px;border:1px solid transparent;border-radius:10px;background:transparent;color:#9dafc7;box-shadow:none;font-size:12px}
.tab:hover{background:#111f35;color:#ecf4ff;transform:none;box-shadow:none}
.tab.active{background:linear-gradient(90deg,rgba(104,220,229,.13),rgba(111,143,255,.08));border-color:rgba(104,220,229,.26);color:#f1fcff;box-shadow:inset 3px 0 #66d7df}
.tab-count{margin-left:auto;background:#14243d;color:#8ea4c2}
.tab[data-view="findings"],.tab[data-view="apps"],.tab[data-view="startup"],.tab[data-view="health"]{margin-top:9px;padding-top:10px;border-top-color:#253751}
#view{min-width:0;padding:28px 30px 34px}
.decision-brief{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(260px,.6fr);gap:12px;margin-bottom:16px}
.brief-main,.brief-next,.scope-band,.depth-card,.plan-lane,.plan-item{border:1px solid #273b59;background:#0a1424;border-radius:16px}
.brief-main{padding:23px;display:grid;grid-template-columns:auto 1fr;gap:18px;align-items:center}
.health-orb{width:82px;height:82px;border-radius:50%;display:grid;place-items:center;border:1px solid rgba(104,220,229,.35);background:radial-gradient(circle,rgba(104,220,229,.2),rgba(111,143,255,.06) 62%,transparent 64%);font:720 18px/1 "Bahnschrift",sans-serif;color:#c9fcff}
.health-orb.critical{border-color:rgba(255,138,126,.45);background:radial-gradient(circle,rgba(255,138,126,.2),rgba(255,138,126,.04) 62%,transparent 64%);color:#ffd0cb}
.health-orb.low{border-color:rgba(255,199,107,.45);background:radial-gradient(circle,rgba(255,199,107,.17),rgba(255,199,107,.03) 62%,transparent 64%);color:#ffe3ad}
.brief-kicker,.depth-status,.lane-kicker{font:650 9px/1.3 "Cascadia Mono",Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:#7f94b1}
.brief-main h2,.brief-next h3{margin:5px 0 7px;font:700 22px/1.15 "Bahnschrift",sans-serif}.brief-main p,.brief-next p{margin:0;color:#adbed4}
.brief-next{padding:22px;background:linear-gradient(145deg,rgba(20,43,66,.96),rgba(11,24,41,.96));border-color:rgba(104,220,229,.24)}
.brief-next button{margin-top:14px;width:100%}
.scope-band{display:grid;grid-template-columns:auto 1fr;gap:12px;padding:14px 16px;margin-bottom:16px;background:rgba(104,220,229,.055)}
.scope-band strong{color:#d9fcff}.scope-band p{margin:1px 0 0;color:#a8bad1}
.decision-numbers{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px;margin-bottom:16px}.decision-number{padding:15px;border:1px solid #263a58;border-radius:13px;background:#0a1424}.decision-number b{display:block;font:700 19px/1.2 "Bahnschrift",sans-serif}.decision-number span{font-size:10px;color:#8498b5;text-transform:uppercase;letter-spacing:.08em}
.depth-heading{display:flex;justify-content:space-between;gap:12px;align-items:end;margin:20px 0 9px}.depth-heading h3{margin:0}.depth-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.depth-card{padding:15px}.depth-card-top{display:flex;justify-content:space-between;gap:10px;align-items:start}.depth-card h4{margin:2px 0 5px;font-size:14px}.depth-card p{margin:0;color:#93a6c0;font-size:12px}.depth-status{padding:5px 7px;border-radius:7px;white-space:nowrap}.depth-status.complete{color:#82e6b9;background:rgba(103,223,169,.1)}.depth-status.partial{color:#ffd384;background:rgba(255,199,107,.1)}.depth-status.blocked{color:#ffaaa1;background:rgba(255,138,126,.1)}.depth-status.not_available{color:#aebdd0;background:rgba(174,189,208,.08)}
.depth-meta{margin-top:9px;padding-top:8px;border-top:1px dashed #273957;color:#8ea2bd;font-size:11px}.depth-limit{color:#ffc983}
.plan-intro{display:grid;grid-template-columns:1.15fr .85fr;gap:12px;margin-bottom:14px}.plan-lane{padding:20px}.plan-lane h2,.plan-lane h3{margin:5px 0 8px}.plan-steps{margin:11px 0 0;padding-left:20px;color:#b8c6d8}.plan-steps li{margin:7px 0}.plan-list{display:grid;gap:10px;margin-top:10px}.plan-item{padding:17px}.plan-item-head{display:flex;justify-content:space-between;gap:16px;align-items:start}.plan-item h4{margin:0 0 4px}.plan-item-size{text-align:right;white-space:nowrap}.plan-item-size b{display:block;color:#80e5b8}.plan-item-path{margin:10px 0;padding:8px 10px;border:1px solid #223550;border-radius:8px;background:#07101d;color:#9fb1c8;font:11px/1.45 "Cascadia Mono",Consolas,monospace;overflow-wrap:anywhere}.plan-explain{display:grid;grid-template-columns:1fr 1fr;gap:9px}.plan-explain div{padding:10px;border-radius:9px;background:#081321}.plan-explain b{display:block;margin-bottom:3px;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#8195b1}.plan-explain p{margin:0;font-size:12px;color:#b8c6d8}.plan-empty{padding:22px;text-align:center;color:#9cafc8}
.chart,.cat-section,.finding-card,.overview-cat-card,.comparebox,.dupcard,.tablewrap,.collector{background:#0a1424;border-color:#273b59}
.chart{padding:20px;border-radius:16px}.chart h3{font:680 16px/1.3 "Bahnschrift","Segoe UI Variable Display",sans-serif}
.diskbar{height:12px;background:#15233a}.diskbar i{background:linear-gradient(90deg,#5b79df,#788fff,#64dae4)}
.overview-cats{grid-template-columns:repeat(auto-fill,minmax(255px,1fr));gap:11px}
.overview-cat-card{border-radius:15px}.overview-cat-card:hover{border-color:#5fbfc9;box-shadow:0 12px 30px rgba(0,0,0,.22)}
.overview-cat-size{color:#82e6be}.cat-pill.active{background:rgba(105,143,255,.18);border-color:#667fc9}
.finding-card{border-radius:15px}.finding-path-bar,.explain-card{background:#07101d;border-color:#243653}
.tablewrap{border-radius:14px}th{background:#101e33;color:#9bacc4}th,td{padding:12px 14px}tr:hover td{background:rgba(104,220,229,.025)}
.bar{background:#15243a}.bar i{background:linear-gradient(90deg,#6c88ef,#67dbe4)}
.notice{background:rgba(255,199,107,.08);color:#ffe5b6;border-left-color:#ffc76b}.error{background:rgba(255,138,126,.09);color:#ffd5d0;border-left-color:#ff8a7e}
.safe,.pill.safe{color:#83e9bc}.review,.pill.review{color:#ffd080}.tooling,.pill.tooling{color:#9fb3ff}.dont,.pill.dont{color:#ffa69d}.info,.pill.info{color:#c4b2ff}

@media(max-width:1120px){
  .wrap{padding-left:280px;padding-right:22px}.hero{width:236px}
  .controls{grid-template-columns:1fr 1fr}.controls::before{grid-column:1/-1}.monitor-card{padding-left:28px;padding-top:218px}.monitor-card::before{left:calc(50% - 71px);top:38px}.monitor-card::after{left:calc(50% - 46px);top:190px}
  #summary > .grid{grid-template-columns:repeat(2,1fr)}
  .decision-brief,.plan-intro{grid-template-columns:1fr}.decision-numbers{grid-template-columns:repeat(2,1fr)}
}
@media(max-width:760px){
  .wrap{padding:14px 14px 44px}.hero{position:relative;inset:auto;width:auto;height:auto;padding:18px;border-radius:19px;gap:12px;margin-bottom:14px}.hero::after{display:none}.brand h1{margin-bottom:11px}.brand p{font-size:12px}.badges{grid-template-columns:1fr 1fr}.badge:last-child{display:none}
  .hero + .panel{padding:22px 17px;border-radius:19px}.controls{grid-template-columns:1fr}.controls::before{font-size:28px}
  .monitor-card{padding:205px 17px 18px;border-radius:19px}.monitor-card::before{top:34px}.monitor-card::after{top:185px}
  .monitor-top{align-items:stretch}.monitor-metrics{width:100%;display:grid;grid-template-columns:1fr 1fr}.monitor-metrics #profileHint{grid-column:1/-1}
  .stepper{grid-template-columns:repeat(7,120px)}
  #summary > .grid{grid-template-columns:1fr}
  #summary > .panel:last-of-type{display:block}.tabs{position:static;max-height:none;display:flex;flex-direction:row;overflow-x:auto;border-right:0;border-bottom:1px solid #263954;padding:12px}.tabs::before{display:none}.tab{width:auto;flex:0 0 auto}.tab:nth-child(n){margin-top:0;border-top-color:transparent}
  #view{padding:20px 15px 26px}.twocol{grid-template-columns:1fr}.toolbar input{min-width:100%}
  .brief-main{grid-template-columns:1fr}.health-orb{width:68px;height:68px}.decision-numbers,.depth-grid,.plan-explain{grid-template-columns:1fr}.plan-item-head{display:block}.plan-item-size{text-align:left;margin-top:8px}
}
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}
}

/* ReconSpace Care — CleanMyMac-inspired desktop experience */
:root{
  --bg:#171123;--surface:#251b35;--surface-card:rgba(255,255,255,.075);--surface-hover:rgba(255,255,255,.11);
  --surface-subtle:rgba(13,9,24,.48);--text:#fff;--text-muted:#c9bfd8;--text-dim:#958aa8;
  --border:rgba(255,255,255,.12);--border-focus:#c59cff;--primary:#a763ff;--primary-hover:#b779ff;
  --good:#76efbe;--warn:#ffc76b;--risk:#ff8b9c;--info:#77ddef;--purple:#c68cff;
  --shadow:0 30px 90px rgba(5,0,14,.42);
}
html{background:#100b18}
body{
  padding-top:38px;min-width:320px;background:
    radial-gradient(ellipse 70% 90% at 92% 10%,rgba(122,58,208,.34),transparent 62%),
    radial-gradient(ellipse 62% 65% at 35% 105%,rgba(27,107,184,.24),transparent 66%),
    linear-gradient(145deg,#191126 0%,#100b19 48%,#1b1230 100%);
  background-attachment:fixed;font-family:"Segoe UI Variable Text","Segoe UI",sans-serif;
}
body::before{z-index:0;background:radial-gradient(circle at 75% 14%,rgba(255,255,255,.035),transparent 28%);mix-blend-mode:screen}
.window-chrome{
  position:fixed;z-index:100;inset:0 0 auto 0;height:38px;padding:0 14px;display:flex;align-items:center;gap:8px;
  color:rgba(255,255,255,.65);background:rgba(17,11,27,.9);border-bottom:1px solid rgba(255,255,255,.08);backdrop-filter:blur(26px);
  -webkit-app-region:drag;font-size:11px;
}
.traffic{display:none}
.traffic-red{background:#ff5f57}.traffic-amber{background:#ffbd2e}.traffic-green{background:#28c840}
.window-title{display:flex;align-items:center;gap:7px;font-weight:650;letter-spacing:.02em}.mini-brand{width:20px;height:20px;display:grid;place-items:center;border-radius:6px;background:linear-gradient(145deg,#c977ff,#5bc9ed);color:#fff;font-size:10px}.window-actions{height:38px;margin:-0px -14px 0 auto;display:flex;align-items:stretch;letter-spacing:0}.window-actions i{width:46px;display:grid;place-items:center;font-style:normal;font-size:12px}.window-actions i:hover{background:rgba(255,255,255,.08)}.window-actions i:last-child:hover{background:#c42b1c;color:#fff}
.wrap{position:relative;z-index:1;max-width:none;margin:0;padding:0}
.hero{
  position:fixed;z-index:30;inset:38px auto 0 0;width:238px;height:auto;margin:0;padding:27px 16px 18px;
  display:flex;flex-direction:column;align-items:stretch;gap:17px;border:0;border-right:1px solid rgba(255,255,255,.1);border-radius:0;
  background:linear-gradient(180deg,rgba(38,26,54,.88),rgba(21,15,31,.82));box-shadow:none;backdrop-filter:blur(34px);overflow-y:auto;
}
.hero::before{width:260px;height:260px;left:-130px;top:-130px;background:radial-gradient(circle,rgba(182,104,255,.16),transparent 70%)}
.hero::after{display:none}.brand{padding:0 9px}.brand h1{grid-template-columns:40px 1fr;column-gap:10px;margin:0;font-family:inherit;font-size:20px;font-weight:720}
.brand h1 .logo-icon{width:40px;height:40px;border-radius:13px;background:conic-gradient(from 210deg,#64e7ee,#5969ef,#b052ed,#ff698d,#ffbf67,#64e7ee);box-shadow:0 9px 30px rgba(144,73,224,.34)}
.brand h1 .logo-icon::before{width:17px;height:17px;border-width:3px;border-color:rgba(255,255,255,.94);box-shadow:none}
.brand h1 .version-badge{font-family:inherit;font-size:10px;letter-spacing:.04em;color:#a99db9}
.rail-nav{display:flex;flex-direction:column;gap:3px}.rail-label{padding:14px 14px 5px;color:#8f829f;font-size:10px;font-weight:720;text-transform:uppercase;letter-spacing:.11em}
.rail-item{
  min-height:42px;width:100%;padding:8px 12px;justify-content:flex-start;gap:12px;background:transparent;border:1px solid transparent;border-radius:12px;
  box-shadow:none;color:#bdb2ca;font-size:13px;font-weight:580;
}
.rail-item:hover:not(:disabled){transform:none;background:rgba(255,255,255,.06);box-shadow:none;color:#fff}
.rail-item.active{color:#fff;background:linear-gradient(100deg,rgba(191,118,255,.27),rgba(111,86,211,.12));border-color:rgba(218,181,255,.18);box-shadow:inset 3px 0 #d9adff}
.rail-icon{width:24px;height:24px;display:grid;place-items:center;border-radius:8px;color:#e2b9ff;font-size:17px;background:rgba(190,117,255,.1)}
.badges{display:flex;flex-direction:column;gap:8px;margin-top:auto}.assistant-card{display:grid;grid-template-columns:34px 1fr auto;gap:9px;align-items:center;padding:11px;background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.09);border-radius:13px;color:#f7f1ff}
.assistant-orb{width:34px;height:34px;display:grid;place-items:center;border-radius:11px;background:linear-gradient(145deg,#ca7dff,#6b68e9);box-shadow:0 8px 18px rgba(134,79,219,.25)}
.assistant-card b,.assistant-card small{display:block}.assistant-card b{font-size:11px}.assistant-card small{font-size:9px;color:#aa9dbb}.assistant-arrow{font-size:19px;color:#a99cb9}
.badge,.badge.dim{width:100%;min-height:0;padding:6px 9px;border:0;background:transparent;color:#887b98;font-size:8px;letter-spacing:.08em}.badge:first-of-type{background:transparent;border:0;color:#65dbaa}
.workspace{min-width:0;margin-left:238px;padding:28px 34px 68px;max-width:1560px}
.workspace-head{height:54px;display:flex;align-items:flex-start;justify-content:space-between;margin:0 3px 16px}.workspace-kicker{color:#9e90ae;font-size:10px;font-weight:650;letter-spacing:.08em;text-transform:uppercase}.workspace-head h1{margin:0;font-size:26px;line-height:1.15;letter-spacing:-.035em}.workspace-actions{display:flex;gap:8px}
.round-action{min-height:36px;width:36px;height:36px;padding:0;display:grid;place-items:center;border:1px solid rgba(255,255,255,.11);border-radius:50%;background:rgba(255,255,255,.055);color:#d8cde4;box-shadow:none;font-size:10px}.round-action:hover:not(:disabled){transform:none;background:rgba(255,255,255,.1);box-shadow:none}
.workspace > .panel:first-of-type{
  position:relative;margin:0;padding:0;border:1px solid rgba(255,255,255,.13);border-radius:28px;overflow:hidden;
  background:linear-gradient(135deg,rgba(99,52,139,.62),rgba(48,31,81,.88) 47%,rgba(29,22,48,.96));box-shadow:0 32px 90px rgba(4,0,15,.38);
}
.workspace > .panel:first-of-type::before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 65% 30%,rgba(192,110,255,.24),transparent 34%),radial-gradient(circle at 78% 17%,rgba(89,186,255,.14),transparent 29%);pointer-events:none}
.smart-stage{position:relative;z-index:1;min-height:275px;display:grid;grid-template-columns:minmax(330px,.85fr) minmax(370px,1.15fr);align-items:center;padding:36px 52px 18px}
.smart-copy{max-width:470px}.smart-eyebrow{display:inline-block;margin-bottom:13px;color:#e1baff;font-size:11px;font-weight:720;text-transform:uppercase;letter-spacing:.12em}.smart-copy h2{margin:0;font-size:clamp(38px,4.4vw,64px);font-weight:720;line-height:.93;letter-spacing:-.06em}.smart-copy h2 span{background:linear-gradient(90deg,#fff,#d8afff 55%,#8ee8ff);-webkit-background-clip:text;background-clip:text;color:transparent}.smart-copy p{max-width:430px;margin:20px 0 0;color:#d4c9df;font-size:14px;line-height:1.6}
.care-visual{position:relative;height:235px;display:grid;place-items:center;filter:drop-shadow(0 30px 38px rgba(5,0,20,.3))}.halo{position:absolute;border-radius:50%;border:1px solid rgba(225,192,255,.2)}.halo-one{width:224px;height:224px;box-shadow:0 0 50px rgba(195,101,255,.12),inset 0 0 50px rgba(121,105,255,.08)}.halo-two{width:170px;height:170px;border-color:rgba(131,224,255,.17);animation:carePulse 3.5s ease-in-out infinite}.care-core{position:relative;width:126px;height:126px;display:grid;place-items:center;border-radius:38px;background:linear-gradient(145deg,rgba(255,255,255,.22),rgba(105,70,177,.32));border:1px solid rgba(255,255,255,.27);box-shadow:inset 0 1px 1px rgba(255,255,255,.35),0 23px 48px rgba(40,10,78,.48);transform:rotate(-5deg)}
.windows-mark{width:56px;height:56px;display:grid;grid-template-columns:1fr 1fr;gap:4px;transform:rotate(5deg)}.windows-mark i{display:block;background:linear-gradient(145deg,#c4fbff,#66d1ff 60%,#7d78ff);box-shadow:0 0 16px rgba(100,219,255,.45)}.spark{position:absolute;color:#f3d8ff;text-shadow:0 0 14px currentColor}.spark-a{left:18%;top:23%;font-size:22px}.spark-b{right:18%;bottom:21%;font-size:17px;color:#85eaff}.spark-c{right:24%;top:16%;font-size:24px;color:#ffb5dd}
@keyframes carePulse{50%{transform:scale(1.07);opacity:.6}}
.care-strip{position:relative;z-index:1;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:9px;padding:0 28px 22px}
.care-tile{min-width:0;min-height:74px;display:grid;grid-template-columns:36px 1fr;align-items:center;gap:9px;padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:16px;background:rgba(16,10,29,.31);backdrop-filter:blur(18px);box-shadow:inset 0 1px rgba(255,255,255,.05)}
.care-tile-icon{width:36px;height:36px;display:grid;place-items:center;border-radius:12px;font-size:20px;background:rgba(255,255,255,.1)}.care-tile b,.care-tile small{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.care-tile b{font-size:11px}.care-tile small{color:#b9acc7;font-size:9px}.care-tile em{grid-column:2;color:#bfb1cb;font-size:8px;font-style:normal;text-transform:uppercase;letter-spacing:.1em;margin-top:-13px}.cleanup .care-tile-icon{color:#8eeeff;background:rgba(73,211,234,.12)}.protection .care-tile-icon{color:#83e8b8;background:rgba(75,220,157,.12)}.performance .care-tile-icon{color:#ffd17f;background:rgba(255,191,84,.12)}.applications .care-tile-icon{color:#ff98c8;background:rgba(255,95,169,.12)}.clutter .care-tile-icon{color:#c39cff;background:rgba(170,101,255,.14)}
.setup-label{position:relative;z-index:1;display:flex;justify-content:space-between;padding:16px 30px 8px;border-top:1px solid rgba(255,255,255,.09);color:#eee6f5;font-size:11px;font-weight:650}.setup-label span:last-child{color:#978aa5;font-weight:500}
.controls{position:relative;z-index:1;display:grid;grid-template-columns:minmax(250px,2fr) minmax(160px,.72fr) minmax(155px,.7fr) 92px auto;gap:10px;align-items:end;padding:0 28px 25px}
.controls::before{display:none}.controls .field label{color:#9e91ad;font-size:8px;letter-spacing:.12em}.controls .field input,.controls .field select{min-height:44px;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(11,7,21,.42);color:#fff}.controls .field input:hover,.controls .field select:hover{border-color:rgba(211,168,255,.36)}
.quick-chips{display:none}#rootHelp{display:none}#scan{width:76px;height:76px;min-height:76px;margin-bottom:-15px;padding:0;align-self:end;justify-content:center;flex-direction:column;gap:3px;border:1px solid rgba(255,255,255,.38);border-radius:50%;background:linear-gradient(145deg,#c977ff,#8752ee);box-shadow:0 15px 38px rgba(132,67,226,.42),inset 0 1px 2px rgba(255,255,255,.44);font-size:11px}#scan:hover:not(:disabled){transform:scale(1.04);background:linear-gradient(145deg,#d68bff,#9565f2);box-shadow:0 18px 45px rgba(132,67,226,.52)}.scan-play{font-size:17px;margin-left:3px}#cancel{min-height:38px;margin-bottom:4px;padding:8px 11px;border-radius:10px;font-size:10px}
.workspace > .panel:first-of-type .advanced{position:relative;z-index:1;margin:0;padding:13px 29px 20px;border-top:1px solid rgba(255,255,255,.08);background:rgba(9,6,17,.2)}.advanced summary{color:#b5a8c3;font-size:11px}
.monitor-card{position:relative;min-height:0;margin:18px 0;padding:24px;border:1px solid rgba(255,255,255,.11);border-radius:24px;background:linear-gradient(145deg,rgba(43,31,59,.92),rgba(24,18,36,.94));box-shadow:0 24px 70px rgba(4,0,13,.28);overflow:hidden}.monitor-card::before{content:"";position:absolute;left:auto;right:-80px;top:-130px;width:330px;height:330px;border:0;border-radius:50%;background:radial-gradient(circle,rgba(158,88,242,.18),transparent 66%);box-shadow:none;animation:none}.monitor-card::after{display:none}.monitor-card:has(.status-pill.running)::before,.monitor-card:has(.status-pill.done)::before{animation:none;box-shadow:none}.monitor-top{position:relative;padding-bottom:17px;border-color:rgba(255,255,255,.09)}.status-pill{border-color:rgba(255,255,255,.1)!important;background:rgba(255,255,255,.07)!important}.status-pill.running{color:#d9b2ff!important}.status-pill.done{color:#7be7b7!important}.metric-box{border-color:rgba(255,255,255,.09);background:rgba(10,6,18,.3)}
.stepper{grid-template-columns:repeat(7,minmax(112px,1fr));gap:7px}.step-node{background:rgba(12,8,22,.35);border-color:rgba(255,255,255,.09)}.step-node.active{border-color:rgba(207,146,255,.47);background:rgba(166,93,240,.12);box-shadow:0 0 20px rgba(163,92,238,.1)}.step-node.completed{border-color:rgba(103,223,169,.28);background:rgba(103,223,169,.06)}.progress{background:rgba(7,4,14,.55);border-color:rgba(255,255,255,.08)}.progress>i{background:linear-gradient(90deg,#a657ef,#d177ff,#79dff0)}.progress-pct{color:#deb4ff}.reassurance-note{background:rgba(130,95,211,.1);border-color:rgba(190,145,255,.22);color:#e4d2f5}.activity-card{background:rgba(8,5,15,.34);border-color:rgba(255,255,255,.08)}.activity-header{border-color:rgba(255,255,255,.08)}
#summary > .panel:first-of-type{background:rgba(37,26,52,.9)}#summary > .panel:last-of-type{background:rgba(27,20,40,.94)}.tabs{background:rgba(18,13,28,.76);border-color:rgba(255,255,255,.09)}.tab.active{background:linear-gradient(90deg,rgba(191,118,255,.19),rgba(104,98,224,.08));border-color:rgba(205,158,255,.25);box-shadow:inset 3px 0 #ce9cff}.tab:hover{background:rgba(255,255,255,.06)}.metric,.brief-main,.brief-next,.scope-band,.depth-card,.plan-lane,.plan-item,.chart,.cat-section,.finding-card,.overview-cat-card,.comparebox,.dupcard,.tablewrap,.collector{border-color:rgba(255,255,255,.1);background:rgba(35,25,49,.86)}
@media(max-width:1180px){.smart-stage{grid-template-columns:1fr 1fr;padding-left:34px;padding-right:34px}.care-strip{grid-template-columns:repeat(3,1fr)}.controls{grid-template-columns:1fr 1fr 1fr}.controls #scan{grid-row:2}.controls #cancel{grid-row:2}.workspace{padding-left:24px;padding-right:24px}}
@media(max-width:820px){body{padding-top:34px}.window-chrome{height:34px}.hero{position:relative;inset:auto;width:auto;min-height:0;margin:0;padding:13px 16px;flex-direction:row;align-items:center;border-right:0;border-bottom:1px solid rgba(255,255,255,.1);overflow-x:auto}.brand{padding:0}.brand h1{grid-template-columns:34px auto}.brand h1 .logo-icon{width:34px;height:34px}.brand h1 .version-badge,.rail-label,.badges{display:none}.rail-nav{margin-left:auto;flex-direction:row}.rail-item{width:auto;min-height:36px;padding:6px 9px}.rail-item span:last-child{display:none}.rail-icon{width:23px;height:23px}.workspace{margin-left:0;padding:18px 14px 45px}.workspace-head{height:46px}.smart-stage{grid-template-columns:1fr;min-height:0;padding:32px 25px 12px}.smart-copy{text-align:center;margin:auto}.smart-copy h2{font-size:43px}.care-visual{height:205px}.care-strip{grid-template-columns:1fr 1fr;padding:0 16px 18px}.care-tile:last-child{grid-column:1/-1}.controls{grid-template-columns:1fr;padding:0 17px 24px}.controls #scan{grid-row:auto;margin:5px auto 0}.controls #cancel{grid-row:auto;margin:auto}.setup-label{padding-left:18px;padding-right:18px}.setup-label span:last-child{display:none}.monitor-card{padding:20px}.stepper{grid-template-columns:repeat(7,120px)}}
@media(max-width:480px){.workspace-actions{display:none}.smart-copy h2{font-size:37px}.care-strip{grid-template-columns:1fr}.care-tile:last-child{grid-column:auto}.care-visual{transform:scale(.88);margin:-10px 0}.workspace > .panel:first-of-type{border-radius:21px}.monitor-card{border-radius:20px}.rail-item:nth-of-type(n+4){display:none}}
/* Unified module workspace */
:root{--surface-subtle:#211d32;--border:rgba(201,189,230,.12);--primary:#a982f4;--primary-hover:#bc9bff}
body{background:radial-gradient(ellipse at 95% 0%,#302043 0%,transparent 50%),#15121e}
.window-chrome{display:none}body{padding-top:0}.hero{top:0;width:216px;background:#191522;padding:24px 13px}.workspace{margin-left:216px;padding:26px 30px 46px;max-width:1600px}.brand h1{font-size:18px}.rail-item{min-height:43px}.rail-icon{background:transparent}.rail-item.active{background:#352747;border-color:transparent;box-shadow:inset 3px 0 #c6a2fc}.assistant-card{text-align:left;white-space:normal;box-shadow:none;min-height:64px}.workspace-head{height:52px;margin-bottom:18px}.workspace-kicker{font-size:9px}.workspace-head h1{font-size:25px;margin-top:4px}.workspace-actions button{min-height:36px;font-size:11px}
#scanComposer{background:radial-gradient(ellipse at 80% 0%,rgba(163,113,233,.16),transparent 65%),#262033;border-radius:20px;padding:0;overflow:hidden;border-color:rgba(209,188,239,.13)}
.smart-stage{min-height:230px;padding:28px 36px 20px;grid-template-columns:1.2fr .8fr}.smart-copy h2{font-size:44px;line-height:1.02;letter-spacing:-.045em}.smart-copy p{font-size:13px;margin-top:16px;max-width:410px}.smart-eyebrow{font-size:9px;margin-bottom:12px}.care-visual{height:180px}.halo-one{width:176px;height:176px}.halo-two{width:137px;height:137px}.care-core{width:99px;height:99px;border-radius:28px}.windows-mark{width:45px;height:45px}.care-strip{padding:0 24px 24px;gap:10px}.care-tile{cursor:pointer;min-height:92px;padding:14px;background:rgba(255,255,255,.035);transition:background .2s,border-color .2s}.care-tile:hover{background:rgba(182,137,243,.12);border-color:#a982f4}.care-tile b{font-size:12px}.care-tile small{font-size:10px}.care-tile em{display:none}.care-tile-icon{height:37px;width:37px}.controls{grid-template-columns:minmax(220px,1.5fr) minmax(190px,1fr) minmax(160px,.8fr) auto auto;padding:5px 24px 20px;align-items:end}.controls .field label{font-size:9px}.controls .field select{padding-right:28px}#scan{width:auto;height:44px;min-height:44px;padding:10px 23px;margin:0;flex-direction:row;border-radius:12px;font-size:13px;box-shadow:0 6px 20px rgba(117,71,180,.25)}#cancel{margin:0;min-height:44px}.setup-label{padding:16px 25px 7px}.monitor-card{padding:20px;border-radius:18px;background:#221c2e}.stepper-wrap{margin-top:14px}.step-node{min-width:112px}.monitor-card::before{display:none!important}.monitor-top{gap:12px}.monitor-metrics{flex-wrap:wrap}.metric-box{font-size:10px}.monitor-metrics #profileHint{font-size:10px;max-width:240px}
.module-banner{display:flex;align-items:center;gap:20px;padding:23px 26px;border:1px solid var(--border);border-radius:18px;background:linear-gradient(110deg,#362747,#252035);margin-bottom:18px}.module-symbol{display:grid;place-items:center;flex:none;width:64px;height:64px;background:linear-gradient(145deg,#a978e0,#55467d);border-radius:20px;font-size:34px;color:#f2e6ff;box-shadow:inset 0 1px rgba(255,255,255,.2)}.module-banner h2{font-size:21px;margin:0 0 4px}.module-banner p{margin:0;color:#bcb1cf;font-size:13px}.module-banner button{margin-left:auto;font-size:11px}.module-empty{min-height:360px;padding:60px 24px;text-align:center;border:1px solid var(--border);border-radius:18px;background:#221c2e}.module-empty h2{font-size:24px;font-weight:650;margin:24px 0 10px}.module-empty p{max-width:420px;margin:0 auto 25px;color:var(--text-muted);font-size:13px}.empty-orbit{width:88px;height:88px;border-radius:28px;display:grid;place-items:center;margin:auto;background:linear-gradient(135deg,#554066,#272238);border:1px solid #715283;font-size:42px;color:#dcb9ff}
#summary{margin-top:18px}#summary > .grid{grid-template-columns:repeat(3,1fr)}.metric{min-height:95px;border-radius:14px;background:#272132}.metric b{font-family:inherit;font-size:23px}#summary > .panel:last-of-type{display:block;border-radius:18px;background:#211b2b}.tabs{position:static;flex-direction:row;flex-wrap:wrap;max-height:none;padding:12px;border:0;border-bottom:1px solid var(--border);background:rgba(0,0,0,.12);gap:5px}.tabs::before{display:none}.tab{width:auto;min-height:36px;padding:7px 13px}.tab:nth-child(n){margin:0;border-top-color:transparent}.tab.active{box-shadow:none;background:#423051;border-color:#69497e}.tab-count{background:rgba(255,255,255,.06);color:#c4b2d7;margin-left:5px}#view{padding:25px}.decision-number,.depth-meta,.plan-item-path,.plan-explain div,.finding-path-bar,.explain-card{background:#211b2d;border-color:var(--border)}th{background:#30263f;color:#c9bfd8}.bar,.diskbar{background:#393044}.bar i,.diskbar i{background:linear-gradient(90deg,#a781ef,#82cfde)}button{background:#986cdc;box-shadow:none}button:hover:not(:disabled){background:#ae85ea;box-shadow:none}.chart,.brief-main,.brief-next,.depth-card{background:#292133;border-color:var(--border)}
body[data-page="settings"] .smart-stage,body[data-page="settings"] .care-strip{display:none}body[data-page="settings"] #scanComposer .advanced{padding:22px 26px}body[data-page="settings"] .quick-chips{display:flex}.workspace > #moduleIntro + #scanComposer .advanced{border-top-color:var(--border)}
@media(max-width:1150px){.controls{grid-template-columns:1fr 1fr}.controls #scan,.controls #cancel{grid-row:auto}.care-strip{grid-template-columns:repeat(3,1fr)}.monitor-status{flex-wrap:wrap}.monitor-top{align-items:flex-start}.module-banner{flex-wrap:wrap}.module-banner button{margin-left:84px}}
@media(max-width:820px){.hero{position:relative;top:auto;width:auto;display:block;padding:14px}.brand{margin-bottom:14px}.rail-nav{display:flex;flex-direction:row;flex-wrap:wrap;margin:0;gap:5px}.rail-label{display:none}.rail-item{width:auto;min-height:35px;gap:5px;padding:6px 9px;font-size:11px}.rail-item span:last-child{display:inline}.rail-item:nth-of-type(n){display:flex}.badges{display:flex;flex-direction:row;margin-top:9px}.badges .assistant-card,.badges .badge{display:none}.workspace{margin:0;padding:20px 14px}.smart-stage{grid-template-columns:1fr auto;padding:26px;gap:10px}.smart-copy h2{font-size:33px}.smart-copy{text-align:left}.care-visual{width:145px;transform:scale(.8)}.care-strip{grid-template-columns:1fr 1fr}.controls{grid-template-columns:1fr 1fr}.controls .field:first-child{grid-column:1/-1}.controls #scan,.controls #cancel{width:100%;margin:0}.workspace-actions{display:flex}#summary > .grid{grid-template-columns:1fr 1fr}.module-banner button{margin:0}.module-banner p{font-size:12px}#view{padding:18px}}
@media(max-width:480px){.care-visual{display:none}.smart-stage{grid-template-columns:1fr}.care-tile{grid-template-columns:1fr;gap:8px}.care-tile small{white-space:normal}.controls{grid-template-columns:1fr}.controls .field:first-child{grid-column:auto}.care-strip .care-tile:last-child{grid-column:1/-1;grid-template-columns:37px 1fr}.workspace-kicker{display:none}.workspace-head{height:auto;align-items:center}.workspace-head h1{margin:0}.workspace-actions button{font-size:10px;padding:8px 12px}#summary > .grid{grid-template-columns:1fr}.module-symbol{width:46px;height:46px;border-radius:14px;font-size:26px}.module-banner{padding:18px;gap:12px}.module-banner div{flex:1}.module-banner button{width:100%;justify-content:center}}
#scanComposer .advanced{margin:0;padding:14px 25px 20px;border-top:1px solid var(--border);background:rgba(0,0,0,.08)}
#scanComposer .advanced summary{width:auto;font-size:11px}
#scanComposer .advanced .field textarea{background:#1b1625;border-color:var(--border)}

/* CleanMyMac Desktop Hub Extensions */
.hub-hero{display:grid;grid-template-columns:auto 1fr auto;gap:20px;align-items:center;padding:24px 28px;border:1px solid var(--border);border-radius:20px;background:linear-gradient(135deg,rgba(169,130,244,.12),rgba(37,32,51,.95));margin-bottom:20px}
.hub-orb{width:64px;height:64px;border-radius:20px;display:grid;place-items:center;font-size:32px;background:linear-gradient(135deg,#b279f0,#6752a3);color:#fff;box-shadow:0 8px 24px rgba(178,121,240,.3)}
.hub-hero h2{margin:0 0 4px;font-size:22px;font-weight:750}
.hub-hero p{margin:0;color:var(--text-muted);font-size:13px;max-width:700px}
.hub-metrics{display:flex;gap:16px;text-align:right}
.hub-metric-val{font-size:22px;font-weight:800;color:var(--text);font-variant-numeric:tabular-nums;display:block}
.hub-metric-lbl{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em}
.hub-card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin:18px 0}
.hub-card{background:#231c2e;border:1px solid var(--border);border-radius:16px;padding:20px;display:flex;flex-direction:column;justify-content:space-between;gap:12px;transition:all .18s}
.hub-card:hover{border-color:var(--primary);transform:translateY(-2px);box-shadow:0 8px 26px rgba(0,0,0,.25)}
.hub-card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.hub-card-title{font-size:15px;font-weight:750;display:flex;align-items:center;gap:8px;color:var(--text)}
.hub-card-desc{font-size:12px;color:var(--text-muted);line-height:1.45;margin:4px 0}
.recipe-box{background:#171221;border:1px solid var(--border);border-radius:10px;padding:10px 12px;display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:6px}
.recipe-code{font-family:Consolas,monospace;font-size:11.5px;color:#c9bfd8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}
.perm-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.perm-badge{background:rgba(255,255,255,.05);border:1px solid var(--border);padding:3px 9px;border-radius:8px;font-size:11px;color:#d8cde4;display:inline-flex;align-items:center;gap:5px}
.lens-tree{display:flex;flex-direction:column;gap:8px;margin-top:14px}
.lens-row{display:grid;grid-template-columns:220px 1fr 100px;align-items:center;gap:14px;background:#231c2e;border:1px solid var(--border);border-radius:12px;padding:12px 16px;cursor:pointer;transition:border-color .15s}
.lens-row:hover{border-color:var(--primary);background:#2b2238}
.lens-bar-wrap{height:8px;border-radius:99px;background:#171221;overflow:hidden}
.lens-bar{height:100%;border-radius:inherit;background:linear-gradient(90deg,#a781ef,#68dce5)}
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 16px;align-items:center}
.filter-btn{background:#231c2e;border:1px solid var(--border);color:var(--text-muted);padding:6px 14px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;transition:all .15s}
.filter-btn:hover{color:var(--text);border-color:var(--primary)}
.filter-btn.active{background:#3d2954;border-color:#b279f0;color:#fff}
.pillar-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}
.pillar-card{background:linear-gradient(145deg,#261e33,#1d1727);border:1px solid var(--border);border-radius:18px;padding:20px;display:flex;flex-direction:column;gap:12px;cursor:pointer;transition:all .2s}
.pillar-card:hover{border-color:var(--primary);transform:translateY(-2px);box-shadow:0 10px 30px rgba(0,0,0,.3)}
.pillar-head{display:flex;justify-content:space-between;align-items:center}
.pillar-icon{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;font-size:22px;background:rgba(255,255,255,.06)}
.cleanup-pillar .pillar-icon{background:rgba(110,238,255,.12);color:#6eeeff}
.protection-pillar .pillar-icon{background:rgba(118,239,190,.12);color:#76efbe}
.performance-pillar .pillar-icon{background:rgba(255,209,127,.12);color:#ffd17f}
.applications-pillar .pillar-icon{background:rgba(255,152,200,.12);color:#ff98c8}
.pillar-title{font-size:16px;font-weight:750;color:var(--text);margin:0}
.pillar-sub{font-size:12px;color:var(--text-muted);line-height:1.4}
.pillar-metric{font-size:20px;font-weight:800;color:var(--good);margin-top:auto}
@media(max-width:1100px){.pillar-grid{grid-template-columns:1fr 1fr}.hub-hero{grid-template-columns:1fr}.hub-metrics{text-align:left}}
@media(max-width:650px){.pillar-grid{grid-template-columns:1fr}.lens-row{grid-template-columns:1fr;gap:6px}}
</style>
</head>
<body>
<div class="window-chrome" aria-hidden="true">
  <span class="traffic traffic-red"></span>
  <span class="traffic traffic-amber"></span>
  <span class="traffic traffic-green"></span>
  <span class="window-title"><span class="mini-brand">✦</span> ReconSpace</span>
  <span class="window-actions"><i>—</i><i>□</i><i>×</i></span>
</div>
<div class="wrap">

<header class="hero">
  <div class="brand">
    <h1>
      <span class="logo-icon" aria-hidden="true"></span>
      <span>ReconSpace</span>
      <span class="version-badge">v__VERSION__ · UI 2026.10.02</span>
    </h1>
  </div>
  <nav class="rail-nav" aria-label="Main navigation">
    <span class="rail-label">Care</span>
    <button type="button" class="rail-item active" data-page="home"><span class="rail-icon">✦</span><span>Smart Audit</span></button>
    <button type="button" class="rail-item" data-page="cleanup"><span class="rail-icon">⌁</span><span>Cleanup</span></button>
    <button type="button" class="rail-item" data-page="protection"><span class="rail-icon">◇</span><span>Protection</span></button>
    <button type="button" class="rail-item" data-page="performance"><span class="rail-icon">↯</span><span>Performance</span></button>
    <span class="rail-label">Manage</span>
    <button type="button" class="rail-item" data-page="applications"><span class="rail-icon">▦</span><span>Applications</span></button>
    <button type="button" class="rail-item" data-page="clutter"><span class="rail-icon">◌</span><span>My Clutter</span></button>
    <button type="button" class="rail-item" data-page="reports"><span class="rail-icon">▤</span><span>Reports</span></button>
  </nav>
  <div class="badges">
    <button type="button" class="assistant-card" data-page="reports"><span class="assistant-orb">✦</span><span><b>Review your PC</b><small>Evidence &amp; action plan</small></span><span class="assistant-arrow">›</span></button>
    <span class="badge">● READ-ONLY ENGINE</span>
    <button type="button" class="rail-item" data-page="settings"><span class="rail-icon">⚙</span><span>Scan settings</span></button>
  </div>
</header>

<main class="workspace">
<div class="workspace-head">
  <div>
    <span class="workspace-kicker">Windows care, made clear</span>
    <h1 id="pageTitle">Smart Audit</h1>
  </div>
  <div class="workspace-actions"><button type="button" class="secondary" data-page="settings">Scan settings</button></div>
</div>

<div id="moduleIntro" class="hidden"></div>
<div class="panel" id="scanComposer">
  <div class="smart-stage">
    <div class="smart-copy">
      <span class="smart-eyebrow">One scan. The full picture.</span>
      <h2>Give your PC<br><span>a fresh start.</span></h2>
      <p>ReconSpace checks storage, safety, performance, applications, and clutter in one thoughtful pass.</p>
    </div>
    <div class="care-visual" aria-hidden="true">
      <div class="halo halo-one"></div><div class="halo halo-two"></div>
      <div class="care-core"><span class="windows-mark"><i></i><i></i><i></i><i></i></span></div>
      <span class="spark spark-a">✦</span><span class="spark spark-b">✧</span><span class="spark spark-c">•</span>
    </div>
  </div>
  <div class="care-strip" aria-label="Smart Audit coverage">
    <div class="care-tile cleanup"><span class="care-tile-icon">⌁</span><span><b>Cleanup</b><small>Files &amp; storage</small></span><em>Ready</em></div>
    <div class="care-tile protection"><span class="care-tile-icon">◇</span><span><b>Protection</b><small>Trust &amp; security</small></span><em>Ready</em></div>
    <div class="care-tile performance"><span class="care-tile-icon">↯</span><span><b>Performance</b><small>Processes &amp; startup</small></span><em>Ready</em></div>
    <div class="care-tile applications"><span class="care-tile-icon">▦</span><span><b>Applications</b><small>Installed software</small></span><em>Ready</em></div>
    <div class="care-tile clutter"><span class="care-tile-icon">◌</span><span><b>My Clutter</b><small>Large &amp; duplicate files</small></span><em>Ready</em></div>
  </div>
  <div class="setup-label"><span>Choose what to scan</span><span>Everything stays on this PC</span></div>
  <div class="controls">
    <div class="field">
      <label for="root">Scan root</label>
      <input id="root" type="text" value="C:\" spellcheck="false" autocomplete="off" aria-describedby="rootHelp" />
      <div class="quick-chips">
        <span class="chip" onclick="setRoot('C:\\')">C:\</span>
        <span class="chip" onclick="setRoot('D:\\')">D:\</span>
        <span class="chip" onclick="setRoot('%USERPROFILE%')">%USERPROFILE%</span>
        <span class="chip" onclick="setRoot('%LOCALAPPDATA%')">%LOCALAPPDATA%</span>
        <span class="chip" onclick="setRoot('%PROGRAMDATA%')">%PROGRAMDATA%</span>
      </div>
      <div id="rootHelp" class="small" style="margin-top:4px">Local drive or directory to inspect.</div>
    </div>
    <div class="field">
      <label for="profile">Profile</label>
      <select id="profile">
        <option value="quick">Quick (fast triage)</option>
        <option value="standard">Standard (balanced)</option>
        <option value="deep" selected>Deep (recommended)</option>
        <option value="forensics">Forensics (full evidence)</option>
      </select>
    </div>
    <div class="field">
      <label for="dupmin">Duplicate threshold</label>
      <select id="dupmin">
        <option value="">Profile default</option>
        <option value="32">32 MB</option>
        <option value="64">64 MB</option>
        <option value="128">128 MB</option>
        <option value="256">256 MB</option>
        <option value="512">512 MB</option>
        <option value="1024">1 GB</option>
      </select>
    </div>
    <button id="scan" type="button"><span class="scan-play">▶</span><span>Scan</span></button>
    <button id="cancel" type="button" class="dangerish" disabled>Cancel scan</button>
  </div>

  <details class="advanced">
    <summary>Advanced scope and evidence controls</summary>
    <div class="twocol" style="margin-top:10px">
      <div class="field">
        <label for="exclude">Explicit exclusions — one absolute path per line</label>
        <textarea id="exclude" spellcheck="false" placeholder="Leave empty for full reachable-root reconnaissance"></textarea>
        <div class="small">Excluded paths receive no scan coverage and are recorded as a limitation.</div>
      </div>
      <div class="field">
        <label for="keep">Protected / keep paths — one absolute path per line</label>
        <textarea id="keep" spellcheck="false" placeholder="Keep visible, but count no reclaimable bytes"></textarea>
        <div class="small">Findings remain visible; reclaim accounting is zeroed and safe labels are downgraded.</div>
      </div>
    </div>
    <div class="field" style="margin-top:10px">
      <label for="rulePacks">Additional JSON rule packs — one local absolute path per line</label>
      <textarea id="rulePacks" spellcheck="false" placeholder="Optional metadata-only rule packs"></textarea>
      <div class="small">Rule packs are validated JSON match rules. They cannot execute code or commands.</div>
    </div>
    <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:12px;color:var(--muted);font-size:12px">
      <label><input id="statefulHash" type="checkbox" style="width:auto;margin-right:7px">Hash VM/forensic/dump files for duplicates</label>
      <label><input id="signatureHashes" type="checkbox" style="width:auto;margin-right:7px">SHA-256 selected persistence binaries</label>
      <label><input id="noSignatures" type="checkbox" style="width:auto;margin-right:7px">Skip Authenticode evidence</label>
      <label><input id="noPermissions" type="checkbox" style="width:auto;margin-right:7px">Skip owner/ACL evidence</label>
      <label><input id="noProcesses" type="checkbox" style="width:auto;margin-right:7px">Skip active processes</label>
      <label><input id="noPrefetch" type="checkbox" style="width:auto;margin-right:7px">Skip Prefetch metadata</label>
    </div>
  </details>
</div>

<!-- Live Audit Execution Monitor (Always Visible & Informative) -->
<div class="monitor-card" id="liveMonitor">
  <div class="monitor-top">
    <div class="monitor-status">
      <span id="statusPill" class="status-pill idle">
        <span class="pulse-dot"></span>
        <span id="statusBadgeText">Ready</span>
      </span>
      <div class="status" style="margin:0">
        <span id="status" role="status" aria-live="polite">Idle — ready to audit.</span>
      </div>
    </div>
    <div class="monitor-metrics">
      <div class="metric-box">
        <span>⏱ Elapsed:</span>
        <b id="elapsedTimer">00:00</b>
      </div>
      <div class="metric-box">
        <span id="heartbeatDot" class="pulse-heartbeat"></span>
        <span id="heartbeatText">Engine Standby</span>
      </div>
      <div id="profileHint" class="small"></div>
    </div>
  </div>

  <!-- 7-Stage Visual Pipeline Stepper -->
  <div class="stepper-wrap">
    <div class="stepper-title">Audit Pipeline Stages</div>
    <div class="stepper" id="pipelineStepper">
      <div class="step-node pending" id="step-0">
        <div class="step-header"><span class="step-idx">1/7</span><span class="step-badge">Pending</span></div>
        <div class="step-name">Filesystem</div>
        <div class="step-desc">Directory tree & metadata</div>
      </div>
      <div class="step-node pending" id="step-1">
        <div class="step-header"><span class="step-idx">2/7</span><span class="step-badge">Pending</span></div>
        <div class="step-name">Duplicates</div>
        <div class="step-desc">Fingerprints & projects</div>
      </div>
      <div class="step-node pending" id="step-2">
        <div class="step-header"><span class="step-idx">3/7</span><span class="step-badge">Pending</span></div>
        <div class="step-name">Applications</div>
        <div class="step-desc">Installed apps & startup</div>
      </div>
      <div class="step-node pending" id="step-3">
        <div class="step-header"><span class="step-idx">4/7</span><span class="step-badge">Pending</span></div>
        <div class="step-name">System Deep</div>
        <div class="step-desc">41 Windows collectors</div>
      </div>
      <div class="step-node pending" id="step-4">
        <div class="step-header"><span class="step-idx">5/7</span><span class="step-badge">Pending</span></div>
        <div class="step-name">Processes</div>
        <div class="step-desc">Process context & owner</div>
      </div>
      <div class="step-node pending" id="step-5">
        <div class="step-header"><span class="step-idx">6/7</span><span class="step-badge">Pending</span></div>
        <div class="step-name">Code Trust</div>
        <div class="step-desc">Signatures & ACL security</div>
      </div>
      <div class="step-node pending" id="step-6">
        <div class="step-header"><span class="step-idx">7/7</span><span class="step-badge">Pending</span></div>
        <div class="step-name">Ownership</div>
        <div class="step-desc">Correlation & review plan</div>
      </div>
    </div>
  </div>

  <!-- Progress Bar -->
  <div class="progress-container">
    <div class="progress-labels">
      <span id="activeDetailText" class="progress-detail">Ready to start audit</span>
      <span id="progressPct" class="progress-pct">0%</span>
    </div>
    <div id="progress" class="progress" role="progressbar" aria-label="Audit progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
      <i id="progressBar"></i>
    </div>
  </div>

  <div id="reassuranceNote" class="reassurance-note hidden"></div>

  <!-- Real-time Event Console Feed -->
  <div class="activity-card">
    <details id="activityDetails">
      <summary class="activity-header">
        <span>LIVE ACTIVITY STREAM (CLICK TO TOGGLE)</span>
        <span id="activityCount">0 events logged</span>
      </summary>
      <div class="activity-feed" id="activityFeed">
        <div class="activity-row"><span class="t">[00:00]</span><span class="m">ReconSpace engine ready. Select scan root and click Start Audit.</span></div>
      </div>
    </details>
  </div>
</div>

<div id="error" class="panel notice error hidden" role="alert"></div>

<div id="summary" class="hidden">
  <div class="grid" id="metrics"></div>

  <div class="panel" style="margin-top:14px">
    <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
      <div>
        <b style="font-size:16px">Audit Results &amp; Intelligence</b>
        <div class="small">Recommendations are evidence, not authorization. Reclaimable estimates still require manual review and approval.</div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="secondary" id="exportPlan">Export approval plan (.md)</button>
        <button class="secondary" id="export">Export report JSON</button>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="tabs" role="tablist" aria-label="Audit result sections" aria-orientation="vertical">
      <button type="button" class="tab active" role="tab" aria-selected="true" data-view="overview">Overview</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="cleanup_hub">Cleanup Hub</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="protection_hub">Protection Hub</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="performance_hub">Performance Hub</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="applications_hub">Applications Hub</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="clutter_hub">My Clutter Hub</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="plan">Action plan <span class="tab-count" id="count-plan">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="findings">Findings <span class="tab-count" id="count-findings">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="dirs">Folders <span class="tab-count" id="count-dirs">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="files">Files <span class="tab-count" id="count-files">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="duplicates">Duplicates <span class="tab-count" id="count-duplicates">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="tooling">Dev / cyber <span class="tab-count" id="count-tooling">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="apps">Applications <span class="tab-count" id="count-apps">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="ownership">Ownership <span class="tab-count" id="count-ownership">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="processes">Processes <span class="tab-count" id="count-processes">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="trust">Trust <span class="tab-count" id="count-trust">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="permissions">Permissions <span class="tab-count" id="count-permissions">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="startup">Startup <span class="tab-count" id="count-startup">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="services">Services <span class="tab-count" id="count-services">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="tasks">Tasks <span class="tab-count" id="count-tasks">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="health">Coverage</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="system">System inventory <span class="tab-count" id="count-system">0</span></button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="compare">Compare</button>
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="notes">Safety</button>
    </div>
    <div id="view" role="tabpanel" aria-labelledby="audit-tab-overview" tabindex="0"></div>
  </div>
</div>

</main>
</div>

<script>
const PROFILE_DEFAULTS=__PROFILES__;
const token=new URLSearchParams(location.search).get('token')||'';
if(token)history.replaceState(null,'',location.pathname);
let REPORT=null,currentView='overview',previousReport=null,pollFailures=0;
let currentPage='home';
const PAGES={
 home:{title:'Smart Audit',icon:'✦',description:'A clear picture of your PC, in one scan.',views:['overview','plan','health']},
 cleanup:{title:'Cleanup',icon:'⌁',description:'Find storage candidates and understand what can be reviewed for cleanup.',views:['cleanup_hub','findings','dirs','files','tooling']},
 protection:{title:'Protection',icon:'◇',description:'Inspect publisher signatures, permissions, and persistence evidence.',views:['protection_hub','trust','permissions','startup','services','tasks']},
 performance:{title:'Performance',icon:'↯',description:'See running processes and what starts with Windows.',views:['performance_hub','processes','startup','services','tasks']},
 applications:{title:'Applications',icon:'▦',description:'Explore installed software and the files associated with each application.',views:['applications_hub','apps','ownership']},
 clutter:{title:'My Clutter',icon:'◌',description:'Review exact duplicates, large files, and folders taking up space.',views:['clutter_hub','duplicates','files','dirs']},
 reports:{title:'Reports',icon:'▤',description:'Review recommendations, inspect coverage, compare reports, and export your evidence.',views:['plan','health','system','compare','notes','overview']},
 settings:{title:'Scan settings',icon:'⚙',description:'Choose a scan root, depth, exclusions, and evidence options.',views:[]}
};
function getPreScanHub(name){
  if(name==='cleanup'){
    return `<div style="margin-top:20px">
      <div class="hub-hero">
        <div class="hub-orb">⌁</div>
        <div>
          <h2>System &amp; Application Cleanup</h2>
          <p>Scan caches, package managers, development artifacts, and disposable files safely with zero destructive deletes.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🗂 System Cache &amp; Temp</div></div>
          <div class="hub-card-desc">Audit Windows temp, Delivery Optimization, crash dumps, and SoftwareDistribution downloads.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🌐 Browser &amp; App Data</div></div>
          <div class="hub-card-desc">Inspect Chrome, Edge, Brave, and Firefox cache directories and profile footprints.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">📦 Developer &amp; Build Caches</div></div>
          <div class="hub-card-desc">Identify node_modules, Python venvs, pip/npm/cargo caches, and Docker artifacts.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='protection'){
    return `<div style="margin-top:20px">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#5dd39e,#348aa7)">◇</div>
        <div>
          <h2>Windows Security &amp; Privacy Health</h2>
          <p>Audit Microsoft Defender status, background app hardware permissions (webcam, mic, location), and unsigned binaries.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🛡 Microsoft Defender Audit</div></div>
          <div class="hub-card-desc">Inspect real-time protection, signature definition age, and threat detection history.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🎙 Privacy &amp; ConsentStore</div></div>
          <div class="hub-card-desc">Audit Windows CapabilityAccessManager consent permissions for webcam, microphone, and location.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🔐 Publisher Trust Verification</div></div>
          <div class="hub-card-desc">Verify Authenticode digital signatures on active binaries and detect unsigned execution.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='performance'){
    return `<div style="margin-top:20px">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#ffd166,#ef476f)">↯</div>
        <div>
          <h2>System Performance &amp; Memory Audit</h2>
          <p>Audit RAM load, working sets of active processes, startup persistence overhead, and system maintenance tasks.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">⚡ RAM &amp; Memory Distribution</div></div>
          <div class="hub-card-desc">Physical and virtual memory breakdown with working set analysis for resource-heavy apps.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🚀 Startup &amp; Persistence Impact</div></div>
          <div class="hub-card-desc">Inspect Startup registry entries, scheduled tasks, and background services delaying boot.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🛠 Maintenance Quick-Fixes</div></div>
          <div class="hub-card-desc">Copy-paste PowerShell recipes for DNS flush, DISM component store cleanup, and SSD TRIM.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='applications'){
    return `<div style="margin-top:20px">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#ff70a6,#70d6ff)">▦</div>
        <div>
          <h2>Installed Applications &amp; Leftovers</h2>
          <p>Track installed software footprints, quiet uninstall commands, and orphaned AppData leftover folders.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🔍 Installed App Footprints</div></div>
          <div class="hub-card-desc">Detect installed applications from 64-bit and 32-bit registry, correlating files and background services.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🧹 Orphaned AppData Leftovers</div></div>
          <div class="hub-card-desc">Discover remnant directories in %LocalAppData% and %AppData% left behind after uninstalls.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">⚡ Silent Uninstaller Audit</div></div>
          <div class="hub-card-desc">Inspect QuietUninstallString and standard uninstaller commands with copyable command line recipes.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='clutter'){
    return `<div style="margin-top:20px">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#06d6a0,#118ab2)">◌</div>
        <div>
          <h2>Space Lens &amp; Clutter Inspector</h2>
          <p>Visual storage hierarchy, exact byte duplicates, and large/old files breakdown.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">🔭 Space Lens Hierarchy</div></div>
          <div class="hub-card-desc">Interactive proportional disk visualization highlighting top space consumers.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">👥 Exact Duplicate Files</div></div>
          <div class="hub-card-desc">SHA-256 duplicate content identification to eliminate wasted duplicate storage.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title">📦 Large &amp; Old Files</div></div>
          <div class="hub-card-desc">Filter archives, ISOs, virtual disks, and forgotten files older than 6 months or 1 year.</div>
        </div>
      </div>
    </div>`;
  }
  return '';
}
function navigatePage(name,updateHistory=true){
  if(!PAGES[name])name='home';
  currentPage=name;
  const page=PAGES[name];
  document.body.dataset.page=name;
  $('#pageTitle').textContent=page.title;
  $$('button[data-page]').forEach(el=>{el.classList.toggle('active',el.dataset.page===name);if(el.classList.contains('rail-item')){if(el.dataset.page===name)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');}});
  $('#scanComposer').classList.toggle('hidden',name!=='home'&&name!=='settings');
  $('#liveMonitor').classList.toggle('hidden',name!=='home');
  const intro=$('#moduleIntro');
  intro.classList.toggle('hidden',name==='home'||name==='settings');
  intro.innerHTML=`<section class="module-banner"><span class="module-symbol">${page.icon}</span><div><h2>${page.title}</h2><p>${page.description}</p></div><button type="button" class="secondary" onclick="navigatePage('settings')">Configure scan</button></section>${!REPORT?getPreScanHub(name):''}`;
  $('#summary').classList.toggle('hidden',!REPORT||name==='settings');
  $$('.tab').forEach(el=>el.classList.toggle('hidden',!page.views.includes(el.dataset.view)));
  if(REPORT&&page.views.length)switchTab(page.views[0]);
  if(name==='settings')$('.advanced').open=true;
  else if(name==='home')$('.advanced').open=false;
  if(updateHistory&&location.hash!=='#'+name)history.pushState(null,'','#'+name);
  window.scrollTo({top:0,behavior:'instant'});
}
const MAX_IMPORTED_REPORT_BYTES=64*1024*1024,MAX_IMPORTED_SECTION_ROWS=100000;
const $=s=>document.querySelector(s), $$=s=>document.querySelectorAll(s);

let scanStartTime=null, timerInterval=null, lastKnownPhase='', activityEventsCount=0;

function setRoot(p){
  let el=$('#root');
  if(el){ el.value=p; el.focus(); }
}

function updateTimer(){
  if(!scanStartTime)return;
  let elapsedSec=Math.floor((Date.now()-scanStartTime)/1000);
  let mins=String(Math.floor(elapsedSec/60)).padStart(2,'0');
  let secs=String(elapsedSec%60).padStart(2,'0');
  let el=$('#elapsedTimer');
  if(el)el.textContent=`${mins}:${secs}`;
}

function logActivity(message, kind='item'){
  let elapsedSec=scanStartTime?Math.floor((Date.now()-scanStartTime)/1000):0;
  let mins=String(Math.floor(elapsedSec/60)).padStart(2,'0');
  let secs=String(elapsedSec%60).padStart(2,'0');
  let timeStr=`[${mins}:${secs}]`;
  let feed=$('#activityFeed');
  if(!feed)return;
  activityEventsCount++;
  $('#activityCount').textContent=`${activityEventsCount} events logged`;
  let row=document.createElement('div');
  row.className=`activity-row ${kind}`;
  row.innerHTML=`<span class="t">${timeStr}</span><span class="m">${esc(message)}</span>`;
  feed.appendChild(row);
  if(feed.childNodes.length>80)feed.removeChild(feed.firstChild);
  feed.scrollTop=feed.scrollHeight;
}

function getStageIndex(phase){
  if(!phase||phase==='idle'||phase==='queued')return -1;
  if(phase==='filesystem'||phase==='filesystem_done')return 0;
  if(phase==='duplicates'||phase==='duplicate_hashing'||phase==='project_context')return 1;
  if(phase==='applications'||phase==='startup')return 2;
  if(phase==='windows_deep_inventory')return 3;
  if(phase==='process_context'||phase==='execution_metadata')return 4;
  if(phase==='binary_trust'||phase==='ownership_permissions')return 5;
  if(phase==='rule_intelligence'||phase==='classification'||phase==='ownership_graph')return 6;
  if(phase==='done')return 7;
  return 0;
}

function updatePipelineStepper(stageIdx, isRunning){
  for(let i=0;i<7;i++){
    let node=$('#step-'+i);
    if(!node)continue;
    let badge=node.querySelector('.step-badge');
    node.classList.remove('pending','active','completed');
    if(stageIdx===-1){
      node.classList.add('pending');
      if(badge)badge.textContent='Pending';
    }else if(i<stageIdx||stageIdx===7){
      node.classList.add('completed');
      if(badge)badge.textContent='Done';
    }else if(i===stageIdx){
      if(isRunning){
        node.classList.add('active');
        if(badge)badge.textContent='Active';
      }else{
        node.classList.add('completed');
        if(badge)badge.textContent='Done';
      }
    }else{
      node.classList.add('pending');
      if(badge)badge.textContent='Pending';
    }
  }
}

function calculateProgressPct(phase, p){
  if(phase==='done')return 100;
  if(!phase||phase==='idle')return 0;
  if(phase==='queued')return 2;
  if(phase==='filesystem'){
    let files=p.files_seen||0;
    return Math.min(25, 3+Math.round((files/40000)*22));
  }
  if(phase==='filesystem_done')return 25;
  if(phase==='duplicates'||phase==='duplicate_hashing'){
    let sub=(p.total&&p.total>0)?Math.round(((p.done||0)/p.total)*12):5;
    return 25+sub;
  }
  if(phase==='project_context')return 38;
  if(phase==='applications')return 42;
  if(phase==='startup')return 48;
  if(phase==='windows_deep_inventory'){
    let sub=(p.total&&p.total>0)?Math.round(((p.done||0)/p.total)*20):10;
    return 50+sub;
  }
  if(phase==='process_context')return 72;
  if(phase==='execution_metadata')return 78;
  if(phase==='rule_intelligence')return 80;
  if(phase==='classification')return 83;
  if(phase==='binary_trust'){
    let sub=(p.total_batches&&p.total_batches>0)?Math.round(((p.batch||1)/p.total_batches)*6):3;
    return 84+sub;
  }
  if(phase==='ownership_permissions'){
    let sub=(p.total_batches&&p.total_batches>0)?Math.round(((p.batch||1)/p.total_batches)*4):2;
    return 90+sub;
  }
  if(phase==='ownership_graph')return 95;
  return 50;
}

function showError(message,kind='application'){
  let box=$('#error');
  box.textContent=String(message||'Unknown error');
  box.dataset.kind=kind;
  box.classList.remove('hidden');
}
function clearError(kind=''){
  let box=$('#error');
  if(kind&&box.dataset.kind!==kind)return;
  box.textContent='';
  delete box.dataset.kind;
  box.classList.add('hidden');
}

function bytes(n){
  if(n===null||n===undefined)return 'Unknown';
  let sign=Number(n)<0?'-':'',v=Math.abs(Number(n)),u=['B','KB','MB','GB','TB','PB'],i=0;
  while(v>=1024&&i<u.length-1){v/=1024;i++}
  return sign+(i?v.toFixed(v>=100?0:v>=10?1:2):Math.round(v))+' '+u[i];
}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function cls(d){return d==='probably_safe_cleanup'?'safe':d==='manual_review'?'review':d==='intentional_tooling'?'tooling':d==='do_not_touch'?'dont':'info'}
function label(d){
  return ({
    probably_safe_cleanup: 'Probably Safe',
    manual_review: 'Manual Review',
    intentional_tooling: 'Developer Tool',
    do_not_touch: 'Protected / Keep',
    informational: 'Informational'
  })[d] || d;
}
function age(d){if(d===null||d===undefined)return 'unknown';return d<1?'<1 day':d<30?Math.round(d)+' days':d<365?(d/30).toFixed(1)+' months':(d/365).toFixed(1)+' years'}

const CATEGORY_META = {
  system_temp: { title: "System & Temporary Files", icon: "◌", desc: "Transient OS caches, crash dumps, and temp files. Review the owning workflow before any cleanup." },
  dev_build: { title: "Development & Build Caches", icon: "⌘", desc: "Dependencies, intermediate compilers, virtualenvs, and package manager caches." },
  ai_ml: { title: "AI & Machine Learning Models", icon: "⬡", desc: "Large weights, transformer models, and checkpoints (Ollama, HuggingFace, PyTorch, ComfyUI)." },
  browser_app: { title: "Browsers & Application Data", icon: "◎", desc: "Browser cache storage, WebKit/Chromium storage, and communication app media buffers." },
  apps_installers: { title: "Applications & Installers", icon: "◇", desc: "Installed software and setup packages. Use Windows or vendor-supported management; never delete program files manually." },
  virtualization: { title: "Virtual Machines & Containers", icon: "▣", desc: "Virtual hard disks (VHDX), container layers, Docker images, and hypervisor disks." },
  diagnostics: { title: "Diagnostics & Storage Candidates", icon: "⌁", desc: "Memory dumps, trace logs, database files, and large files requiring review." },
  app_leftovers: { title: "Application Leftovers", icon: "⌂", desc: "Residual AppData and ProgramData folders from uninstalled applications." },
  privacy_permissions: { title: "Privacy & Permissions", icon: "🛡", desc: "Hardware consent permissions, Defender status, and security findings." },
  system_maintenance: { title: "System Maintenance", icon: "⚡", desc: "System memory pressure, performance optimization, and routine maintenance candidates." },
  other: { title: "Other Storage Findings", icon: "·", desc: "Miscellaneous storage items and files requiring assessment." }
};

const CATEGORY_MAP = {
  temp: 'system_temp', cache: 'system_temp', crash_dumps: 'system_temp', windows_delivery_optimization: 'system_temp', windows_error_reporting: 'system_temp', repro: 'system_temp', logs: 'system_temp', recycle_bin: 'system_temp', installer_package_cache: 'system_temp', windows_upgrade_residue: 'system_temp', prefetch: 'system_temp',
  pip_cache: 'dev_build', npm_cache: 'dev_build', yarn_cache: 'dev_build', pnpm_cache: 'dev_build', cargo_cache: 'dev_build', gradle_cache: 'dev_build', nuget_cache: 'dev_build', node_modules: 'dev_build', rust_target: 'dev_build', python_venv: 'dev_build', build_output: 'dev_build',
  huggingface_cache: 'ai_ml', torch_cache: 'ai_ml', ollama_models: 'ai_ml', comfyui_models: 'ai_ml', ai_model_cache: 'ai_ml',
  browser_cache: 'browser_app', electron_cache: 'browser_app', spotify_cache: 'browser_app', discord_cache: 'browser_app', slack_cache: 'browser_app', teams_cache: 'browser_app',
  downloads: 'apps_installers', steam_games: 'apps_installers', epic_games: 'apps_installers', store_apps: 'apps_installers', isolated_installs: 'apps_installers',
  wsl_disks: 'virtualization', docker_data: 'virtualization', vm_disks: 'virtualization',
  orphaned_app_data: 'app_leftovers', application_leftover: 'app_leftovers', privacy_consent_store: 'privacy_permissions', defender_status: 'privacy_permissions', system_memory_status: 'system_maintenance',
  memory_dump: 'diagnostics', large_file: 'diagnostics', archive: 'diagnostics'
};

let selectedCategory = 'all';

function getCollector(name){
  return (REPORT&&REPORT.collectors||[]).find(c=>c.name===name);
}

function getCategoryGroup(f) {
  if (f && f.category_group && CATEGORY_META[f.category_group]) return f.category_group;
  let cat = String(f?.category || '').toLowerCase();
  return CATEGORY_MAP[cat] || 'other';
}

function selectCat(catId) {
  selectedCategory = catId;
  render();
}

function switchTab(viewName) {
  let activeTab=null;
  $$('.tab').forEach(x => {
    let active = x.dataset.view === viewName;
    x.classList.toggle('active', active);
    x.setAttribute('aria-selected', active ? 'true' : 'false');
    x.setAttribute('tabindex', active ? '0' : '-1');
    if(active)activeTab=x;
  });
  if(activeTab)$('#view').setAttribute('aria-labelledby',activeTab.id);
  currentView = viewName;
  render();
}

function switchCategory(catId) {
  selectedCategory = catId;
  switchTab('findings');
}

function copyPath(btn, path) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(path).then(() => {
      let old = btn.textContent;
      btn.textContent = '✓ Copied';
      btn.style.color = 'var(--good)';
      setTimeout(() => { btn.textContent = old; btn.style.color = ''; }, 1600);
    }).catch(() => {});
  }
}

function simpleTable(rows,cols){
  if(!rows||!rows.length)return '<div class="notice">No records were returned for this section.</div>';
  let h='<div class="tablewrap"><table><thead><tr>'+cols.map(c=>`<th scope="col">${esc(c[0])}</th>`).join('')+'</tr></thead><tbody>';
  for(let row of rows){
    h+='<tr>'+cols.map(c=>`<td class="${c[2]||''}">${c[1](row)}</td>`).join('')+'</tr>';
  }
  return h+'</tbody></table></div>';
}

function barChart(title,rows){
  let max=Math.max(1,...rows.map(x=>Number(x.value)||0));
  return `<div class="chart"><h3>${esc(title)}</h3>`+rows.map(x=>`<div class="barrow"><div class="barlabel" title="${esc(x.label)}">${esc(x.label)}</div><div class="bar"><i style="width:${Math.max(1,(Number(x.value)||0)/max*100)}%"></i></div><div class="barval">${bytes(x.value)}</div></div>`).join('')+'</div>';
}

function profileHint(){
  let p=$('#profile').value,d=PROFILE_DEFAULTS[p];
  $('#profileHint').textContent=`${p}: ${d.scan_duplicates?'duplicates '+d.duplicate_min_mb+' MB–'+bytes(d.duplicate_max_mb*1024*1024):'duplicate hashing off'} · top ${d.top_files} files · ${d.deep_windows_inventory?'deep Windows inventory':'basic Windows inventory'}`;
}

function renderMetrics(){
  let r=REPORT,s=r.stats,rs=r.reclaim_summary||{},ah=r.audit_health||{};
  let total=s.filesystem_total_bytes||0,used=s.filesystem_used_bytes||0;
  $('#metrics').innerHTML=`
    <div class="metric"><span>Filesystem used</span><b>${bytes(used)}</b><span>${total?Math.round(used/total*100)+'% of '+bytes(total):'volume total unavailable'}</span></div>
    <div class="metric"><span>Free space</span><b>${bytes(s.filesystem_free_bytes)}</b><span>at scan start</span></div>
    <div class="metric good"><span>Conservative path candidates</span><b>${bytes(rs.path_candidates_nonoverlap_bytes||0)}</b><span>overlap-suppressed; requires review</span></div>
    <div class="metric warn"><span>Duplicate potential</span><b>${bytes(rs.duplicate_potential_bytes_separate||0)}</b><span>separate / non-additive</span></div>
    <div class="metric info"><span>Traversed</span><b>${bytes(s.bytes_seen)}</b><span>${Number(s.files_seen||0).toLocaleString()} files · ${Number(s.scan_rate_files_per_second||0).toLocaleString(undefined,{maximumFractionDigits:0})}/s</span></div>
    <div class="metric"><span>Audit coverage</span><b>${ah.coverage_score??'n/a'}</b><span>${esc(ah.coverage_grade||'unknown')} · ${ah.collectors_succeeded||0}/${ah.collectors_requested||0} collectors</span></div>
  `;

  // Update tab counts
  $('#count-plan').textContent=Number(rs.actionable_findings_total||0).toLocaleString();
  $('#count-findings').textContent=Number((r.findings||[]).length).toLocaleString();
  $('#count-dirs').textContent=Number((r.top_directories||[]).length).toLocaleString();
  $('#count-files').textContent=Number((r.top_files||[]).length).toLocaleString();
  $('#count-duplicates').textContent=Number((r.duplicates||[]).length).toLocaleString();
  $('#count-tooling').textContent=Number((r.project_artifacts||[]).length).toLocaleString();
  $('#count-apps').textContent=Number((r.applications||[]).length).toLocaleString();
  $('#count-ownership').textContent=Number((r.application_footprints||[]).length).toLocaleString();
  $('#count-processes').textContent=Number((r.processes||[]).length).toLocaleString();
  $('#count-trust').textContent=Number((r.binary_trust||[]).length).toLocaleString();
  $('#count-permissions').textContent=Number((r.path_security||[]).length).toLocaleString();
  $('#count-startup').textContent=Number((r.startup||[]).length).toLocaleString();
  $('#count-services').textContent=Number((r.services||[]).length).toLocaleString();
  $('#count-tasks').textContent=Number((r.scheduled_tasks||[]).length).toLocaleString();
  $('#count-system').textContent=Number((r.collectors||[]).length).toLocaleString();
}

function scopeBanner(){
  let root=REPORT.stats?.root||'the selected root';
  return `<div class="scope-band"><span aria-hidden="true">⌖</span><div><strong>Two scopes, kept separate</strong><p>File sizes, folders, duplicates, and path cleanup candidates are limited to <span class="path">${esc(root)}</span>. Installed apps, processes, startup entries, services, tasks, WSL/Docker, trust, and Windows platform evidence describe the wider host. Their estimates are shown separately and are not added to path cleanup totals.</p></div></div>`;
}

function depthMatrix(){
  let domains=REPORT.audit_health?.depth_domains||[];
  if(!domains.length)return '<div class="notice">This imported report predates the domain-level depth ledger. Collector details remain available under System inventory.</div>';
  let labels={complete:'Complete',partial:'Partial',blocked:'Blocked',not_available:'Not available'};
  let cards=domains.map(d=>{
    let requested=Number(d.checks_requested||0),succeeded=Number(d.checks_succeeded||0),unavailable=Number(d.checks_not_available||0);
    let limitations=(d.limitations||[]).slice(0,4).map(x=>String(x).replaceAll('_',' ')).join(', ');
    return `<div class="depth-card"><div class="depth-card-top"><div><div class="brief-kicker">Evidence domain</div><h4>${esc(d.title)}</h4></div><span class="depth-status ${esc(d.status)}">${esc(labels[d.status]||d.status)}</span></div><p>${esc(d.description)}</p><div class="depth-meta">${succeeded}/${requested} applicable checks succeeded${unavailable?` · ${unavailable} not available`:''}${limitations?`<div class="depth-limit">Limited: ${esc(limitations)}</div>`:''}</div></div>`;
  }).join('');
  return `<div class="depth-heading"><div><div class="brief-kicker">Depth proof</div><h3>What ReconSpace actually inspected</h3></div><button type="button" class="secondary" onclick="switchTab('system')">Open raw collector evidence</button></div><div class="depth-grid">${cards}</div>`;
}

function decisionBrief(){
  let s=REPORT.stats||{},rs=REPORT.reclaim_summary||{},ah=REPORT.audit_health||{},findings=REPORT.findings||[];
  let total=Number(s.filesystem_total_bytes||0),free=Number(s.filesystem_free_bytes||0),freePct=total?free/total*100:null;
  let storageClass=freePct!==null&&freePct<5?'critical':freePct!==null&&freePct<10?'low':'';
  let storageLabel=freePct===null?'Unknown':freePct<5?'Critical':freePct<10?'Low':freePct<15?'Watch':'Healthy';
  let safe=findings.filter(f=>f.disposition==='probably_safe_cleanup'&&Number(f.estimated_reclaimable_bytes||0)>0);
  let review=findings.filter(f=>f.disposition==='manual_review'&&Number(f.estimated_reclaimable_bytes||0)>0);
  let protectedCount=findings.filter(f=>f.disposition==='intentional_tooling'||f.disposition==='do_not_touch').length;
  let nextTitle=safe.length?`Review ${safe.length} lower-risk candidate${safe.length===1?'':'s'} first`:review.length?`Review ${review.length} candidate${review.length===1?'':'s'} manually`:'No direct path cleanup candidate needs action';
  let nextText=safe.length?'Confirm applications are closed, check the explanation and risk, then use the owning tool’s supported cleanup workflow only after approval.':review.length?'Start with the highest reclaim estimate. Confirm ownership, current use, backups, and the supported management workflow.':'Inspect application and platform opportunities separately; they may be system-wide and overlap other estimates.';
  return `<div class="decision-brief"><section class="brief-main"><div class="health-orb ${storageClass}">${freePct===null?'—':freePct.toFixed(freePct<10?1:0)+'%'}</div><div><div class="brief-kicker">Decision brief · ${esc(storageLabel)} free-space state</div><h2>${bytes(free)} free on the scanned volume</h2><p>${bytes(s.bytes_seen||0)} traversed across ${Number(s.files_seen||0).toLocaleString()} files. Coverage: ${esc(ah.coverage_grade||'unknown')} (${ah.coverage_score??'n/a'}/100). Coverage measures evidence quality—not cleanliness or security.</p></div></section><section class="brief-next"><div class="brief-kicker">Recommended next move</div><h3>${esc(nextTitle)}</h3><p>${esc(nextText)}</p><button type="button" onclick="switchTab('plan')">Open guided action plan</button></section></div>${scopeBanner()}<div class="decision-numbers"><div class="decision-number"><span>Probably safe paths</span><b class="safe">${bytes(rs.probably_safe_path_bytes||0)}</b></div><div class="decision-number"><span>Manual-review paths</span><b class="review">${bytes(rs.manual_review_path_bytes||0)}</b></div><div class="decision-number"><span>Protected / tooling</span><b>${protectedCount.toLocaleString()} items</b></div><div class="decision-number"><span>Deep checks</span><b>${ah.collectors_succeeded||0}/${ah.collectors_requested||0}</b></div></div>`;
}

function planItems(rows,emptyText){
  if(!rows.length)return `<div class="plan-empty">${esc(emptyText)}</div>`;
  return `<div class="plan-list">${rows.slice(0,20).map(f=>`<article class="plan-item"><div class="plan-item-head"><div><h4>${esc(f.title)}</h4><span class="pill ${cls(f.disposition)}">${label(f.disposition)}</span> <span class="small">Risk ${esc(f.risk||'unknown')} · Confidence ${esc(f.confidence||'unknown')}</span></div><div class="plan-item-size"><b>${bytes(f.estimated_reclaimable_bytes||0)}</b><span class="small">estimated reclaim</span></div></div><div class="plan-item-path">${esc(f.path)}</div><div class="plan-explain"><div style="grid-column:1/-1"><b>What it is / why it exists</b><p>${esc(f.why_it_exists||'No explanation recorded.')}</p></div><div><b>What you can do</b><p>${esc(f.recommendation||'Review before taking action.')}</p></div><div><b>What can go wrong</b><p>${esc(f.removal_risk||'The effect is unknown; preserve it until ownership is confirmed.')}</p></div></div></article>`).join('')}</div>`;
}

function actionPlan(){
  let findings=[...(REPORT.findings||[])],rs=REPORT.reclaim_summary||{},ah=REPORT.audit_health||{};
  let safe=findings.filter(f=>f.disposition==='probably_safe_cleanup'&&Number(f.estimated_reclaimable_bytes||0)>0).sort((a,b)=>(b.priority_score||0)-(a.priority_score||0));
  let review=findings.filter(f=>f.disposition==='manual_review'&&Number(f.estimated_reclaimable_bytes||0)>0).sort((a,b)=>(b.priority_score||0)-(a.priority_score||0));
  let held=findings.filter(f=>f.disposition==='intentional_tooling'||f.disposition==='do_not_touch');
  return `${scopeBanner()}<div class="plan-intro"><section class="plan-lane"><div class="lane-kicker">Plan-only workflow</div><h2>From evidence to an approved decision</h2><ol class="plan-steps"><li>Confirm scan coverage and limitations. Current evidence quality: <b>${esc(ah.coverage_grade||'unknown')} ${ah.coverage_score??'n/a'}/100</b>.</li><li>Review “Probably Safe” items. This means regenerable or supported cleanup—not automatic permission.</li><li>Review manual items for ownership, current use, backup, retention, and overlap.</li><li>Export the approval plan. ReconSpace executes nothing.</li></ol><button type="button" id="planExportInline" style="margin-top:10px">Export full approval plan</button></section><section class="plan-lane"><div class="lane-kicker">Non-additive estimates</div><h3>Keep totals honest</h3><div class="decision-numbers" style="grid-template-columns:1fr 1fr;margin:12px 0 0"><div class="decision-number"><span>Path candidates</span><b>${bytes(rs.path_candidates_nonoverlap_bytes||0)}</b></div><div class="decision-number"><span>Duplicates</span><b>${bytes(rs.duplicate_potential_bytes_separate||0)}</b></div><div class="decision-number"><span>Applications</span><b>${bytes(rs.application_potential_bytes_separate||0)}</b></div><div class="decision-number"><span>Platforms</span><b>${bytes(rs.platform_potential_bytes_separate||0)}</b></div></div><p class="small">These four figures can overlap. Never add them into one promised recovery number.</p></section></div><section class="plan-lane"><div class="lane-kicker">Stage 1 · lower-risk review</div><h3>Probably safe candidates (${safe.length})</h3><p class="small">Still verify active work, offline needs, and the owning tool’s supported cleanup method.</p>${planItems(safe,'No probably-safe reclaim candidates were identified in this scan.')}</section><section class="plan-lane" style="margin-top:12px"><div class="lane-kicker">Stage 2 · ownership required</div><h3>Manual-review candidates (${review.length})</h3><p class="small">Potentially valuable data, applications, environments, or shared state. No removal until ownership is confirmed.</p>${planItems(review,'No manual-review reclaim candidates were identified in this scan.')}</section><div class="notice" style="margin-top:12px">${held.length} protected or intentional-tooling finding(s) are excluded from the actionable plan. Open Findings to inspect them; they remain visible precisely so valuable development, cybersecurity, VM, container, and forensic data is not mistaken for junk.</div>`;
}

function treemap(rows){
  let total=rows.reduce((n,x)=>n+(Number(x.size_bytes)||0),0)||1;
  return `<div class="chart"><h3>Retained folder treemap</h3><div style="display:flex;flex-wrap:wrap;gap:4px;min-height:260px;align-content:stretch">${rows.map((x,i)=>{let weight=Math.max(7,(Number(x.size_bytes)||0)/total*100);return `<div title="${esc(x.path)} — ${bytes(x.size_bytes)}" style="flex:${weight} 1 ${Math.max(90,weight*8)}px;min-height:${70+(i%3)*18}px;border:1px solid var(--border);border-radius:8px;padding:8px;background:linear-gradient(135deg,rgba(99,102,241,.18),rgba(56,189,248,.10));overflow:hidden"><b>${bytes(x.size_bytes)}</b><div class="path">${esc(x.path)}</div></div>`}).join('')}</div><div class="small" style="margin-top:8px">Area is proportional only within the retained top-folder set, not the entire filesystem.</div></div>`;
}

function overview(){
  let s=REPORT.stats,total=s.filesystem_total_bytes||0,used=s.filesystem_used_bytes||0,pct=total?Math.min(100,used/total*100):0;
  let dirRows=(REPORT.top_directories||[]).filter(x=>x.path!==s.root).slice(0,18);
  let dirs=dirRows.slice(0,12).map(x=>({label:x.path,value:x.size_bytes}));
  let exts=(REPORT.extension_summary||[]).slice(0,12).map(x=>({label:x.extension,value:x.bytes}));
  let ages=(REPORT.age_summary||[]).map(x=>({label:x.bucket+' ('+Number(x.files).toLocaleString()+' files)',value:x.bytes}));
  
  // Calculate category breakdowns
  let catCounts={},catBytes={},catReclaim={};
  for(let f of (REPORT.findings||[])){
    let cg=getCategoryGroup(f);
    catCounts[cg]=(catCounts[cg]||0)+1;
    catBytes[cg]=(catBytes[cg]||0)+(f.size_bytes||0);
    catReclaim[cg]=(catReclaim[cg]||0)+(f.estimated_reclaimable_bytes||0);
  }

  // 4 Care Pillar metrics
  let totalReclaim=(REPORT.findings||[]).reduce((a,c)=>a+(c.estimated_reclaimable_bytes||0),0);
  let defColl=getCollector('defender_status');
  let defOk=defColl&&defColl.ok&&defColl.data?.Status?.RealTimeProtectionEnabled!==false;
  let privColl=getCollector('privacy_consent_store');
  let privCount=0;
  if(privColl&&privColl.ok&&privColl.data){for(let k in privColl.data)privCount+=(privColl.data[k]||[]).length;}
  let protMetric=defColl?(defOk?'Protected':'Attention needed'):(privCount?privCount+' permissions':'Audited');
  let memColl=getCollector('system_memory_status');
  let memLoad=memColl&&memColl.ok&&memColl.data?.memory_load_pct!=null?memColl.data.memory_load_pct+'% RAM load':((REPORT.processes||[]).length?(REPORT.processes||[]).length+' processes':'Audited');
  let appCount=(REPORT.applications||[]).length;
  let orphColl=getCollector('orphaned_app_data');
  let orphCount=orphColl&&orphColl.ok&&Array.isArray(orphColl.data)?orphColl.data.length:0;
  let appMetric=appCount?`${appCount} apps`+(orphCount?` · ${orphCount} leftovers`:''):'Audited';

  let pillarGrid=`
    <div class="pillar-grid">
      <div class="pillar-card cleanup-pillar" onclick="navigatePage('cleanup')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('cleanup')}" role="button" tabindex="0" title="Open Cleanup module">
        <div class="pillar-head">
          <span class="pillar-title">Cleanup</span>
          <div class="pillar-icon">⌁</div>
        </div>
        <div class="pillar-sub">System caches, build folders, browser temp &amp; logs</div>
        <div class="pillar-metric">${totalReclaim>0?bytes(totalReclaim)+' reclaim':(REPORT.findings||[]).length+' findings'}</div>
      </div>
      <div class="pillar-card protection-pillar" onclick="navigatePage('protection')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('protection')}" role="button" tabindex="0" title="Open Protection module">
        <div class="pillar-head">
          <span class="pillar-title">Protection</span>
          <div class="pillar-icon">◇</div>
        </div>
        <div class="pillar-sub">Defender status, app privacy permissions &amp; binary trust</div>
        <div class="pillar-metric" style="color:${defOk?'var(--good)':'var(--warn)'}">${protMetric}</div>
      </div>
      <div class="pillar-card performance-pillar" onclick="navigatePage('performance')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('performance')}" role="button" tabindex="0" title="Open Performance module">
        <div class="pillar-head">
          <span class="pillar-title">Performance</span>
          <div class="pillar-icon">↯</div>
        </div>
        <div class="pillar-sub">Memory load, startup items &amp; maintenance routines</div>
        <div class="pillar-metric">${memLoad}</div>
      </div>
      <div class="pillar-card applications-pillar" onclick="navigatePage('applications')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('applications')}" role="button" tabindex="0" title="Open Applications module">
        <div class="pillar-head">
          <span class="pillar-title">Applications</span>
          <div class="pillar-icon">▦</div>
        </div>
        <div class="pillar-sub">Installed software footprints &amp; orphaned leftovers</div>
        <div class="pillar-metric">${appMetric}</div>
      </div>
    </div>
  `;

  let catCards='';
  let order=['system_temp','dev_build','ai_ml','browser_app','apps_installers','virtualization','app_leftovers','system_maintenance','privacy_permissions','diagnostics','other'];
  for(let cid of order){
    let count=catCounts[cid]||0;
    if(!count)continue;
    let meta=CATEGORY_META[cid]||{title:cid,icon:'·',desc:''};
    let sz=catBytes[cid]||0,rc=catReclaim[cid]||0;
    catCards+=`
      <div class="overview-cat-card" onclick="switchCategory('${cid}')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();switchCategory('${cid}')}" role="button" tabindex="0" title="Open ${esc(meta.title)} findings">
        <div class="overview-cat-top">
          <div class="overview-cat-title"><span style="font-size:18px">${meta.icon}</span> ${esc(meta.title)}</div>
          <div class="overview-cat-size">${bytes(sz)}</div>
        </div>
        <div class="small" style="line-height:1.4">${esc(meta.desc)}</div>
        <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px dashed var(--border);padding-top:8px;margin-top:4px">
          <span class="overview-cat-count">${count} findings</span>
          ${rc>0?`<span class="safe" style="font-weight:700;font-size:12px">Est. ${bytes(rc)} reclaim</span>`:''}
        </div>
      </div>
    `;
  }

  return `${decisionBrief()}
    ${pillarGrid}
    <div class="chart">
      <h3>Volume capacity</h3>
      <div><b>${bytes(used)}</b> used of ${bytes(total)} · <span class="safe">${bytes(s.filesystem_free_bytes)} free</span></div>
      <div class="diskbar"><i style="width:${pct}%"></i></div>
      <div class="small">Scanned ${esc(REPORT.profile)} profile in ${Number(s.duration_seconds||0).toFixed(1)}s. Logical file bytes traversed can differ from allocated volume usage because of filesystem metadata, sparse/compressed files, reparse handling, restore data and inaccessible locations.</div>
    </div>
    ${catCards?`
    <div style="margin-top:18px">
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Findings by Category</h3>
        <span class="small">Click any category to inspect individual findings</span>
      </div>
      <div class="overview-cats">${catCards}</div>
    </div>`:''}
    <div style="margin-top:16px">${treemap(dirRows)}</div>
    <div class="twocol" style="margin-top:16px">${barChart('Largest retained folders',dirs)}${barChart('Largest file types',exts)}</div>
    <div style="margin-top:16px">${barChart('File age distribution',ages)}</div>
    ${depthMatrix()}
  `;
}

function findings(){
  let allRows=[...(REPORT.findings||[])];
  let disp=$('#findDisp')?.value||'',q=($('#findQ')?.value||'').toLowerCase(),sort=$('#findSort')?.value||'score';
  
  // Filter by disposition & query first
  let filtered=allRows;
  if(disp)filtered=filtered.filter(x=>x.disposition===disp);
  if(q)filtered=filtered.filter(x=>(x.title+' '+x.path+' '+x.category+' '+(x.related_to||[]).join(' ')+' '+(x.why_it_exists||'')+' '+(x.recommendation||'')).toLowerCase().includes(q));

  // Category counts under active filters
  let catCounts={all:filtered.length};
  for(let f of filtered){
    let cg=getCategoryGroup(f);
    catCounts[cg]=(catCounts[cg]||0)+1;
  }

  // Build category filter pills
  let order=['system_temp','dev_build','ai_ml','browser_app','apps_installers','virtualization','diagnostics','other'];
  let pills=`<div class="cat-bar"><button type="button" class="cat-pill ${selectedCategory==='all'?'active':''}" onclick="selectCat('all')">All Categories <span class="sub">(${catCounts.all||0})</span></button>`;
  for(let cid of order){
    let count=catCounts[cid]||0;
    if(!count)continue;
    let meta=CATEGORY_META[cid]||{title:cid,icon:'·'};
    pills+=`<button type="button" class="cat-pill ${selectedCategory===cid?'active':''}" onclick="selectCat('${cid}')">${meta.icon} ${esc(meta.title)} <span class="sub">(${count})</span></button>`;
  }
  pills+=`</div>`;

  // Apply selected category filter
  let displayRows=selectedCategory==='all'?filtered:filtered.filter(x=>getCategoryGroup(x)===selectedCategory);

  // Sort
  displayRows.sort((a,b)=>sort==='size'?(b.size_bytes-a.size_bytes):sort==='reclaim'?((b.estimated_reclaimable_bytes||0)-(a.estimated_reclaimable_bytes||0)):((b.priority_score||0)-(a.priority_score||0)));

  let totalReclaim=displayRows.reduce((acc,x)=>acc+(x.estimated_reclaimable_bytes||0),0);

  let toolbar=`<div class="toolbar"><input id="findQ" placeholder="Filter title, path, category, tooling…" value="${esc(q)}"><select id="findDisp"><option value="">All dispositions</option>${['probably_safe_cleanup','manual_review','intentional_tooling','do_not_touch','informational'].map(x=>`<option value="${x}" ${disp===x?'selected':''}>${label(x)}</option>`).join('')}</select><select id="findSort"><option value="score" ${sort==='score'?'selected':''}>Priority score</option><option value="reclaim" ${sort==='reclaim'?'selected':''}>Reclaimable size</option><option value="size" ${sort==='size'?'selected':''}>Observed size</option></select><span class="small">${displayRows.length} findings · ${bytes(totalReclaim)} reclaimable</span></div>`;

  if(!displayRows.length){
    return pills+toolbar+'<div class="notice">No records were returned for this section.</div>';
  }

  // Group by category for structured presentation
  let groups={};
  for(let f of displayRows.slice(0,300)){
    let cg=getCategoryGroup(f);
    if(!groups[cg])groups[cg]=[];
    groups[cg].push(f);
  }

  let body='';
  let groupOrder=selectedCategory==='all'?order:[selectedCategory];
  for(let cid of groupOrder){
    let gRows=groups[cid];
    if(!gRows||!gRows.length)continue;
    let meta=CATEGORY_META[cid]||{title:cid,icon:'·',desc:''};
    let gBytes=gRows.reduce((acc,x)=>acc+(x.size_bytes||0),0);
    let gReclaim=gRows.reduce((acc,x)=>acc+(x.estimated_reclaimable_bytes||0),0);

    body+=`<div class="cat-section">`;
    body+=`<div class="cat-section-header"><div><h4 class="cat-section-title">${meta.icon} ${esc(meta.title)}</h4><div class="cat-section-desc">${esc(meta.desc)}</div></div><div class="cat-section-badge"><span>${gRows.length} items · ${bytes(gBytes)} total</span>${gReclaim>0?`<span style="color:var(--good)"> · ${bytes(gReclaim)} est. reclaim</span>`:''}</div></div>`;

    for(let f of gRows){
      let pScore=Number(f.priority_score||0).toFixed(0);
      let pColor=pScore>=75?'var(--good)':pScore>=45?'var(--warn)':'var(--text-muted)';
      body+=`
        <div class="finding-card">
          <div class="finding-top">
            <div class="finding-title-box">
              <div class="finding-title">
                <span>${esc(f.title)}</span>
                <span class="pill ${cls(f.disposition)}">${label(f.disposition)}</span>
                ${f.age_days!=null?`<span class="small" style="background:rgba(255,255,255,.05);padding:2px 8px;border-radius:6px">age ${age(f.age_days)}</span>`:''}
              </div>
              <div class="small">${esc(f.category)}${(f.related_to||[]).length?` · ${esc(f.related_to.join(', '))}`:''}</div>
            </div>
            <div class="finding-sizes">
              <div>
                <b style="font-size:16px;display:block">${bytes(f.size_bytes)}</b>
                <span class="small">Observed</span>
              </div>
              <div class="finding-reclaim">
                <b>${bytes(f.estimated_reclaimable_bytes)}</b>
                <span>Est. Reclaim</span>
              </div>
              <div style="text-align:center;min-width:44px">
                <strong style="font-size:18px;color:${pColor}">${pScore}</strong>
                <span class="small" style="display:block">/100</span>
              </div>
            </div>
          </div>

          <div class="finding-path-bar">
            <span class="finding-path-text" title="${esc(f.path)}">${esc(f.path)}</span>
            <button type="button" class="copy-btn" onclick="copyPath(this,${JSON.stringify(f.path)})" title="Copy absolute path">Copy</button>
          </div>

          <div class="explain-grid">
            <div class="explain-card">
              <div class="explain-card-lbl"><span>i</span> Why It Exists</div>
              <p class="explain-card-txt">${esc(f.why_it_exists||'Not specified')}</p>
            </div>
            <div class="explain-card">
              <div class="explain-card-lbl"><span>🎯</span> Recommended Action</div>
              <p class="explain-card-txt">${esc(f.recommendation||'Review before removal')}</p>
            </div>
            <div class="explain-card">
              <div class="explain-card-lbl"><span>⚠️</span> Risk If Removed</div>
              <p class="explain-card-txt">${esc(f.removal_risk||'Potential service disruption')}</p>
            </div>
          </div>

          <details class="finding-tech">
            <summary>Technical Details & Evidence</summary>
            <div class="tech-pills">
              <span class="tech-pill">Risk: <b>${esc(f.risk||'unknown')}</b></span>
              <span class="tech-pill">Confidence: <b>${esc(f.confidence||'unknown')}</b></span>
              <span class="tech-pill">Basis: <b>${esc(f.evidence?.reclaim_basis||'triage heuristics')}</b></span>
              ${f.evidence?.scope_type?`<span class="tech-pill">Scope: <b>${esc(f.evidence.scope_type)}</b></span>`:''}
              ${(f.related_to||[]).length?`<span class="tech-pill">Related: <b>${esc(f.related_to.join(', '))}</b></span>`:''}
            </div>
          </details>
        </div>
      `;
    }
    body+=`</div>`;
  }

  return pills + toolbar + body;
}

function duplicates(){
  let rows=REPORT.duplicates||[];
  if(!rows.length)return '<div class="small">No exact duplicate groups were verified at this profile/threshold.</div>';
  return rows.slice(0,150).map((d,i)=>`<div class="dupcard"><div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap"><div><b>Duplicate group ${i+1}</b><div class="small mono">SHA-256 ${esc(d.sha256)}</div></div><div><b>${bytes(d.reclaimable_bytes)} potentially reclaimable</b><div class="small">${d.paths.length} paths · ${d.distinct_file_instances} distinct file instances · ${bytes(d.size_bytes_each)} each</div></div></div>${d.note?`<div class="notice" style="margin-top:8px">${esc(d.note)}</div>`:''}<div class="paths">${d.paths.map(p=>`<div class="path">${esc(p)}</div>`).join('')}</div></div>`).join('');
}

function tooling(){
  let rows=REPORT.project_artifacts||[];
  return simpleTable(rows,[['Size',x=>bytes(x.size_bytes)],['Type',x=>`<b>${esc(x.artifact_type)}</b><div class="small">${esc((x.related_to||[]).join(', '))}</div>`],['Age',x=>age(x.age_days)],['Rebuildable',x=>x.rebuildable?'<span class="safe">Likely</span>':'<span class="warn">Not assumed</span>'],['Path / project',x=>`<div class="path">${esc(x.path)}</div>${x.project_root?`<div class="small">Project: <span class="mono">${esc(x.project_root)}</span><br>Markers: ${esc((x.project_markers||[]).join(', '))}</div>`:''}`,'pathcell']]);
}

function collectors(){
  return (REPORT.collectors||[]).map(c=>`<details class="collector"><summary><span class="${c.applicable===false?'small':(c.ok?'safe':'review')}">${c.applicable===false?'–':(c.ok?'●':'○')}</span> <b>${esc(c.name)}</b>${c.error?` <span class="small">— ${esc(c.error)}</span>`:''}</summary><pre>${esc(typeof c.data==='string'?c.data:JSON.stringify(c.data,null,2))}</pre></details>`).join('');
}

function compareView(){
  let box=`<div class="comparebox"><b>Compare with a previous ReconSpace JSON report</b><div class="small">The file is read locally by this browser page; ReconSpace does not automatically store scan history. Maximum import size: 64 MiB.</div><div class="field" style="margin-top:10px"><label for="priorFile">Previous report JSON</label><input id="priorFile" type="file" accept=".json,application/json"></div></div><div id="compareResults" style="margin-top:12px" aria-live="polite"></div>`;
  setTimeout(bindCompare,0);
  return box;
}

function mapBy(rows,key){
  let m=new Map();
  for(let r of rows||[])m.set(key(r),r);
  return m;
}

function deltaClass(n){return n>0?'plus':n<0?'minus':''}

function clientCompare(oldr,newr){
  let os=oldr.stats||{},ns=newr.stats||{},oldRoot=String(os.root||'').replaceAll('/','\\').replace(/\\+$/,'').toLowerCase(),newRoot=String(ns.root||'').replaceAll('/','\\').replace(/\\+$/,'').toLowerCase(),sameRoot=oldRoot&&oldRoot===newRoot,free=(sameRoot&&typeof os.filesystem_free_bytes==='number'&&typeof ns.filesystem_free_bytes==='number')?ns.filesystem_free_bytes-os.filesystem_free_bytes:null;
  let oldd=mapBy(oldr.top_directories,x=>(x.path||'').toLowerCase()),newd=mapBy(newr.top_directories,x=>(x.path||'').toLowerCase()),deltas=[];
  for(let k of new Set([...oldd.keys(),...newd.keys()])){let a=oldd.get(k)?.size_bytes||0,b=newd.get(k)?.size_bytes||0;if(a!==b)deltas.push({path:(newd.get(k)||oldd.get(k)).path,before:a,after:b,delta:b-a})}
  deltas.sort((a,b)=>Math.abs(b.delta)-Math.abs(a.delta));
  let oldf=mapBy(oldr.findings,x=>((x.title||'')+'|'+(x.path||'')).toLowerCase()),newf=mapBy(newr.findings,x=>((x.title||'')+'|'+(x.path||'')).toLowerCase()),added=[...newf.keys()].filter(k=>!oldf.has(k)).map(k=>newf.get(k)),resolved=[...oldf.keys()].filter(k=>!newf.has(k)).map(k=>oldf.get(k));
  let h=`<div class="grid"><div class="metric"><span>Free-space change</span><b class="delta ${deltaClass(-Number(free||0))}">${free==null?'Unknown':(free>=0?'+':'')+bytes(free)}</b><span>positive = more free space</span></div><div class="metric"><span>New findings</span><b>${added.length}</b><span>appeared since prior report</span></div><div class="metric"><span>Resolved findings</span><b>${resolved.length}</b><span>no longer reported</span></div></div><h3>Largest retained-folder changes</h3>`;
  h+=simpleTable(deltas.slice(0,40),[['Delta',x=>`<span class="delta ${deltaClass(x.delta)}">${x.delta>0?'+':''}${bytes(x.delta)}</span>`],['Before',x=>bytes(x.before)],['After',x=>bytes(x.after)],['Path',x=>esc(x.path),'pathcell']]);
  h+=`<div class="twocol" style="margin-top:12px"><div class="chart"><h3>New findings</h3>${added.sort((a,b)=>(b.size_bytes||0)-(a.size_bytes||0)).slice(0,30).map(x=>`<div style="margin:7px 0"><b>${esc(x.title)}</b> · ${bytes(x.size_bytes)}<div class="path">${esc(x.path)}</div></div>`).join('')||'<span class="small">None</span>'}</div><div class="chart"><h3>Resolved findings</h3>${resolved.sort((a,b)=>(b.size_bytes||0)-(a.size_bytes||0)).slice(0,30).map(x=>`<div style="margin:7px 0"><b>${esc(x.title)}</b> · ${bytes(x.size_bytes)}<div class="path">${esc(x.path)}</div></div>`).join('')||'<span class="small">None</span>'}</div></div><div class="notice" style="margin-top:12px">Folder changes compare each report's retained top-N directories, not every filesystem object. ${sameRoot?'Free-space delta is shown because both reports use the same scan root.':'Free-space delta is suppressed because the scan roots differ.'}</div>`;
  return h;
}

function validateImportedReport(value){
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Expected a JSON report object');
  if(!value.stats||typeof value.stats!=='object'||Array.isArray(value.stats))throw new Error('Missing stats object');
  for(let key of ['top_directories','findings']){
    let rows=value[key];
    if(rows===undefined)continue;
    if(!Array.isArray(rows))throw new Error(`${key} must be an array`);
    if(rows.length>MAX_IMPORTED_SECTION_ROWS)throw new Error(`${key} has too many rows`);
    if(rows.some(row=>!row||typeof row!=='object'||Array.isArray(row)))throw new Error(`${key} entries must be objects`);
  }
  return value;
}

function bindCompare(){
  let input=$('#priorFile');
  if(!input)return;
  input.onchange=async()=>{
    let f=input.files?.[0];
    if(!f)return;
    try{
      if(f.size>MAX_IMPORTED_REPORT_BYTES)throw new Error(`Report is too large (${bytes(f.size)}; maximum 64 MiB)`);
      previousReport=validateImportedReport(JSON.parse(await f.text()));
      $('#compareResults').innerHTML=clientCompare(previousReport,REPORT);
    }catch(e){
      previousReport=null;
      $('#compareResults').innerHTML=`<div class="notice error">Could not read report: ${esc(e.message)}</div>`;
    }
  };
}

function ownership(){return simpleTable(REPORT.application_footprints||[],[['Combined',x=>bytes((x.installed_size_bytes||0)+(x.related_data_bytes||0))],['Application',x=>`<b>${esc(x.name)}</b><div class="small">${esc(x.publisher)} · ${esc(x.version)} · confidence ${esc(x.ownership_confidence)}</div>`],['Evidence',x=>`<div>Active: ${(x.active_processes||[]).map(esc).join(', ')||'none observed'}</div><div class="small">Startup ${Number((x.startup_items||[]).length)} · services ${Number((x.services||[]).length)} · tasks ${Number((x.scheduled_tasks||[]).length)} · prefetch ${Number((x.execution_evidence||[]).length)}</div>`],['Related data',x=>`${bytes(x.related_data_bytes||0)}<div class="small">${esc((x.related_paths||[]).slice(0,8).join(' | '))}</div>`],['Interpretation',x=>esc(x.review_note)]])}
function processes(){return simpleTable(REPORT.processes||[],[['Working set',x=>bytes(x.working_set_bytes)],['PID',x=>esc(x.pid)],['Process',x=>`<b>${esc(x.name)}</b><div class="small">${esc(x.owner||'owner unavailable')}</div>`],['Executable',x=>esc(x.executable_path),'pathcell'],['Command line',x=>esc(x.command_line),'pathcell']])}
function trust(){return simpleTable(REPORT.binary_trust||[],[['Status',x=>`<b class="${String(x.signature_status||'').toLowerCase()==='valid'?'safe':'review'}">${esc(x.signature_status||'Unknown')}</b><div class="small">${x.exists===false?'missing target':''}</div>`],['Sources',x=>esc((x.source_kinds||[]).join(', '))],['Signer',x=>`<div>${esc(x.signer_subject||'')}</div><div class="small">${esc(x.signer_issuer||'')}</div>`],['SHA-256',x=>esc(x.sha256||'(not requested)'),'pathcell'],['Path',x=>esc(x.path),'pathcell']])}
function permissions(){return simpleTable(REPORT.path_security||[],[['Signal',x=>x.broad_write_detected?'<span class="review">BROAD WRITE</span>':'<span class="safe">No broad-write rule detected</span>'],['Owner',x=>esc(x.owner)],['Rules',x=>`${x.access_rule_count||0} total · ${x.explicit_rule_count||0} explicit · ${x.deny_rule_count||0} deny`],['Broad identities',x=>esc((x.broad_write_identities||[]).join(' | '))],['Path',x=>esc(x.path),'pathcell']])}
function health(){let h=REPORT.audit_health||{},rules=REPORT.rule_pack_info||{};let out=`${scopeBanner()}<div class="grid"><div class="metric"><span>Coverage score</span><b>${h.coverage_score??'n/a'}</b><span>${esc(h.coverage_grade||'unknown')} · not a system/security score</span></div><div class="metric"><span>Collectors</span><b>${h.collectors_succeeded||0}/${h.collectors_requested||0}</b><span>${h.collectors_failed||0} failed · ${h.collectors_not_applicable||0} not applicable</span></div><div class="metric"><span>Rules</span><b>${rules.rules_loaded||0}</b><span>${rules.matches||0} metadata matches</span></div></div><div class="notice" style="margin-top:12px">${esc(h.interpretation||'')}</div>${depthMatrix()}<div class="twocol" style="margin-top:12px"><div class="chart"><h3>Coverage issues</h3>${(h.issues||[]).map(x=>`<div style="margin:8px 0"><b>${esc(x.severity||'info')}</b> · ${esc(x.message||'')}</div>`).join('')||'<span class="small">None reported.</span>'}</div><div class="chart"><h3>Coverage strengths</h3>${(h.strengths||[]).map(x=>`<div style="margin:8px 0" class="safe">${esc(x)}</div>`).join('')||'<span class="small">No explicit strengths recorded.</span>'}</div></div><h3>Rule packs</h3>`;out+=simpleTable(rules.packs||[],[['Pack',x=>`<b>${esc(x.name)}</b><div class="small">${esc(x.version)} · ${esc(x.source)}</div>`],['Rules',x=>esc(x.rules)],['Matches',x=>esc(x.matches)],['Warnings',x=>esc((x.warnings||[]).join(' | '))]]);return out}

let clutterFilter='all';
function setClutterFilter(f){
  clutterFilter=f;
  render();
}

function cleanupHub(){
  let s=REPORT.stats||{};
  let csColl = getCollector('component_store_analysis');
  let csData = (csColl && csColl.ok && csColl.data) || {};
  let wuColl = getCollector('windows_update_cache');
  let wuData = (wuColl && wuColl.ok && wuColl.data) || {};
  let totalReclaim=(REPORT.findings||[]).reduce((a,c)=>a+(c.estimated_reclaimable_bytes||0),0);
  let cleanupFindings=(REPORT.findings||[]).filter(f=>['system_temp','dev_build','ai_ml','browser_app','apps_installers','virtualization','app_leftovers'].includes(getCategoryGroup(f)));
  let topReclaimable=[...cleanupFindings].sort((a,b)=>(b.estimated_reclaimable_bytes||0)-(a.estimated_reclaimable_bytes||0)).slice(0,8);

  let cats=[
    {id:'system_temp',title:'System & Windows Temp',icon:'◌',desc:'Windows temp, Delivery Optimization, WER crash dumps, and SoftwareDistribution.'},
    {id:'dev_build',title:'Developer & Build Caches',icon:'⌘',desc:'Node modules, Python virtualenvs, Rust target, Pip/NPM/Cargo caches.'},
    {id:'browser_app',title:'Browser & App Data',icon:'◎',desc:'Chromium and Firefox caches, electron storage, and media buffers.'},
    {id:'ai_ml',title:'AI & Machine Learning Models',icon:'⬡',desc:'PyTorch, Hugging Face, Ollama models, and ComfyUI weights.'},
    {id:'virtualization',title:'Virtual Disks & Containers',icon:'▣',desc:'WSL virtual hard disks (ext4.vhdx), Docker layers, and hypervisor images.'},
    {id:'app_leftovers',title:'Orphaned AppData Leftovers',icon:'⌂',desc:'Residual folders left behind by uninstalled applications.'}
  ];

  let catCards=cats.map(c=>{
    let rows=cleanupFindings.filter(f=>getCategoryGroup(f)===c.id);
    let sz=rows.reduce((a,x)=>a+(x.size_bytes||0),0);
    let rc=rows.reduce((a,x)=>a+(x.estimated_reclaimable_bytes||0),0);
    return `<div class="hub-card">
      <div class="hub-card-head">
        <div>
          <div class="hub-card-title"><span>${c.icon}</span> ${esc(c.title)}</div>
          <div class="hub-card-desc">${esc(c.desc)}</div>
        </div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:10px;border-top:1px dashed var(--border)">
        <div><b>${bytes(sz)}</b> <span class="small">(${rows.length} items)</span></div>
        ${rc>0?`<span class="safe" style="font-weight:700;font-size:12px">Est. ${bytes(rc)} reclaim</span>`:''}
      </div>
      <div style="margin-top:8px">
        <button type="button" class="secondary" style="font-size:11px;padding:4px 10px;width:100%" onclick="switchCategory('${c.id}')">Inspect findings</button>
      </div>
    </div>`;
  }).join('');

  return `
    <div class="hub-hero">
      <div class="hub-orb">⌁</div>
      <div>
        <h2>Cleanup Intelligence</h2>
        <p>Comprehensive audit of disposable system caches, developer artifacts, browser caches, and orphaned application leftovers. Strictly read-only with copyable PowerShell commands.</p>
      </div>
      <div class="hub-metrics">
        <div>
          <span class="hub-metric-val safe">${bytes(totalReclaim)}</span>
          <span class="hub-metric-lbl">Est. Reclaimable</span>
        </div>
        <div>
          <span class="hub-metric-val">${cleanupFindings.length}</span>
          <span class="hub-metric-lbl">Candidates</span>
        </div>
      </div>
    </div>

    <div style="margin-top:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Cleanup Categories</h3>
        <span class="small">Click any card to review individual files &amp; findings</span>
      </div>
      <div class="hub-card-grid">${catCards}</div>
    </div>

    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Top Reclaimable Candidates</h3>
        <span class="small">Copy PowerShell command to safely inspect or clean after your own review</span>
      </div>
      ${simpleTable(topReclaimable, [
        ['Item / Path', x => `<b>${esc(x.title)}</b><div class="small mono">${esc(x.path)}</div>`],
        ['Size', x => bytes(x.size_bytes)],
        ['Est. Reclaim', x => `<span class="safe" style="font-weight:700">${bytes(x.estimated_reclaimable_bytes||0)}</span>`],
        ['Disposition', x => `<span class="${cls(x.disposition)}">${label(x.disposition)}</span>`],
        ['Action Recipe', x => `
          <div class="recipe-box" style="margin:0">
            <span class="recipe-code">Get-ChildItem -Path "${esc(x.path)}" -Recurse</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-ChildItem -Path \\'${esc(x.path).replace(/'/g, "''")}\\' -Recurse')">Copy</button>
          </div>
        `]
      ])}
    </div>

    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Windows Storage Audit Recipes</h3>
        <span class="small">Standard Microsoft admin inspection commands for storage assessment</span>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-title">🗂 Windows Temp Directory</div>
          <div class="hub-card-desc">Audit temporary files older than 24 hours in user Temp folder.</div>
          <div class="recipe-box">
            <span class="recipe-code">Get-ChildItem $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Where-Object LastWriteTime -lt (Get-Date).AddDays(-1) | Measure-Object -Property Length -Sum</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-ChildItem $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Where-Object LastWriteTime -lt (Get-Date).AddDays(-1) | Measure-Object -Property Length -Sum')">Copy</button>
          </div>
        </div>
        <div class="hub-card">
          <div class="hub-card-title">📦 DISM Component Store Analysis</div>
          <div class="hub-card-desc">
            ${csData.actual_size_bytes ? `<div>WinSxS Actual Physical: <b>${bytes(csData.actual_size_bytes)}</b> (Reported: ${bytes(csData.explorer_reported_bytes)})</div><div style="margin-top:2px">Hardlink Deduplication Savings: <b class="safe">${bytes(csData.hardlink_dedup_savings_bytes)}</b></div><div style="margin-top:2px">Cleanup Recommended: <b class="${csData.cleanup_recommended?'review':'safe'}">${csData.cleanup_recommended?'Yes':'No'}</b></div>` : 'Analyze superseded Windows packages to evaluate WinSxS reclaim potential.'}
          </div>
          <div class="recipe-box">
            <span class="recipe-code">Dism.exe /online /Cleanup-Image /AnalyzeComponentStore</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Dism.exe /online /Cleanup-Image /AnalyzeComponentStore')">Copy</button>
          </div>
        </div>
        <div class="hub-card">
          <div class="hub-card-title">🚀 Windows Update &amp; Delivery Cache</div>
          <div class="hub-card-desc">
            ${wuData.software_distribution_download_bytes != null ? `<div>Update Download Cache: <b>${bytes(wuData.software_distribution_download_bytes)}</b> (${wuData.software_distribution_download_files||0} files)</div><div>Update DataStore: <b>${bytes(wuData.software_distribution_datastore_bytes)}</b></div>` : 'Inspect cached peer delivery bandwidth and downloaded update payloads.'}
          </div>
          <div class="recipe-box">
            <span class="recipe-code">Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-ChildItem &quot;$env:SystemRoot\\SoftwareDistribution\\Download&quot; -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum')">Copy</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

function protectionHub(){
  let defColl = getCollector('defender_status');
  let privColl = getCollector('privacy_consent_store');
  let browserColl = getCollector('browser_privacy_footprints');
  let trustRows = REPORT.binary_trust || [];
  let unsignedCount = trustRows.filter(x => String(x.signature_status||'').toLowerCase() !== 'valid').length;
  
  let defStatus = (defColl && defColl.ok && defColl.data?.Status) || {};
  let defThreats = (defColl && defColl.ok && defColl.data?.Threats) || [];
  let rtEnabled = defStatus.RealTimeProtectionEnabled;
  let sigAge = defStatus.AntivirusSignatureAge;
  let engVer = defStatus.ProductVersion || defStatus.EngineVersion || 'Windows Defender';

  let privData = (privColl && privColl.ok && privColl.data) || {};
  let webcamApps = privData.webcam || [];
  let micApps = privData.microphone || [];
  let locApps = privData.location || [];
  let totalPerms = webcamApps.length + micApps.length + locApps.length;

  let browsers = (browserColl && browserColl.ok && browserColl.data) || [];

  let extColl = getCollector('browser_extensions');
  let extList = (extColl && extColl.ok && Array.isArray(extColl.data)) ? extColl.data : [];
  let highRiskExts = extList.filter(x => x.risk_level === 'high');

  let persistColl = getCollector('extended_persistence');
  let persistList = (persistColl && persistColl.ok && Array.isArray(persistColl.data)) ? persistColl.data : [];

  let adsColl = getCollector('alternate_data_streams');
  let adsData = (adsColl && adsColl.ok && adsColl.data) || {};
  let totalStreams = adsData.total_streams || 0;

  return `
    <div class="hub-hero">
      <div class="hub-orb" style="background:linear-gradient(135deg,#5dd39e,#348aa7)">◇</div>
      <div>
        <h2>Security &amp; Privacy Protection</h2>
        <p>Windows security posture audit: Microsoft Defender real-time protection, signature currency, hardware privacy permissions (ConsentStore), browser footprints, and Authenticode binary trust.</p>
      </div>
      <div class="hub-metrics">
        <div>
          <span class="hub-metric-val ${rtEnabled === false ? 'review' : 'safe'}">${rtEnabled === false ? 'Disabled' : (defColl ? 'Active' : 'N/A')}</span>
          <span class="hub-metric-lbl">Defender RT Protection</span>
        </div>
        <div>
          <span class="hub-metric-val">${totalPerms}</span>
          <span class="hub-metric-lbl">Active Permissions</span>
        </div>
        <div>
          <span class="hub-metric-val ${unsignedCount > 0 ? 'review' : 'safe'}">${unsignedCount}</span>
          <span class="hub-metric-lbl">Unsigned Binaries</span>
        </div>
      </div>
    </div>

    <!-- Defender Health Card -->
    <div style="margin-top:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Microsoft Defender Antivirus Status</h3>
        <span class="small">Read via Get-MpComputerStatus</span>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-title">🛡 Real-Time &amp; Antivirus Protection</div>
          <div class="hub-card-desc">
            <div>Antivirus Enabled: <b>${defStatus.AntivirusEnabled ?? 'Yes'}</b></div>
            <div>Real-Time Protection: <b class="${rtEnabled === false ? 'review' : 'safe'}">${rtEnabled === false ? 'Disabled (Attention!)' : 'Enabled'}</b></div>
            <div>Behavior Monitor: <b>${defStatus.BehaviorMonitorEnabled ?? 'Enabled'}</b></div>
            <div>Tamper Protection: <b>${defStatus.TamperProtection ?? 'Active'}</b></div>
          </div>
          <div class="recipe-box">
            <span class="recipe-code">Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureAge</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureAge')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">📅 Antivirus Definitions &amp; Engine</div>
          <div class="hub-card-desc">
            <div>Engine Version: <b>${esc(engVer)}</b></div>
            <div>Signatures Age: <b class="${(sigAge > 7) ? 'review' : 'safe'}">${sigAge != null ? sigAge + ' day(s) old' : 'Current'}</b></div>
            <div>Last Updated: <b>${esc(defStatus.AntivirusSignatureLastUpdated || 'Recent')}</b></div>
          </div>
          <div class="recipe-box">
            <span class="recipe-code">Update-MpSignature</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Update-MpSignature')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">⚠️ Threat Detection Log</div>
          <div class="hub-card-desc">
            ${defThreats.length > 0 ? defThreats.map(t => `<div>• <b>${esc(t.ThreatName || 'Threat')}</b> <span class="small">(${esc(t.InitialDetectionTime||'')})</span></div>`).join('') : '<span class="safe">No active threat detections logged.</span>'}
          </div>
          <div class="recipe-box">
            <span class="recipe-code">Get-MpThreatDetection | Select-Object ThreatName, InitialDetectionTime, ThreatStatusID</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-MpThreatDetection | Select-Object ThreatName, InitialDetectionTime, ThreatStatusID')">Copy</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Hardware Privacy ConsentStore -->
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Hardware Privacy Permissions (ConsentStore)</h3>
        <span class="small">Desktop &amp; Packaged apps granted hardware sensors</span>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-title">📷 Webcam Access (${webcamApps.length} apps)</div>
          <div class="hub-card-desc">Apps granted access to your video camera:</div>
          <div class="perm-list">
            ${webcamApps.length ? webcamApps.map(a => `<span class="perm-badge">📷 ${esc(a.name.split('/').pop())} <small>(${esc(a.scope)})</small></span>`).join('') : '<span class="small">No third-party camera grants detected.</span>'}
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">🎙 Microphone Access (${micApps.length} apps)</div>
          <div class="hub-card-desc">Apps granted access to your audio microphone:</div>
          <div class="perm-list">
            ${micApps.length ? micApps.map(a => `<span class="perm-badge">🎙 ${esc(a.name.split('/').pop())} <small>(${esc(a.scope)})</small></span>`).join('') : '<span class="small">No third-party microphone grants detected.</span>'}
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">📍 Location Access (${locApps.length} apps)</div>
          <div class="hub-card-desc">Apps granted access to device geolocation:</div>
          <div class="perm-list">
            ${locApps.length ? locApps.map(a => `<span class="perm-badge">📍 ${esc(a.name.split('/').pop())} <small>(${esc(a.scope)})</small></span>`).join('') : '<span class="small">No third-party location grants detected.</span>'}
          </div>
        </div>
      </div>
      <div class="recipe-box" style="margin-top:10px">
        <span class="recipe-code">Get-ChildItem "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore" -Recurse</span>
        <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-ChildItem \\'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\' -Recurse')">Copy</button>
      </div>
    </div>

    <!-- Browser Privacy Footprints -->
    ${browsers.length ? `
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Browser Privacy Profile Footprints</h3>
        <span class="small">Local history, cookies, and SQLite databases</span>
      </div>
      <div class="hub-card-grid">
        ${browsers.map(b => `
          <div class="hub-card">
            <div class="hub-card-title">🌐 ${esc(b.browser)}</div>
            <div class="hub-card-desc">
              <div>Total profile data: <b>${bytes(b.total_bytes)}</b></div>
              <div class="small" style="margin-top:4px">
                ${Object.entries(b.data_files||{}).map(([k,v]) => `${esc(k)}: ${bytes(v)}`).join(' · ')}
              </div>
            </div>
            <div class="recipe-box">
              <span class="recipe-code">Get-Item "${esc(b.profile_path)}"</span>
              <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-Item \\'${esc(b.profile_path).replace(/'/g, "''")}\\'')">Copy</button>
            </div>
          </div>
        `).join('')}
      </div>
    </div>` : ''}

    <!-- Binary Trust Summary -->
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Authenticode Binary Trust</h3>
        <button type="button" class="secondary" style="font-size:11px" onclick="switchTab('trust')">View full trust table (${trustRows.length})</button>
      </div>
      ${simpleTable(trustRows.slice(0, 8), [
        ['Status', x => `<b class="${String(x.signature_status||'').toLowerCase()==='valid'?'safe':'review'}">${esc(x.signature_status||'Unknown')}</b>`],
        ['Binary / Signer', x => `<b>${esc(x.signer_subject||'Unsigned')}</b><div class="small mono">${esc(x.path)}</div>`],
        ['Sources', x => esc((x.source_kinds||[]).join(', '))]
      ])}
    </div>

    <!-- Browser Extensions Privacy & Security -->
    ${extList.length ? `
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Browser Extensions Privacy &amp; Permissions</h3>
        <span class="small">${extList.length} extensions audited (${highRiskExts.length} elevated)</span>
      </div>
      ${simpleTable(extList.slice(0, 8), [
        ['Risk', x => `<b class="${x.risk_level === 'high' ? 'review' : 'safe'}">${esc(x.risk_level.toUpperCase())}</b>`],
        ['Extension', x => `<b>${esc(x.name)}</b> <span class="small">(v${esc(x.version)})</span><div class="small">${esc(x.browser)} · ${esc(x.profile)}</div>`],
        ['Key Permissions', x => `<div class="small mono">${esc((x.permissions||[]).slice(0, 5).join(', ')||'none')}</div>`]
      ])}
    </div>` : ''}

    <!-- Extended Persistence (Shell ContextMenuHandlers, AppInit, Winlogon) -->
    ${persistList.length ? `
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Extended Autoruns &amp; Shell Extensions</h3>
        <span class="small">${persistList.length} persistence entries audited</span>
      </div>
      ${simpleTable(persistList.slice(0, 8), [
        ['Type', x => `<b>${esc(x.category)}</b>`],
        ['Handler Name', x => `<b>${esc(x.name)}</b><div class="small mono">${esc(x.target_path||x.clsid||'')}</div>`],
        ['Security Check', x => x.is_user_writable ? '<b class="review">User-Writable Path</b>' : (x.target_exists === false ? '<b class="review">Missing Target</b>' : '<b class="safe">System Protected</b>')]
      ])}
    </div>` : ''}

    <!-- Alternate Data Streams (ADS) -->
    ${totalStreams > 0 ? `
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Alternate Data Streams (ADS)</h3>
        <span class="small">${totalStreams} streams detected (${adsData.zone_identifier_streams || 0} Zone.Identifier download markers)</span>
      </div>
      ${simpleTable((adsData.streams || []).slice(0, 6), [
        ['File', x => `<b>${esc(x.file_name)}</b><div class="small mono">${esc(x.file_path)}</div>`],
        ['Stream', x => `<span class="mono">${esc(x.stream_name)}</span>`],
        ['Size', x => bytes(x.size_bytes)],
        ['Type', x => x.is_zone_identifier ? '<span class="safe">Mark of the Web (Zone.Identifier)</span>' : '<span class="review">Hidden NTFS Data Stream</span>']
      ])}
    </div>` : ''}
  `;
}

function performanceHub(){
  let memColl = getCollector('system_memory_status');
  let mem = (memColl && memColl.ok && memColl.data) || {};
  let totalPhys = mem.total_physical_bytes || 0;
  let availPhys = mem.available_physical_bytes || 0;
  let usedPhys = mem.used_physical_bytes || (totalPhys - availPhys);
  let loadPct = mem.memory_load_pct != null ? mem.memory_load_pct : (totalPhys ? Math.round(usedPhys / totalPhys * 100) : 0);
  let totalPage = mem.total_pagefile_bytes || 0;
  let availPage = mem.available_pagefile_bytes || 0;
  let usedPage = totalPage - availPage;

  let procs = [...(REPORT.processes || [])].sort((a,b) => (b.working_set_bytes||0) - (a.working_set_bytes||0));
  let topProcs = procs.slice(0, 10);
  let startupItems = REPORT.startup || [];

  return `
    <div class="hub-hero">
      <div class="hub-orb" style="background:linear-gradient(135deg,#ffd166,#ef476f)">↯</div>
      <div>
        <h2>System Performance &amp; Speed</h2>
        <p>Monitor physical RAM pressure, working set distribution across running processes, boot persistence overhead, and run standard Microsoft maintenance recipes.</p>
      </div>
      <div class="hub-metrics">
        <div>
          <span class="hub-metric-val ${loadPct >= 85 ? 'review' : 'safe'}">${loadPct}%</span>
          <span class="hub-metric-lbl">RAM Load</span>
        </div>
        <div>
          <span class="hub-metric-val">${bytes(availPhys)}</span>
          <span class="hub-metric-lbl">Available RAM</span>
        </div>
        <div>
          <span class="hub-metric-val">${startupItems.length}</span>
          <span class="hub-metric-lbl">Startup Items</span>
        </div>
      </div>
    </div>

    <!-- RAM Usage Bar -->
    <div class="chart" style="margin-top:20px">
      <h3>Memory Allocation &amp; Pressure (Win32 GlobalMemoryStatusEx)</h3>
      <div><b>${bytes(usedPhys)}</b> physical RAM used of <b>${bytes(totalPhys)}</b> · <span class="safe">${bytes(availPhys)} free</span></div>
      <div class="diskbar" style="margin:10px 0"><i style="width:${loadPct}%;background:${loadPct>=85?'var(--bad)':loadPct>=70?'var(--warn)':'var(--primary)'}"></i></div>
      ${totalPage > 0 ? `<div class="small" style="margin-top:4px">Committed Pagefile: <b>${bytes(usedPage)}</b> of <b>${bytes(totalPage)}</b> (${bytes(availPage)} free)</div>` : ''}
    </div>

    <!-- Top Processes by Working Set -->
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Top Memory-Consuming Processes</h3>
        <button type="button" class="secondary" style="font-size:11px" onclick="switchTab('processes')">All processes (${procs.length})</button>
      </div>
      ${simpleTable(topProcs, [
        ['Working Set', x => `<b>${bytes(x.working_set_bytes)}</b>`],
        ['PID', x => esc(x.pid)],
        ['Process Name', x => `<b>${esc(x.name)}</b><div class="small">${esc(x.owner||'')}</div>`],
        ['Executable Path', x => esc(x.executable_path), 'pathcell']
      ])}
    </div>

    <!-- Maintenance Recipes Grid (8 items) -->
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Windows Speed &amp; Maintenance Recipes</h3>
        <span class="small">Safe, standard Windows PowerShell administrative routines</span>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-title">🌐 Flush DNS Client Cache</div>
          <div class="hub-card-desc">Resolves host connection stalls and stale local DNS lookups.</div>
          <div class="recipe-box">
            <span class="recipe-code">Clear-DnsClientCache</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Clear-DnsClientCache')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">⚡ Optimize &amp; TRIM Solid State Drive</div>
          <div class="hub-card-desc">Sends TRIM commands to SSD to maintain high write speeds.</div>
          <div class="recipe-box">
            <span class="recipe-code">Optimize-Volume -DriveLetter C -Defrag -Verbose</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Optimize-Volume -DriveLetter C -Defrag -Verbose')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">📦 Analyze Component Store (DISM)</div>
          <div class="hub-card-desc">Checks if superseded system files can be safely pruned.</div>
          <div class="recipe-box">
            <span class="recipe-code">dism.exe /Online /Cleanup-Image /AnalyzeComponentStore</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'dism.exe /Online /Cleanup-Image /AnalyzeComponentStore')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">🛠 Repair Windows System Image (DISM)</div>
          <div class="hub-card-desc">Repairs corrupted Windows components from official Windows Update.</div>
          <div class="recipe-box">
            <span class="recipe-code">DISM.exe /Online /Cleanup-Image /RestoreHealth</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'DISM.exe /Online /Cleanup-Image /RestoreHealth')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">🔍 System File Checker (SFC)</div>
          <div class="hub-card-desc">Scans integrity of all protected system files and repairs damaged ones.</div>
          <div class="recipe-box">
            <span class="recipe-code">sfc /scannow</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'sfc /scannow')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">🧹 Audit WER Crash Dump Storage</div>
          <div class="hub-card-desc">Inspect storage consumed by accumulated user-mode application crash dumps.</div>
          <div class="recipe-box">
            <span class="recipe-code">Get-ChildItem -Path "$env:LOCALAPPDATA\\CrashDumps" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-ChildItem -Path \"$env:LOCALAPPDATA\\CrashDumps\" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">🚀 Delivery Optimization Status</div>
          <div class="hub-card-desc">Inspect peer delivery bandwidth and cache size.</div>
          <div class="recipe-box">
            <span class="recipe-code">Get-DeliveryOptimizationStatus</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-DeliveryOptimizationStatus')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">🔎 Windows Search Indexer Status</div>
          <div class="hub-card-desc">Inspect Windows search catalog service status and startup mode.</div>
          <div class="recipe-box">
            <span class="recipe-code">Get-Service -Name WSearch | Select-Object Name, Status, StartType</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-Service -Name WSearch | Select-Object Name, Status, StartType')">Copy</button>
          </div>
        </div>

        <div class="hub-card">
          <div class="hub-card-title">⚡ Trim Process Working Sets (EmptyWorkingSet)</div>
          <div class="hub-card-desc">Signals Windows Memory Manager to trim working set pages into standby list, relieving active physical RAM.</div>
          <div class="recipe-box">
            <span class="recipe-code">[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.Diagnostics.Process]::GetProcesses() | ForEach-Object { try { $_.MinWorkingSet = $_.MinWorkingSet } catch {} }</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, '[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.Diagnostics.Process]::GetProcesses() | ForEach-Object { try { $_.MinWorkingSet = $_.MinWorkingSet } catch {} }')">Copy</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

function applicationsHub(){
  let apps = REPORT.applications || [];
  let orphColl = getCollector('orphaned_app_data');
  let orphList = (orphColl && orphColl.ok && Array.isArray(orphColl.data)) ? orphColl.data : [];
  let orphBytes = orphList.reduce((a, x) => a + (x.size_bytes || 0), 0);

  let wingetColl = getCollector('winget_catalog_correlation');
  let wingetData = (wingetColl && wingetColl.ok && wingetColl.data) || {};
  let wingetUpgrades = wingetData.upgrades || [];

  let extColl = getCollector('browser_extensions');
  let extList = (extColl && extColl.ok && Array.isArray(extColl.data)) ? extColl.data : [];

  return `
    <div class="hub-hero">
      <div class="hub-orb" style="background:linear-gradient(135deg,#ff70a6,#70d6ff)">▦</div>
      <div>
        <h2>Applications &amp; Leftovers Manager</h2>
        <p>Inspect installed software footprints, discover residual AppData folders left behind by uninstalled applications (Bulk Crap Uninstaller heuristics), and review silent uninstall recipes.</p>
      </div>
      <div class="hub-metrics">
        <div>
          <span class="hub-metric-val">${apps.length}</span>
          <span class="hub-metric-lbl">Installed Apps</span>
        </div>
        <div>
          <span class="hub-metric-val safe">${orphList.length}</span>
          <span class="hub-metric-lbl">Orphan Leftovers</span>
        </div>
        <div>
          <span class="hub-metric-val">${bytes(orphBytes)}</span>
          <span class="hub-metric-lbl">Leftover Bytes</span>
        </div>
      </div>
    </div>

    <!-- Orphaned AppData Leftovers Section -->
    <div style="margin-top:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Orphaned AppData Leftovers</h3>
        <span class="small">Folders found in AppData / ProgramData with no matching registered application</span>
      </div>
      ${orphList.length > 0 ? simpleTable(orphList, [
        ['Leftover Name', x => `<b>${esc(x.name)}</b><div class="small mono">${esc(x.location_env||'AppData')}</div>`],
        ['Size', x => `<b class="safe">${bytes(x.size_bytes)}</b>`],
        ['Path', x => esc(x.path), 'pathcell'],
        ['Inspect Recipe', x => `
          <div class="recipe-box" style="margin:0">
            <span class="recipe-code">Get-ChildItem -Path "${esc(x.path)}" -Recurse</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-ChildItem -Path \\'${esc(x.path).replace(/'/g, "''")}\\' -Recurse')">Copy</button>
          </div>
        `]
      ]) : '<div class="notice">No orphaned application directories detected in scanned AppData locations.</div>'}
    </div>

    <!-- Installed Applications with Quiet Uninstall Recipes -->
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Installed Software &amp; Uninstall Commands</h3>
        <div style="display:flex;gap:8px">
          <button type="button" class="secondary" style="font-size:11px" onclick="switchTab('ownership')">Application Footprints</button>
          <button type="button" class="secondary" style="font-size:11px" onclick="switchTab('apps')">Full Applications View</button>
        </div>
      </div>
      ${simpleTable(apps.slice(0, 15), [
        ['Application', x => `<b>${esc(x.name)}</b><div class="small">${esc(x.publisher||'')} · v${esc(x.version||'')}</div>`],
        ['Estimated Size', x => bytes(x.estimated_size_bytes)],
        ['Install Path', x => esc(x.install_location||'(Windows registry)'), 'pathcell'],
        ['Uninstall Recipe', x => `
          <div class="recipe-box" style="margin:0">
            <span class="recipe-code">winget uninstall --name "${esc(x.name)}"</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'winget uninstall --name \\'${esc(x.name).replace(/'/g, "''")}\\'')">Copy</button>
          </div>
        `]
      ])}
    </div>

    <!-- WinGet Upgrades Section -->
    ${wingetUpgrades.length > 0 ? `
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">WinGet Application Updates Available (${wingetUpgrades.length})</h3>
        <span class="small">Correlated against Microsoft WinGet catalog</span>
      </div>
      ${simpleTable(wingetUpgrades.slice(0, 10), [
        ['Application', x => `<b>${esc(x.name)}</b><div class="small mono">${esc(x.id)}</div>`],
        ['Current', x => `v${esc(x.version)}`],
        ['Available', x => `<b class="safe">v${esc(x.available_version)}</b>`],
        ['Upgrade Recipe', x => `
          <div class="recipe-box" style="margin:0">
            <span class="recipe-code">winget upgrade --id "${esc(x.id)}"</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'winget upgrade --id \\'${esc(x.id).replace(/'/g, "''")}\\'')">Copy</button>
          </div>
        `]
      ])}
    </div>` : ''}

    <!-- Installed Browser Extensions & Add-ons -->
    ${extList.length > 0 ? `
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Installed Browser Extensions &amp; Add-ons</h3>
        <span class="small">${extList.length} extensions audited across Chrome, Edge, Brave, and Firefox</span>
      </div>
      ${simpleTable(extList.slice(0, 12), [
        ['Extension', x => `<b>${esc(x.name)}</b> <span class="small">v${esc(x.version)}</span><div class="small">${esc(x.browser)} · ${esc(x.profile)}</div>`],
        ['Risk', x => `<b class="${x.risk_level==='high'?'review':x.risk_level==='medium'?'warn':'safe'}">${esc(x.risk_level.toUpperCase())}</b>`],
        ['Permissions', x => `<div class="small mono">${esc((x.permissions||[]).slice(0, 4).join(', ')||'none')}</div>`]
      ])}
    </div>` : ''}
  `;
}

function clutterHub(){
  let s = REPORT.stats || {};
  let dups = REPORT.duplicates || [];
  let dupBytes = dups.reduce((a, d) => a + (d.wasted_bytes || 0), 0);
  let files = REPORT.top_files || [];
  let dirs = (REPORT.top_directories || []).filter(x => x.path !== s.root).slice(0, 12);
  let maxDirSize = Math.max(...dirs.map(x => x.size_bytes || 0), 1);

  let nowSec = Date.now() / 1000;
  let archiveExts = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.vhd', '.vhdx', '.wim']);
  let mediaExts = new Set(['.mp4', '.mkv', '.mov', '.avi', '.mp3', '.wav', '.flac', '.png', '.jpg', '.jpeg']);
  
  let filteredFiles = files.filter(f => {
    let sz = f.size_bytes || 0;
    let ageDays = f.modified_ts ? (nowSec - f.modified_ts) / 86400 : 0;
    let ext = (f.extension || '').toLowerCase();
    if(clutterFilter === '1gb') return sz >= 1024 * 1024 * 1024;
    if(clutterFilter === '500mb') return sz >= 500 * 1024 * 1024 && sz < 1024 * 1024 * 1024;
    if(clutterFilter === '1yr') return ageDays >= 365;
    if(clutterFilter === '6mo') return ageDays >= 180;
    if(clutterFilter === 'archives') return archiveExts.has(ext);
    if(clutterFilter === 'media') return mediaExts.has(ext);
    return true;
  });

  return `
    <div class="hub-hero">
      <div class="hub-orb" style="background:linear-gradient(135deg,#06d6a0,#118ab2)">◌</div>
      <div>
        <h2>My Clutter &amp; Space Lens</h2>
        <p>Interactive visual disk hierarchy (Space Lens), exact duplicate byte analysis, and large &amp; forgotten file inspector to quickly pinpoint and eliminate disk bloat.</p>
      </div>
      <div class="hub-metrics">
        <div>
          <span class="hub-metric-val safe">${bytes(dupBytes)}</span>
          <span class="hub-metric-lbl">Duplicate Waste</span>
        </div>
        <div>
          <span class="hub-metric-val">${dups.length}</span>
          <span class="hub-metric-lbl">Duplicate Sets</span>
        </div>
        <div>
          <span class="hub-metric-val">${files.length}</span>
          <span class="hub-metric-lbl">Large Files</span>
        </div>
      </div>
    </div>

    <!-- Space Lens Hierarchy -->
    <div style="margin-top:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Space Lens — Proportional Folder Map</h3>
        <span class="small">Click any folder to inspect its direct contents in the Folders tab</span>
      </div>
      <div class="lens-tree">
        ${dirs.map(d => {
          let pct = Math.min(100, Math.round((d.size_bytes || 0) / maxDirSize * 100));
          return `
            <div class="lens-row" onclick="switchTab('dirs')" title="Inspect ${esc(d.path)} in Folders view">
              <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600">📁 ${esc(d.path.split(/[\\/]/).filter(Boolean).pop()||d.path)}</div>
              <div class="lens-bar-wrap"><div class="lens-bar" style="width:${pct}%"></div></div>
              <div style="text-align:right;font-weight:750">${bytes(d.size_bytes)}</div>
            </div>
          `;
        }).join('')}
      </div>
    </div>

    <!-- Duplicate Summary Card -->
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Exact Duplicate Files</h3>
        <button type="button" class="secondary" style="font-size:11px" onclick="switchTab('duplicates')">View all duplicate groups (${dups.length})</button>
      </div>
      <div class="notice">
        <b>${dups.length} duplicate sets</b> consuming <b>${bytes(dupBytes)}</b> of redundant disk space. Hardlink deduplication or manual cleanup can recover this storage.
      </div>
    </div>

    <!-- Large & Old Files Filter Bar and Table -->
    <div style="margin-top:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Large &amp; Old Files Inspector</h3>
        <span class="small">${filteredFiles.length} file(s) matched filter</span>
      </div>
      <div class="filter-bar">
        <button type="button" class="filter-btn ${clutterFilter==='all'?'active':''}" onclick="setClutterFilter('all')">All Large Files</button>
        <button type="button" class="filter-btn ${clutterFilter==='1gb'?'active':''}" onclick="setClutterFilter('1gb')">&gt; 1 GB</button>
        <button type="button" class="filter-btn ${clutterFilter==='500mb'?'active':''}" onclick="setClutterFilter('500mb')">500 MB – 1 GB</button>
        <button type="button" class="filter-btn ${clutterFilter==='1yr'?'active':''}" onclick="setClutterFilter('1yr')">Older than 1 Year</button>
        <button type="button" class="filter-btn ${clutterFilter==='6mo'?'active':''}" onclick="setClutterFilter('6mo')">Older than 6 Months</button>
        <button type="button" class="filter-btn ${clutterFilter==='archives'?'active':''}" onclick="setClutterFilter('archives')">Archives &amp; ISOs</button>
        <button type="button" class="filter-btn ${clutterFilter==='media'?'active':''}" onclick="setClutterFilter('media')">Media &amp; Video</button>
      </div>
      ${simpleTable(filteredFiles.slice(0, 20), [
        ['Size', x => `<b>${bytes(x.size_bytes)}</b>`],
        ['Type', x => esc(x.extension || '(none)')],
        ['Age / Modified', x => x.modified_ts ? new Date(x.modified_ts * 1000).toLocaleDateString() : 'unknown'],
        ['Path', x => esc(x.path), 'pathcell'],
        ['Inspect', x => `
          <div class="recipe-box" style="margin:0">
            <span class="recipe-code">Get-Item "${esc(x.path)}"</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-Item \\'${esc(x.path).replace(/'/g, "''")}\\'')">Copy</button>
          </div>
        `]
      ])}
    </div>
  `;
}

function render(){
  if(!REPORT)return;
  let v=currentView,h='';
  if(v==='overview')h=overview();
  else if(v==='cleanup_hub')h=cleanupHub();
  else if(v==='protection_hub')h=protectionHub();
  else if(v==='performance_hub')h=performanceHub();
  else if(v==='applications_hub')h=applicationsHub();
  else if(v==='clutter_hub')h=clutterHub();
  else if(v==='plan')h=actionPlan();
  else if(v==='findings')h=findings();
  else if(v==='dirs')h=simpleTable(REPORT.top_directories||[],[['Size',x=>bytes(x.size_bytes)],['Direct files',x=>bytes(x.direct_size_bytes)],['Path',x=>esc(x.path),'pathcell']]);
  else if(v==='files')h=simpleTable(REPORT.top_files||[],[['Logical',x=>bytes(x.size_bytes)],['Allocated',x=>x.allocated_bytes==null?'Unknown':bytes(x.allocated_bytes)],['Type',x=>esc(x.extension||'(none)')],['Modified',x=>x.modified_ts?new Date(x.modified_ts*1000).toLocaleString():''],['Links',x=>String(x.link_count||1)],['Path',x=>esc(x.path),'pathcell']]);
  else if(v==='duplicates')h=duplicates();
  else if(v==='tooling')h=tooling();
  else if(v==='apps')h=simpleTable(REPORT.applications||[],[['Size',x=>bytes(x.estimated_size_bytes)],['Application',x=>`<b>${esc(x.name)}</b><div class="small">${esc(x.publisher)} · ${esc(x.version)}</div>`],['Class',x=>esc(x.classification)],['Install location',x=>esc(x.install_location),'pathcell']]);
  else if(v==='ownership')h=ownership();
  else if(v==='processes')h=processes();
  else if(v==='trust')h=trust();
  else if(v==='permissions')h=permissions();
  else if(v==='health')h=health();
  else if(v==='startup')h=simpleTable(REPORT.startup||[],[['Hint',x=>x.risk_hint?`<span class="review">REVIEW</span><div class="small">${esc(x.reason)}</div>`:'<span class="safe">No simple indicator</span>'],['Name',x=>`<b>${esc(x.name)}</b><div class="small">${esc(x.source)}</div>`],['Command',x=>esc(x.command),'pathcell']]);
  else if(v==='services')h=simpleTable(REPORT.services||[],[['Hint',x=>x.risk_hint?`<span class="review">REVIEW</span><div class="small">${esc(x.reason)}</div>`:'<span class="safe">No simple indicator</span>'],['State',x=>esc(x.state)],['Start',x=>esc(x.start_mode)],['Service',x=>`<b>${esc(x.display_name)}</b><div class="small">${esc(x.name)} · ${esc(x.start_name||'')}</div>`],['Binary/path',x=>esc(x.path_name),'pathcell']]);
  else if(v==='tasks')h=simpleTable(REPORT.scheduled_tasks||[],[['Hint',x=>x.risk_hint?`<span class="review">REVIEW</span><div class="small">${esc(x.reason)}</div>`:'<span class="safe">No simple indicator</span>'],['State',x=>esc(x.state)],['Task',x=>`<b>${esc(x.task_name)}</b><div class="small">${esc(x.task_path)} · ${esc(x.author)}${x.hidden?' · hidden':''}</div>`],['Actions',x=>esc((x.actions||[]).join(' | ')),'pathcell']]);
  else if(v==='system')h=collectors();
  else if(v==='compare')h=compareView();
  else if(v==='notes')h=(REPORT.notes||[]).map(n=>`<div class="notice" style="margin:8px 0">${esc(n)}</div>`).join('');
  
  let activeId=document.activeElement?document.activeElement.id:null;
  let selStart=document.activeElement?document.activeElement.selectionStart:null;
  let selEnd=document.activeElement?document.activeElement.selectionEnd:null;

  $('#view').innerHTML=h;

  if(v==='plan'){
    let planExport=$('#planExportInline');
    if(planExport)planExport.onclick=()=>$('#exportPlan').click();
  }

  if(v==='findings'){
    ['findQ','findDisp','findSort'].forEach(id=>{
      let e=$('#'+id);
      if(e){
        e.oninput=()=>render();
        e.onchange=()=>render();
      }
    });
    if(activeId){
      let el=$('#'+activeId);
      if(el){
        el.focus();
        if(selStart!==null&&el.setSelectionRange){
          el.setSelectionRange(selStart,selEnd);
        }
      }
    }
  }
}

async function poll(){
  let nextPollMs=2400;
  try{
    if(!token)throw new Error('This dashboard link has no local session token. Close it and launch ReconSpace again.');
    let r=await fetch('/api/status',{cache:'no-store',credentials:'omit',headers:{'X-ReconSpace-Token':token}});
    if(!r.ok)throw new Error(r.status===403?'The local session expired. Close this page and launch ReconSpace again.':`Dashboard status request failed (${r.status}).`);
    let s=await r.json();
    pollFailures=0;
    clearError('connection');

    // Pulse heartbeat
    let beat=$('#heartbeatDot');
    if(beat){
      beat.classList.add('beat');
      setTimeout(()=>beat.classList.remove('beat'),300);
      $('#heartbeatText').textContent=s.running?'Engine Active':'Engine Standby';
    }

    $('#scan').disabled=s.running;
    $('#cancel').disabled=!s.running;

    let p=s.progress||{},phase=p.phase||'idle';
    let stageIdx=getStageIndex(phase);
    updatePipelineStepper(stageIdx,s.running);

    let pct=calculateProgressPct(phase,p);
    $('#progressBar').style.width=pct+'%';
    $('#progressPct').textContent=pct+'%';
    $('#progress').setAttribute('aria-valuenow',String(pct));

    // Determine headline and detail
    let headline='Ready to audit',detail='',text=phase.replaceAll('_',' ');
    if(phase==='queued'){
      headline='Audit Queued';
      detail='Preparing environment and checking root permissions…';
    }else if(phase==='filesystem'){
      headline=`Scanning Filesystem (${Number(p.files_seen||0).toLocaleString()} files traversed)`;
      detail=p.path||'Traversing directory tree…';
      text+=` — ${Number(p.files_seen).toLocaleString()} files, ${bytes(p.bytes_seen||0)} traversed — ${p.path||''}`;
    }else if(phase==='filesystem_done'){
      headline='Filesystem Traversal Complete';
      detail=`Discovered ${Number(p.files_seen||0).toLocaleString()} files (${bytes(p.bytes_seen||0)})`;
    }else if(phase==='duplicates'||phase==='duplicate_hashing'){
      if(p.stage){
        headline=`Duplicate Content Analysis (${p.stage})`;
        detail=`Hashing candidate: ${p.path||''}${p.size_bytes?` (${bytes(p.size_bytes)})`:''}`;
        text+=` (${p.stage}) — ${p.path||''}${p.size_bytes?` (${bytes(p.size_bytes)})`:''}`;
      }else{
        headline=`Duplicate Group Collation [${Number(p.done||0).toLocaleString()} / ${Number(p.total||0).toLocaleString()}]`;
        detail='Grouping candidate files by byte length and hardlink identity…';
        text+=` — ${Number(p.done||0).toLocaleString()} / ${Number(p.total||0).toLocaleString()} candidates`;
      }
    }else if(phase==='project_context'){
      headline='Discovering Project & Tooling Artifacts';
      detail='Classifying build outputs, node_modules, cache, and virtualenvs…';
    }else if(phase==='applications'){
      headline='Auditing Installed Applications';
      detail='Querying Windows Uninstall registry and AppX/MSIX packages…';
    }else if(phase==='startup'){
      headline='Auditing Windows Startup & Persistence';
      detail='Inspecting HKCU/HKLM Run keys and startup folder links…';
    }else if(phase==='windows_deep_inventory'){
      let itemStr=(p.item||'').replaceAll('_',' ');
      headline=`Windows Deep System Inventory [${p.done||0}/${p.total||41}]`;
      detail=p.detail||`Checking ${itemStr}…`;
      text=`windows deep inventory [${p.done||0}/${p.total||41}] — ${p.item||''}`;
    }else if(phase==='process_context'){
      headline='Active Process Context & Security Tokens';
      detail='Inspecting process memory footprints and query owner security accounts…';
    }else if(phase==='execution_metadata'){
      headline='Reading Execution Metadata';
      detail='Inspecting Windows Prefetch metadata timestamps…';
    }else if(phase==='rule_intelligence'){
      headline='Evaluating Heuristic Rule Packs';
      detail='Executing metadata-only pattern matching against discovered files…';
    }else if(phase==='classification'){
      headline='Normalizing Findings & Storage Health';
      detail='Ranking candidate sizes and safety ratings…';
    }else if(phase==='binary_trust'){
      headline=`Verifying Authenticode Signatures ${p.batch?`[Batch ${p.batch}/${p.total_batches}]`:''}`;
      detail=p.detail||'Checking digital signatures and catalog trust…';
      text=`binary trust ${p.batch?`[batch ${p.batch}/${p.total_batches}]`:''} — ${p.detail||''}`;
    }else if(phase==='ownership_permissions'){
      headline=`Auditing Security Permissions ${p.batch?`[Batch ${p.batch}/${p.total_batches}]`:''}`;
      detail=p.detail||'Evaluating folder ACL rules for broad write access…';
      text=`ownership permissions ${p.batch?`[batch ${p.batch}/${p.total_batches}]`:''} — ${p.detail||''}`;
    }else if(phase==='ownership_graph'){
      headline='Building Application Ownership Graph';
      detail='Correlating directories, data paths, active processes, and services…';
    }else if(phase==='done'){
      headline='Audit Completed Successfully';
      detail=`Identified ${Number(p.findings||0).toLocaleString()} findings. Results available below.`;
      text='Audit complete';
    }else if(phase==='cancelled'){
      headline='Audit Cancelled by User';
      detail='Audit was safely interrupted before modifying any state.';
      text='Audit cancelled';
    }else if(phase==='failed'){
      headline='Audit Failed';
      detail=s.error||'An unexpected error occurred during execution.';
      text='Audit failed';
    }

    $('#status').textContent=text;
    $('#activeDetailText').textContent=detail?`${headline} — ${detail}`:headline;

    // Status pill state
    let pill=$('#statusPill');
    let pillText=$('#statusBadgeText');
    pill.className='status-pill '+(s.running?'running':phase==='done'?'done':phase==='cancelled'?'cancelled':phase==='failed'?'failed':'idle');
    pillText.textContent=s.running?'Live Audit Running':phase==='done'?'Audit Completed':phase==='cancelled'?'Cancelled':phase==='failed'?'Failed':'Ready';

    // Reassurance note during process owner lookup
    let note=$('#reassuranceNote');
    if(phase==='process_context'){
      note.textContent='Process security-token queries can take 30–90 seconds or longer on service-heavy systems. Live timer confirms engine activity.';
      note.classList.remove('hidden');
    }else{
      note.classList.add('hidden');
    }

    // Log significant changes to activity feed
    if(phase!==lastKnownPhase){
      lastKnownPhase=phase;
      if(phase==='done'){
        logActivity(`Audit finished: ${Number(p.findings||0).toLocaleString()} findings generated`, 'success');
      }else if(phase==='cancelled'){
        logActivity(`Audit cancelled by user`, 'item');
      }else if(phase==='failed'){
        logActivity(`Audit failed: ${s.error}`, 'item');
      }else{
        logActivity(`Stage: ${headline}`, 'stage');
      }
    }else if(p.item&&p.done%5===0){
      logActivity(`  Collector [${p.done}/${p.total}]: ${p.item.replaceAll('_',' ')}`, 'item');
    }else if(p.batch){
      logActivity(`  Trust check batch ${p.batch}/${p.total_batches}`, 'item');
    }

    if(s.running){
      nextPollMs=800;
      $('#progress').classList.add('indeterminate');
      if(!timerInterval){
        timerInterval=setInterval(updateTimer,250);
      }
    }else{
      $('#progress').classList.remove('indeterminate');
      if(timerInterval){
        clearInterval(timerInterval);
        timerInterval=null;
      }
    }

    if(s.error)showError(s.error);

    if(s.has_report&&!REPORT){
      let reportResponse=await fetch('/api/report',{cache:'no-store',credentials:'omit',headers:{'X-ReconSpace-Token':token}});
      if(!reportResponse.ok)throw new Error(`Report request failed (${reportResponse.status}).`);
      REPORT=await reportResponse.json();
      $('#summary').classList.remove('hidden');
      renderMetrics();
      navigatePage(currentPage,false);
    }
  }catch(e){
    pollFailures++;
    if(pollFailures>=2){
      let detail=String(e?.message||'');
      let message=/failed to fetch|networkerror|load failed/i.test(detail)?'Cannot reach the local ReconSpace service. Close this page and launch ReconSpace again if the app was stopped.':(detail||'Cannot reach the local ReconSpace service.');
      showError(message,'connection');
      $('#status').textContent='Disconnected from local service';
      $('#scan').disabled=true;
      $('#cancel').disabled=true;
    }
  }
  setTimeout(poll,nextPollMs);
}

$('#scan').onclick=async()=>{
  let root=$('#root').value.trim().replace(/^["']|["']$/g,'').trim();
  if(!root){
    showError('Enter a local drive or folder to scan.');
    $('#root').focus();
    return;
  }
  REPORT=null;
  previousReport=null;
  $('#summary').classList.add('hidden');
  clearError();
  $('#scan').disabled=true;
  $('#status').textContent='Submitting audit…';
  scanStartTime=Date.now();
  activityEventsCount=0;
  $('#activityFeed').innerHTML='';
  logActivity(`Initiating audit on ${root} (${$('#profile').value} profile)...`, 'stage');
  
  let lines=id=>$(id).value.split(/\r?\n/).map(x=>x.trim().replace(/^["']|["']$/g,'').trim()).filter(Boolean);
  let body={
    root,
    profile:$('#profile').value,
    excluded_paths:lines('#exclude'),
    keep_paths:lines('#keep'),
    rule_pack_paths:lines('#rulePacks'),
    hash_stateful_files:$('#statefulHash').checked,
    signature_hashes:$('#signatureHashes').checked,
    skip_signatures:$('#noSignatures').checked,
    skip_permissions:$('#noPermissions').checked,
    skip_processes:$('#noProcesses').checked,
    skip_prefetch:$('#noPrefetch').checked
  };
  if($('#dupmin').value)body.duplicate_min_mb=Number($('#dupmin').value);
  try{
    let r=await fetch('/api/scan',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json','X-ReconSpace-Token':token},body:JSON.stringify(body)});
    if(!r.ok)throw new Error(await r.text());
    $('#status').textContent='Audit queued…';
    logActivity('Audit received and queued by engine', 'item');
  }catch(e){
    showError(e.message||'Could not start the audit.');
    $('#status').textContent='Audit did not start';
    $('#scan').disabled=false;
    scanStartTime=null;
  }
};

$('#cancel').onclick=async()=>{
  try{
    let r=await fetch('/api/cancel',{method:'POST',credentials:'omit',headers:{'X-ReconSpace-Token':token}});
    if(!r.ok)throw new Error(await r.text());
    $('#status').textContent='Cancelling audit…';
    logActivity('Cancellation signal sent to engine...', 'stage');
  }catch(e){
    showError(e.message||'Could not cancel the audit.');
  }
};

function initTabs(){
  let tabs=[...$$('.tab')];
  let tablist=$('.tabs');
  let syncOrientation=()=>tablist.setAttribute('aria-orientation',matchMedia('(max-width:760px)').matches?'horizontal':'vertical');
  syncOrientation();
  addEventListener('resize',syncOrientation,{passive:true});
  tabs.forEach((button,index)=>{
    button.id=`audit-tab-${button.dataset.view}`;
    button.setAttribute('aria-controls','view');
    button.setAttribute('tabindex',index===0?'0':'-1');
    button.onclick=()=>switchTab(button.dataset.view);
    button.onkeydown=event=>{
      let delta=event.key==='ArrowDown'||event.key==='ArrowRight'?1:event.key==='ArrowUp'||event.key==='ArrowLeft'?-1:0;
      let target=event.key==='Home'?0:event.key==='End'?tabs.length-1:delta?(index+delta+tabs.length)%tabs.length:-1;
      if(target<0)return;
      event.preventDefault();
      switchTab(tabs[target].dataset.view);
      tabs[target].focus();
    };
  });
}

$$('button[data-page]').forEach(button=>button.addEventListener('click',()=>navigatePage(button.dataset.page)));
$$('.care-tile').forEach((tile,index)=>{
  const page=['cleanup','protection','performance','applications','clutter'][index];
  tile.setAttribute('role','button');tile.setAttribute('tabindex','0');
  tile.onclick=()=>navigatePage(page);
  tile.onkeydown=event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage(page);}};
});
addEventListener('popstate',()=>navigatePage(location.hash.slice(1),false));
navigatePage(location.hash.slice(1)||'home',false);

function planMarkdown(){
  let items=(REPORT.findings||[]).filter(f=>['probably_safe_cleanup','manual_review'].includes(f.disposition)&&(f.estimated_reclaimable_bytes||0)>0).sort((a,b)=>(b.priority_score||0)-(a.priority_score||0));
  let rs=REPORT.reclaim_summary||{},ah=REPORT.audit_health||{};
  let md=[
    '# ReconSpace Review / Approval Plan','','**Mode: PLAN ONLY — NO EXECUTION**','',
    `- Scan root: \`${String(REPORT.stats?.root||'').replaceAll('`',"'")}\``,
    `- Profile: **${REPORT.profile||''}**`,
    `- Pending items: **${items.length}**`,
    `- Audit evidence quality: **${ah.coverage_grade||'unknown'} (${ah.coverage_score??'n/a'}/100)**`,
    '- Scope: File/folder candidates are limited to the selected root. Application, process, persistence, virtualization and Windows platform evidence can describe the wider host.',
    `- Conservative non-overlapping path candidates: **${bytes(rs.path_candidates_nonoverlap_bytes||0)}**`,
    `- Duplicate potential (separate / non-additive): **${bytes(rs.duplicate_potential_bytes_separate||0)}**`,
    `- Application potential (separate / non-additive): **${bytes(rs.application_potential_bytes_separate||0)}**`,
    `- Platform potential (separate / non-additive): **${bytes(rs.platform_potential_bytes_separate||0)}**`,
    '','## Guardrails','',
    '- No filesystem, application, container, VM, service, task, Registry, driver or Windows cleanup action is executed by this plan.',
    '- Every item remains pending review until ownership, current use, backup/retention needs and the supported management workflow are confirmed.',
    '- DO NOT TOUCH and INTENTIONAL TOOLING findings are excluded from the actionable total.',
    '- Reclaim estimates are triage estimates, not guarantees.',
    '- Path, duplicate, application and platform potentials can overlap and MUST NOT be added together without manual review.',
    '','## Audit depth',''
  ];
  (ah.depth_domains||[]).forEach(d=>{
    let limits=(d.limitations||[]).slice(0,6).map(x=>String(x).replaceAll('_',' ')).join(', ');
    md.push(`- **${d.title}: ${String(d.status||'unknown').replaceAll('_',' ').toUpperCase()}** — ${d.checks_succeeded||0}/${d.checks_requested||0} applicable checks succeeded${limits?`; limited/unavailable: ${limits}`:''}`);
  });
  md.push('','## Ranked pending items','');
  items.forEach((f,i)=>{
    let p=String(f.path||'').replaceAll('`',"'");
    md.push(
      `### [ ] RS-${String(i+1).padStart(4,'0')} — ${f.title}`,
      '- Approval: **PENDING_REVIEW**',
      `- Path: \`${p}\``,
      `- Observed / estimated reclaimable: **${bytes(f.size_bytes)} / ${bytes(f.estimated_reclaimable_bytes)}**`,
      `- Disposition: **${f.disposition}** | Risk: **${f.risk}** | Confidence: **${f.confidence}** | Priority: **${Number(f.priority_score||0).toFixed(1)}**`,
      `- Why it exists: ${f.why_it_exists}`,
      `- Recommended management: ${f.recommendation}`,
      `- Risk if removed: ${f.removal_risk}`,
      '- Execution: **NONE**',''
    );
  });
  return md.join('\n');
}

$('#exportPlan').onclick=()=>{
  if(!REPORT)return;
  let blob=new Blob([planMarkdown()],{type:'text/markdown'}),a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='reconspace-approval-plan.md';
  a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
};

$('#export').onclick=()=>{
  if(!REPORT)return;
  let blob=new Blob([JSON.stringify(REPORT,null,2)],{type:'application/json'}),a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  let dt=(REPORT.stats?.finished_at||'').replaceAll(':','-').replaceAll('+','_');
  a.download=`reconspace-${REPORT.profile||'scan'}-${dt||'audit'}.json`;
  a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
};

$('#profile').onchange=profileHint;
initTabs();
profileHint();
poll();
</script>
</body>
</html>'''.replace("__PROFILES__", profiles).replace("__VERSION__", __version__)


class Handler(BaseHTTPRequestHandler):
    server_version = f"ReconSpace/{__version__}"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _token_ok(self) -> bool:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        provided = qs.get("token", [""])[0] or self.headers.get("X-ReconSpace-Token", "")
        return secrets.compare_digest(provided, TOKEN)

    def _headers(self, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(length))

    def _send_json(self, obj: object, status: int = 200) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, text: str, status: int = 400) -> None:
        payload = text.encode("utf-8", "replace")
        self.send_response(status)
        self._headers("text/plain; charset=utf-8", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            payload = _html().encode("utf-8")
            self.send_response(200)
            self._headers("text/html; charset=utf-8", len(payload))
            self.end_headers()
            self.wfile.write(payload)
            return
        if not self._token_ok():
            self._send_json({"error": "invalid local session token"}, 403)
            return
        if parsed.path == "/api/status":
            self._send_json(STATE.snapshot())
            return
        if parsed.path == "/api/report":
            with STATE.lock:
                report = STATE.report
            if report is None:
                self._send_json({"error": "no report yet"}, 404)
            else:
                self._send_json(report)
            return
        self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if not self._token_ok():
            self._send_json({"error": "invalid local session token"}, 403)
            return

        if parsed.path == "/api/cancel":
            with STATE.lock:
                running = STATE.running
                if running:
                    STATE.cancel_event.set()
                    STATE.progress = {"phase": "cancelling"}
            self._send_json({"ok": True, "running": running}, 202 if running else 200)
            return

        if parsed.path != "/api/scan":
            self._send_json({"error": "not found"}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 1024 * 1024:
                self._send_text("request body too large", 413)
                return
            body = json.loads(self.rfile.read(length) or b"{}", parse_constant=_reject_json_constant)
            if not isinstance(body, dict):
                self._send_text("request body must be a JSON object", 400)
                return
            root_value = body.get("root", "C:\\")
            root = _request_path(root_value, "scan root")
            if not os.path.exists(root):
                self._send_text(f"scan root does not exist: {root}", 400)
                return
            if not os.path.isdir(root):
                self._send_text(f"scan root is not a directory: {root}", 400)
                return
            profile = str(body.get("profile") or "deep")
            if profile not in PROFILE_DEFAULTS:
                self._send_text("invalid scan profile", 400)
                return
            dup_raw = body.get("duplicate_min_mb")
            if dup_raw in {None, ""}:
                dup = None
            elif isinstance(dup_raw, bool) or not isinstance(dup_raw, int):
                self._send_text("duplicate_min_mb must be an integer", 400)
                return
            else:
                dup = dup_raw
            if dup is not None and not 1 <= dup <= 1024 * 1024:
                self._send_text("duplicate_min_mb out of range", 400)
                return
            exclusions_raw = body.get("excluded_paths") or []
            if not isinstance(exclusions_raw, list) or len(exclusions_raw) > 50:
                self._send_text("excluded_paths must be a list of at most 50 paths", 400)
                return
            exclusions: list[str] = []
            for item in exclusions_raw:
                p = _request_path(item, "excluded path")
                if not _scope_contains(root, p):
                    self._send_text(f"excluded path must be a strict descendant of scan root: {p}", 400)
                    return
                exclusions.append(p)
            keep_raw = body.get("keep_paths") or []
            if not isinstance(keep_raw, list) or len(keep_raw) > 100:
                self._send_text("keep_paths must be a list of at most 100 paths", 400)
                return
            keep_paths: list[str] = []
            for item in keep_raw:
                p = _request_path(item, "keep path")
                if not _scope_equal_or_contains(root, p):
                    self._send_text(f"keep path must be the scan root or a descendant: {p}", 400)
                    return
                keep_paths.append(p)

            rule_raw = body.get("rule_pack_paths") or []
            if not isinstance(rule_raw, list) or len(rule_raw) > 20:
                self._send_text("rule_pack_paths must be a list of at most 20 paths", 400)
                return
            rule_paths: list[str] = []
            for item in rule_raw:
                p = _request_path(item, "rule pack path")
                if not os.path.isfile(p) or not p.casefold().endswith(".json"):
                    self._send_text(f"rule pack must be an existing JSON file: {p}", 400)
                    return
                if os.path.getsize(p) > 2 * 1024 * 1024:
                    self._send_text(f"rule pack is larger than 2 MiB: {p}", 400)
                    return
                rule_paths.append(p)

            bool_fields = {
                "hash_stateful_files": False,
                "signature_hashes": False,
                "skip_signatures": False,
                "skip_permissions": False,
                "skip_processes": False,
                "skip_prefetch": False,
            }
            values: dict[str, bool] = {}
            for key, default in bool_fields.items():
                value = body.get(key, default)
                if not isinstance(value, bool):
                    self._send_text(f"{key} must be a boolean", 400)
                    return
                values[key] = value
            config = AuditConfig(
                root=root,
                profile=profile,
                duplicate_min_mb=dup,
                excluded_paths=tuple(exclusions),
                keep_paths=tuple(keep_paths),
                rule_pack_paths=tuple(rule_paths),
                hash_stateful_files=values["hash_stateful_files"],
                signature_hashes=True if values["signature_hashes"] else None,
                verify_signatures=False if values["skip_signatures"] else None,
                collect_path_security=False if values["skip_permissions"] else None,
                collect_processes=False if values["skip_processes"] else None,
                collect_prefetch=False if values["skip_prefetch"] else None,
            )
        except (ValueError, TypeError, OverflowError, json.JSONDecodeError) as exc:
            self._send_text(f"invalid request: {exc}", 400)
            return

        with STATE.lock:
            if STATE.running:
                self._send_text("an audit is already running", 409)
                return
            STATE.running = True
            STATE.report = None
            STATE.error = ""
            STATE.cancel_event.clear()
            STATE.progress = {"phase": "queued", "root": config.root, "profile": config.profile}

        def worker() -> None:
            def progress(p: dict) -> None:
                with STATE.lock:
                    STATE.progress = p
            try:
                report = run_audit(config, progress=progress, cancel=STATE.cancel_event.is_set)
                with STATE.lock:
                    STATE.report = report.to_dict()
                    STATE.progress = {"phase": "done", "findings": len(report.findings)}
            except (ScanCancelled, DuplicateScanCancelled):
                with STATE.lock:
                    STATE.progress = {"phase": "cancelled"}
                    STATE.error = ""
            except Exception as exc:  # UI boundary: surface error, never mutate system state.
                with STATE.lock:
                    STATE.error = f"{type(exc).__name__}: {exc}"
                    STATE.progress = {"phase": "failed"}
            finally:
                with STATE.lock:
                    STATE.running = False

        threading.Thread(target=worker, daemon=True, name="ReconSpaceAudit").start()
        self._send_json({"ok": True, "root": config.root, "profile": config.profile}, 202)


class LocalThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("ReconSpace UI intentionally binds only to loopback/localhost")
    server = LocalThreadingHTTPServer((host, port), Handler)
    actual_host, actual_port = server.server_address[:2]
    shown_host = "127.0.0.1" if actual_host in {"0.0.0.0", "::"} else actual_host
    url = f"http://{shown_host}:{actual_port}/?token={TOKEN}"
    print("ReconSpace read-only UI:")
    print(url)
    print("No cleanup/removal endpoint exists. Reports persist only when you explicitly export them.")
    if open_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    p = argparse.ArgumentParser(description="ReconSpace local read-only audit UI")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true")
    args = p.parse_args()
    serve("127.0.0.1", args.port, not args.no_browser)


if __name__ == "__main__":
    main()
