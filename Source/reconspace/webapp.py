from __future__ import annotations

import argparse
import errno
import json
import ntpath
import os
import secrets
import threading
import webbrowser
from importlib.resources import files
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .ai_advisor import (
    AIProviderConfig,
    ai_review_to_json,
    build_advisor_prompt,
    query_ai_advisor,
    render_ai_review_markdown,
)
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


def _sample_preview_report() -> dict[str, object]:
    return {
        "version": __version__,
        "profile": "deep",
        "root": "C:\\",
        "summary": {
            "reclaimable_bytes": 14_850_000_000,
            "reclaimable_breakdown": {
                "system_cache": 4_200_000_000,
                "delivery_optimization": 3_500_000_000,
                "crash_dumps": 1_850_000_000,
                "recycle_bin": 2_100_000_000,
                "developer_artifacts": 3_200_000_000,
            },
            "total_files": 412_000,
            "total_dirs": 48_000,
        },
        "findings": [
            {
                "id": "sample-hibernation",
                "category": "system_cache",
                "severity": "info",
                "title": "Hibernation File (Dism++ style)",
                "detail": "hiberfil.sys is 16 GiB. Reduced hibernation could reclaim 8 GiB.",
                "reclaimable_bytes": 8_589_934_592,
            }
        ],
        "system_inventory": {
            "os": "Windows 11 Pro 64-bit",
            "hibernation_pagefile": {"hibernation_enabled": True, "hiberfil_size_bytes": 17179869184},
            "battery_health": {"has_battery": True, "wear_level_percent": 4.5},
        },
    }


def _html() -> str:
    profiles = json.dumps({k: v for k, v in PROFILE_DEFAULTS.items()}, separators=(",", ":"))
    return r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ReconSpace — Windows Storage Intelligence</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='18' fill='%23111e35'/%3E%3Ccircle cx='32' cy='32' r='18' fill='none' stroke='%2368dce5' stroke-width='4'/%3E%3Ccircle cx='32' cy='32' r='5' fill='%23dfffff'/%3E%3C/svg%3E" />
<style>__CARE_CSS__</style>
</head>
<body>
<!-- Global SVG Gradient Definitions & Symbols -->
<svg style="position:absolute;width:0;height:0;overflow:hidden;pointer-events:none;" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="cmmGradSmart" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f43f5e"/>
      <stop offset="50%" stop-color="#75c6d7"/>
      <stop offset="100%" stop-color="#38bdf8"/>
    </linearGradient>
    <linearGradient id="cmmGradClean" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f2fe"/>
      <stop offset="60%" stop-color="#38bdf8"/>
      <stop offset="100%" stop-color="#7fc6d5"/>
    </linearGradient>
    <linearGradient id="cmmGradProt" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#10b981"/>
      <stop offset="50%" stop-color="#34d399"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <linearGradient id="cmmGradPerf" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#fbbf24"/>
      <stop offset="50%" stop-color="#f97316"/>
      <stop offset="100%" stop-color="#ef4444"/>
    </linearGradient>
    <linearGradient id="cmmGradApps" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ec4899"/>
      <stop offset="50%" stop-color="#68bccd"/>
      <stop offset="100%" stop-color="#7bc8d7"/>
    </linearGradient>
    <linearGradient id="cmmGradClutter" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#75c6d7"/>
      <stop offset="50%" stop-color="#7fc6d5"/>
      <stop offset="100%" stop-color="#60bed1"/>
    </linearGradient>
    <linearGradient id="cmmGradReports" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#06b6d4"/>
      <stop offset="100%" stop-color="#8b5cf6"/>
    </linearGradient>
    <linearGradient id="cmmGradAi" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#9cd8e4"/>
      <stop offset="50%" stop-color="#38bdf8"/>
      <stop offset="100%" stop-color="#f472b6"/>
    </linearGradient>
    <linearGradient id="cmmGradSettings" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#9badb1"/>
      <stop offset="100%" stop-color="#cbd5e1"/>
    </linearGradient>
    <g id="cmm-ico-smart">
      <path d="M12 2L14.6 8.4L21 11L14.6 13.6L12 20L9.4 13.6L3 11L9.4 8.4L12 2Z" fill="url(#cmmGradSmart)"/>
      <circle cx="12" cy="11" r="2.5" fill="#ffffff"/>
      <circle cx="18" cy="5" r="1.2" fill="#38bdf8"/>
      <circle cx="6" cy="17" r="1" fill="#f43f5e"/>
    </g>
    <g id="cmm-ico-clean">
      <path d="M15 4l5 5-9.5 9.5a2.5 2.5 0 01-1.77.73H5v-3.73a2.5 2.5 0 01.73-1.77L15 4z" fill="url(#cmmGradClean)"/>
      <path d="M9 15l2 2" stroke="#ffffff" stroke-width="1.6" stroke-linecap="round"/>
      <circle cx="19" cy="4" r="1.5" fill="#ffffff"/>
      <circle cx="7" cy="5" r="1.2" fill="#00f2fe"/>
      <circle cx="18" cy="14" r="1.2" fill="#38bdf8"/>
    </g>
    <g id="cmm-ico-protection">
      <path d="M12 3l8 3.5v5.5c0 5-3.5 9.5-8 10.5-4.5-1-8-5.5-8-10.5V6.5L12 3z" fill="url(#cmmGradProt)"/>
      <path d="M9 12l2 2 4-4" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <g id="cmm-ico-performance">
      <path d="M14.5 9.5L5 19H3v-2l9.5-9.5" fill="url(#cmmGradPerf)"/>
      <path d="M13 2.5l4.5 4.5c2 2 2 4.5.5 6.5l-2.5 2.5-5-5 2.5-2.5c2-1.5 4.5-1.5 6.5.5" fill="url(#cmmGradPerf)" opacity="0.9"/>
      <circle cx="14" cy="7" r="1.6" fill="#ffffff"/>
      <path d="M3 21l3.5-1-2.5-2.5-1 3.5z" fill="#f59e0b"/>
    </g>
    <g id="cmm-ico-applications">
      <rect x="3" y="3" width="7.5" height="7.5" rx="2.5" fill="url(#cmmGradApps)"/>
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="2.5" fill="url(#cmmGradApps)" opacity="0.85"/>
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="2.5" fill="url(#cmmGradApps)" opacity="0.85"/>
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="2.5" fill="url(#cmmGradApps)"/>
      <circle cx="6.75" cy="6.75" r="1.5" fill="#ffffff"/>
      <circle cx="17.25" cy="17.25" r="1.5" fill="#ffffff"/>
    </g>
    <g id="cmm-ico-clutter">
      <circle cx="12" cy="12" r="9" stroke="url(#cmmGradClutter)" stroke-width="2" fill="none"/>
      <circle cx="12" cy="12" r="5.5" stroke="rgba(255,255,255,0.4)" stroke-width="1.5" fill="url(#cmmGradClutter)" fill-opacity="0.3"/>
      <circle cx="12" cy="12" r="2.5" fill="#ffffff"/>
      <path d="M12 3v3M12 18v3M3 12h3M18 12h3" stroke="rgba(255,255,255,0.5)" stroke-width="1.5" stroke-linecap="round"/>
    </g>
    <g id="cmm-ico-reports">
      <path d="M6 3h8l5 5v13H6V3z" fill="url(#cmmGradReports)"/>
      <path d="M14 3v5h5" fill="rgba(255,255,255,0.3)"/>
      <path d="M9 13h6M9 17h4" stroke="#ffffff" stroke-width="1.6" stroke-linecap="round"/>
    </g>
    <g id="cmm-ico-ai">
      <path d="M12 2l2.5 7.5L22 12l-7.5 2.5L12 22l-2.5-7.5L2 12l7.5-2.5L12 2z" fill="url(#cmmGradAi)"/>
      <circle cx="12" cy="12" r="3" fill="#ffffff"/>
    </g>
    <g id="cmm-ico-settings">
      <path d="M12 15a3 3 0 100-6 3 3 0 000 6z" fill="#ffffff"/>
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z" fill="url(#cmmGradSettings)"/>
    </g>
  </defs>
</svg>

<div class="wrap">

<header class="hero">
  <div class="brand">
    <h1>
      <span class="logo-icon" aria-hidden="true"></span>
      <span>ReconSpace</span>
      <span class="version-badge">v__VERSION__</span>
    </h1>
  </div>
  <nav class="rail-nav" aria-label="Main navigation">
    <span id="railSelection" class="rail-selection" aria-hidden="true"></span>
    <span class="rail-label">Care</span>
    <button type="button" class="rail-item active" data-page="home"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-smart"/></svg></span><span>Smart Audit</span></button>
    <button type="button" class="rail-item" data-page="cleanup"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-clean"/></svg></span><span>Cleanup</span></button>
    <button type="button" class="rail-item" data-page="protection"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-protection"/></svg></span><span>Protection</span></button>
    <button type="button" class="rail-item" data-page="performance"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-performance"/></svg></span><span>Performance</span></button>
    <span class="rail-label">Manage</span>
    <button type="button" class="rail-item" data-page="applications"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-applications"/></svg></span><span>Applications</span></button>
    <button type="button" class="rail-item" data-page="clutter"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-clutter"/></svg></span><span>My Clutter</span></button>
    <button type="button" class="rail-item" data-page="reports"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-reports"/></svg></span><span>Reports</span></button>
    <button type="button" class="rail-item" data-page="ai"><span class="rail-icon"><svg viewBox="0 0 24 24" width="20" height="20"><use href="#cmm-ico-ai"/></svg></span><span>AI Advisor</span></button>
  </nav>
  <div class="badges">
    <button type="button" class="assistant-card" data-page="ai" title="Open AI Audit Advisor"><span class="assistant-orb" style="background:linear-gradient(135deg,#9cd8e4,#38bdf8)"><svg viewBox="0 0 24 24" width="18" height="18"><use href="#cmm-ico-ai"/></svg></span><span><b>✦ AI Advisor</b><small id="topAiSub">Intelligent system review</small></span><span style="font-size:18px;color:var(--text-dim)">›</span></button>
    <span class="badge">● READ-ONLY ENGINE</span>
    <button type="button" class="rail-item" data-page="settings"><span class="rail-icon"><svg viewBox="0 0 24 24" width="18" height="18"><use href="#cmm-ico-settings"/></svg></span><span>Scan settings</span></button>
  </div>
</header>

<main class="workspace">
<div class="workspace-head">
  <div>
    <span class="workspace-kicker">Windows care, made clear</span>
    <h1 id="pageTitle">Smart Audit</h1>
  </div>
  <div class="workspace-actions"><label class="motion-choice" for="motionPreference">Motion<select id="motionPreference" onchange="CareMotion.setPreference(this.value)"><option value="system">System</option><option value="full">Full</option><option value="reduced">Reduced</option></select></label><button class="secondary zoom-control" type="button" aria-label="Zoom out" onclick="setZoom(-.05)">−</button><button class="secondary zoom-readout" id="zoomReadout" type="button" aria-label="Reset zoom" onclick="setZoom(0)">100%</button><button class="secondary zoom-control" type="button" aria-label="Zoom in" onclick="setZoom(.05)">+</button><button type="button" class="secondary" data-page="settings">Scan settings</button></div>
</div>

<div id="moduleIntro" class="hidden"></div>
<nav id="flowNavigation" class="flow-navigation hidden" aria-label="Review navigation"></nav>
<div id="flowContent" class="hidden"></div>
<dialog id="flowDialog" aria-label="Review and scan confirmation"></dialog>
<div class="panel" id="scanComposer">
  <div class="smart-stage">
    <div class="smart-copy">
      <span class="smart-eyebrow">A little care goes a long way</span>
      <h2>Your PC.<br><span class="cmm-aurora-text">A clearer picture.</span></h2>
      <p>Discover what takes up space, understand your system, and review what deserves a closer look.</p><div class="intro-features"><button class="intro-feature" onclick="navigatePage('cleanup')"><span>◷</span><span>Understand your storage</span></button><button class="intro-feature" onclick="navigatePage('performance')"><span>↗</span><span>Explore your system activity</span></button><button class="intro-feature" onclick="navigatePage('protection')"><span>◇</span><span>Review trust and protection</span></button></div>
    </div>
    <div class="care-visual" data-parallax aria-hidden="true">
      <span class="scene-halo"></span><span class="scene-ring ring-one"></span><span class="scene-ring ring-two"></span>
      <div class="parallax-object"><img class="desktop-art" src="/assets/care-desktop.png" alt="" fetchpriority="high" width="400" height="350"></div>
    </div>
  </div>
  <div id="welcomeActions" class="welcome-actions">
    <button type="button" class="scope-choice" onclick="navigatePage('settings')"><span id="scopeSummary">C:\ · Deep audit</span><span>Change scope ›</span></button>
    <p class="welcome-note">An audit only. Your files stay exactly where they are.</p>
  </div>
  <div class="care-strip" aria-label="Smart Audit coverage">
    <div class="care-tile cleanup" tabindex="0" role="button" onclick="navigatePage('cleanup')">
      <span class="care-tile-icon"><svg viewBox="0 0 24 24" width="24" height="24"><use href="#cmm-ico-clean"/></svg></span>
      <div><b>Cleanup</b><small>Files &amp; storage</small></div>
      <span class="care-tile-status">Ready</span>
    </div>
    <div class="care-tile protection" tabindex="0" role="button" onclick="navigatePage('protection')">
      <span class="care-tile-icon"><svg viewBox="0 0 24 24" width="24" height="24"><use href="#cmm-ico-protection"/></svg></span>
      <div><b>Protection</b><small>Trust &amp; security</small></div>
      <span class="care-tile-status">Ready</span>
    </div>
    <div class="care-tile performance" tabindex="0" role="button" onclick="navigatePage('performance')">
      <span class="care-tile-icon"><svg viewBox="0 0 24 24" width="24" height="24"><use href="#cmm-ico-performance"/></svg></span>
      <div><b>Performance</b><small>Processes &amp; startup</small></div>
      <span class="care-tile-status">Ready</span>
    </div>
    <div class="care-tile applications" tabindex="0" role="button" onclick="navigatePage('applications')">
      <span class="care-tile-icon"><svg viewBox="0 0 24 24" width="24" height="24"><use href="#cmm-ico-applications"/></svg></span>
      <div><b>Applications</b><small>Installed software</small></div>
      <span class="care-tile-status">Ready</span>
    </div>
    <div class="care-tile clutter" tabindex="0" role="button" onclick="navigatePage('clutter')">
      <span class="care-tile-icon"><svg viewBox="0 0 24 24" width="24" height="24"><use href="#cmm-ico-clutter"/></svg></span>
      <div><b>My Clutter</b><small>Large &amp; duplicate files</small></div>
      <span class="care-tile-status">Ready</span>
    </div>
    <div class="care-tile ai" tabindex="0" role="button" onclick="navigatePage('ai')" title="Open AI Audit Advisor">
      <span class="care-tile-icon"><svg viewBox="0 0 24 24" width="24" height="24"><use href="#cmm-ico-ai"/></svg></span>
      <div><b>AI Advisor</b><small>Intelligent review</small></div>
      <span class="care-tile-status" id="homeAiStatus">Ready</span>
    </div>
  </div>
  <div class="setup-label"><span>Choose what to scan</span><span>Everything stays on this PC</span></div>
  <div class="controls">
    <div class="field">
      <label for="root">Scan root</label>
      <input id="root" type="text" value="C:\" spellcheck="false" autocomplete="off" aria-describedby="rootHelp" />
      <div class="quick-chips">
        <button type="button" class="chip" onclick="setRoot('C:\\')">C:\</button>
        <button type="button" class="chip" onclick="setRoot('D:\\')">D:\</button>
        <button type="button" class="chip" onclick="setRoot('%USERPROFILE%')">%USERPROFILE%</button>
        <button type="button" class="chip" onclick="setRoot('%LOCALAPPDATA%')">%LOCALAPPDATA%</button>
        <button type="button" class="chip" onclick="setRoot('%PROGRAMDATA%')">%PROGRAMDATA%</button>
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
    <div id="scanSlot"><button id="scan" type="button"><span class="scan-play">▶</span><span>Scan</span></button></div>
    <button id="cancel" type="button" class="dangerish" disabled>Cancel scan</button>
    <div class="ai-strip" style="grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:rgba(44,131,148,0.12);border:1px solid rgba(44,131,148,0.3);border-radius:12px;margin-top:4px">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
        <input type="checkbox" id="autoAiReview" checked>
        <span><b>✦ Auto-Generate AI Audit Review</b> upon scan completion (offline heuristic or configured cloud LLM)</span>
      </label>
      <button type="button" class="secondary" style="font-size:11px;padding:3px 10px" onclick="navigatePage('ai')">Configure AI</button>
    </div>
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
    <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:12px;color:var(--text-muted);font-size:12px">
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
  <div class="scan-spotlight"><div class="scan-orbit"><div class="scan-orbit-ring"></div><span id="scanOrbitIcon"></span></div><span class="smart-eyebrow">Getting to know your PC</span><h2 id="scanHeadline">A little care, in progress.</h2><p id="scanPhase">Preparing your audit…</p><button id="cancelSpotlight" type="button" class="secondary" disabled onclick="document.querySelector('#cancel').click()">Stop audit</button></div>
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
<section id="careResults" class="hidden" aria-label="Audit overview"></section>

<div id="summary" class="hidden">
  <div class="grid" id="metrics"></div>

  <div class="panel result-toolbar" style="margin-top:14px">
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
      <button type="button" class="tab" role="tab" aria-selected="false" data-view="ai_review">✦ AI Advisor</button>
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
__CARE_MOTION__
__SPACE_LENS__
__CARE_FLOW__
const token=(()=>{const supplied=new URLSearchParams(location.search).get('token')||'';try{if(supplied)sessionStorage.setItem('rs_session',supplied);return supplied||sessionStorage.getItem('rs_session')||'';}catch{return supplied;}})();
if(token)history.replaceState(null,'',location.pathname+location.hash);
let REPORT=null,currentView='overview',previousReport=null,pollFailures=0;
let currentPage='home';

let iconSerial=0;
function cmmIcon(name, size=20, extraClass=''){
  const id='care-icon-'+(++iconSerial);
  const colors={smart:['#ffe6cf','#b7dae1'],clean:['#ffd4bb','#e599aa'],cleanup:['#ffd4bb','#e599aa'],protection:['#bce8e3','#70aaa7'],performance:['#fff0be','#e5b579'],applications:['#dcf2f6','#9ebdc3'],clutter:['#d8edf1','#9ac1c9'],reports:['#c9e4fc','#94b5bb'],ai:['#dbeef2','#a1c2c9'],settings:['#d9e4e6','#98a9ac']};
  const [light,dark]=colors[name]||colors.smart;
  const shapes={smart:'<path d="M32 12l5.5 14.5L52 32l-14.5 5.5L32 52l-5.5-14.5L12 32l14.5-5.5z"/>',clean:'<path d="M13 30a19 19 0 1030-14L32 32z"/><path d="M34 12v16h17A18 18 0 0034 12z"/>',protection:'<path d="M32 10c7 5 12 6 19 7v16c0 12-9 18-19 22C22 51 13 45 13 33V17c7-1 12-2 19-7z"/><path d="M23 32l7 7 12-15" fill="none" stroke="#fff" stroke-width="3"/>',performance:'<path d="M37 9L16 36h14l-3 20 23-30H35z"/>',applications:'<rect x="12" y="12" width="17" height="17" rx="5"/><rect x="35" y="12" width="17" height="17" rx="5"/><rect x="12" y="35" width="17" height="17" rx="5"/><rect x="35" y="35" width="17" height="17" rx="5"/>',clutter:'<path d="M11 18h17l5 6h21v25a5 5 0 01-5 5H16a5 5 0 01-5-5z"/><path d="M15 13h15l5 6h15" fill="none" stroke-width="4"/>',reports:'<rect x="13" y="33" width="9" height="19" rx="3"/><rect x="28" y="23" width="9" height="29" rx="3"/><rect x="43" y="12" width="9" height="40" rx="3"/>',ai:'<path d="M32 10l7 15 15 7-15 7-7 15-7-15-15-7 15-7z"/><circle cx="32" cy="32" r="5" fill="#fff"/>',settings:'<path d="M27 11h10l2 7 7 4 7-1 5 9-5 5v8l-5 9-7-2-7 4-2 6H22l-2-7-7-4-7 1-5-9 5-5v-8l5-9 7 2 7-4z" transform="translate(4 -4) scale(.9)"/><circle cx="32" cy="32" r="8" fill="#4d585a"/>'};
  return `<svg class="cmm-icon ${extraClass}" viewBox="0 0 64 64" width="${size}" height="${size}" aria-hidden="true"><defs><linearGradient id="${id}" x2=".8" y2="1"><stop stop-color="${light}"/><stop offset="1" stop-color="${dark}"/></linearGradient></defs><g fill="url(#${id})" stroke="${light}" stroke-width="1.1" stroke-linejoin="round">${shapes[name==='cleanup'?'clean':name]||shapes.smart}</g></svg>`;
}

const PAGES={
 home:{title:'Smart Audit',icon:cmmIcon('smart',24),description:'A clear picture of your PC, in one scan.',views:['overview','ai_review','plan','health']},
 cleanup:{title:'Cleanup',icon:cmmIcon('clean',24),description:'Find storage candidates and understand what can be reviewed for cleanup.',views:['cleanup_hub','findings','dirs','files','tooling']},
 protection:{title:'Protection',icon:cmmIcon('protection',24),description:'Inspect publisher signatures, permissions, and persistence evidence.',views:['protection_hub','trust','permissions','startup','services','tasks']},
 performance:{title:'Performance',icon:cmmIcon('performance',24),description:'See running processes and what starts with Windows.',views:['performance_hub','processes','startup','services','tasks']},
 applications:{title:'Applications',icon:cmmIcon('applications',24),description:'Explore installed software and the files associated with each application.',views:['applications_hub','apps','ownership']},
 clutter:{title:'My Clutter',icon:cmmIcon('clutter',24),description:'Review exact duplicates, large files, and folders taking up space.',views:['clutter_hub','duplicates','files','dirs']},
 reports:{title:'Reports',icon:cmmIcon('reports',24),description:'Review recommendations, inspect coverage, compare reports, and export your evidence.',views:['plan','ai_review','health','system','compare','notes','overview']},
 ai:{title:'AI Advisor',icon:cmmIcon('ai',24),description:'AI-assisted audit review with intelligent triage, safety warnings, and copyable PowerShell recipes.',views:['ai_review']},
 settings:{title:'Scan settings',icon:cmmIcon('settings',24),description:'Choose a scan root, depth, exclusions, and evidence options.',views:[]}
};

function getPreScanHub(name){
  if(name==='ai'){
    let savedKey = localStorage.getItem('rs_ai_key') || '';
    let savedProvider = localStorage.getItem('rs_ai_provider') || 'heuristic';
    let savedModel = localStorage.getItem('rs_ai_model') || '';
    let savedEndpoint = localStorage.getItem('rs_ai_endpoint') || '';

    return `<div style="margin-top:20px" class="zoom-stage">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#2c8394,#65bbcc)">✦</div>
        <div>
          <h2>AI Audit Advisor</h2>
          <p>Triage Windows telemetry with an intelligent AI systems analyst. Supports OpenAI-compatible endpoints, Anthropic Claude, Google Gemini, Ollama (local LLM), and built-in offline heuristics.</p>
        </div>
      </div>

      <!-- Configuration Card (available before and after scan) -->
      <div class="panel" style="margin-top:20px;padding:20px">
        <h3 style="margin-top:0;font-size:16px;font-weight:750">AI Advisor Configuration &amp; Setup</h3>
        <p class="small" style="margin-bottom:12px">Configure your AI engine below. Settings persist locally in your browser with zero background network pingbacks.</p>
        <div class="grid" style="grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:14px;margin-top:14px">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">AI Engine / Provider</label>
            <select id="aiProviderSelectPre" style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="onAIProviderChange(this.value);localStorage.setItem('rs_ai_provider',this.value)">
              <option value="heuristic" ${savedProvider==='heuristic'?'selected':''}>Offline Heuristic Engine (No Key Required)</option>
              <option value="openai" ${savedProvider==='openai'?'selected':''}>OpenAI / OpenRouter / Groq</option>
              <option value="anthropic" ${savedProvider==='anthropic'?'selected':''}>Anthropic Claude</option>
              <option value="gemini" ${savedProvider==='gemini'?'selected':''}>Google Gemini</option>
              <option value="ollama" ${savedProvider==='ollama'?'selected':''}>Ollama (Local LLM)</option>
            </select>
          </div>
          <div id="aiKeyBoxPre" style="${savedProvider==='heuristic'||savedProvider==='ollama'?'display:none':''}">
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">API Key (Saved locally)</label>
            <input type="password" id="aiApiKeyInputPre" value="${esc(savedKey)}" placeholder="sk-..." style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="localStorage.setItem('rs_ai_key', this.value.trim())">
          </div>
          <div id="aiModelBoxPre">
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">Model Override (Optional)</label>
            <input type="text" id="aiModelInputPre" value="${esc(savedModel)}" placeholder="Default for provider" style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="localStorage.setItem('rs_ai_model', this.value.trim())">
          </div>
          <div id="aiEndpointBoxPre" style="${savedProvider==='heuristic'?'display:none':''}">
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">Custom Endpoint (Optional)</label>
            <input type="text" id="aiEndpointInputPre" value="${esc(savedEndpoint)}" placeholder="Default provider API URL" style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="localStorage.setItem('rs_ai_endpoint', this.value.trim())">
          </div>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-top:16px;padding-top:14px;border-top:1px solid var(--border)">
          <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer">
            <input type="checkbox" id="aiRedactTogglePre" checked>
            <span><b>Privacy Guard:</b> Sanitize usernames, hostnames, paths, and secrets before prompting</span>
          </label>
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <button type="button" class="secondary" onclick="copySanitizedPrompt(this)">📋 Preview Prompt Format</button>
            <label class="button secondary" style="cursor:pointer;margin:0;padding:6px 12px;border-radius:8px;font-size:13px;display:inline-flex;align-items:center">
              📂 Load Saved Report (.json)
              <input type="file" accept=".json,application/json" style="display:none" onchange="handleReportImport(event)">
            </label>
            <button type="button" class="primary" style="background:linear-gradient(135deg,#2c8394,#65bbcc);border:none" onclick="startAuditWithAI()">
              ✦ Start Full Audit with AI Review
            </button>
          </div>
        </div>
      </div>

      <div class="hub-card-grid" style="margin-top:16px">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-protection"/></svg> Privacy-First Redaction</div></div>
          <div class="hub-card-desc">Usernames, hostnames, paths, and secret tokens are automatically sanitized before prompting.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-performance"/></svg> Structured Recommendations</div></div>
          <div class="hub-card-desc">Classified into Critical Actions, Quick Wins, Safety Warnings (never touch dev workspaces), and Architecture Explainers.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-clean"/></svg> Copyable PowerShell Recipes</div></div>
          <div class="hub-card-desc">Every action includes standard Microsoft PowerShell commands ready for 1-click clipboard copy.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='cleanup'){
    return `<div style="margin-top:20px" class="zoom-stage">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#00f2fe,#4facfe)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-clean"/></svg></div>
        <div>
          <h2>System &amp; Application Cleanup</h2>
          <p>Scan caches, package managers, development artifacts, and disposable files safely with zero destructive deletes.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-clean"/></svg> System Cache &amp; Temp</div></div>
          <div class="hub-card-desc">Audit Windows temp, Delivery Optimization, crash dumps, and SoftwareDistribution downloads.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-clean"/></svg> Browser &amp; App Data</div></div>
          <div class="hub-card-desc">Inspect Chrome, Edge, Brave, and Firefox cache directories and profile footprints.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-performance"/></svg> Developer &amp; Build Caches</div></div>
          <div class="hub-card-desc">Identify node_modules, Python venvs, pip/npm/cargo caches, and Docker artifacts.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='protection'){
    return `<div style="margin-top:20px" class="zoom-stage">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#10b981,#06b6d4)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-protection"/></svg></div>
        <div>
          <h2>Windows Security &amp; Privacy Health</h2>
          <p>Audit Microsoft Defender status, background app hardware permissions (webcam, mic, location), and unsigned binaries.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-protection"/></svg> Microsoft Defender Audit</div></div>
          <div class="hub-card-desc">Inspect real-time protection, signature definition age, and threat detection history.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-protection"/></svg> Privacy &amp; ConsentStore</div></div>
          <div class="hub-card-desc">Audit Windows CapabilityAccessManager consent permissions for webcam, microphone, and location.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-protection"/></svg> Publisher Trust Verification</div></div>
          <div class="hub-card-desc">Verify Authenticode digital signatures on active binaries and detect unsigned execution.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='performance'){
    return `<div style="margin-top:20px" class="zoom-stage">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#fbbf24,#ef4444)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-performance"/></svg></div>
        <div>
          <h2>System Performance &amp; Memory Audit</h2>
          <p>Audit RAM load, working sets of active processes, startup persistence overhead, and system maintenance tasks.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-performance"/></svg> RAM &amp; Memory Distribution</div></div>
          <div class="hub-card-desc">Physical and virtual memory breakdown with working set analysis for resource-heavy apps.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-performance"/></svg> Startup &amp; Persistence Impact</div></div>
          <div class="hub-card-desc">Inspect Startup registry entries, scheduled tasks, and background services delaying boot.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-performance"/></svg> Maintenance Quick-Fixes</div></div>
          <div class="hub-card-desc">Copy-paste PowerShell recipes for DNS flush, DISM component store cleanup, and SSD TRIM.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='applications'){
    return `<div style="margin-top:20px" class="zoom-stage">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#ec4899,#7bc8d7)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-applications"/></svg></div>
        <div>
          <h2>Installed Applications &amp; Leftovers</h2>
          <p>Track installed software footprints, quiet uninstall commands, and orphaned AppData leftover folders.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-applications"/></svg> Installed App Footprints</div></div>
          <div class="hub-card-desc">Detect installed applications from 64-bit and 32-bit registry, correlating files and background services.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-applications"/></svg> Orphaned AppData Leftovers</div></div>
          <div class="hub-card-desc">Discover remnant directories in %LocalAppData% and %AppData% left behind after uninstalls.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-applications"/></svg> Silent Uninstaller Audit</div></div>
          <div class="hub-card-desc">Inspect QuietUninstallString and standard uninstaller commands with copyable command line recipes.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='clutter'){
    return `<div style="margin-top:20px" class="zoom-stage">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#75c6d7,#60bed1)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-clutter"/></svg></div>
        <div>
          <h2>Space Lens &amp; Clutter Inspector</h2>
          <p>Visual storage hierarchy, exact byte duplicates, and large/old files breakdown.</p>
        </div>
      </div>
      <div class="hub-card-grid">
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-clutter"/></svg> Space Lens Hierarchy</div></div>
          <div class="hub-card-desc">Interactive proportional disk visualization highlighting top space consumers.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-clutter"/></svg> Exact Duplicate Files</div></div>
          <div class="hub-card-desc">SHA-256 duplicate content identification to eliminate wasted duplicate storage.</div>
        </div>
        <div class="hub-card">
          <div class="hub-card-head"><div class="hub-card-title"><svg viewBox="0 0 24 24" width="20" height="20" style="margin-right:6px"><use href="#cmm-ico-clutter"/></svg> Large &amp; Old Files</div></div>
          <div class="hub-card-desc">Filter archives, ISOs, virtual disks, and forgotten files older than 6 months or 1 year.</div>
        </div>
      </div>
    </div>`;
  }
  if(name==='reports'){
    return `<div style="margin-top:20px" class="zoom-stage">
      <div class="hub-hero">
        <div class="hub-orb" style="background:linear-gradient(135deg,#06b6d4,#7bc8d7)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-reports"/></svg></div>
        <div>
          <h2>System Care Reports &amp; Evidence</h2>
          <p>Review comprehensive audit findings, export forensic Markdown Action Plans, inspect depth ledgers, and compare reports over time.</p>
        </div>
      </div>
      <div class="panel" style="margin-top:20px;padding:24px;text-align:center">
        <p style="font-size:15px;margin:0 0 12px 0">Run a scan from <b>Smart Audit</b> or import a previously exported ReconSpace report to generate actionable reports.</p>
        <div style="display:flex;justify-content:center;gap:12px;flex-wrap:wrap">
          <button type="button" class="primary" onclick="navigatePage('home')">✦ Run Smart Audit</button>
          <label class="button secondary" style="cursor:pointer;margin:0;padding:6px 14px;border-radius:8px;display:inline-flex;align-items:center">
            📂 Load Saved Report (.json)
            <input type="file" accept=".json,application/json" style="display:none" onchange="handleReportImport(event)">
          </label>
        </div>
      </div>
    </div>`;
  }
  return '';
}

let scanRunning=false, scanSubmitting=false, pageTransition=null, navigationSequence=0;
let uiZoom=1;
function setZoom(delta){
  uiZoom=delta===0?1:Math.max(.85,Math.min(1.15,uiZoom+delta));
  document.body.dataset.zoom=String(uiZoom);
  document.body.style.setProperty('--ui-zoom',String(uiZoom));
  $('#zoomReadout').textContent=Math.round(uiZoom*100)+'%';
}
function navigatePage(name,updateHistory=true){
  const sequence=++navigationSequence;
  if(pageTransition)pageTransition.skipTransition();
  CareMotion.cancel();
  document.body.dataset.motionDirection=name==='home'?'back':'forward';
  const update=()=>{if(sequence!==navigationSequence)return;applyPage(name,updateHistory);CareMotion.marker();};
  if(!CareMotion.reduced()){
    pageTransition=REPORT||!document.startViewTransition?CareMotion.stage(update,document.body.dataset.motionDirection):document.startViewTransition(update);
    pageTransition.ready.catch(()=>{});
    pageTransition.finished.then(()=>{if(sequence===navigationSequence&&currentPage===name)CareMotion.reveal();},()=>{});
  }else {update();CareMotion.reveal();}
}
function moduleWelcome(name){
  const p=PAGES[name];
  return `<section class="module-welcome"><div class="module-art" data-parallax><div class="parallax-object">${careArtwork(name)}</div></div><div class="module-welcome-copy"><span class="smart-eyebrow">Your PC, understood</span><h2>${esc(p.title)}</h2><p>${esc(p.description)}</p><p class="small">Start a read-only audit to discover real evidence. Nothing is removed or changed.</p>${['cleanup','protection','performance','applications','clutter'].includes(name)?`<button onclick="CareFlow.setup(\'${name}\')">Scan & review →</button>`:'<button onclick="navigatePage(\'home\')">Go to Smart Audit</button>'}${name==='reports'?'<label class="import-button">Import report JSON<input aria-label="Import report JSON" type="file" accept=".json,application/json" onchange="handleReportImport(event)"></label>':''}</div></section>`;
}
function renderCareResults(){
  if(!REPORT)return;
  const rs=REPORT.reclaim_summary||{}, h=REPORT.audit_health||{};
  const collectedCount=(rows,suffix)=>rows.length?rows.length+' '+suffix:'No records';
  const cards=[['cleanup','clean','Storage',bytes(rs.path_candidates_nonoverlap_bytes||0),'Path candidates · review required'],['protection','protection','Protection',collectedCount(REPORT.binary_trust||[],'records'),'Signature inventory · check audit coverage'],['performance','performance','Performance',collectedCount(REPORT.processes||[],'processes'),'Process inventory · may be limited by profile'],['applications','applications','Applications',(REPORT.applications||[]).length+' apps','Installed application inventory'],['clutter','clutter','My Clutter',(REPORT.duplicates||[]).length+' groups','Duplicate potential · separate estimate']];
  $('#careResults').innerHTML=`<div class="results-heading"><span class="smart-eyebrow">Your audit is ready</span><h2>A clearer picture of your PC.</h2><p>Explore your findings. You decide what happens next.</p></div><div class="results-grid">${cards.map(([page,icon,title,value,note])=>`<button class="result-card" data-parallax onclick="CareFlow.openModule('${page}',true)"><span class="result-art">${careArtwork(page)}</span><span class="result-title">${title}</span><b>${esc(value)}</b><small>${note}</small><span class="result-review">Review →</span></button>`).join('')}</div><div class="evidence-footer"><span>Evidence coverage: ${h.coverage_score===undefined?'not recorded':esc(h.coverage_score)+'/100'} · evidence quality, not PC health</span><button class="secondary" onclick="navigatePage('reports')">View audit evidence →</button></div><div class="results-footer"><span class="small">Read-only audit · no changes made</span><button onclick="CareFlow.setup('home')">Start another audit</button></div>`;
}
function applyPage(name,updateHistory=true){
  if(!PAGES[name])name='home';
  currentPage=name;
  const page=PAGES[name];
  document.body.dataset.page=name;
  $('#pageTitle').textContent=page.title;
  $$('button[data-page]').forEach(el=>{el.classList.toggle('active',el.dataset.page===name);if(el.classList.contains('rail-item')){if(el.dataset.page===name)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');}});
  $('#scanComposer').classList.toggle('hidden',name==='home'?(scanRunning||!!REPORT):name!=='settings');
  $('#liveMonitor').classList.toggle('hidden',name!=='home'||!scanRunning);
  $('#careResults').classList.toggle('hidden',name!=='home'||!REPORT||scanRunning);
  (name==='home'?$('#welcomeActions'):$('#scanSlot')).appendChild($('#scan'));
  $('#scopeSummary').textContent=$('#root').value+' · '+$('#profile').value+' audit';
  const intro=$('#moduleIntro');
  intro.classList.toggle('hidden',name==='home'||name==='settings');
  intro.innerHTML=`<section class="module-banner"><span class="module-symbol">${careArtwork(name)}</span><div><h2>${page.title}</h2><p>${page.description}</p></div><button type="button" class="secondary" onclick="navigatePage('settings')">Configure scan</button></section>${!REPORT?(name==='ai'?getPreScanHub(name):moduleWelcome(name)):''}`;
  $('#summary').classList.toggle('hidden',!REPORT||name==='settings'||name==='home');
  $$('.tab').forEach(el=>el.classList.toggle('hidden',!page.views.includes(el.dataset.view)));
  const guided=CareFlow.enterPage(name);
  if(REPORT&&page.views.length&&name!=='home'&&!guided)switchTab(page.views[0],false);
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
  system_temp: { title: "System & Temporary Files", icon: cmmIcon('clean', 20), desc: "Transient OS caches, crash dumps, and temp files. Review the owning workflow before any cleanup." },
  dev_build: { title: "Development & Build Caches", icon: cmmIcon('performance', 20), desc: "Dependencies, intermediate compilers, virtualenvs, and package manager caches." },
  ai_ml: { title: "AI & Machine Learning Models", icon: cmmIcon('ai', 20), desc: "Large weights, transformer models, and checkpoints (Ollama, HuggingFace, PyTorch, ComfyUI)." },
  browser_app: { title: "Browsers & Application Data", icon: cmmIcon('clean', 20), desc: "Browser cache storage, WebKit/Chromium storage, and communication app media buffers." },
  apps_installers: { title: "Applications & Installers", icon: cmmIcon('applications', 20), desc: "Installed software and setup packages. Use Windows or vendor-supported management; never delete program files manually." },
  virtualization: { title: "Virtual Machines & Containers", icon: cmmIcon('clutter', 20), desc: "Virtual hard disks (VHDX), container layers, Docker images, and hypervisor disks." },
  diagnostics: { title: "Diagnostics & Storage Candidates", icon: cmmIcon('reports', 20), desc: "Memory dumps, trace logs, database files, and large files requiring review." },
  app_leftovers: { title: "Application Leftovers", icon: cmmIcon('applications', 20), desc: "Residual AppData and ProgramData folders from uninstalled applications." },
  privacy_permissions: { title: "Privacy & Permissions", icon: cmmIcon('protection', 20), desc: "Hardware consent permissions, Defender status, and security findings." },
  system_maintenance: { title: "System Maintenance", icon: cmmIcon('performance', 20), desc: "System memory pressure, performance optimization, and routine maintenance candidates." },
  other: { title: "Other Storage Findings", icon: cmmIcon('smart', 20), desc: "Miscellaneous storage items and files requiring assessment." }
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

function switchTab(viewName,animateView=true) {
  if(REPORT&&!PAGES[currentPage].views.includes(viewName)){
    const owner=Object.keys(PAGES).find(name=>name!=='home'&&PAGES[name].views.includes(viewName));
    if(owner)applyPage(owner,true);
  }
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
  CareFlow.raw();
  render();
  if(animateView)CareMotion.animate($('#view'),[{opacity:.45,transform:'translateY(5px)'},{opacity:1,transform:'none'}],{duration:240,easing:'ease-out'});
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
  return `<div class="chart"><h3>Retained folder treemap</h3><div style="display:flex;flex-wrap:wrap;gap:4px;min-height:260px;align-content:stretch">${rows.map((x,i)=>{let weight=Math.max(7,(Number(x.size_bytes)||0)/total*100);return `<div title="${esc(x.path)} — ${bytes(x.size_bytes)}" style="flex:${weight} 1 ${Math.max(90,weight*8)}px;min-height:${70+(i%3)*18}px;border:1px solid var(--border);border-radius:8px;padding:8px;background:linear-gradient(135deg,rgba(127,198,213,.18),rgba(56,189,248,.10));overflow:hidden"><b>${bytes(x.size_bytes)}</b><div class="path">${esc(x.path)}</div></div>`}).join('')}</div><div class="small" style="margin-top:8px">Area is proportional only within the retained top-folder set, not the entire filesystem.</div></div>`;
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

  let dupBytes=(REPORT.duplicates||[]).reduce((a,c)=>a+(c.waste_bytes||0),0);
  let largeFilesCount=(REPORT.top_files||[]).filter(x=>(x.size_bytes||0)>=500*1024*1024).length;
  let clutterMetric=dupBytes>0?`${bytes(dupBytes)} duplicate waste`:(largeFilesCount?`${largeFilesCount} large files`:'Space Lens mapped');
  let aiMetric=AI_RESULT ? `Score: ${AI_RESULT.overall_score}/100` : 'Ready to analyze';

  let hiberColl=getCollector('hibernation_pagefile_intelligence');
  let hiberData=(hiberColl&&hiberColl.ok&&hiberColl.data)||{};
  let doColl=getCollector('delivery_optimization_status');
  let doData=(doColl&&doColl.ok&&doColl.data)||{};
  let batColl=getCollector('battery_power_health');
  let batData=(batColl&&batColl.ok&&batColl.data)||{};
  let dumpsColl=getCollector('crash_dumps_inventory');
  let dumpsData=(dumpsColl&&dumpsColl.ok&&dumpsColl.data)||{};
  let rbColl=getCollector('recycle_bin_metrics');
  let rbData=(rbColl&&rbColl.ok&&rbColl.data)||{};

  let aiBanner = `
    <div class="panel ai-overview-banner" style="margin-top:16px;padding:18px 22px;border-left:4px solid #2c8394;background:linear-gradient(135deg,rgba(44,131,148,0.12),rgba(101,187,204,0.08));display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;border-radius:18px">
      <div style="display:flex;align-items:center;gap:16px">
        <div style="width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,#2c8394,#65bbcc);display:flex;align-items:center;justify-content:center;color:#fff;font-size:22px;flex-shrink:0;box-shadow:0 6px 18px rgba(44,131,148,0.35)">✦</div>
        <div>
          <div style="font-weight:750;font-size:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <span>AI Audit Advisor</span>
            ${AI_RESULT ? `
              <span class="badge" style="background:${AI_RESULT.overall_score>=80?'#06d6a0':(AI_RESULT.overall_score>=60?'#ffd166':'#ef476f')};color:#000;font-weight:800;font-size:12px;padding:3px 10px;border-radius:12px">
                System Wellness: ${AI_RESULT.overall_score}/100
              </span>
            ` : `
              <span class="badge" style="background:rgba(255,255,255,0.1);color:var(--fg);font-size:11px">Ready to analyze</span>
            `}
          </div>
          <div class="small" style="margin-top:4px;color:var(--muted);line-height:1.4">
            ${AI_RESULT ? `
              <b>${(AI_RESULT.critical_actions||[]).length}</b> critical action(s) · <b>${(AI_RESULT.quick_wins||[]).length}</b> quick win(s) · <b>${(AI_RESULT.safety_warnings||[]).length}</b> developer invariants guarded
            ` : `
              Synthesize Windows storage findings, Defender posture, RAM loads, and developer toolchain invariants using OpenAI, Claude, Gemini, or private local Ollama.
            `}
          </div>
        </div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        ${AI_RESULT ? `
          <button type="button" class="primary" style="background:linear-gradient(135deg,#2c8394,#65bbcc);border:none;padding:10px 18px;border-radius:12px;font-weight:700" onclick="navigatePage('ai')">✦ View Full AI Review</button>
        ` : `
          <button type="button" class="primary" style="background:linear-gradient(135deg,#2c8394,#65bbcc);border:none;padding:10px 18px;border-radius:12px;font-weight:700" onclick="runAIReview()" ${AI_RUNNING?'disabled':''}>
            ${AI_RUNNING ? '⏳ Analyzing Telemetry...' : '✦ Run AI Analysis Now'}
          </button>
          <button type="button" class="secondary" style="padding:10px 14px;border-radius:12px" onclick="navigatePage('ai')">⚙ Configure Engine</button>
        `}
      </div>
    </div>
  `;

  let pillarGrid=`
    <div class="pillar-grid" style="margin-top:16px">
      <div class="pillar-card cleanup-pillar" onclick="navigatePage('cleanup')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('cleanup')}" role="button" tabindex="0" title="Open Cleanup module">
        <div class="pillar-head">
          <span class="pillar-title">Cleanup</span>
          <div class="pillar-icon"><svg viewBox="0 0 24 24" width="26" height="26"><use href="#cmm-ico-clean"/></svg></div>
        </div>
        <div class="pillar-sub">System caches, build folders, browser temp &amp; logs</div>
        <div class="pillar-metric">${totalReclaim>0?bytes(totalReclaim)+' reclaim':(REPORT.findings||[]).length+' findings'}</div>
      </div>
      <div class="pillar-card protection-pillar" onclick="navigatePage('protection')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('protection')}" role="button" tabindex="0" title="Open Protection module">
        <div class="pillar-head">
          <span class="pillar-title">Protection</span>
          <div class="pillar-icon"><svg viewBox="0 0 24 24" width="26" height="26"><use href="#cmm-ico-protection"/></svg></div>
        </div>
        <div class="pillar-sub">Defender status, app privacy permissions &amp; binary trust</div>
        <div class="pillar-metric" style="color:${defOk?'var(--good)':'var(--warn)'}">${protMetric}</div>
      </div>
      <div class="pillar-card performance-pillar" onclick="navigatePage('performance')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('performance')}" role="button" tabindex="0" title="Open Performance module">
        <div class="pillar-head">
          <span class="pillar-title">Performance</span>
          <div class="pillar-icon"><svg viewBox="0 0 24 24" width="26" height="26"><use href="#cmm-ico-performance"/></svg></div>
        </div>
        <div class="pillar-sub">Memory load, startup items &amp; maintenance routines</div>
        <div class="pillar-metric">${memLoad}</div>
      </div>
      <div class="pillar-card applications-pillar" onclick="navigatePage('applications')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('applications')}" role="button" tabindex="0" title="Open Applications module">
        <div class="pillar-head">
          <span class="pillar-title">Applications</span>
          <div class="pillar-icon"><svg viewBox="0 0 24 24" width="26" height="26"><use href="#cmm-ico-applications"/></svg></div>
        </div>
        <div class="pillar-sub">Installed software footprints &amp; orphaned leftovers</div>
        <div class="pillar-metric">${appMetric}</div>
      </div>
      <div class="pillar-card clutter-pillar" onclick="navigatePage('clutter')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('clutter')}" role="button" tabindex="0" title="Open My Clutter module">
        <div class="pillar-head">
          <span class="pillar-title">My Clutter</span>
          <div class="pillar-icon"><svg viewBox="0 0 24 24" width="26" height="26"><use href="#cmm-ico-clutter"/></svg></div>
        </div>
        <div class="pillar-sub">Space Lens tree, exact duplicates &amp; large old files</div>
        <div class="pillar-metric">${clutterMetric}</div>
      </div>
      <div class="pillar-card ai-pillar" onclick="navigatePage('ai')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();navigatePage('ai')}" role="button" tabindex="0" title="Open AI Advisor module">
        <div class="pillar-head">
          <span class="pillar-title">AI Advisor</span>
          <div class="pillar-icon"><svg viewBox="0 0 24 24" width="26" height="26"><use href="#cmm-ico-ai"/></svg></div>
        </div>
        <div class="pillar-sub">AI triage, system wellness score &amp; PowerShell recipes</div>
        <div class="pillar-metric" style="color:#9cd8e4">${aiMetric}</div>
      </div>
    </div>
  `;

  let sysIntelCards = `
    <div style="margin-top:20px">
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px">
        <h3 style="margin:0;font-size:16px;font-weight:750">Open-Source Windows Intelligence Telemetry</h3>
        <span class="small">Dism++, PrivaZer, Stacer &amp; Microsoft Sysinternals collectors</span>
      </div>
      <div class="grid" style="grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:12px">
        <div class="panel" style="padding:14px;border-radius:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <span style="font-weight:700;font-size:13px">Dism++ Hibernation Sizing</span>
            <span class="small mono">${esc(hiberData.drive||'C:')}</span>
          </div>
          <div style="font-size:16px;font-weight:800;color:var(--primary)">${bytes(hiberData.hiberfil_bytes||0)}</div>
          <div class="small" style="margin-top:2px;color:var(--muted)">Mode: <b>${esc(hiberData.hiber_file_type||'Standard')}</b></div>
          ${hiberData.potential_reduced_savings_bytes > 0 ? `<div class="small safe" style="font-weight:700;margin-top:4px">Save ~${bytes(hiberData.potential_reduced_savings_bytes)} in Reduced Mode</div>` : ''}
        </div>

        <div class="panel" style="padding:14px;border-radius:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <span style="font-weight:700;font-size:13px">Delivery Optimization P2P</span>
            <span class="badge ${doData.bytes_uploaded_to_peers>1024*1024*1024?'review':'safe'}">${doData.cache_size_bytes!=null?bytes(doData.cache_size_bytes):'Ready'}</span>
          </div>
          <div style="font-size:16px;font-weight:800">${bytes(doData.cache_size_bytes||0)}</div>
          <div class="small" style="margin-top:2px;color:var(--muted)">Uploaded to Peers: <b>${bytes(doData.bytes_uploaded_to_peers||0)}</b></div>
        </div>

        <div class="panel" style="padding:14px;border-radius:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <span style="font-weight:700;font-size:13px">Crash Dumps &amp; Recycle Bin</span>
            <span class="small mono">${dumpsData.total_dumps_count||0} dumps</span>
          </div>
          <div style="font-size:16px;font-weight:800">${bytes((dumpsData.total_size_bytes||0)+(rbData.total_size_bytes||0))}</div>
          <div class="small" style="margin-top:2px;color:var(--muted)">WER Dumps: <b>${bytes(dumpsData.total_size_bytes||0)}</b> · Recycle Bin: <b>${bytes(rbData.total_size_bytes||0)}</b></div>
        </div>

        ${batData.is_battery_present ? `
          <div class="panel" style="padding:14px;border-radius:14px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
              <span style="font-weight:700;font-size:13px">Battery &amp; Power Health</span>
              <span class="badge ${batData.wear_level_percent>30?'review':'safe'}">${batData.charge_percent!=null?batData.charge_percent+'%':''}</span>
            </div>
            <div style="font-size:16px;font-weight:800">${esc(batData.status||'Active')}</div>
            <div class="small" style="margin-top:2px;color:var(--muted)">Wear Level: <b>${batData.wear_level_percent!=null?batData.wear_level_percent+'%':'Good'}</b></div>
          </div>
        ` : `
          <div class="panel" style="padding:14px;border-radius:14px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
              <span style="font-weight:700;font-size:13px">Hardware ConsentStore</span>
              <span class="safe">${privCount} permissions</span>
            </div>
            <div style="font-size:16px;font-weight:800">${privCount} Granted</div>
            <div class="small" style="margin-top:2px;color:var(--muted)">Webcam, microphone &amp; location access</div>
          </div>
        `}
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
    ${aiBanner}
    ${pillarGrid}
    ${sysIntelCards}
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
  let doColl = getCollector('delivery_optimization_status');
  let doData = (doColl && doColl.ok && doColl.data) || {};
  let dumpsColl = getCollector('crash_dumps_inventory');
  let dumpsData = (dumpsColl && dumpsColl.ok && dumpsColl.data) || {};
  let rbColl = getCollector('recycle_bin_metrics');
  let rbData = (rbColl && rbColl.ok && rbColl.data) || {};
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
      <div class="hub-orb" style="background:linear-gradient(135deg,#00f2fe,#4facfe)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-clean"/></svg></div>
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
        <div class="hub-card">
          <div class="hub-card-title">🌐 Delivery Optimization P2P Cache</div>
          <div class="hub-card-desc">
            ${doData.cache_size_bytes != null ? `<div>Cache Size: <b>${bytes(doData.cache_size_bytes)}</b></div><div>Uploaded to Peers: <b class="${doData.bytes_uploaded_to_peers>1024*1024*1024?'review':'safe'}">${bytes(doData.bytes_uploaded_to_peers||0)}</b></div><div class="small" style="margin-top:2px">Mode: ${esc(doData.download_mode||'Default')}</div>` : 'Windows Update peer distribution cache and upload bandwidth telemetry.'}
          </div>
          <div class="recipe-box">
            <span class="recipe-code">Delete-DeliveryOptimizationCache</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Delete-DeliveryOptimizationCache')">Copy</button>
          </div>
        </div>
        <div class="hub-card">
          <div class="hub-card-title">💥 Windows Crash Dumps &amp; WER</div>
          <div class="hub-card-desc">
            ${dumpsData.total_dumps_count != null ? `<div>Total Crash Dumps: <b>${dumpsData.total_dumps_count}</b></div><div>Accumulated Size: <b class="${dumpsData.total_size_bytes>500*1024*1024?'review':'safe'}">${bytes(dumpsData.total_size_bytes||0)}</b></div>` : 'Audit memory dumps, minidumps, and Windows Error Reporting crash traces.'}
          </div>
          <div class="recipe-box">
            <span class="recipe-code">Get-ChildItem -Path '$env:LOCALAPPDATA\\CrashDumps', '$env:SystemRoot\\Minidump' -Filter *.dmp -ErrorAction SilentlyContinue</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, 'Get-ChildItem -Path \\'$env:LOCALAPPDATA\\\\CrashDumps\\', \\'$env:SystemRoot\\\\Minidump\\' -Filter *.dmp -ErrorAction SilentlyContinue')">Copy</button>
          </div>
        </div>
        <div class="hub-card">
          <div class="hub-card-title">🗑️ Recycle Bin Depth (${esc(rbData.drive||'C:')})</div>
          <div class="hub-card-desc">
            ${rbData.item_count != null ? `<div>Deleted Items: <b>${rbData.item_count}</b></div><div>Volume Allocated: <b class="${rbData.total_size_bytes>500*1024*1024?'review':'safe'}">${bytes(rbData.total_size_bytes||0)}</b></div>` : 'Query exact items and allocated bytes inside $Recycle.Bin.'}
          </div>
          <div class="recipe-box">
            <span class="recipe-code">${esc(rbData.inspect_recipe || "Get-ChildItem -Path 'C:\\$Recycle.Bin' -Force -Recurse | Measure-Object -Property Length -Sum")}</span>
            <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, '${esc(rbData.inspect_recipe || "Get-ChildItem -Path 'C:\\$Recycle.Bin' -Force -Recurse | Measure-Object -Property Length -Sum").replace(/'/g, "\\'")}')">Copy</button>
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
      <div class="hub-orb" style="background:linear-gradient(135deg,#10b981,#06b6d4)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-protection"/></svg></div>
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
  let hiberColl = getCollector('hibernation_pagefile_intelligence');
  let hiberData = (hiberColl && hiberColl.ok && hiberColl.data) || {};
  let batColl = getCollector('battery_power_health');
  let batData = (batColl && batColl.ok && batColl.data) || {};
  let netColl = getCollector('network_adapters_telemetry');
  let netData = (netColl && netColl.ok && netColl.data) || {};
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
      <div class="hub-orb" style="background:linear-gradient(135deg,#fbbf24,#ef4444)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-performance"/></svg></div>
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

    <!-- Windows Hibernation & Pagefile Sizing Intelligence (Dism++ style) -->
    <div class="chart" style="margin-top:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h3 style="margin:0;font-size:15px;font-weight:750">Windows Hibernation &amp; Pagefile Sizing (Dism++ Intelligence)</h3>
        <span class="small mono">${esc(hiberData.drive || 'C:')}</span>
      </div>
      <div class="grid" style="grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:12px;margin-top:10px">
        <div style="background:var(--card);padding:12px;border-radius:8px;border:1px solid var(--border)">
          <div class="small" style="font-weight:600">Hibernation File (hiberfil.sys)</div>
          <div style="font-size:18px;font-weight:750;margin-top:4px">${bytes(hiberData.hiberfil_bytes||0)}</div>
          <div class="small" style="margin-top:4px;color:var(--muted)">Mode: <b>${esc(hiberData.hiber_file_type||'unknown')}</b></div>
          ${hiberData.potential_reduced_savings_bytes > 0 ? `
            <div style="margin-top:8px">
              <span class="safe small" style="font-weight:700">Save ~${bytes(hiberData.potential_reduced_savings_bytes)} in Reduced Mode</span>
              <div class="recipe-box" style="margin-top:6px">
                <span class="recipe-code">powercfg /hibernate /type reduced</span>
                <button type="button" class="secondary" style="font-size:10px;padding:2px 6px" onclick="copyPath(this, 'powercfg /hibernate /type reduced')">Copy</button>
              </div>
            </div>
          ` : ''}
        </div>
        <div style="background:var(--card);padding:12px;border-radius:8px;border:1px solid var(--border)">
          <div class="small" style="font-weight:600">Virtual Memory Pagefile (pagefile.sys)</div>
          <div style="font-size:18px;font-weight:750;margin-top:4px">${bytes(hiberData.pagefile_bytes||0)}</div>
          <div class="small" style="margin-top:4px;color:var(--muted)">Committed swap backing store</div>
        </div>
        <div style="background:var(--card);padding:12px;border-radius:8px;border:1px solid var(--border)">
          <div class="small" style="font-weight:600">App Suspend Swap (swapfile.sys)</div>
          <div style="font-size:18px;font-weight:750;margin-top:4px">${bytes(hiberData.swapfile_bytes||0)}</div>
          <div class="small" style="margin-top:4px;color:var(--muted)">Windows UWP / Modern App suspend</div>
        </div>
      </div>
    </div>

    <!-- Battery & Power Health (Stacer / Glances style) -->
    ${batData.is_battery_present ? `
      <div class="chart" style="margin-top:20px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <h3 style="margin:0;font-size:15px;font-weight:750">Battery &amp; Power Health</h3>
          <span class="badge ${batData.wear_level_percent && batData.wear_level_percent > 30 ? 'review' : 'safe'}">Wear: ${batData.wear_level_percent != null ? batData.wear_level_percent + '%' : 'Good'}</span>
        </div>
        <div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap">
          <div><b>Charge:</b> ${batData.charge_percent != null ? batData.charge_percent + '%' : 'Unknown'} (${esc(batData.status || 'Active')})</div>
          ${batData.design_capacity_mwh ? `<div><b>Design:</b> ${batData.design_capacity_mwh} mWh · <b>Full:</b> ${batData.full_charge_capacity_mwh} mWh</div>` : ''}
          ${batData.estimated_runtime_minutes ? `<div><b>Est. Runtime:</b> ${batData.estimated_runtime_minutes} mins</div>` : ''}
          <div class="recipe-box" style="margin:0;margin-left:auto">
            <span class="recipe-code">powercfg /batteryreport</span>
            <button type="button" class="secondary" style="font-size:10px;padding:2px 6px" onclick="copyPath(this, 'powercfg /batteryreport /output $HOME\\\\battery-report.html')">Generate Report</button>
          </div>
        </div>
      </div>
    ` : ''}

    <!-- Active Network Adapters Telemetry (Glances style) -->
    ${netData.adapters && netData.adapters.length ? `
      <div class="chart" style="margin-top:20px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <h3 style="margin:0;font-size:15px;font-weight:750">Active Network Adapters &amp; Telemetry</h3>
          <span class="small">${netData.active_adapters_count} active of ${netData.total_adapters_count}</span>
        </div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:8px">
          ${netData.adapters.map(a => `
            <div style="background:var(--card);padding:10px 14px;border-radius:8px;border:1px solid var(--border);min-width:180px">
              <div style="display:flex;align-items:center;gap:6px">
                <span class="${a.is_up ? 'safe' : 'small'}">●</span>
                <b>${esc(a.name)}</b>
              </div>
              <div class="small mono" style="margin-top:4px">${esc(a.link_speed || '0 bps')} · ${esc(a.status)}</div>
              <div class="small" style="color:var(--muted);margin-top:2px">${esc(a.description || '')}</div>
            </div>
          `).join('')}
        </div>
      </div>
    ` : ''}

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
      <div class="hub-orb" style="background:linear-gradient(135deg,#ec4899,#7bc8d7)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-applications"/></svg></div>
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
      <div class="hub-orb" style="background:linear-gradient(135deg,#75c6d7,#60bed1)"><svg viewBox="0 0 24 24" width="34" height="34"><use href="#cmm-ico-clutter"/></svg></div>
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

    ${spaceLens()}

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

let AI_RESULT = null;
let AI_RUNNING = false;
let AI_CATEGORY_FILTER = 'all';

function onAIProviderChange(val){
  localStorage.setItem('rs_ai_provider', val);
  ['#aiKeyBox', '#aiKeyBoxPre'].forEach(id=>{
    let el = $(id);
    if(el) el.style.display = (val === 'heuristic' || val === 'ollama') ? 'none' : '';
  });
  ['#aiEndpointBox', '#aiEndpointBoxPre'].forEach(id=>{
    let el = $(id);
    if(el) el.style.display = val === 'heuristic' ? 'none' : '';
  });
  ['#aiModelInput', '#aiModelInputPre'].forEach(id=>{
    let modelInput = $(id);
    if(modelInput && !modelInput.value){
      if(val === 'openai') modelInput.placeholder = 'gpt-4o';
      else if(val === 'anthropic') modelInput.placeholder = 'claude-3-5-sonnet-20241022';
      else if(val === 'gemini') modelInput.placeholder = 'gemini-1.5-flash';
      else if(val === 'ollama') modelInput.placeholder = 'llama3:latest';
    }
  });
}

function setAICategoryFilter(cat){
  AI_CATEGORY_FILTER = cat;
  render();
}

async function copySanitizedPrompt(btn){
  let oldText = btn.textContent;
  btn.textContent = '⏳ Preparing prompt...';
  try{
    let resp = await fetch('/api/ai-prompt?token=' + encodeURIComponent(token), {
      method: REPORT ? 'POST' : 'GET',
      headers: REPORT ? {'Content-Type': 'application/json'} : {},
      body: REPORT ? JSON.stringify({report: REPORT}) : undefined
    });
    if(!resp.ok) throw new Error('Failed to fetch prompt');
    let data = await resp.json();
    let promptText = data.prompt || '';
    if(navigator.clipboard && navigator.clipboard.writeText){
      await navigator.clipboard.writeText(promptText);
    }else{
      let ta = document.createElement('textarea');
      ta.value = promptText;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    btn.textContent = '✓ Copied to Clipboard!';
    setTimeout(() => btn.textContent = oldText, 2500);
  }catch(e){
    alert('Failed to copy prompt: ' + e.message);
    btn.textContent = oldText;
  }
}

async function runAIReview(){
  let provider = ($('#aiProviderSelect') && $('#aiProviderSelect').value) ||
                 ($('#aiProviderSelectPre') && $('#aiProviderSelectPre').value) ||
                 localStorage.getItem('rs_ai_provider') || 'heuristic';
  let apiKey = ($('#aiApiKeyInput') && $('#aiApiKeyInput').value.trim()) ||
               ($('#aiApiKeyInputPre') && $('#aiApiKeyInputPre').value.trim()) ||
               localStorage.getItem('rs_ai_key') || '';
  let model = ($('#aiModelInput') && $('#aiModelInput').value.trim()) ||
              ($('#aiModelInputPre') && $('#aiModelInputPre').value.trim()) ||
              localStorage.getItem('rs_ai_model') || '';
  let endpoint = ($('#aiEndpointInput') && $('#aiEndpointInput').value.trim()) ||
                 ($('#aiEndpointInputPre') && $('#aiEndpointInputPre').value.trim()) ||
                 localStorage.getItem('rs_ai_endpoint') || '';
  let redact = true;
  if($('#aiRedactToggle')) redact = $('#aiRedactToggle').checked;
  else if($('#aiRedactTogglePre')) redact = $('#aiRedactTogglePre').checked;

  try{
    localStorage.setItem('rs_ai_provider', provider);
    if(apiKey) localStorage.setItem('rs_ai_key', apiKey);
    if(model) localStorage.setItem('rs_ai_model', model);
    if(endpoint) localStorage.setItem('rs_ai_endpoint', endpoint);
  }catch(e){}

  if(!REPORT){
    alert('Please run a Smart Audit or load a saved report first before running AI review.');
    return;
  }

  AI_RUNNING = true;
  render();

  try{
    let resp = await fetch('/api/ai-review?token=' + encodeURIComponent(token), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        provider: provider,
        api_key: apiKey,
        model: model,
        endpoint: endpoint,
        redact: redact,
        report: REPORT
      })
    });
    if(!resp.ok){
      let errText = await resp.text();
      throw new Error(errText || 'AI review request failed');
    }
    let res = await resp.json();
    if(!res.ok && res.error){
      alert('AI Advisor Notice: ' + res.error);
    }
    AI_RESULT = res;
  }catch(err){
    alert('AI Review error: ' + err.message);
  }finally{
    AI_RUNNING = false;
    render();
  }
}

function exportAIReviewMarkdown(){
  if(!AI_RESULT) return;
  let r = AI_RESULT;
  let md = '# ReconSpace AI Audit Advisor - Executive Review\n\n' +
    '**System Wellness Score:** `' + r.overall_score + '/100`  \n' +
    '**AI Engine:** `' + r.provider + '` (`' + r.model + '`)  \n' +
    '**Total Reclaimable Potential:** `' + bytes(r.total_potential_reclaim_bytes||0) + '`  \n\n' +
    '## Executive Summary\n\n> ' + r.summary_verdict + '\n\n';

  ['critical_actions', 'quick_wins', 'safety_warnings', 'explainers'].forEach(cat => {
    let items = r[cat] || [];
    if(!items.length) return;
    let title = cat === 'critical_actions' ? 'Critical Actions' : (cat === 'quick_wins' ? 'Quick Wins' : (cat === 'safety_warnings' ? 'Safety Warnings' : 'Explainers'));
    md += '## ' + title + '\n\n';
    items.forEach(item => {
      md += '### [' + item.id + '] ' + item.title + '\n';
      md += '- **Safety:** `' + item.safety_rating + '`' + (item.impact_reclaim_bytes ? ' | **Reclaim:** `' + bytes(item.impact_reclaim_bytes) + '`' : '') + '\n';
      md += '- **Summary:** ' + item.summary + '\n';
      if(item.technical_detail) md += '- **Technical Detail:** ' + item.technical_detail + '\n';
      if(item.suggested_action) md += '- **Action:**\n  ```powershell\n  ' + item.suggested_action + '\n  ```\n';
      md += '\n';
    });
  });

  let blob = new Blob([md], {type: 'text/markdown;charset=utf-8'});
  let url = URL.createObjectURL(blob);
  let a = document.createElement('a');
  a.href = url;
  a.download = 'reconspace-ai-review.md';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function exportAIReviewJSON(){
  if(!AI_RESULT) return;
  let blob = new Blob([JSON.stringify(AI_RESULT, null, 2)], {type: 'application/json;charset=utf-8'});
  let url = URL.createObjectURL(blob);
  let a = document.createElement('a');
  a.href = url;
  a.download = 'reconspace-ai-review.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function aiReviewView(){
  if(!REPORT){
    return getPreScanHub('ai');
  }

  let savedKey = localStorage.getItem('rs_ai_key') || '';
  let savedProvider = localStorage.getItem('rs_ai_provider') || 'heuristic';
  let savedModel = localStorage.getItem('rs_ai_model') || '';
  let savedEndpoint = localStorage.getItem('rs_ai_endpoint') || '';

  let html = `
    <div class="hub-hero">
      <div class="hub-orb" style="background:linear-gradient(135deg,#2c8394,#65bbcc)">✦</div>
      <div>
        <h2>ReconSpace AI Audit Advisor</h2>
        <p>AI-powered Windows architecture &amp; security review. Triages telemetry, flags developer tooling invariants, detects bloat patterns, and provides verified PowerShell recipes.</p>
      </div>
    </div>

    <!-- Configuration Card -->
    <div class="panel" style="margin-top:20px;padding:20px">
      <h3 style="margin-top:0;font-size:16px;font-weight:750">AI Advisor Configuration</h3>
      <div class="grid" style="grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:14px;margin-top:14px">
        <div>
          <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">AI Engine / Provider</label>
          <select id="aiProviderSelect" style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="onAIProviderChange(this.value)">
            <option value="heuristic" ${savedProvider==='heuristic'?'selected':''}>Offline Heuristic Engine (No Key Required)</option>
            <option value="openai" ${savedProvider==='openai'?'selected':''}>OpenAI / OpenRouter / Groq</option>
            <option value="anthropic" ${savedProvider==='anthropic'?'selected':''}>Anthropic Claude</option>
            <option value="gemini" ${savedProvider==='gemini'?'selected':''}>Google Gemini</option>
            <option value="ollama" ${savedProvider==='ollama'?'selected':''}>Ollama (Local LLM)</option>
          </select>
        </div>
        <div id="aiKeyBox" style="${savedProvider==='heuristic'||savedProvider==='ollama'?'display:none':''}">
          <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">API Key (Saved locally)</label>
          <input type="password" id="aiApiKeyInput" value="${esc(savedKey)}" placeholder="sk-..." style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="localStorage.setItem('rs_ai_key', this.value.trim())">
        </div>
        <div id="aiModelBox">
          <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">Model Override (Optional)</label>
          <input type="text" id="aiModelInput" value="${esc(savedModel)}" placeholder="Default for provider" style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="localStorage.setItem('rs_ai_model', this.value.trim())">
        </div>
        <div id="aiEndpointBox" style="${savedProvider==='heuristic'?'display:none':''}">
          <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">Custom Endpoint (Optional)</label>
          <input type="text" id="aiEndpointInput" value="${esc(savedEndpoint)}" placeholder="Default provider API URL" style="width:100%;padding:7px;border-radius:6px;background:var(--card);color:var(--fg);border:1px solid var(--border)" onchange="localStorage.setItem('rs_ai_endpoint', this.value.trim())">
        </div>
      </div>

      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-top:16px;padding-top:14px;border-top:1px solid var(--border)">
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer">
          <input type="checkbox" id="aiRedactToggle" checked>
          <span><b>Privacy Guard:</b> Sanitize usernames, hostnames, paths, and secrets before prompting</span>
        </label>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button type="button" class="secondary" onclick="copySanitizedPrompt(this)">📋 Copy Sanitized Prompt for Web Chat</button>
          <button type="button" id="btnRunAI" class="primary" style="background:linear-gradient(135deg,#2c8394,#65bbcc);border:none" onclick="runAIReview()" ${AI_RUNNING?'disabled':''}>
            ${AI_RUNNING ? '⏳ Analyzing Telemetry...' : '✦ Run AI Audit Review'}
          </button>
        </div>
      </div>
    </div>
  `;

  if(AI_RUNNING){
    html += `
      <div class="panel" style="margin-top:20px;text-align:center;padding:40px">
        <div style="font-size:24px;margin-bottom:10px">✦</div>
        <h3>ReconSpace AI Advisor is Analyzing Your System...</h3>
        <p class="small">Correlating storage findings, Defender security posture, Win32 RAM loads, open-source intelligence metrics, and developer tooling invariants.</p>
      </div>
    `;
    return html;
  }

  if(!AI_RESULT){
    html += `
      <div class="panel" style="margin-top:20px;padding:30px;text-align:center">
        <p style="margin:0 0 10px 0;font-size:15px">Click <b>✦ Run AI Audit Review</b> above to generate evidence-based recommendations, quick wins, safety invariants, and architectural explainers.</p>
        <p class="small">The offline heuristic engine runs instantly without internet access or an API key.</p>
      </div>
    `;
    return html;
  }

  let res = AI_RESULT;
  let crit = res.critical_actions || [];
  let quick = res.quick_wins || [];
  let warns = res.safety_warnings || [];
  let expls = res.explainers || [];
  let all = res.recommendations || (crit.concat(quick, warns, expls));

  let displayed = all;
  if(AI_CATEGORY_FILTER === 'critical') displayed = crit;
  else if(AI_CATEGORY_FILTER === 'quick_wins') displayed = quick;
  else if(AI_CATEGORY_FILTER === 'safety') displayed = warns;
  else if(AI_CATEGORY_FILTER === 'explainers') displayed = expls;

  let scoreColor = res.overall_score >= 80 ? 'var(--good)' : (res.overall_score >= 60 ? 'var(--warn)' : 'var(--bad)');

  html += `
    <!-- Results Header / Wellness Score -->
    <div class="chart" style="margin-top:20px;display:flex;align-items:center;gap:24px;flex-wrap:wrap">
      <div style="text-align:center;min-width:110px">
        <div style="font-size:42px;font-weight:800;color:${scoreColor};line-height:1">${res.overall_score}</div>
        <div class="small" style="font-weight:700;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px">Health Score</div>
      </div>
      <div style="flex:1;min-width:260px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span class="badge" style="background:#203a43;color:#2af598">Engine: ${esc(res.provider)} (${esc(res.model)})</span>
          <span class="badge safe">Est. Reclaim: ${bytes(res.total_potential_reclaim_bytes||0)}</span>
          ${res.sanitization_summary&&res.sanitization_summary.redacted ? '<span class="badge">🛡️ Redacted PII</span>' : ''}
        </div>
        <div style="font-size:14px;line-height:1.45;color:var(--fg)">${esc(res.summary_verdict)}</div>
      </div>
      <div style="display:flex;gap:8px">
        <button type="button" class="secondary" style="font-size:11px" onclick="exportAIReviewMarkdown()">Export .MD</button>
        <button type="button" class="secondary" style="font-size:11px" onclick="exportAIReviewJSON()">Export JSON</button>
      </div>
    </div>

    <!-- Category Filter Tabs -->
    <div style="display:flex;gap:8px;margin-top:20px;flex-wrap:wrap">
      <button type="button" class="secondary ${AI_CATEGORY_FILTER==='all'?'active':''}" style="${AI_CATEGORY_FILTER==='all'?'background:var(--primary);color:#fff;':''}" onclick="setAICategoryFilter('all')">All Recommendations (${all.length})</button>
      <button type="button" class="secondary ${AI_CATEGORY_FILTER==='critical'?'active':''}" style="${AI_CATEGORY_FILTER==='critical'?'background:#ef476f;color:#fff;':''}" onclick="setAICategoryFilter('critical')">🚨 Critical Actions (${crit.length})</button>
      <button type="button" class="secondary ${AI_CATEGORY_FILTER==='quick_wins'?'active':''}" style="${AI_CATEGORY_FILTER==='quick_wins'?'background:#06d6a0;color:#000;':''}" onclick="setAICategoryFilter('quick_wins')">⚡ Quick Wins (${quick.length})</button>
      <button type="button" class="secondary ${AI_CATEGORY_FILTER==='safety'?'active':''}" style="${AI_CATEGORY_FILTER==='safety'?'background:#118ab2;color:#fff;':''}" onclick="setAICategoryFilter('safety')">🛡️ Safety Warnings (${warns.length})</button>
      <button type="button" class="secondary ${AI_CATEGORY_FILTER==='explainers'?'active':''}" style="${AI_CATEGORY_FILTER==='explainers'?'background:#2c8394;color:#fff;':''}" onclick="setAICategoryFilter('explainers')">📚 Explainers (${expls.length})</button>
    </div>

    <!-- Cards List -->
    <div style="margin-top:16px;display:flex;flex-direction:column;gap:14px">
      ${displayed.map(r => {
        let catBadge = r.category === 'critical_action'
          ? '<span style="background:#ef476f;color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:750">CRITICAL</span>'
          : (r.category === 'quick_win'
            ? '<span style="background:#06d6a0;color:#000;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:750">QUICK WIN</span>'
            : (r.category === 'safety_warning'
              ? '<span style="background:#118ab2;color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:750">SAFETY WARNING</span>'
              : '<span style="background:#2c8394;color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:750">EXPLAINER</span>'));

        let safetyBadge = r.safety_rating === 'do_not_touch'
          ? '<span class="review" style="font-size:11px">DO NOT TOUCH</span>'
          : (r.safety_rating === 'requires_manual_review'
            ? '<span class="review" style="font-size:11px">MANUAL REVIEW</span>'
            : '<span class="safe" style="font-size:11px">HIGH SAFETY</span>');

        return `
          <div class="panel" style="padding:16px 20px;border-left:4px solid ${r.category==='critical_action'?'#ef476f':(r.category==='quick_win'?'#06d6a0':(r.category==='safety_warning'?'#118ab2':'#2c8394'))}">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap">
              <div>
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                  ${catBadge}
                  <span class="mono small" style="font-weight:700">${esc(r.id)}</span>
                  ${safetyBadge}
                  ${r.impact_reclaim_bytes > 0 ? `<span class="safe" style="font-weight:700;font-size:12px">+${bytes(r.impact_reclaim_bytes)}</span>` : ''}
                </div>
                <h4 style="margin:0 0 6px 0;font-size:16px;font-weight:750">${esc(r.title)}</h4>
              </div>
            </div>
            <div style="margin-top:6px;font-size:13px;line-height:1.45;color:var(--fg)">${esc(r.summary)}</div>
            ${r.technical_detail ? `<div class="small" style="margin-top:8px;color:var(--muted);line-height:1.4"><b>Technical Rationale:</b> ${esc(r.technical_detail)}</div>` : ''}
            ${r.suggested_action ? `
              <div class="recipe-box" style="margin-top:10px">
                <span class="recipe-code">${esc(r.suggested_action)}</span>
                <button type="button" class="secondary" style="font-size:11px;padding:3px 8px" onclick="copyPath(this, '${esc(r.suggested_action).replace(/'/g, "\\'")}')">Copy</button>
              </div>
            ` : ''}
            ${r.affected_paths && r.affected_paths.length ? `
              <div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap">
                ${r.affected_paths.map(p => `<span class="badge mono" style="font-size:10px">${esc(p)}</span>`).join('')}
              </div>
            ` : ''}
          </div>
        `;
      }).join('')}
    </div>
  `;

  return html;
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
  else if(v==='ai_review')h=aiReviewView();
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
  if(v==='clutter_hub')bindSpaceLens();
  $$('#view .hub-orb').forEach(el=>{el.innerHTML=cmmIcon(currentPage==='cleanup'?'clean':currentPage,48);});

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

    const running=s.running||scanSubmitting;
    $('#scan').disabled=running;
    $('#cancel').disabled=!s.running||s.progress?.phase==='cancelling';
    $('#cancelSpotlight').disabled=$('#cancel').disabled;
    if(scanRunning!==running){scanRunning=running;navigatePage(currentPage,false);}

    let p=s.progress||{},phase=p.phase||'idle';
    if(s.running)CareMotion.phaseArtwork(phase.includes('duplicate')?'clutter':phase.includes('trust')||phase.includes('permission')?'protection':phase.includes('process')?'performance':phase.includes('application')||phase.includes('startup')?'applications':phase.includes('filesystem')?'cleanup':'home');
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
    }else if(phase==='cancelling'){
      headline='Stopping safely after the current check…';
      detail='A Windows collector may need to finish or time out before the audit stops.';
      text='Cancelling audit…';
    }else if(phase==='failed'){
      headline='Audit Failed';
      detail=s.error||'An unexpected error occurred during execution.';
      text='Audit failed';
    }

    $('#status').textContent=text;
    $('#scanPhase').textContent=headline;
    $('#scanHeadline').textContent='A little care, in progress.';
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

    if(phase==='cancelled'&&!REPORT&&!running)CareFlow.cancelled();
    if(phase==='failed'&&!REPORT&&!running)CareFlow.failed();
    if(s.has_report&&!REPORT&&!running){
      let reportResponse=await fetch('/api/report',{cache:'no-store',credentials:'omit',headers:{'X-ReconSpace-Token':token}});
      if(!reportResponse.ok)throw new Error(`Report request failed (${reportResponse.status}).`);
      REPORT=await reportResponse.json();
      $('#scanComposer').classList.remove('scanning-active');
      renderCareResults();
      renderMetrics();
      navigatePage(CareFlow.scanFinished(currentPage));
      if($('#autoAiReview') && $('#autoAiReview').checked){
        runAIReview();
      }
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
  CareFlow.scanStarted();
  if(scanRunning)return;
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
  $('#scanPhase').textContent='Preparing your audit…';
  $('#statusBadgeText').textContent='Preparing';
  $('#scanComposer').classList.add('scanning-active');
  scanRunning=true;
  scanSubmitting=true;
  navigatePage('home');
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
    scanSubmitting=false;
    $('#status').textContent='Audit queued…';
    $('#cancel').disabled=false;
    $('#cancelSpotlight').disabled=false;
    logActivity('Audit received and queued by engine', 'item');
  }catch(e){
    scanSubmitting=false;
    showError(e.message||'Could not start the audit.');
    $('#status').textContent='Audit did not start';
    $('#scan').disabled=false;
    scanStartTime=null;
    scanRunning=false;
    $('#scanComposer').classList.remove('scanning-active');
    const failedDestination=CareFlow.scanFailed();
    navigatePage(REPORT?failedDestination:'settings');
  }
};

$('#cancel').onclick=async()=>{
  try{
    let r=await fetch('/api/cancel',{method:'POST',credentials:'omit',headers:{'X-ReconSpace-Token':token}});
    if(!r.ok)throw new Error(await r.text());
    $('#status').textContent='Cancelling audit…';
    $('#scanPhase').textContent='Stopping safely after the current check…';
    $('#cancelSpotlight').disabled=true;
    logActivity('Cancellation signal sent to engine...', 'stage');
  }catch(e){
    showError(e.message||'Could not cancel the audit.');
  }
};

function initTabs(){
  let tabs=[...$$('.tab')];
  let tablist=$('.tabs');
  let syncOrientation=()=>tablist.setAttribute('aria-orientation','horizontal');
  syncOrientation();
  addEventListener('resize',syncOrientation,{passive:true});
  tabs.forEach((button,index)=>{
    button.id=`audit-tab-${button.dataset.view}`;
    button.setAttribute('aria-controls','view');
    button.setAttribute('tabindex',index===0?'0':'-1');
    button.onclick=()=>switchTab(button.dataset.view);
    button.onkeydown=event=>{
      const visible=tabs.filter(t=>!t.classList.contains('hidden'));
      const position=visible.indexOf(button);
      let delta=event.key==='ArrowDown'||event.key==='ArrowRight'?1:event.key==='ArrowUp'||event.key==='ArrowLeft'?-1:0;
      let target=event.key==='Home'?0:event.key==='End'?visible.length-1:delta?(position+delta+visible.length)%visible.length:-1;
      if(target<0)return;
      event.preventDefault();
      switchTab(visible[target].dataset.view);
      visible[target].focus();
    };
  });
}

$$('button[data-page]').forEach(button=>button.addEventListener('click',()=>navigatePage(button.dataset.page)));
$$('.rail-item').forEach(button=>{const icon=button.querySelector('.rail-icon');if(icon)icon.innerHTML=cmmIcon(button.dataset.page==='home'?'smart':button.dataset.page,26);});
$('#scanOrbitIcon').innerHTML=careArtwork('home');
$$('.care-tile').forEach((tile,index)=>{
  const page=['cleanup','protection','performance','applications','clutter','ai'][index];
  tile.setAttribute('role','button');tile.setAttribute('tabindex','0');
  tile.querySelector('.care-tile-icon').innerHTML=careArtwork(page);
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

function startAuditWithAI(){
  if($('#autoAiReview')) $('#autoAiReview').checked = true;
  let prov = $('#aiProviderSelectPre') ? $('#aiProviderSelectPre').value : '';
  let key = $('#aiApiKeyInputPre') ? $('#aiApiKeyInputPre').value.trim() : '';
  let mod = $('#aiModelInputPre') ? $('#aiModelInputPre').value.trim() : '';
  let ep = $('#aiEndpointInputPre') ? $('#aiEndpointInputPre').value.trim() : '';
  try{
    if(prov) localStorage.setItem('rs_ai_provider', prov);
    if(key) localStorage.setItem('rs_ai_key', key);
    if(mod) localStorage.setItem('rs_ai_model', mod);
    if(ep) localStorage.setItem('rs_ai_endpoint', ep);
  }catch(e){}
  navigatePage('home');
  $('#scan').click();
}

async function handleReportImport(e){
  let file = e.target.files && e.target.files[0];
  if(!file) return;
  if(file.size > MAX_IMPORTED_REPORT_BYTES){
    alert('Report file is too large (max 64MB)');
    return;
  }
  try{
    let text = await file.text();
    let imported = validateImportedReport(JSON.parse(text));
    REPORT = imported;
    $('#scanComposer').classList.remove('scanning-active');
    $('#summary').classList.remove('hidden');
    renderMetrics();
    renderCareResults();
    navigatePage(currentPage === 'home' || currentPage === 'settings' ? 'home' : currentPage, false);
    if(currentPage === 'ai'){
      switchTab('ai_review');
    }
  }catch(err){
    alert('Failed to load report: ' + err.message);
  }finally{
    e.target.value = '';
  }
}

$('#profile').onchange=profileHint;
initTabs();
profileHint();
poll();
</script>
</body>
</html>'''.replace("__PROFILES__", profiles).replace("__VERSION__", __version__).replace("__CARE_CSS__", "\n".join(files("reconspace").joinpath("assets", name).read_text(encoding="utf-8") for name in ("care.css", "experience.css", "care-flow.css"))).replace("__CARE_MOTION__", files("reconspace").joinpath("assets/care-motion.js").read_text(encoding="utf-8")).replace("__SPACE_LENS__", files("reconspace").joinpath("assets/space-lens.js").read_text(encoding="utf-8")).replace("__CARE_FLOW__", files("reconspace").joinpath("assets/care-flow.js").read_text(encoding="utf-8"))


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
        if parsed.path in {f"/assets/care-{name}.png" for name in ("desktop", "storage", "protection", "performance", "applications", "clutter")}:
            payload = files("reconspace").joinpath("assets", parsed.path.rsplit("/", 1)[-1]).read_bytes()
            self.send_response(200)
            self._headers("image/png", len(payload))
            self.end_headers()
            self.wfile.write(payload)
            return
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
        if parsed.path == "/api/ai-prompt":
            with STATE.lock:
                report = STATE.report
            if report is None:
                report = _sample_preview_report()
            sys_prompt, user_prompt, summary = build_advisor_prompt(report, redact=True)
            combined = f"--- SYSTEM PROMPT ---\n{sys_prompt}\n\n--- USER PROMPT ---\n{user_prompt}\n"
            self._send_json({"prompt": combined, "sanitization": summary})
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

        if parsed.path == "/api/ai-prompt":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}", parse_constant=_reject_json_constant) if length > 0 else {}
                custom_report = body.get("report") if isinstance(body, dict) else None
                if custom_report is None:
                    with STATE.lock:
                        custom_report = STATE.report
                if custom_report is None:
                    custom_report = _sample_preview_report()
                sys_prompt, user_prompt, summary = build_advisor_prompt(custom_report, redact=True)
                combined = f"--- SYSTEM PROMPT ---\n{sys_prompt}\n\n--- USER PROMPT ---\n{user_prompt}\n"
                self._send_json({"prompt": combined, "sanitization": summary})
                return
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 500)
                return

        if parsed.path == "/api/ai-review":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 50 * 1024 * 1024:
                    self._send_text("request body too large", 413)
                    return
                body = json.loads(self.rfile.read(length) or b"{}", parse_constant=_reject_json_constant)
                if not isinstance(body, dict):
                    self._send_text("request body must be a JSON object", 400)
                    return
                custom_report = body.get("report")
                if custom_report is None:
                    with STATE.lock:
                        custom_report = STATE.report
                if not custom_report or not isinstance(custom_report, dict):
                    self._send_text("no report available to review", 400)
                    return
                provider = str(body.get("provider") or "heuristic")
                api_key = str(body.get("api_key") or "")
                model = str(body.get("model") or "")
                endpoint = str(body.get("endpoint") or "")
                redact = bool(body.get("redact", True))
                cfg = AIProviderConfig(
                    provider=provider,
                    api_key=api_key,
                    model=model,
                    endpoint=endpoint,
                )
                result = query_ai_advisor(custom_report, config=cfg, redact=redact)
                self._send_json(ai_review_to_json(result))
                return
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 500)
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
    try:
        server = LocalThreadingHTTPServer((host, port), Handler)
    except OSError as error:
        # Windows exclusive/reserved ports may report WSAEACCES rather than address-in-use.
        if error.errno not in {errno.EADDRINUSE, errno.EACCES} and getattr(error, "winerror", None) not in {10048, 10013}:
            raise
        server = LocalThreadingHTTPServer((host, 0), Handler)
        print(f"Port {port} is unavailable; opened ReconSpace on a free local port instead.")
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
