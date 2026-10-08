# Changelog

## 1.3.0 — 2026-10-05

- Researched MacPaw's Smart Care, 3D/parallax design, Space Lens interaction and accessibility guidance; saved a complete experience plan.
- Added five original transparent glass illustrations, graphic-led module welcomes and results, real-phase scan artwork, pointer parallax, directional zoom/fade stages and a sliding sidebar marker.
- Added an accessible linked storage bubble map with retained-evidence drill-down and breadcrumbs. No fabricated filesystem nodes or cleanup claims.
- Added tab-scoped refresh session recovery, persistent motion preferences, hidden-tab animation pausing, and eliminated stacked legacy animation/reflow.
- Preserved the graphite/icy-blue/mint palette and existing read-only audit engine, exports, tabs and AI Advisor.

## 1.2.0 — 2026-10-05

- Rebuilt the complete visual system around a focused welcome → audit → review experience: graphite surfaces, icy-blue/mint accents, original generated desktop artwork, and a coherent vector icon family. Purple was removed following user review.
- Dedicated scanning spotlight and results overview, functioning module navigation, packaged local artwork, restrained zoom/fade transitions, zoom controls, and reduced-motion support.
- Fixed hidden-tab keyboard navigation and report-import summary refresh; retained the existing audit engine, detailed module hubs, exports, and AI Advisor.
- Shipped the same UI in App, portable PYZ, and complete ZIP. See CARE_UI_QA.md for verification and limitations.

## 1.1.0 — 2026-10-03

### Open-Source System Intelligence Deepening & AI Audit Advisor

- **AI Audit Advisor (`reconspace.ai_advisor`)**:
  - Multi-provider architecture supporting OpenAI, Anthropic Claude, Google Gemini, Ollama local models, and offline deterministic heuristic analysis with zero runtime external dependencies (Python 3.11+ stdlib only via `urllib.request`).
  - Automatic report sanitization and PII redaction (`build_advisor_prompt`) transforming sensitive user paths, tokens, and system names into generic environment placeholders.
  - High-signal context condensation (`build_condensed_audit_context`) synthesizing storage, memory load, Defender state, crash dumps, delivery cache, and system internals.
  - Structured advisor schema outputting an overall System Wellness Score (0–100), Critical Actions, Quick Wins, Safety Warnings (guarding virtualenvs, WinSxS hardlinks, WSL VHDX files), and Architectural Explainers.
  - Safe inspection commands and recipes for one-click operator review.
- **Deepened Open-Source Windows Telemetry (`reconspace.windows_collectors`)**:
  - `collect_hibernation_pagefile_intelligence`: Dism++ inspired analysis checking `hiberfil.sys` sizing and calculating ~50% RAM disk savings via Windows reduced hibernation mode (`powercfg /hibernate /type reduced`).
  - `collect_delivery_optimization_status`: Windows Update peer-to-peer distribution cache sizing and upload bandwidth metrics (`Get-DeliveryOptimizationPerfSnap`).
  - `collect_battery_power_health`: Mobile/desktop power diagnostics via CIM `Win32_Battery` reporting charge percentage, wear levels, and AC connected states.
  - `collect_network_adapters_telemetry`: Glances/Stacer style network adapter inventory reporting active interfaces, link speeds, and interface types via `Get-NetAdapter`.
  - `collect_crash_dumps_inventory`: Forensic memory and user crash dump sizing across `%SystemRoot%\MEMORY.DMP`, minidumps, and `%LocalAppData%\CrashDumps`.
  - `collect_recycle_bin_metrics`: PrivaZer inspired volume-level Recycle Bin sizing via Win32 `SHQueryRecycleBinW` with robust directory walk fallback.
- **Web UI & CLI Integration**:
  - Added CLI `ai-review` subcommand supporting `--provider`, `--api-key`, `--model`, `--endpoint`, `--prompt-only`, `--json`, `--output`, and `--no-redact`.
  - Integrated dedicated AI Advisor view into the Web UI with live provider configuration, prompt inspection, wellness score meter, recommendation filter pills, and Markdown/JSON export.
  - Deepened Cleanup and Performance Hubs with cards and telemetry for the new open-source collectors.
  - Added backend endpoints `POST /api/ai-review` and `GET /api/ai-prompt`.
- **Safety & Quality**:
  - Full adherence to read-only scanner invariant verified by `test_safety.py`.
  - Expanded test suite to 158 tests passing at 100%.

## 1.0.0 — 2026-10-02

### Production Safe-Execution Runner & Milestone Release

- **Cryptographic Manifest Integrity**: Added SHA-256 plan manifest hashing (`compute_manifest_hash`) and tamper verification (`verify_plan_manifest`) to protect against unauthorized modifications or disk drift.
- **Strict Safe-Execution Runner**: Implemented `execute_approved_plan` in `reconspace.runner`:
  - Enforces `is_system_protected_path` boundary guards covering system roots, Windows directories, user profiles, and critical system volumes.
  - Restricts automated actions strictly to `probably_safe_cleanup` items; rejects `manual_review` or unsafe items.
  - Dry-run simulation enabled by default; requires explicit `--confirm` flag for live execution.
  - Win32 Recycle Bin execution via `ctypes.windll.shell32.SHFileOperationW` with `FOF_ALLOWUNDO` to ensure complete reversibility.
- **CLI Execution Command**: Added `reconspace execute-plan` subcommand supporting dry-run inspection, selected item approval, and safe execution.
- **Milestone Verification**: Complete test suite expanded to 135 tests passing with 0 failures, maintaining 100% compliance with read-only audit engine safety invariants.

## 0.9.0 — 2026-10-02

### Advanced Persistence & Windows Servicing Intelligence

- **Extended Persistence Auditing**: Added `collect_extended_persistence` for Explorer Context Menu handlers (`*`, `Directory`, `Folder`), `AppInit_DLLs`, Winlogon Shell/Userinit entries, and Browser Helper Objects (BHOs) with CLSID resolution and user-writable path detection.
- **NTFS Alternate Data Streams (ADS)**: Added `collect_alternate_data_streams` using Win32 `FindFirstStreamW`/`FindNextStreamW` to detect Zone.Identifier (Mark-of-the-Web) tags and hidden data streams.
- **WinSxS Hardlink Deduplication Delta**: Enhanced DISM Component Store analysis to compute the delta between Explorer-reported virtual sizes and actual allocated physical bytes, eliminating deceptive reclaim estimates.
- **Windows Update & Delivery Cache**: Added `collect_windows_update_cache` auditing SoftwareDistribution `Download` and `DataStore` directories, Delivery Optimization cache, and service statuses for `wuauserv`, `bits`, and `dosvc`.

## 0.8.0 — 2026-10-02

### Accelerated Traversal & Package Manager Catalog

- **Win32 NTFS Volume & MFT Metadata**: Added `reconspace.ntfs` module querying NTFS volume parameters, MFT record sizes, cluster geometries, and USN Journal metadata via `DeviceIoControl` (`FSCTL_GET_NTFS_VOLUME_DATA`, `FSCTL_QUERY_USN_JOURNAL`).
- **WinGet Catalog Correlation**: Added `collect_winget_catalog_correlation` parsing `winget list`, tracking package versions, detecting available upgrades, and surfacing copyable upgrade commands.
- **Multi-Browser Extension Auditing**: Added `collect_browser_extensions` parsing manifest data across Chrome, Edge, Brave, and Firefox, classifying extensions into high, medium, and low risk profiles based on sensitive permissions (e.g. `<all_urls>`, `webRequest`, `nativeMessaging`).
- **RAM Working Set Trimming**: Added non-invasive Win32 `EmptyWorkingSet` memory optimization guidance to the Performance Hub.

## 0.7.0 — 2026-10-02

### CleanMyMac for PC Architecture & Open-Source Tool Synthesis

- Implemented four Care Pillars on Overview (`cleanup`, `protection`, `performance`, `applications`) linking directly to module hubs.
- Added 5 dedicated Module Hubs (`cleanup_hub`, `protection_hub`, `performance_hub`, `applications_hub`, `clutter_hub`) with interactive visual telemetry, metrics, and copyable Microsoft PowerShell inspection recipes.
- Added pre-scan module cards (`getPreScanHub`) enabling full navigation and orientation before initiating an audit.
- Added non-invasive Win32 physical RAM load & pagefile pressure collector via `ctypes` `GlobalMemoryStatusEx` with zero-safe arithmetic guards.
- Added Windows Defender security posture collector auditing real-time protection, signature definition currency, and threat detections via CIM.
- Added Windows ConsentStore hardware privacy permissions collector auditing webcam, microphone, location, and notification listeners across Desktop and Packaged UWP applications.
- Added browser profile footprint collector measuring SQLite databases and cache storage across Chrome, Edge, Brave, and Firefox.
- Added orphaned AppData/ProgramData leftover collector inspired by Bulk Crap Uninstaller heuristics with token normalization, running process cross-checks, and a 14-day stale cutoff to eliminate false positives on active developer tools.
- Added Space Lens interactive proportional folder map and multi-tier Large & Old Files filter bar (>1 GB, 500 MB, >1 year, 6 months, archives, media).
- Added 8 standard administrative PowerShell maintenance and performance recipes (DNS flush, SSD TRIM, DISM component store analysis, SFC integrity, search indexer repair, WER dumps, Delivery Optimization).
- Published comprehensive comparative research and Grand Plan roadmap in `RESEARCH_AND_ROADMAP.md`.
- Expanded automated test suite to 119 unit and safety regression tests.

## 0.6.1 — 2026-10-02

- Rebuilt the portable application and complete release with the repaired UI.
- Added working module navigation, page history, scan settings, and contextual report tabs.
- Refined desktop and compact layouts and removed decorative window controls.
- Displayed the UI build identifier to distinguish this release from older v0.6 packages.

## 0.6.0 — 2026-09-28

### Decision guidance and depth transparency

- Added a plain-language post-scan decision brief with free-space state, evidence quality, actionable counts, and a concrete next step.
- Added an in-dashboard plan-only workflow that separates probably-safe candidates, manual-review candidates, and protected/developer/cybersecurity tooling.
- Added an eight-domain depth ledger covering the storage map, Windows recovery/storage, apps/toolchains, virtualization, persistence, activity/ownership, trust/permissions, and rule/duplicate evidence.
- Made selected-root filesystem scope versus host-wide Windows inventory explicit in the dashboard, Markdown report, JSON/Markdown approval plans, and coverage view.
- Added honest non-additive estimates for path, duplicate, application, and platform opportunities throughout the guided plan.
- Fixed Windows limited-codepage consoles failing after a successful scan when Markdown contained unsupported symbols.
- Stopped scheduled-task COM handlers and bare commands from becoming project-relative missing-binary findings; reduced built-in Microsoft task noise while retaining high-signal user-writable/encoded/temp-path warnings.
- Replaced per-process WMI owner calls with bounded batched task-list correlation, cutting the observed process phase from roughly two minutes to about 36 seconds on the validation host.
- Protected Microsoft Edge and WebView2 from being counted as ordinary uninstall reclaim opportunities.
- Added regression coverage for scope guidance, depth-domain status, decision UI, plan UI, richer Markdown, and console-safe output.

## 0.5.0 — 2026-09-28

### Dashboard redesign

- Rebuilt the browser UI as a high-contrast Windows storage observatory with a permanent product rail, focused scan composer, and responsive mobile layout.
- Added a radar-style audit-state visualization and made seven pipeline stages, current work, progress, elapsed time, and engine state visible without opening a log.
- Replaced the crowded horizontal results tabs with a sticky vertical audit map on desktop and a swipeable strip on mobile.
- Restyled metrics, findings, tables, category summaries, charts, controls, empty states, and exports into one cohesive visual system.
- Added arrow-key, Home, and End navigation for result tabs; made category cards keyboard-operable; added visible focus and reduced-motion behavior.
- Embedded a local data-URI favicon and reduced completed/idle status polling from 800 ms to 2.4 seconds.
- Validated desktop and mobile layouts, live audit completion, result navigation, console output, and network responses in a real Chromium browser.

## 0.4.2 — 2026-08-31

### Reliability and release integrity

- Extended cooperative cancellation from filesystem and duplicate hashing into every subsequent audit phase, with cancellation checks between optional inventory commands and trust/ACL batches.
- Bounded CLI report loading to 256 MiB, rejected non-finite JSON, and validated all known list-section row shapes before comparison, query, trend, plan, validation, redaction, or export processing.
- Bounded browser comparison imports to 64 MiB and 100,000 relevant rows per section, added structural validation, and labeled the file input for assistive technology.
- Added friendly CLI error handling and strict TCP-port and duplicate-threshold bounds, including rejection of inverted duplicate minimum/maximum ranges.
- Made complete-release builds reject any shippable project file missing from `RELEASE_MANIFEST.txt`, duplicate manifest paths, and links/junctions that could package content outside the release tree.
- Added an atomic release-manifest updater/checker so intentional release changes can be reproduced without hand-editing hashes.
- Added regression tests for every boundary above.

## 0.4.1 — 2026-08-31

### Usability and hardening

- Associated dashboard labels with their controls and added tab, status, progress, and alert semantics for keyboard and assistive-technology users.
- Replaced silent dashboard request failures with actionable expired-session, disconnected-service, scan-start, and cancellation messages.
- Added useful empty states for evidence tables and prevented duplicate scan submissions while the request is being accepted.
- Rejected non-string paths, null-byte/oversized paths, and non-finite JSON numbers at the local API boundary.
- Added same-origin resource, frame-denial, and browser permissions security headers.
- Made the Windows launcher fall back to a compatible `python` executable when the `py` launcher is unavailable and forward optional serve arguments.
- Added a reproducible, dependency-free portable `.pyz` builder that excludes local bytecode caches and replaces the output atomically.
- Added a manifest-verifying complete-release ZIP builder so the distributed source and portable package cannot silently drift apart.
- Added regression coverage for the accessibility, validation, connection-error, empty-state, and security-header changes.
- Removed `platform.py` calls from `doctor`; on a cold Python 3.14 Windows runtime, `platform.system()` could internally execute `ver`, contradicting the diagnostic's no-external-command guarantee.

## 0.4.0 — 2026-08-17

### Research-driven capabilities

- Added validated declarative JSON rule packs inspired by extensible cleaner-rule ecosystems, but restricted to metadata classification with no action or execution fields.
- Added explicit keep/protected paths that remain visible while reclaim values are zeroed and safe labels are downgraded.
- Added a report query language with size/age/numeric comparisons, substring, regex, OR groups, sorting, selected columns, and table/JSON/CSV output.
- Added explicit multi-report growth and capacity trend analysis with consistency, same-volume, timestamp, and major-resize checks.
- Added selected owner/ACL evidence, local Authenticode metadata, optional SHA-256 trust evidence, active-process context, and Prefetch metadata.
- Added storage reliability, richer Docker/WSL/Hyper-V, BitLocker, storage-pool, driver-store, and runtime/package-tool inventory.
- Added application footprint/ownership graph linking applications to related paths, active processes, startup entries, services, tasks, and execution evidence.
- Added a conservative audit coverage/evidence-quality score with explicit non-applicability semantics.
- Added static, self-contained, no-script HTML evidence export with optional redaction.
- Expanded CSV export to 16 evidence tables for schema-v4 reports.

### Correctness and safety fixes

- Fixed custom file rules being silently limited to a hard-coded extension allowlist; validated rule requirements now influence a bounded large-file metadata-retention threshold.
- Added explicit metadata-candidate eligibility/retention/omission metrics and coverage warnings.
- Fixed rule-derived file/folder reclaim findings being omitted from the conservative path total because they used a generic scope label.
- Fixed Windows `MEMORY.DMP` reclaim evidence inheriting stale allocated-size data from a previously classified file.
- File reclaim now prefers allocated bytes and treats a single hard-link path as zero guaranteed physical reclaim.
- Improved rule candidate indexing, nearest-project-marker lookup, `match_mode=any|all`, and validation without mutating caller JSON.
- Preserved Windows backslashes in unquoted report queries; fixed mixed-type sorting and missing-value ordering; bounded regex length.
- Disabled capacity forecasts for inconsistent total/used/free counters or material capacity changes.
- Improved collector applicability so missing optional/platform tools do not reduce coverage as failures.
- Improved cross-machine redaction and scrubbed common CLI/API-key/password/token/bearer/URL-credential forms.
- Added escaping and a restrictive Content Security Policy to static HTML output.
- Preserved strict no-execution behavior in plans, dashboard APIs, rules, and platform collectors.

### Verification

- Expanded to 72 automated tests under both `unittest` and `pytest`.
- Added a 2,520-file full-pipeline synthetic acceptance run covering scan, duplicate/hard-link handling, stateful-file policy, rule packs, keep policy, query, validation, approval plan, 16-table CSV export, redaction, static HTML, comparison, and trend forecasting.
- Added a separate 50,000-file traversal stress run with bounded-memory sanity measurements.
- Continued source-level destructive-API/command regression checks and localhost dashboard route/security checks.

## 0.3.0 — 2026-08-17

- Added logical/allocated-size evidence, hard-link-aware duplicates, cloud/stateful hashing policy, conservative overlap accounting, improved persistence/system collectors, report validation, CSV export, privacy copy, and native-Windows validation guidance.

## 0.2.0 — 2026-08-17

- Added scan profiles, cancellation, age/extension summaries, project context, Windows deep collectors, comparison, approval-plan export, and redesigned localhost dashboard.

## 0.1.0

- Initial read-only filesystem/application audit MVP.
