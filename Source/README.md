# ReconSpace 1.3.0

ReconSpace is a **local, read-only Windows storage, software, persistence, ownership, and developer-tooling reconnaissance suite**. It is designed for machines where a conventional “junk cleaner” is too blunt—especially development, cybersecurity, virtualization, Docker, WSL, Android, game-development, forensic, and lab workstations.

**Version:** 1.3.0
**Report schema:** 4  
**Runtime dependencies:** Python 3.11+ only for source/`.pyz` usage  
**Default network behavior:** none; the optional dashboard binds to `127.0.0.1` only. The AI Audit Advisor can query LLM endpoints if explicitly requested with your own API key, and automatically redacts PII before transmission.

ReconSpace observes, measures, attributes, correlates, ranks, queries, compares, and exports evidence. It has **no cleanup executor** in its core scanning engine and no endpoint or command that deletes files, uninstalls applications, prunes Docker, unregisters WSL, changes the Registry, modifies services/tasks/ACLs, disables hibernation, removes restore points, compresses files, or changes Windows servicing state.

## What is new in 1.3.0

Care 1.3 extends this experience with five original glass illustrations, coordinated pointer parallax, a sliding navigation marker, real-phase scan graphics, art-led review tiles, linked storage bubbles with retained-evidence drill-down, persistent reduced-motion preferences, and page-refresh session recovery. See [CARE_EXPERIENCE_PLAN.md](CARE_EXPERIENCE_PLAN.md) and [qa/care-13-report.md](qa/care-13-report.md).

## What was new in 1.2.0

A rebuilt Care interface: original desktop artwork, coordinated icons, welcome/scan/results stages, smooth zoom-and-fade navigation, adjustable UI zoom, and reduced-motion support. The top-level launcher and portable release both serve this UI. See [CARE_UI_QA.md](CARE_UI_QA.md) for verification.

## What was added in 1.1.0

Version 1.1.0 introduces the **AI Audit Advisor** and deepens open-source Windows reconnaissance collectors:
- **AI Audit Advisor**: Multi-provider analysis (OpenAI, Anthropic Claude, Google Gemini, Ollama local models, and offline deterministic heuristics) that synthesizes audit telemetry into an executive brief, System Wellness Score (0–100), Critical Actions, Quick Wins, Safety Warnings (guarding developer virtual environments, WinSxS hardlinks, and WSL VHDX files), and Architectural Explainers.
- **Automatic PII Redaction**: Telemetry sent to AI providers is strictly sanitized by default, replacing sensitive user names, profile paths, and environment tokens with generic placeholders.
- **Dism++ Hibernation & Sizing Intelligence**: Checks `hiberfil.sys` and calculates ~50% RAM space reclamation via Windows reduced hibernation mode (`powercfg /hibernate /type reduced`) without disabling Fast Startup.
- **Delivery Optimization & Network Telemetry**: Audits peer update cache bytes, upload bandwidth consumption, and active network adapters with link speeds.
- **Battery & Power Health**: CIM `Win32_Battery` diagnostics reporting charge percentage, wear levels, design capacity, and AC power state.
- **Forensic Crash Dump Inventory**: Audits `MEMORY.DMP`, minidumps, and `%LocalAppData%\CrashDumps` storage footprints.
- **PrivaZer-Style Recycle Bin Sizing**: Queries volume-level Recycle Bin allocation via Win32 `SHQueryRecycleBinW`.
- **Zero Runtime External Dependencies**: Built 100% on the Python standard library (`urllib.request`).

## What was added in 1.0.0

Version 1.0.0 introduced cryptographic plan verification and a strict, reversible safe-execution runner:
- **Cryptographic Plan Manifests**: Every generated plan features a SHA-256 integrity hash to prevent disk drift or tampering before execution.
- **Strict Safe-Execution Runner**: Actions are restricted strictly to items classified as `probably_safe_cleanup`. Automated execution rejects system boundaries (`System32`, `WinSxS`, system volume directories, user profile roots).
- **Reversible Recycle Bin Execution**: Safe file cleanup delegates to Win32 `SHFileOperationW` with `FOF_ALLOWUNDO`, routing files to the Windows Recycle Bin rather than executing permanent deletions.
- **Dry-Run by Default**: Simulation mode operates by default; execution requires explicit `--confirm`.

## What was added in 0.7.0 – 0.9.0

- **CleanMyMac Care Pillars & Module Hubs**: Dedicated interactive hubs for Cleanup, Protection, Performance, Applications, and Space Lens visual disk mapping.
- **Extended Persistence Audit**: Explorer context menu handlers, `AppInit_DLLs`, Winlogon Shell/Userinit, and Browser Helper Objects.
- **NTFS Alternate Data Streams (ADS)**: Detection of hidden streams and Zone.Identifier (Mark-of-the-Web) tags.
- **WinSxS Deduplication Delta**: Computing actual physical disk allocation vs Explorer-reported virtual sizes.
- **WinGet Catalog Correlation**: Identifying available version updates for installed packages.
- **Hardware Privacy Permissions**: Auditing Windows ConsentStore access for webcam, microphone, and location.
- **Multi-Browser Extensions & Footprints**: Inspecting extension manifests for sensitive permissions and measuring SQLite profile caches across Chrome, Edge, Brave, and Firefox.
- **Windows Defender Posture**: Verifying real-time protection, signature status, and threat alerts.

## What was added in 0.6.0

Version 0.6.0 turns raw reconnaissance into a guided decision workflow. The dashboard now opens with a plain-language decision brief, explicitly separates selected-root filesystem evidence from host-wide Windows inventory, exposes an eight-domain audit-depth ledger, and adds an in-app action plan organized into probably-safe, manual-review, protected, and intentional-tooling decisions. Markdown and approval-plan exports carry the same scope, depth, risk, and next-step explanations. Windows consoles with limited character encodings now degrade unsupported symbols safely instead of failing after a successful scan.

## What was added in 0.5.0

Version 0.5.0 rebuilds the dashboard as a Windows storage observatory. It adds a permanent navigation rail, focused scan composer, live radar-style audit state, compact pipeline telemetry, a vertical results map, clearer data cards, higher contrast, responsive mobile layouts, keyboard-driven result navigation, reduced-motion support, and slower idle polling. Every existing audit and export capability remains available; the engine remains read-only.

## What was added in 0.4

Version 0.4 is a research-driven intelligence and evidence release. It adds:

- validated **declarative JSON rule packs** that can recognize additional storage patterns without executing code or cleanup actions;
- explicit `--keep` / protected-path policy that leaves evidence visible while zeroing reclaim estimates and downgrading “safe” labels;
- a report **query language** with numeric/size/age comparisons, text matching, regular expressions, OR groups, sorting, column selection, and CSV/JSON/table output;
- multi-snapshot **growth, change, and capacity trend analysis** across explicitly selected report files;
- active-process context, local Authenticode metadata, optional SHA-256 evidence, selected owner/ACL summaries, and Windows Prefetch filename/timestamp metadata;
- storage reliability evidence, richer Docker/WSL/Hyper-V inventory, BitLocker/storage-pool/driver-store/runtime inventory, and safer Windows component-store interpretation;
- a conservative **application ownership/footprint graph** connecting installed applications to install paths, related data paths, active processes, startup items, services, tasks, and Prefetch evidence;
- a scan **coverage/evidence-quality score** that treats unavailable/non-applicable collectors separately from failures and is explicitly *not* a system-health, security, malware, or cleanliness score;
- a static, portable, no-script **HTML evidence report**, plus JSON, Markdown, CSV, comparison, trend, approval-plan, validation, and privacy-redacted exports;
- improved cross-machine privacy redaction for scan roots, profiles, host/user identifiers, common command-line secrets, bearer tokens, and URL credentials;
- bounded large-file metadata retention driven by validated rule requirements, with explicit coverage warnings if the bound is reached;
- numerous correctness fixes around hard links, allocated versus logical size, stale evidence reuse, rule matching, query sorting, trend forecasting, and reclaim overlap accounting.

See [RESEARCH_AND_ROADMAP.md](RESEARCH_AND_ROADMAP.md) for the comparative research and adoption decisions.

## Core capabilities

### Storage reconnaissance

- full recursive traversal of the selected root;
- largest files and directories;
- logical size and allocated-size evidence where available;
- sparse/compressed/offline/reparse metadata;
- hidden/system files reached through ordinary filesystem enumeration;
- age and extension distributions;
- large installers, archives, ISOs, dumps, logs, backups, partial downloads, VM disks, packet captures, forensic images, security datasets, and game/developer assets;
- hard-link-aware accounting and exact duplicate verification;
- bounded error/access-denied reporting rather than permission bypass;
- no traversal of directory junctions/reparse loops;
- no content reads for cloud/offline/reparse placeholders during duplicate analysis;
- stateful VM/forensics/dump formats excluded from duplicate hashing unless explicitly opted in.

### Development and cybersecurity context

ReconSpace recognizes or contextualizes common storage associated with:

- Node.js, npm, pnpm, Yarn, `node_modules`, web-framework build caches;
- Python venvs, Conda, pip, uv, test/type/lint caches;
- Gradle, Maven, NuGet, Cargo, Go, Composer, Flutter/Dart;
- Visual Studio, VS Code, JetBrains IDEs;
- Android SDK/AVDs and emulators;
- Unity, Unreal, Terraform, browser-automation binaries;
- Docker images, build cache, containers, volumes, and backing storage;
- WSL distributions and `ext4.vhdx` backing files;
- Hyper-V, VMware, VirtualBox, VHD/VHDX/VDI/VMDK/QCOW2 state;
- PCAPs, wordlists, malware-analysis labs, E01/AFF4/raw forensic images, dumps, traces, and incident evidence;
- AI/ML model stores such as Hugging Face, Torch, and Ollama.

Large or unusual tooling is not automatically junk. It is normally classified as **Likely intentional cybersecurity/development tooling**, with a separate manual-review opportunity only when there is stronger evidence such as a reproducible manifest, old project timestamps, inactive context, or tool-specific reclaim metadata.

### Windows software and persistence audit

- installed Win32/MSI applications and AppX/MSIX packages;
- estimated size, publisher, version, install location, scope, architecture, and runtime/framework context;
- Startup entries, services, and scheduled tasks;
- missing targets, user-writable launch locations, hidden tasks, script hosts, encoded PowerShell indicators, and unquoted service-path review signals;
- active process/executable/command-line/owner/working-set context;
- selected Authenticode signer/certificate metadata and optional local SHA-256;
- selected owner and ACL summaries with broad-write indicators;
- Prefetch execution metadata where available.

These are **review signals**, never malware verdicts. ReconSpace does not query or upload to online reputation services.

### Windows-managed and virtualized storage

Read-only collectors cover or attempt to cover:

- Windows Update and Delivery Optimization data;
- Windows Error Reporting and crash dumps;
- Recycle Bin metadata;
- pagefile, hibernation, swap, Reserved Storage;
- VSS/shadow-storage and restore-point metadata;
- component-store analysis via DISM’s read-only analysis mode rather than raw WinSxS folder size alone;
- physical disks, partitions, volumes, Storage Spaces, reliability counters, BitLocker status, and driver-store inventory;
- WSL distribution registration/backing paths;
- Docker disk-usage details;
- Hyper-V and VirtualBox inventory;
- installed .NET, Python, npm, pip, Conda, and uv runtimes/tools.

Collector availability depends on Windows edition, privileges, installed tools, and system configuration. Missing optional tools are reported as **not applicable/unavailable**, not silently treated as a successful scan.

## Quick start

Extract the complete ZIP, then double-click:

```text
run_reconspace.bat
```

Or launch the local dashboard from a terminal:

```powershell
py -3 -m reconspace serve
```

Run a Deep audit and explicitly export JSON:

```powershell
py -3 -m reconspace scan --root C:\ --profile deep --json .\reconspace-audit.json
```

Run the single-file package:

```powershell
py -3 ReconSpace-v1.2.pyz
```

For better coverage, you may manually open an elevated Terminal and run the same command. ReconSpace never self-elevates and never changes permissions.

## Scan profiles

| Profile | Intended use | Duplicate hashing | Windows evidence depth | Retained top-N |
|---|---|---:|---|---:|
| `quick` | Fast overview | Off | Basic | 150–180 |
| `standard` | Routine audit | On, conservative | Standard collectors | 300 |
| `deep` | Recommended C: audit | On | Processes, signatures, ACLs, Prefetch, platform inventory | 500 |
| `forensics` | Highest evidence depth | On; optional SHA-256 trust evidence | Includes broader process/trust/VM inventory | 800 |

Stateful VM/forensic/dump formats remain excluded from duplicate hashing unless `--hash-stateful-files` is supplied. That option can create heavy local I/O and should be used only with a clear reason.

## Important commands

Read-only readiness diagnostic:

```powershell
py -3 -m reconspace doctor --root C:\ --pretty
```

Validate an exported report:

```powershell
py -3 -m reconspace validate-report .\reconspace-audit.json --pretty
```

Generate an approval-only plan:

```powershell
py -3 -m reconspace plan .\reconspace-audit.json
```

Every item remains `PENDING_REVIEW`, and execution remains `NONE`.

Run the AI Audit Advisor (offline deterministic heuristic by default):

```powershell
py -3 -m reconspace ai-review .\reconspace-audit.json
```

Run AI review with OpenAI, Anthropic, Gemini, or Ollama:

```powershell
py -3 -m reconspace ai-review .\reconspace-audit.json --provider openai --api-key sk-... --output review.md
py -3 -m reconspace ai-review .\reconspace-audit.json --provider anthropic --api-key sk-ant-... --json
py -3 -m reconspace ai-review .\reconspace-audit.json --provider ollama --model llama3:latest
```

Inspect the auto-sanitized / redacted prompt without making any network calls:

```powershell
py -3 -m reconspace ai-review .\reconspace-audit.json --prompt-only
```

Export complete tables:

```powershell
py -3 -m reconspace export-csv .\reconspace-audit.json .\evidence-csv
```

Export a self-contained static HTML report:

```powershell
py -3 -m reconspace export-html .\reconspace-audit.json .\reconspace-audit.html
```

Create a redacted HTML sharing copy:

```powershell
py -3 -m reconspace export-html .\reconspace-audit.json .\shareable.html --redact
```

Create a redacted JSON sharing copy:

```powershell
py -3 -m reconspace redact .\reconspace-audit.json .\shareable.json
```

Compare two audits:

```powershell
py -3 -m reconspace compare .\old.json .\new.json --pretty
```

Analyze three or more snapshots and estimate a growth trend:

```powershell
py -3 -m reconspace trend .\june.json .\july.json .\august.json --pretty
```

ReconSpace never creates automatic background history. Trend analysis uses only report files you explicitly select.

## Query language

Example: show low-risk findings with more than 1 GiB estimated reclaimable space:

```powershell
py -3 -m reconspace query .\audit.json findings --where "reclaim>1GiB risk:low" --sort=-reclaim
```

Example: locate Docker, WSL, VM, or security-tooling findings:

```powershell
py -3 -m reconspace query .\audit.json findings --where "related:docker or related:wsl or related:virtualization or related:cybersecurity"
```

Example: find unsigned/untrusted selected binaries in user-writable locations:

```powershell
py -3 -m reconspace query .\audit.json binary-trust --where "user_writable=true signature!=Valid"
```

See [QUERY_LANGUAGE.md](QUERY_LANGUAGE.md).

## Rule packs and protected paths

Validate an additional metadata-only rule pack:

```powershell
py -3 -m reconspace validate-rules .\my-rules.json --pretty
```

Use it during a scan:

```powershell
py -3 -m reconspace scan --root C:\ --profile deep --rule-pack .\my-rules.json
```

Protect a path from reclaim accounting without hiding it:

```powershell
py -3 -m reconspace scan --root C:\ --profile deep --keep C:\Labs --keep C:\Evidence
```

Rule packs cannot contain commands, scripts, deletion actions, Registry operations, or dynamic code. See [RULE_PACKS.md](RULE_PACKS.md) and [examples/custom-rules.example.json](examples/custom-rules.example.json).

## Understanding reclaim estimates

ReconSpace intentionally avoids one misleading “you can free X GB” number.

It reports:

1. **Non-overlapping path candidates** — parent folders suppress covered descendants when the parent represents near-full reclaim.
2. **Exact duplicate potential** — separate, because a duplicate can also be inside another candidate path.
3. **Application potential** — separate, because uninstall estimates overlap install directories and related data.
4. **Platform potential** — separate, because Docker/Windows-managed estimates can overlap filesystem paths.

Logical size is not always physical reclaim. Sparse, compressed, cloud, hard-linked, component-store, VHDX, and platform-managed data require additional interpretation. File findings use allocated size where available; hard-link aliases are not credited as guaranteed reclaim.

## Privacy and report sharing

Reports can contain usernames, project/client/case names, paths, application names, command lines, hashes, and other sensitive evidence.

`redact` and `export-html --redact` attempt to remove:

- scan-root and profile prefixes;
- common Windows/Linux user-profile paths;
- host/user identifiers found in structured fields;
- common `--password`, `--token`, `--api-key`, bearer-token, and URL-password forms.

Redaction is **best effort**, not a formal anonymization or secrecy guarantee. Manually inspect a shareable copy before sending it elsewhere.

## Verification

From the source ZIP on Windows:

```text
verify_reconspace.bat
```

The release suite contains 108 automated tests covering correctness, safety boundaries, cancellation across phases and collectors, duplicate hashing, hard links, cloud/stateful-file policy, project/tooling context, rules, keep policy, queries, trends, report-import limits, trust/ACL evidence, ownership graph, decision guidance, scope/depth transparency, privacy, exports, dashboard responsive design/accessibility/security, API validation, release-manifest scope, and destructive-operation regressions.

See [TESTING.md](TESTING.md), [TEST_REPORT.md](TEST_REPORT.md), and [WINDOWS_VALIDATION.md](WINDOWS_VALIDATION.md).

## Building a Windows EXE

The source ZIP contains:

```text
build_windows_exe.bat
```

It creates an isolated `.build-venv`, installs PyInstaller 6.x there, and produces:

```text
dist\ReconSpace.exe
```

Building is an explicit developer action. The distributed source and `.pyz` do not require PyInstaller.

## Rebuilding the portable Python package

The dependency-free single-file package can be rebuilt without downloading anything:

```text
build_portable_pyz.bat
```

This recreates `ReconSpace-v1.2.pyz` from the current source tree, including local artwork and styles, while excluding bytecode caches. You can optionally pass a different output path.

Release maintainers can rebuild the complete distribution only after the release manifest validates:

```powershell
py -3 build_portable_pyz.py
py -3 update_release_manifest.py
py -3 update_release_manifest.py --check
py -3 build_release_zip.py
```

The manifest updater writes atomically. The ZIP builder verifies every listed file's SHA-256 and size, rejects unlisted release files, and replaces the output archive atomically.

## Known limitations and intentional deferrals

- This release does not include an unverified raw NTFS MFT/USN parser. Recursive traversal is slower than MFT-native tools but works across ordinary filesystems and preserves a simpler safety model.
- There is no online VirusTotal/reputation lookup or upload.
- There is no automatic scheduled scan, hidden service, background history database, or telemetry.
- There is no network/distributed enterprise agent.
- Owner/ACL and Authenticode inspection target selected high-value paths/binaries rather than every filesystem object.
- Top-file/top-directory history compares retained top-N evidence, not a full historical object index.
- Windows-only collectors were implemented and parser/safety tested in a Linux build environment, but must still be acceptance-tested on a real Windows machine.
- There is no cleanup executor by design.

## License

See [LICENSE.txt](LICENSE.txt).
