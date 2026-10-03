# ReconSpace: CleanMyMac for PC Architecture, Research & Grand Plan

**Document Version:** 1.0.0  
**Date:** 2026-10-02  
**Product:** ReconSpace — Windows Storage, Performance, Protection & Applications Intelligence  
**Design Philosophy:** Strictly Read-Only Audit Engine + Transparent Administrative Recipes + Cryptographic Safe Runner

---

## 1. Executive Vision: Building CleanMyMac for Windows PC

On macOS, **CleanMyMac X** (by MacPaw) became the gold standard for desktop maintenance because of three core qualities:
1. **Holistic System Care**: A single unified view (Smart Care) that evaluates Storage Bloat, Security/Privacy Posture, Performance Stalls, and Application Leftovers simultaneously.
2. **Exemplary Visual Design**: Clean modular pillars, tactile hero graphics, proportional storage breakdown (Space Lens), and intuitive categorization.
3. **Safe, Predictable Operations**: Transparent explanations of what each file is, why it exists, and the safety impact of removing it.

Historically, the Windows PC ecosystem suffered from the polar opposite:
- Unscrupulous "PC Cleaners" (CCleaner, IObit, Glary, Registry Cleaners) bundled aggressive adware, installed background telemetry services, made wild claims about "speeding up your PC by 300%", and corrupted systems by aggressively deleting necessary registry keys, development SDKs, and system files.
- On modern developer, engineering, and cybersecurity workstations (running Docker, WSL, Android Studio, Python venvs, node_modules, Hyper-V, and security datasets), conventional cleaners are outright dangerous.

**ReconSpace bridges this gap.** It delivers the beautiful, intuitive, modular experience of CleanMyMac X while upholding a **100% read-only, zero-destruction safety model**. ReconSpace identifies waste, benchmarks RAM pressure, audits Defender security and hardware privacy permissions, detects orphaned software leftovers, and visualizes disk clutter with an interactive Space Lens—accompanied by standard, copyable Microsoft PowerShell inspection recipes.

---

## 2. Left Menu Modular Architecture & CleanMyMac Mapping

| ReconSpace Left Menu Module | CleanMyMac X Equivalent | Primary Focus & Capabilities |
|---|---|---|
| **✦ Smart Audit (`home`)** | **Smart Care (All-in-One)** | 360-degree system health check: volume capacity, care pillar summaries, decision brief, category breakdown, and instant scan launch. |
| **⌁ Cleanup (`cleanup`)** | **System Junk, Mail, Trash** | Identifies disposable caches (Windows Temp, Delivery Optimization, WER crash dumps, SoftwareDistribution), build artifacts, and browser data with conservative reclaim estimates. |
| **◇ Protection (`protection`)** | **Malware Removal & Privacy** | Microsoft Defender real-time protection currency, signature freshness, threat history, Windows ConsentStore hardware permissions (webcam, mic, location), and Authenticode trust. |
| **↯ Performance (`performance`)** | **Optimization & Maintenance** | Win32 physical RAM load, committed pagefile pressure, top working-set processes, boot startup impact, and 8 standard administrative PowerShell maintenance recipes. |
| **▦ Applications (`applications`)** | **Uninstaller, Updater, Extensions** | Installed software footprints across 64/32-bit Win32 and AppX packages, silent uninstaller recipes via WinGet, and orphaned AppData leftover detection (inspired by BCUninstaller). |
| **◌ My Clutter (`clutter`)** | **Space Lens & Large/Old Files** | Interactive proportional folder map (Space Lens), exact SHA-256 duplicate byte analysis, and multi-tier large/old file filters (>1 GB, 500 MB, >1 year, archives, media). |
| **▤ Reports (`reports`)** | **Summary & Review** | Structured Action Plan (.md export), 8-domain depth ledger, client-side report comparison (free space delta & folder changes), and full JSON export. |
| **⚙ Settings (`settings`)** | **Preferences** | Profile selection (quick, standard, deep, forensics), custom scan roots, path exclusions, keep paths, rule packs, and evidence switches. |

---

## 3. Deep Research: Open-Source PC Tool Arsenal & Techniques

To build an unmatched desktop utility, we researched and synthesized techniques from the leading open-source Windows utilities and system tools:

### 3.1. BleachBit (CleanerML & Deep Cleanups)
- **Reference**: https://github.com/bleachbit/bleachbit | https://docs.bleachbit.org/cml/cleanerml.html
- **Techniques Analyzed**:
  - Declarative XML-based `CleanerML` defining paths, deep regex pattern matching, and SQLite database compaction (`VACUUM`).
  - Cataloging temporary directories: `%TEMP%`, `C:\Windows\Temp`, Windows Error Reporting (`%LocalAppData%\CrashDumps`), and Windows Delivery Optimization.
- **How ReconSpace Benefits**:
  - Adapted CleanerML's declarative approach into validated, strictly read-only JSON Rule Packs.
  - Zero execution risk: ReconSpace rule packs only recognize metadata and calculate conservative reclaim estimates without running arbitrary deletion scripts.
  - Audits SQLite profile footprints across Chrome, Edge, Brave, and Firefox (History, Cookies, Login Data) without file-lock collisions.

### 3.2. Czkawka & Krokiet (Qarmin)
- **Reference**: https://github.com/qarmin/czkawka
- **Techniques Analyzed**:
  - Blazing-fast multi-threaded duplicate finding in Rust using progressive hashing: Length check → Partial hash (first 1 KB) → Full cryptographic hash (Blake3 / xxHash).
  - Specialized algorithms for empty directories, biggest files, bad extensions, and similar images/audio.
- **How ReconSpace Benefits**:
  - Hardlink-aware duplicate collation: Distinguishes between duplicate copies and hardlink aliases sharing the same inode/MFT record.
  - Conservative reclaim calculation: Ensures duplicate reclaim is reported separately and non-additively with path candidates.
  - Cloud/offline placeholder protection: Skips reading OneDrive/iCloud reparse points during duplicate analysis to prevent accidental cloud file hydration.

### 3.3. Bulk Crap Uninstaller (BCUninstaller - Klocman)
- **Reference**: https://github.com/Klocman/Bulk-Crap-Uninstaller
- **Techniques Analyzed**:
  - World-class leftover detection heuristics scanning `%LocalAppData%`, `%AppData%`, and `%ProgramData%` for directories whose owners have been uninstalled.
  - Normalization of display names, publishers, and installation directory tokens.
  - Extraction of quiet uninstallation command lines (`QuietUninstallString`, MSI `/qn`, Inno Setup `/VERYSILENT`, NSIS `/S`).
- **How ReconSpace Benefits**:
  - Implemented `collect_orphaned_app_data()`: Uses BCUninstaller-inspired tokenization to discover residual folders left behind in AppData/ProgramData.
  - Stale Timestamp Guard: Enforces a 14-day modification cutoff to prevent false positives on actively used tools.
  - WinGet Integration: Provides copyable `winget uninstall --name "<App>"` and `winget upgrade` commands for installed applications.

### 3.4. Microsoft Sysinternals Suite (Mark Russinovich)
- **Reference**: https://learn.microsoft.com/sysinternals/
- **Techniques Analyzed**:
  - **Autoruns**: Comprehensive inspection of 30+ persistence locations: `HKCU/HKLM\...\Run`, Startup folders, Scheduled Tasks, Windows Services, Image File Execution Options, AppInit_DLLs.
  - **Sigcheck**: Local Authenticode signature verification, catalog signing lookup, and user-writable binary risk heuristics.
  - **Process Explorer**: Process working set memory metrics, private committed bytes, and security token owner accounts.
- **How ReconSpace Benefits**:
  - Batched Authenticode inspection evaluating digital signatures for active persistence targets.
  - Flags unsigned binaries running from user-writable locations (`AppData`, `Temp`).
  - Batched tasklist process indexing to display top memory-consuming processes alongside Win32 physical RAM load.

### 3.5. WizTree, WinDirStat & TreeSize
- **Reference**: https://diskanalyzer.com/ | https://windirstat.net/
- **Techniques Analyzed**:
  - Proportional disk visualization and treemaps for instant visual cognition of disk bloat.
  - Direct NTFS MFT indexing for high-speed scanning versus portable recursive traversal.
- **How ReconSpace Benefits**:
  - Built **Space Lens**: An interactive, proportional folder breakdown displaying size bars relative to top directory consumers.
  - Retained an audited, portable recursive traversal engine that runs with identical safety guarantees across standard user and elevated privileges.

### 3.6. Windows Security & Privacy Primitives
- **Reference**: `Get-MpComputerStatus`, `Get-MpThreatDetection`, Windows `CapabilityAccessManager`
- **Techniques Analyzed**:
  - Querying Defender real-time protection, signature definition age, and threat detection log via CIM/WMI without mutating security policies.
  - Reading `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore` for camera, microphone, and location permissions granted to Desktop and Packaged UWP apps.
- **How ReconSpace Benefits**:
  - Implemented `collect_privacy_consent_store()` and `collect_system_memory_status()` using Win32 API `GlobalMemoryStatusEx`.
  - Implemented `build_protection_findings()` to warn users of disabled real-time protection, stale definitions (>7 days), or active threat events.

---

## 4. Key Differentiators: Why ReconSpace is Something That Does Not Yet Exist

| Feature | Conventional Windows Cleaners | CleanMyMac X (Mac) | ReconSpace (This Build) |
|---|---|---|---|
| **Platform** | Windows | macOS only | **Windows PC** |
| **Execution Model** | Destructive deletes (often dangerous) | Autonomous cleanup | **Zero-risk read-only audit + copyable recipes** |
| **Developer/Lab Safety** | Destroys node_modules, Docker, venvs | Limited developer awareness | **Full awareness of WSL, Docker, PyTorch, venvs, Git** |
| **Telemetry & Ads** | High (popups, bundled tools, telemetry) | Commercial license | **Zero telemetry, zero network calls, localhost only** |
| **Hardware Privacy** | None | macOS permissions audit | **Windows ConsentStore (webcam, mic, location)** |
| **Space Lens Visuals** | Raw static lists | Visual bubble/treemap | **Interactive Space Lens + Proportional Folder Tree** |
| **Process & Persistence** | None or registry-only | Basic login items | **Batched working set RAM + Authenticode trust audit** |
| **Export Integrity** | Proprietary or none | Summary report | **Markdown, JSON, 16-table CSV, and approval plans** |

---

## 5. The Grand Plan & Multi-Phase Roadmap

### Phase 1: Foundation & CleanMyMac Hub Integration (v0.6.1 – v0.7.0) — **Completed**
- [x] Implement 4 Care Pillars on Overview (`cleanup`, `protection`, `performance`, `applications`).
- [x] Implement dedicated Hub Views for all 5 core modules (`cleanup_hub`, `protection_hub`, `performance_hub`, `applications_hub`, `clutter_hub`).
- [x] Pre-scan module cards (`getPreScanHub`) for immediate orientation prior to running an audit.
- [x] Win32 `GlobalMemoryStatusEx` physical RAM load collector with zero-safe guards.
- [x] Windows Defender real-time protection, signature age, and threat history collector.
- [x] Windows `CapabilityAccessManager\ConsentStore` hardware privacy permissions audit.
- [x] SQLite browser profile footprints collector (Chrome, Edge, Brave, Firefox).
- [x] BCUninstaller-inspired orphaned AppData/ProgramData leftover heuristics with 14-day stale cutoff and token normalization.
- [x] Space Lens proportional folder map and multi-tier Large & Old Files filter bar.
- [x] Standard Microsoft administrative PowerShell inspection recipes with 1-click clipboard copy.

### Phase 2: Accelerated Traversal & Package Manager Catalog (v0.8.0) — **Completed**
- [x] Optional direct NTFS `$MFT` read-only scanner backend for near-instant C:\ volume enumeration on NTFS partitions (`reconspace/ntfs.py`).
- [x] Deep WinGet catalog correlation: Matching installed software against `winget search`/`list` manifests for automated version currency checks.
- [x] Browser extension & add-on auditing (Chrome, Firefox, Edge, Brave) via manifest inspection and sensitive permission risk profiling.
- [x] Memory working set trimming recipe (`EmptyWorkingSet` via Win32 ctypes) in Performance Hub.

### Phase 3: Advanced Persistence & Windows Servicing Intelligence (v0.9.0) — **Completed**
- [x] Extended Autoruns persistence audit: Explorer Shell Extensions (`HKCR\*\shellex\ContextMenuHandlers`), AppInit_DLLs, Winlogon Shell/Userinit, and BHOs with user-writable risk detection.
- [x] Alternate Data Streams (ADS) audit: Detecting hidden `:Zone.Identifier` (Mark-of-the-Web) and large hidden NTFS streams via `FindFirstStreamW`.
- [x] Component Store DISM reclamation forecast with hardlink deduplication delta calculation.
- [x] Windows Update cache health check (SoftwareDistribution Download & DataStore) and Delivery Optimization cache sizing.

### Phase 4: Production v1.0.0 Milestone — **Completed**
- [x] Native Windows acceptance lab matrix across Windows 10, Windows 11, and modern servicing environments.
- [x] Signed approval plan manifests with cryptographic SHA-256 checksums (`verify_plan_manifest`).
- [x] Standalone audited action runner (`execute_approved_plan`) with strict boundary protections (`is_system_protected_path`), required `--confirm`, and Windows Recycle Bin reversibility (`SHFileOperationW`).

