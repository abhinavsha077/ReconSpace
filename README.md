# ReconSpace 🔭

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-167%20passed-brightgreen.svg)](Source/qa/care-14-report.md)
[![Privacy](https://img.shields.io/badge/telemetry-0%25%20(local%20only)-blueviolet.svg)](SECURITY.md)
[![Safety Model](https://img.shields.io/badge/safety-read--only%20core%20%2B%20reversible%20recycle%20bin-success.svg)](Source/SAFETY.md)

**ReconSpace** is an advanced, transparent, and principled **Windows storage observatory, system audit, persistence, and developer-tooling reconnaissance suite**. It is designed for engineers, cybersecurity specialists, developers, and power users who need deep visibility into their machines without the risks of black-box "PC cleaners" or destructive registry wipers.

Current runnable build: **1.4.0 Guided Care** — graphite, icy blue and mint; original 3D artwork and coordinated motion; focused module summaries, grouped item review, an evidence inspector, selection confirmation and a downloadable plan receipt. Technical tools remain under Advanced evidence. Cancelled scans preserve earlier review work. Run `run_reconspace.bat` from this directory. Close older app/server sessions first. Latest portable builds are in `Releases`; historical builds are recoverably archived under `Archives`. Researched interaction plan: [CARE_FLOW_PLAN.md](Source/CARE_FLOW_PLAN.md). This guided workflow exports review plans, not destructive actions.

ReconSpace synthesizes the guided ergonomics of modern system care tools with strict, forensic-grade engineering: **read-only observation by default, zero telemetry, non-overlapping reclaim math, deep developer context, and cryptographic execution safety**.

---

## 🚀 Key Highlights & Care Pillars

### 1. 🧹 Cleanup & Storage Observatory
- **Space Lens Interactive Proportional Map**: Visualize disk consumption hierarchically and identify storage hogs at a glance.
- **Large & Old Files Engine**: Instantly filter across multi-tier thresholds (`>1 GB`, `500 MB`, `>1 year`, `6 months`) and file archetypes (archives, installers, disk images, media).
- **True Non-Overlapping Reclaim Math**: Eliminates inflated "free up 80 GB" marketing numbers. Accurately segregates filesystem paths, duplicate candidates, platform caches, and application uninstalls to prevent double-counting.
- **Windows Servicing & Update Audits**: Analyzes DISM WinSxS component-store hardlink deduplication deltas, SoftwareDistribution caches, and Delivery Optimization data.

### 2. 🛡️ Protection & Persistence Audit
- **Deep Persistence Surface Recon**: Scans Windows Startup items, Services, Scheduled Tasks, Explorer Context Menu handlers (`*`, `Directory`, `Folder`), `AppInit_DLLs`, Winlogon Shell/Userinit entries, and Browser Helper Objects (BHOs).
- **NTFS Alternate Data Streams (ADS)**: Detects hidden streams and Zone.Identifier (Mark-of-the-Web) tags on downloaded binaries.
- **Binary Trust & Authenticode Signatures**: Evaluates digital signatures, signer subjects, and issuer metadata on high-value launch targets.
- **Hardware Privacy Permissions**: Audits Windows `ConsentStore` access rights (webcam, microphone, location, notifications) across Desktop and UWP packaged apps.
- **Windows Defender Posture**: Verifies real-time protection status, definition currency, and engine readiness.

### 3. ⚡ Performance & System Diagnostics
- **RAM & Pagefile Telemetry**: Non-invasive physical memory load and commit charge monitoring via Win32 `GlobalMemoryStatusEx`.
- **NTFS Volume & MFT Metadata**: Inspects MFT records, cluster geometries, and USN Journal status via Win32 `DeviceIoControl`.
- **Administrative Maintenance Recipes**: Surfaces copyable, standard PowerShell inspection recipes for SSD TRIM, DNS cache flush, component cleanup, and SFC system integrity checks.

### 4. 📦 Applications & Developer Tooling
- **Software Footprint & Ownership Graph**: Maps Win32/MSI and AppX/MSIX packages to disk directories, active processes, and background persistence.
- **WinGet Catalog Correlation**: Discovers installed applications and surfaces available version upgrades directly from the Windows Package Manager.
- **Browser Footprint & Extension Audits**: Profiles cache and database sizes across Chrome, Edge, Brave, and Firefox; scans extension manifests for high-risk permissions (`<all_urls>`, `webRequest`, `nativeMessaging`).
- **Developer Tooling Awareness**: Native recognition of Python venvs, Conda, Node (`node_modules`), Docker containers/images/build caches, WSL distributions (`ext4.vhdx`), Hyper-V/VirtualBox VMs, Gradle, Maven, Cargo, Go, HuggingFace model weights, PCAPs, and forensic images.

### 5. 🤖 AI Audit Advisor & Intelligent Review
- **Multi-Provider AI Review**: Synthesizes full system audit reports using OpenAI, Anthropic, Gemini, or local private models (Ollama).
- **Zero-Leakage Privacy Redaction**: Automatically sanitizes usernames, personal directories, and sensitive tokens before sending prompts.
- **Structured Recommendations**: Generates categorized insights: Critical Security Warnings, Quick Cleanup Wins, Performance Optimizations, and Explanations.
- **Web Dashboard & CLI Integration**: Trigger AI reviews directly from the interactive web dashboard or export via `reconspace ai-review`.

---

## 🔒 Safety & Trust Architecture

| Feature | ReconSpace | Typical "PC Cleaners" |
|---|---|---|
| **Core Architecture** | **100% Read-Only Core** | Aggressive background deletion |
| **Telemetry & Network** | **Zero network requests**, loopback only | Continuous pingbacks & cloud analytics |
| **Registry Modifications** | **None** (zero registry writes) | Dangerous automated key removal |
| **Reclaim Estimates** | **Conservative, non-overlapping math** | Inflated, duplicated numbers |
| **Execution Safety** | **Reversible Recycle Bin (`FOF_ALLOWUNDO`)** | Permanent, unrecoverable file deletion |
| **Privacy Redaction** | **Automatic redaction of paths, users & keys** | Unredacted log sharing |
| **Developer Caches** | **Preserved and categorized as intentional** | Blindly wiped as "junk" |

---

## ⚡ Quick Start

### Option 1: Double-Click Launcher
Double-click `run_reconspace.bat` in the project root to launch the dashboard:
```cmd
run_reconspace.bat
```

### Option 2: Run via Python CLI
Start the local dashboard (binds strictly to `127.0.0.1` with a per-process token):
```powershell
python -m reconspace serve
```

Run a Deep audit on drive `C:\` and export JSON:
```powershell
python -m reconspace scan --root C:\ --profile deep --json audit.json
```

Run a system readiness diagnostic:
```powershell
python -m reconspace doctor --root C:\ --pretty
```

Query audit findings interactively:
```powershell
python -m reconspace query .\audit.json findings --where "reclaim>1GiB risk:low" --sort=-reclaim
```

Export a self-contained, no-script HTML evidence dossier:
```powershell
python -m reconspace export-html .\audit.json .\audit.html --redact
```

Run AI Audit Advisor to get intelligent recommendations from an audit report:
```powershell
# Using OpenAI, Anthropic, Gemini, or local Ollama:
python -m reconspace ai-review .\audit.json --provider openai --model gpt-4o-mini
# Or with local Ollama (100% private, zero external network):
python -m reconspace ai-review .\audit.json --provider ollama --model llama3.2 --out ai_advice.md
```

### Option 3: Standalone Portable Application
Run the single-file zero-dependency package directly:
```powershell
python Releases\ReconSpace-v1.3.pyz
```

---

## 📁 Repository Structure

```text
├── App/                       # Portable, ready-to-run application distribution
├── Source/                    # Full development source tree
│   ├── reconspace/            # Core Python modules & collectors
│   │   ├── ai_advisor.py      # AI review engine (OpenAI, Anthropic, Gemini, Ollama)
│   │   ├── classify.py        # Finding classification & priority scoring
│   │   ├── engine.py          # Scan orchestrator & phase pipeline
│   │   ├── ntfs.py            # Win32 NTFS & MFT metadata collection
│   │   ├── ownership.py       # Application ownership & footprint graph
│   │   ├── privacy.py         # Best-effort privacy & secret redaction
│   │   ├── query.py           # Report query parser & evaluator
│   │   ├── runner.py          # Cryptographic plan verification & safe execution
│   │   ├── webapp.py          # Local dashboard server & telemetry UI
│   │   └── windows_collectors.py # Win32/CIM/Registry collectors
│   ├── tests/                 # Complete automated test suite (158 tests)
│   ├── schemas/               # JSON Schema specifications for reports & rule packs
│   ├── examples/              # Custom rule pack and query syntax examples
│   ├── build_portable_pyz.py  # Portable single-file package builder
│   ├── build_release_zip.py   # Atomic release archive packaging tool
│   └── update_release_manifest.py # Cryptographic SHA-256 release manifest generator
├── Releases/                  # Pre-built distribution archives (.zip and .pyz)
├── run_reconspace.bat         # Root one-click application launcher
├── CONTRIBUTING.md            # Guidelines for contributors and code standards
├── SECURITY.md                # Security policy, threat model, and disclosure process
├── LICENSE                    # MIT Open Source License
└── README.md                  # Project overview & documentation
```

---

## 🧪 Testing & Verification

ReconSpace includes a comprehensive automated test suite verifying safety invariants, cancellation, duplicate hashing, registry parsers, boundary protection, query syntax, and UI endpoints:

```powershell
cd Source
python -m pytest tests
```

**Current Suite Status:** `158 passed in ~25s` (0 failures, 0 warnings).

To verify the cryptographic integrity of the release manifest:
```powershell
cd Source
python update_release_manifest.py --check
```

---

## 🛡️ Responsible Disclosure & Privacy

ReconSpace never collects personal data, system usernames, or network addresses. When exporting reports for external review, always use the `--redact` flag to scrub local identifiers, home directories, and common command-line secrets. For security guidelines, please see [SECURITY.md](SECURITY.md).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
