# ReconSpace 0.6.0 Release Test Report

Release preparation date: 2026-09-28

## Automated correctness and safety

- `python -m compileall -q reconspace tests` — PASS
- `python -m unittest discover -s tests -q` — **108 tests PASS**
- `python -m pytest -q` — **108 tests PASS**
- built-in metadata-only rule-pack validation — PASS
- destructive Python API regression scan — PASS
- mutating PowerShell/Windows/Docker/WSL/VSS/service/task command regression scan — PASS
- dynamic rule-execution primitive scan — PASS
- localhost dashboard mutating-route scan — PASS

The 0.6.0 regression additions verify the decision brief, guided action plan, selected-root versus host-wide scope explanation, eight-domain audit-depth ledger, richer Markdown/plan output, and Windows console encoding fallback. The 0.5.0 visual, responsive, keyboard, reduced-motion, polling, and browser checks remain covered. Existing cancellation, report-import, CLI, packaging, dashboard-security, and engine regression coverage remains in the suite.

## Defects found and fixed during 0.4 validation

1. **Rule file reachability:** file rules were evaluated only against a hard-coded “interesting extension” set, so `.crdownload` and arbitrary custom extensions could be unreachable. The scanner now retains a bounded pool of all sufficiently large files, and validated rule thresholds influence the retention floor.
2. **Rule reclaim accounting:** rule findings used a generic `scope_type=path`, while conservative reclaim accepted only `file`/`folder`; rule reclaim was omitted. Rule findings now identify their true scope and participate in overlap suppression.
3. **Memory dump evidence leakage:** the Windows `MEMORY.DMP` finding could inherit allocated-size evidence from a previously classified file. It now derives reclaim evidence from the dump record itself.
4. **Hard-link reclaim:** deleting one link name was over-creditable in some file finding contexts. A single hard-link path now receives zero guaranteed physical reclaim.
5. **Trend validity:** inconsistent volume counters or material capacity changes could produce invalid forecasts. Forecasting now disables itself with explicit warnings.
6. **Collector applicability:** unavailable platform collectors could be interpreted as failed coverage. `applicable=false` is now modeled separately.
7. **Cross-machine redaction:** redaction formerly depended too heavily on the machine performing the redaction. It now derives profile/root/host/user replacements from report contents and scrubs common command-line/URL secrets.
8. **Query handling:** Windows backslashes and mixed-type sorting had edge cases. Paths are preserved, regex is bounded, and missing values remain last.

Every issue above has regression coverage.

## Synthetic full-pipeline acceptance

Input:

- 2,520 files;
- 34 directories;
- 405,825,417 logical bytes;
- Node.js project with `node_modules` and `.next` cache;
- Python project with `.pytest_cache`;
- Hugging Face model storage;
- explicit protected cache;
- exact duplicate pair and hard-link alias;
- sparse VHDX;
- PCAP and dump;
- old archive, installer, ISO, and partial download;
- 2,500 log files;
- custom low-threshold metadata-only rule pack.

Results:

- findings: **14**;
- exact duplicate groups: **1**;
- hard-link aliases: **1**;
- stateful hash-policy skips: **2**;
- conservative non-overlapping path potential: **147,849,216 bytes**;
- custom+built-in rule matches: **5**;
- non-applicable collectors correctly identified: **9**;
- audit coverage score in this synthetic host context: **100.0**;
- CSV tables: **16**;
- query matches: **4**;
- static HTML size: **41,687 bytes**;
- three-snapshot trend fit: available, positive growth, `R²=1.0` for the intentionally linear test series;
- all assertions: **PASS**.

## 50,000-file scale sanity

- files: **50,000**;
- directories: **201**;
- elapsed: **4.6563 seconds**;
- scan rate: **10,738.8 files/second**;
- peak traced Python memory: **3.86 MiB**;
- errors: **0**;
- result: **PASS**.

All performance figures are Linux build-container synthetic measurements. They are not Windows C: benchmarks.

## Native-Windows validation

The 0.6.0 decision/depth release was live-run on Windows using the Deep profile. The run exercised the 41-check Windows inventory, installed applications, startup entries, services, scheduled tasks, active-process context, Authenticode batches, selected ACL checks, application ownership correlation, audit-depth reporting, and Markdown/JSON output. Platform-dependent collectors still report unavailable or access-limited states honestly; no claim is made that every collector will be available on every Windows edition or privilege level.
