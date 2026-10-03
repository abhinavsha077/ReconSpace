# ReconSpace 0.6.0 Verification Notes

## Automated suite

Final source tree at release preparation: **108 automated tests** passing under both:

```powershell
py -3 -m unittest discover -s tests -v
```

and, when pytest is installed:

```powershell
py -3 -m pytest -q
```

Coverage includes:

- recursive directory accounting and bounded top-N retention;
- cooperative cancellation within very large flat directories;
- cooperative cancellation between audit phases, optional collectors, and trust/ACL batches;
- logical/allocated/sparse metadata;
- exact duplicate verification and file-change rejection;
- NTFS-style hard-link alias accounting and hardlink-only duplicate suppression;
- cloud/offline/reparse and stateful VM/forensic hash policy;
- project marker and semantic tooling detection;
- intentional `node_modules` classification and separate dormant/reproducible review evidence;
- custom JSON rule validation, forbidden execution fields, `any`/`all` semantics, candidate indexing, arbitrary file-extension reachability, and conservative reclaim participation;
- keep/protected-path behavior;
- application footprint/ownership relationships and active-process protection;
- persistence executable parsing, hidden tasks, missing targets, script-host and unquoted-service-path signals;
- local binary trust and selected ACL insight conversion;
- storage reliability insight conversion;
- Docker, WSL, VSS, pagefile, component-store, and platform insight conversion;
- conservative overlap suppression and physical reclaim basis;
- query parsing, Windows paths, regex limits, mixed-type sorting, table/CSV rendering;
- trend forecasting, same-volume checks, inconsistent counters, and capacity changes;
- report comparison compatibility warnings;
- bounded, finite, structurally validated report loading in the CLI and dashboard;
- plan-only output;
- 16-table CSV export and static no-script HTML escaping/CSP;
- cross-machine and common-secret privacy redaction;
- report validation and collector applicability;
- dashboard token, loopback, accessibility semantics, visible connection failures, CSP/no-sniff/frame/same-origin headers, option validation, and no-mutation routes;
- desktop/mobile observatory layout, keyboard result navigation, visible focus, reduced motion, local favicon, and bounded idle polling;
- source-level destructive API/command regressions;
- complete-release manifest scope and unlisted-file detection;
- atomic release-manifest regeneration and stale-manifest checking;
- centralized `subprocess.run` with `shell=False`;
- rule engine absence of dynamic execution primitives.

## Full-pipeline synthetic acceptance run

A generated developer/security workstation tree containing **2,520 files across 34 directories** was processed through:

```text
filesystem scan
 -> project/tooling context
 -> exact duplicate verification
 -> hard-link accounting
 -> stateful-file policy
 -> custom and built-in rules
 -> keep-path policy
 -> classification and reclaim summary
 -> report validation
 -> query
 -> approval plan
 -> 16-table CSV export
 -> privacy redaction
 -> static HTML export
 -> comparison
 -> three-snapshot trend forecast
```

Validated outcomes:

- one exact duplicate group verified;
- one hard-link alias separated from independently reclaimable data;
- VHDX/dump stateful hashing policy applied;
- custom partial-download, web-cache, Python-cache, protected-path, and ML-model rules matched;
- protected finding retained but counted as zero reclaim;
- intentional development/ML/VM context preserved;
- rule-derived candidates included in the non-overlapping path total;
- report validation passed;
- query returned expected matches;
- plan remained `PLAN ONLY — NO EXECUTION` / `PENDING_REVIEW` / `Execution: NONE`;
- 16 CSV tables generated;
- JSON and HTML share copies removed common test secrets;
- static HTML contained no script element;
- three internally consistent capacity snapshots produced a valid forecast;
- non-applicable Linux/Windows collectors did not count as failures.

Build-environment observation: 405,825,417 logical bytes, 14 findings, 1 duplicate group. The scanner-reported 0.024 seconds / 105,000 files per second is a tiny cached synthetic-tree signal only, not a Windows benchmark.

## Scale sanity run

A separate **50,000-file / 201-directory** tree of small files was traversed with bounded retention:

- elapsed: **4.6563 seconds**;
- scanner rate: **10,738.8 files/second**;
- peak Python `tracemalloc`: **3.86 MiB**;
- errors: **0**;
- 200 top files and 201 top directories retained;
- no unnecessary large-file metadata candidates retained.

This Linux container result is a memory/algorithm sanity check, not a prediction for an actual Windows C: drive, antivirus configuration, spinning disk, network share, or cloud-backed profile.

## Release checks

The release process also performs:

- `compileall` for source and tests;
- `unittest` and `pytest` runs;
- built-in rule-pack validation;
- dashboard JavaScript extraction and `node --check` when Node is available;
- static safety vocabulary/AST tests;
- standalone `.pyz` help, doctor, scan, validate, query, plan, CSV, HTML, redact, compare, and trend smoke tests;
- ZIP extraction into a fresh directory;
- release-manifest hash verification;
- external ZIP/PYZ SHA-256 verification;
- cache/build-artifact cleanliness checks.

## Windows-specific limitation

The build environment is Linux. Windows-only Registry, PowerShell, WSL, Docker Desktop, DISM, VSS, Hyper-V, Storage-module, BitLocker, driver-store, Authenticode, ACL, and NTFS command collectors cannot be live-executed here against an actual Windows C: drive.

They are covered by fixed command forms, parser/result tests, source safety checks, result-to-finding tests, and per-collector applicability/error handling. Run `verify_reconspace.bat`, `doctor`, and the native checklist before treating a particular machine as validated.
