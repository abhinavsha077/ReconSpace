# ReconSpace 0.4 Architecture

## Design goals

1. Remain useful without modification privileges.
2. Separate observation, interpretation, planning, and any hypothetical future execution.
3. Prefer conservative uncertainty over an attractive but misleading reclaim number.
4. Preserve cybersecurity/development/VM context.
5. Keep network use, telemetry, online reputation, and background history absent by default.
6. Make extensibility declarative and non-executable.

## Pipeline

```text
AuditConfig + profile + validated rule packs + keep paths
        |
        v
bounded recursive filesystem scanner
        |-- logical directory totals
        |-- allocated/sparse/compressed/reparse metadata
        |-- age/extension/project markers
        |-- bounded large-file metadata pool shaped by rule thresholds
        |-- duplicate candidates with cloud/stateful policy
        |
        +--> staged stable duplicate hashing
        |       size -> identity/hardlink collapse -> quick fingerprint -> SHA-256
        |
        +--> project/tooling semantic analysis
        |
        +--> Windows application/persistence/process/platform collectors
        |       Registry/CIM/PowerShell/fixed inventory-only CLIs
        |
        +--> rule-pack metadata evaluation
        |
        v
classification + system/security insights
        |
        +--> binary trust / selected ACL evidence
        +--> application ownership-footprint graph
        +--> active-process and explicit keep-path protection
        |
        v
finding normalization + priority scoring
        |
        v
conservative non-overlapping reclaim model
        |
        v
ScanReport schema v4 + audit coverage indicator
   |        |        |        |       |       |       |
 JSON   Markdown   dashboard  query  compare trend  plan
   |        |                              |          |
 CSV    static HTML                    redaction   validation
```

## Module responsibilities

- `scanner.py` — one-pass reachable-root traversal, logical directory accounting, allocated/sparse/compressed metadata, top-N heaps, bounded large-file metadata retention, extension/age distributions, project markers, duplicate-candidate policy, cancellation, and coverage metrics.
- `sizeutil.py` — metadata-only allocated-size lookup.
- `storage_basis.py` — physical-versus-logical file reclaim basis and hard-link conservatism.
- `duplicates.py` — file-identity collapse, quick fingerprint, SHA-256, mutation/stability checks, hard-link sets, and conservative reclaim math.
- `insights.py` — project/cache/VM/security artifact discovery from path and manifest context.
- `rules.py` — validated JSON metadata-only rule packs, candidate indexing, project-marker requirements, and keep-path policy. It contains no subprocess or dynamic execution primitive.
- `classify.py` — storage/application/persistence classification and priority scoring.
- `windows_collectors.py` — Windows Registry/CIM/PowerShell/fixed CLI inventory. This is the only runtime module allowed to invoke subprocesses, always with `shell=False`.
- `system_insights.py` — converts Windows/WSL/Docker/VSS/component-store/platform data into user-facing findings.
- `security_insights.py` — converts binary-trust, selected ACL, and storage-reliability evidence into conservative review findings.
- `ownership.py` — application footprint graph, active-process protection, and relationship evidence.
- `reclaim.py` — non-overlapping path totals and separate duplicate/application/platform alternatives.
- `audit_health.py` — scan coverage/evidence-quality indicator; not a health/security score.
- `engine.py` — validates rule packs, plans metadata retention, orchestrates phases, and assembles the report.
- `models.py` — schema-v4 dataclasses.
- `query.py` — report query parser/evaluator and table/CSV rendering.
- `trend.py` — explicit multi-report growth and capacity analysis with consistency checks.
- `compare.py` — two-report delta analysis with root/profile/coverage warnings.
- `plan.py` — approval-only review output; never execution commands.
- `report.py` — JSON/Markdown output.
- `exporter.py` — explicit CSV bundle and static no-script HTML report.
- `privacy.py` — explicit best-effort identifier and common-secret redaction.
- `validation.py` — structural/safety-enum report validation.
- `doctor.py` — in-process runtime/readiness inspection.
- `webapp.py` — loopback/token-protected read-only dashboard and scan controller.
- `commandline.py` — non-executing Windows command-line parsing for persistence hints.

## Memory and retention model

The scanner does not retain a full record for every file. It retains:

- one aggregate record per directory;
- extension and age counters;
- bounded top-file/top-directory heaps;
- a bounded large-file metadata pool used by classification and file rules;
- only sufficiently large duplicate-candidate paths;
- bounded project-marker metadata;
- bounded representative error lists.

Rule packs are validated before traversal. The lowest requested file-rule threshold can lower the metadata-retention threshold, but a 1 MiB floor prevents a rule from forcing millions of tiny-file records into memory. The pool retains at most 10,000 candidates and reports omissions explicitly if the bound is reached.

Directory aggregation still scales with directory count because every traversed directory needs a recursive total. A future optional indexed/MFT backend could accelerate NTFS scans, but an unverified raw-disk parser is intentionally not part of 0.4.

## Accuracy model

### Logical versus physical size

Directory totals are logical namespace totals. File findings prefer allocated-size evidence when available. Sparse, compressed, cloud, and hard-linked data can make logical size differ materially from physical reclaim.

### Hard links

File identity is used to identify aliases. Directory totals remain namespace totals, but duplicate hashing collapses hard-linked aliases, and an individual hard-link path receives zero guaranteed physical reclaim because the underlying clusters remain until the final link is removed.

### Reclaim overlap

Path candidates are de-overlapped by suppressing descendants covered by a near-full-reclaim parent. Duplicate, application, and platform potentials remain separate because they can overlap path candidates and each other.

### Stateful and cloud files

Directory reparse points are never followed. Cloud/offline/reparse regular files are metadata-inventoried but not content-hashed to avoid hydration. VM/forensic/dump formats are excluded from duplicate hashing unless an expert explicitly opts in.

## Collector applicability

Each collector returns:

- `ok`: whether complete usable evidence was returned;
- `applicable`: whether the collector/tool/platform applied to this host;
- `data` and `error`.

A missing optional Windows tool on Linux, or an unavailable Docker/Hyper-V feature, is not treated as a failed Windows C: audit. The coverage indicator distinguishes unavailable/non-applicable evidence from requested-but-incomplete evidence.

## Trust boundaries

- The dashboard binds only to loopback and requires a random per-process token.
- The token is removed from the visible URL after initialization and sent in an API header.
- The dashboard has no cleanup, delete, uninstall, prune, remove, or execute route.
- Rule packs are JSON data, not plugins; execution/action fields are rejected.
- No online reputation or file upload is performed.
- Report exports occur only when the user supplies a destination.
- Trend/history analysis occurs only on explicitly selected reports.

## Future architecture

The recommended next major work is an optional, independently testable acceleration/index layer and a richer ownership graph—not a cleanup engine. See `RESEARCH_AND_ROADMAP.md`.
