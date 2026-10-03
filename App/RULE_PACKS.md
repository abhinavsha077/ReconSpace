# ReconSpace Metadata-Only Rule Packs

Rule packs extend classification without extending execution. They are JSON documents validated before filesystem traversal.

## Safety contract

A rule pack can:

- match retained file or directory metadata;
- require nearby project markers;
- apply size and age thresholds;
- create an explanatory finding;
- classify risk, confidence, disposition, and related tooling;
- estimate a reclaim fraction for triage.

A rule pack cannot:

- run commands, scripts, PowerShell, or executables;
- delete, move, rename, truncate, shred, compress, or modify files;
- write Registry values;
- uninstall software;
- change services, tasks, permissions, Docker, WSL, VSS, or Windows servicing;
- import Python or dynamically execute code.

Execution/action-like fields are rejected during validation.

## Basic structure

```json
{
  "schema_version": 1,
  "name": "Organization storage rules",
  "version": "1.0",
  "description": "Metadata-only classification rules.",
  "rules": []
}
```

See `examples/custom-rules.example.json` and `schemas/rule-pack-v1.schema.json`.

## Rule fields

Required:

- `id`: 1–80 characters, letters/numbers/`.`/`_`/`-`;
- `title`;
- `scope`: `file` or `directory`;
- `match`;
- `category`;
- `disposition`;
- `risk`;
- `confidence`;
- `why_it_exists`;
- `recommendation`;
- `removal_risk`.

Optional:

- `match_mode`: `any` (default) or `all` across populated match predicates;
- `min_size_bytes`;
- `min_age_days`;
- `reclaim_fraction`: 0.0–1.0;
- `related_to`;
- `exclude_contains_any`;
- `require_ancestor_marker_any`;
- `max_matches`.

Allowed dispositions:

- `probably_safe_cleanup`
- `manual_review`
- `intentional_tooling`
- `do_not_touch`
- `informational`

Allowed risks: `low`, `medium`, `high`, `critical`.

Allowed confidence: `low`, `medium`, `high`.

Reclaim fractions are forced to zero for `intentional_tooling`, `do_not_touch`, and `informational` findings.

## Match predicates

- `segments_any`: exact path-segment match;
- `path_contains_any`: substring anywhere in normalized path;
- `path_suffix_any`: normalized path suffix;
- `extensions`: file extensions;
- `name_regex`: regex against basename;
- `path_regex`: regex against path.

Regex length is capped. Unknown match fields are rejected.

## Project-marker context

`require_ancestor_marker_any` walks upward to the nearest discovered project-root marker set. It can distinguish a generic `build` directory from one inside Gradle, Node.js, Python, or other recognized projects.

Example:

```json
{
  "segments_any": [".cache"]
}
```

combined with:

```json
"require_ancestor_marker_any": ["package.json", "pnpm-lock.yaml"]
```

## File-candidate retention

File rules are evaluated against a bounded large-file metadata pool. ReconSpace validates rule packs before traversal and may lower the profile’s candidate threshold to the lowest file-rule threshold.

Safeguards:

- minimum retention floor: 1 MiB;
- maximum retained file candidates: 10,000;
- omissions are reported in scan stats, audit coverage, report notes, and `rule_pack_info.file_candidate_retention`.

A file rule requesting objects smaller than 1 MiB may have incomplete coverage. This prevents a custom rule from forcing a full in-memory record for millions of tiny files.

Directory rules operate on the directory aggregate map and are not limited by the file-candidate pool.

## Validate and use

```powershell
py -3 -m reconspace validate-rules .\my-rules.json --pretty
py -3 -m reconspace scan --root C:\ --profile deep --rule-pack .\my-rules.json
```

Multiple `--rule-pack` arguments are supported.

## Keep policy versus exclusions

Use `--keep PATH` when a path must remain visible but should not count toward cleanup. Use `--exclude PATH` only when the path must not be traversed. Exclusions reduce coverage; keep paths preserve evidence.
