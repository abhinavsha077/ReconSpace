# ReconSpace Report Query Language

The query command filters an existing exported JSON report. It does not rescan or modify the system.

```powershell
py -3 -m reconspace query REPORT.json SECTION --where "EXPRESSION" [options]
```

## Sections

Common aliases include:

- `findings`
- `files` / `top_files`
- `directories` / `top_directories`
- `applications` / `apps`
- `duplicates`
- `projects` / `project_artifacts`
- `startup`
- `services`
- `tasks` / `scheduled_tasks`
- `processes`
- `binary-trust` / `binary_trust`
- `permissions` / `path_security`
- `footprints` / `application_footprints`
- `collectors`

## Operators

| Operator | Meaning |
|---|---|
| `:` | case-insensitive substring |
| `=` | exact text or numeric equality |
| `!=` | exact text or numeric inequality |
| `>` `>=` `<` `<=` | numeric, byte-size, or age comparison |
| `~` | case-insensitive regular expression |

Multiple conditions in a group use AND. Use `or`, `|`, or `||` between groups.

## Units

Byte units: `B`, `KB`, `MB`, `GB`, `TB`, `KiB`, `MiB`, `GiB`, `TiB`.

Age units: `d`, `day`, `days`, `w`, `week`, `weeks`, `mo`, `month`, `months`, `y`, `year`, `years`.

Examples:

```text
reclaim>5GiB risk:low
age>180d path:Downloads
size>1GiB extension:.vhdx
signature!=Valid user_writable=true
owner:Users broad_write=true
related:docker or related:wsl or related:virtualization
path~"(?i)node_modules|\.venv|\.gradle"
```

Regular expressions are limited to 512 characters.

## Field aliases

Useful aliases include:

- `size` → `size_bytes`
- `reclaim` → `estimated_reclaimable_bytes`
- `age` → `age_days`
- `path`
- `risk`
- `confidence`
- `disposition`
- `category`
- `related`
- `publisher`
- `version`
- `signature`
- `user_writable`
- `owner`
- `broad_write`
- `working_set`

Nested fields can be addressed with dots when present, for example `evidence.rule_id:partial-download`.

## Output

Table output:

```powershell
py -3 -m reconspace query audit.json findings --where "reclaim>1GiB" --sort=-reclaim
```

JSON output:

```powershell
py -3 -m reconspace query audit.json files --where "size>500MiB" --format json
```

CSV output with selected columns:

```powershell
py -3 -m reconspace query audit.json findings --where "risk:low" --format csv --columns title,path,estimated_reclaimable_bytes,risk --output low-risk.csv
```

Sorting uses `--sort=field`; prefix with `-` for descending. Missing values remain last in both directions.

## Windows paths

Unquoted backslashes are preserved, so this is valid:

```powershell
--where "path:C:\Users\Alice\Downloads"
```

Quote the complete expression when spaces or shell-sensitive characters are present.

## Limitations

The query engine operates only on fields retained in the exported report. Top-file/top-directory sections are bounded top-N evidence, not complete filesystem indexes.
