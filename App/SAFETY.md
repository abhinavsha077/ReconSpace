# ReconSpace Safety Model — 0.4

## Primary invariant

ReconSpace is a **read-only reconnaissance and planning application**. It has no cleanup executor.

The runtime does not provide functionality to:

- delete, unlink, truncate, shred, rename, move, or compress user/system files;
- uninstall Win32/MSI/AppX applications;
- write/delete Registry keys or values;
- stop, disable, delete, or reconfigure services;
- disable or delete scheduled tasks;
- modify owners, ACLs, permissions, or file attributes;
- prune Docker images, containers, build cache, or volumes;
- unregister WSL distributions or directly modify their VHDX files;
- delete VSS snapshots/restore points;
- run component-store cleanup/reset operations;
- disable hibernation/pagefile/Reserved Storage;
- change partitions, BitLocker, storage pools, drivers, boot, recovery, or Windows Update state.

The source-level safety suite scans for destructive Python APIs, mutating Windows/PowerShell/Docker/WSL/VSS/service/task command forms, dynamic rule execution, and mutating dashboard routes.

## Observation can still have side effects

A nominally read-only scanner can still create I/O, hydrate cloud files, lock stateful files, or overload a live system. ReconSpace therefore:

- never follows directory junctions/reparse points;
- metadata-counts cloud/offline/reparse regular files but does not content-hash them;
- skips VM/forensic/dump formats during duplicate hashing by default;
- allows stateful hashing only through explicit expert opt-in;
- uses bounded candidate pools and retained top-N tables;
- checks cancellation during large directory enumeration and duplicate hashing;
- never self-elevates or changes ACLs to bypass access denial;
- reports access and collector coverage gaps.

## Rule-pack boundary

Rule packs are validated JSON metadata. They may describe match conditions and explanatory recommendations, but cannot contain commands, scripts, action types, executables, Registry operations, deletion paths, or dynamic code.

The rule engine does not use `eval`, `exec`, compilation, imports, subprocesses, PowerShell, or shell commands. Rule files can only create findings.

A 1 MiB file-candidate retention floor prevents a custom rule from forcing millions of tiny-file records into memory. If the 10,000-candidate bound is reached, omissions are reported.

## Protected/keep paths

`--keep` does not hide a path or skip analysis. It:

- leaves findings visible;
- records which keep path matched;
- preserves the pre-policy reclaim estimate as evidence;
- sets counted reclaimable bytes to zero;
- downgrades `probably_safe_cleanup` to `manual_review`;
- raises low risk to medium.

This prevents an intentional lab, evidence store, backup, or project area from inflating cleanup totals while preserving audit visibility.

## Windows collector boundary

`windows_collectors.py` is the only runtime module allowed to launch subprocesses. Calls use fixed argument arrays and `shell=False`.

Permitted operations are inventory/query forms such as:

- Registry reads;
- CIM/Get-* queries;
- Authenticode and ACL reads;
- Docker disk-usage/list queries;
- WSL distribution listing;
- VSS shadow-storage listing;
- DISM component-store analysis;
- NTFS/USN status queries;
- Hyper-V/VirtualBox inventory;
- physical disk/storage reliability queries.

Mutating forms are rejected by regression tests.

## Dashboard boundary

- listens on `127.0.0.1` only;
- generates a random per-process token;
- requires the token on API calls;
- removes the token from the visible URL after initialization;
- uses no-store, no-referrer, no-sniff, and Content Security Policy headers;
- validates root/exclusion options;
- exposes scan/status/report/cancel operations only;
- has no cleanup/delete/uninstall/prune/remove/execute API.

Cancellation changes only in-memory scan control state.

## Static HTML boundary

Static HTML export:

- is generated only to an explicitly supplied path;
- contains no active scripts or network calls;
- HTML-escapes report content;
- declares a restrictive CSP;
- contains no action controls.

## Export and privacy boundary

ReconSpace writes reports only when the user explicitly supplies a destination. It creates no automatic history database, telemetry, scheduled task, service, startup entry, or cloud upload.

Redaction is best-effort. It does not prove anonymity. Filenames, project names, hashes, free-form evidence, and uncommon secret formats can remain sensitive. Review redacted copies manually.

## Approval plan boundary

Plans contain explanation, evidence, risk, estimated impact, and supported management guidance. Every item remains `PENDING_REVIEW`; execution remains `NONE`. Plans are not scripts and contain no cleanup commands.

## Elevation

ReconSpace never self-elevates. Manual elevation may improve read coverage, but the application still remains read-only. Compare normal-user and elevated reports rather than treating one as automatically authoritative.

## Future execution

Any future cleanup capability should be a separate, independently permissioned component with signed/explicit manifests, exact preconditions, backups/rollback, path identity checks, process checks, and per-action approval. It should not weaken the reconnaissance engine’s no-modification contract.
