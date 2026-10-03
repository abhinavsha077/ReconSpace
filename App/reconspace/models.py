from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Disposition = Literal[
    "probably_safe_cleanup",
    "manual_review",
    "intentional_tooling",
    "do_not_touch",
    "informational",
]
Risk = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


@dataclass(slots=True)
class Finding:
    title: str
    path: str
    size_bytes: int
    category: str
    disposition: Disposition
    risk: Risk
    confidence: Confidence
    why_it_exists: str
    recommendation: str
    removal_risk: str
    related_to: list[str] = field(default_factory=list)
    estimated_reclaimable_bytes: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)
    priority_score: float = 0.0
    age_days: float | None = None
    category_group: str = ""


@dataclass(slots=True)
class FileRecord:
    path: str
    size_bytes: int
    modified_ts: float | None = None
    created_ts: float | None = None
    extension: str = ""
    file_identity: str = ""
    link_count: int = 1
    allocated_bytes: int | None = None
    file_attributes: int = 0
    is_reparse: bool = False
    is_offline: bool = False
    is_sparse: bool = False
    is_compressed: bool = False
    content_hash_eligible: bool = True


@dataclass(slots=True)
class DirectoryRecord:
    path: str
    size_bytes: int
    direct_size_bytes: int = 0
    modified_ts: float | None = None


@dataclass(slots=True)
class DuplicateGroup:
    size_bytes_each: int
    total_logical_bytes: int
    reclaimable_bytes: int
    sha256: str
    paths: list[str]
    distinct_file_instances: int = 0
    hardlink_sets: list[list[str]] = field(default_factory=list)
    allocated_bytes_total: int | None = None
    reclaimable_basis: str = "logical"
    note: str = ""


@dataclass(slots=True)
class ExtensionSummary:
    extension: str
    files: int
    bytes: int


@dataclass(slots=True)
class AgeBucket:
    bucket: str
    files: int
    bytes: int


@dataclass(slots=True)
class ProjectArtifactRecord:
    path: str
    size_bytes: int
    artifact_type: str
    project_root: str = ""
    project_markers: list[str] = field(default_factory=list)
    rebuildable: bool = False
    age_days: float | None = None
    related_to: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ApplicationRecord:
    name: str
    version: str = ""
    publisher: str = ""
    estimated_size_bytes: int | None = None
    install_location: str = ""
    install_date: str = ""
    scope: str = ""
    architecture: str = ""
    classification: str = ""
    note: str = ""
    package_type: str = ""
    is_framework: bool = False


@dataclass(slots=True)
class StartupRecord:
    source: str
    name: str
    command: str
    risk_hint: str = ""
    reason: str = ""
    target_path: str = ""
    target_exists: bool | None = None


@dataclass(slots=True)
class ServiceRecord:
    name: str
    display_name: str
    state: str
    start_mode: str
    path_name: str
    start_name: str = ""
    process_id: int | None = None
    description: str = ""
    target_path: str = ""
    target_exists: bool | None = None
    risk_hint: str = ""
    reason: str = ""


@dataclass(slots=True)
class ScheduledTaskRecord:
    task_name: str
    task_path: str
    state: str
    author: str = ""
    actions: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    hidden: bool = False
    user_id: str = ""
    run_level: str = ""
    last_run_time: str = ""
    next_run_time: str = ""
    last_task_result: int | None = None
    risk_hint: str = ""
    reason: str = ""
    target_paths: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ProcessRecord:
    pid: int
    name: str
    executable_path: str = ""
    command_line: str = ""
    owner: str = ""
    working_set_bytes: int | None = None
    creation_date: str = ""


@dataclass(slots=True)
class BinaryTrustRecord:
    path: str
    source_kinds: list[str] = field(default_factory=list)
    exists: bool | None = None
    signature_status: str = ""
    signer_subject: str = ""
    signer_issuer: str = ""
    certificate_thumbprint: str = ""
    sha256: str = ""
    size_bytes: int | None = None
    modified_time: str = ""
    is_user_writable_location: bool = False
    note: str = ""


@dataclass(slots=True)
class PathSecurityRecord:
    path: str
    owner: str = ""
    access_rule_count: int = 0
    explicit_rule_count: int = 0
    deny_rule_count: int = 0
    broad_write_detected: bool = False
    broad_write_identities: list[str] = field(default_factory=list)
    protected_acl: bool | None = None
    error: str = ""


@dataclass(slots=True)
class ApplicationFootprintRecord:
    name: str
    version: str = ""
    publisher: str = ""
    install_location: str = ""
    installed_size_bytes: int | None = None
    related_data_bytes: int = 0
    related_paths: list[str] = field(default_factory=list)
    active_processes: list[str] = field(default_factory=list)
    startup_items: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    scheduled_tasks: list[str] = field(default_factory=list)
    execution_evidence: list[str] = field(default_factory=list)
    ownership_confidence: str = "low"
    review_note: str = ""


@dataclass(slots=True)
class CollectorResult:
    name: str
    ok: bool
    data: Any = None
    error: str = ""
    applicable: bool = True


@dataclass(slots=True)
class ScanStats:
    root: str
    started_at: str
    finished_at: str = ""
    duration_seconds: float = 0.0
    files_seen: int = 0
    directories_seen: int = 0
    bytes_seen: int = 0
    access_denied: int = 0
    reparse_points_skipped: int = 0
    reparse_files_counted: int = 0
    stat_errors: int = 0
    filesystem_total_bytes: int | None = None
    filesystem_used_bytes: int | None = None
    filesystem_free_bytes: int | None = None
    scan_cancelled: bool = False
    hardlink_aliases_seen: int = 0
    hardlink_duplicate_logical_bytes: int = 0
    cloud_or_offline_files: int = 0
    duplicate_hash_policy_skipped_files: int = 0
    duplicate_hash_policy_skipped_bytes: int = 0
    metadata_candidate_files_seen: int = 0
    metadata_candidate_files_retained: int = 0
    metadata_candidate_files_omitted: int = 0
    scan_rate_files_per_second: float = 0.0


@dataclass(slots=True)
class ScanReport:
    version: str
    profile: str
    stats: ScanStats
    top_files: list[FileRecord]
    top_directories: list[DirectoryRecord]
    extension_summary: list[ExtensionSummary]
    age_summary: list[AgeBucket]
    project_artifacts: list[ProjectArtifactRecord]
    findings: list[Finding]
    duplicates: list[DuplicateGroup]
    applications: list[ApplicationRecord]
    startup: list[StartupRecord]
    services: list[ServiceRecord]
    scheduled_tasks: list[ScheduledTaskRecord]
    collectors: list[CollectorResult]
    notes: list[str] = field(default_factory=list)
    reclaim_summary: dict[str, Any] = field(default_factory=dict)
    processes: list[ProcessRecord] = field(default_factory=list)
    binary_trust: list[BinaryTrustRecord] = field(default_factory=list)
    path_security: list[PathSecurityRecord] = field(default_factory=list)
    application_footprints: list[ApplicationFootprintRecord] = field(default_factory=list)
    rule_pack_info: dict[str, Any] = field(default_factory=dict)
    audit_health: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 4

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
