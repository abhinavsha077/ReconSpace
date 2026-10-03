from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any, Iterable

from reconspace.classify import CATEGORY_GROUPS, resolve_category_group


def _scalar(value: Any) -> str | int | float | bool:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _write_rows(path: Path, rows: Iterable[dict[str, Any]], fields: list[str] | None = None) -> None:
    materialized = list(rows)
    if fields is None:
        seen: list[str] = []
        for row in materialized:
            for key in row:
                if key not in seen:
                    seen.append(key)
        fields = seen
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in materialized:
            writer.writerow({k: _scalar(row.get(k)) for k in fields})


def export_csv_bundle(report: dict[str, Any], destination: str) -> list[Path]:
    """Explicitly export report tables. This writes only to the requested destination."""
    dest = Path(destination).expanduser().resolve()
    dest.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []

    tables = {
        "findings.csv": report.get("findings") or [],
        "top_files.csv": report.get("top_files") or [],
        "top_directories.csv": report.get("top_directories") or [],
        "applications.csv": report.get("applications") or [],
        "startup.csv": report.get("startup") or [],
        "services.csv": report.get("services") or [],
        "scheduled_tasks.csv": report.get("scheduled_tasks") or [],
        "project_artifacts.csv": report.get("project_artifacts") or [],
        "extensions.csv": report.get("extension_summary") or [],
        "age_summary.csv": report.get("age_summary") or [],
    }
    optional_tables = {
        "processes.csv": "processes",
        "binary_trust.csv": "binary_trust",
        "path_security.csv": "path_security",
        "application_footprints.csv": "application_footprints",
        "collectors.csv": "collectors",
    }
    for filename, key in optional_tables.items():
        if key in report:
            tables[filename] = report.get(key) or []
    for name, rows in tables.items():
        path = dest / name
        _write_rows(path, rows)
        files.append(path)

    duplicate_rows = []
    for i, group in enumerate(report.get("duplicates") or [], 1):
        base = {k: v for k, v in group.items() if k not in {"paths", "hardlink_sets"}}
        for p in group.get("paths") or []:
            duplicate_rows.append({"group_id": i, "path": p, **base})
    path = dest / "duplicates.csv"
    _write_rows(path, duplicate_rows)
    files.append(path)
    return files


def _bytes(value: Any) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return ""
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    index = 0
    while abs(number) >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    return f"{number:,.0f} {units[index]}" if index == 0 else f"{number:,.2f} {units[index]}"


def _cell(value: Any, *, limit: int = 800) -> str:
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "Yes" if value else "No"
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    else:
        text = str(value)
    text = text.replace("\x00", "").replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return html.escape(text, quote=True)


def _table(
    title: str,
    rows: Any,
    columns: list[tuple[str, str]],
    *,
    max_rows: int,
    byte_fields: set[str] | None = None,
    empty_note: str = "No records were captured for this section.",
) -> str:
    materialized = [row for row in (rows or []) if isinstance(row, dict)]
    shown = materialized[:max_rows]
    byte_fields = byte_fields or set()
    head = "".join(f"<th>{html.escape(label)}</th>" for _field, label in columns)
    body_rows: list[str] = []
    for row in shown:
        cells = []
        for field, _label in columns:
            value = row.get(field)
            rendered = html.escape(_bytes(value)) if field in byte_fields and value is not None else _cell(value)
            css = " class=\"mono\"" if "path" in field or field in {"sha256", "command", "actions"} else ""
            cells.append(f"<td{css}>{rendered}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    if not body_rows:
        body = f'<tr><td colspan="{len(columns)}" class="empty">{html.escape(empty_note)}</td></tr>'
    else:
        body = "".join(body_rows)
    omission = ""
    if len(materialized) > len(shown):
        omission = f'<p class="footnote">Showing {len(shown):,} of {len(materialized):,} rows. Use JSON/CSV exports for complete evidence.</p>'
    return (
        f'<section><h2>{html.escape(title)} <span class="count">{len(materialized):,}</span></h2>'
        f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>{omission}</section>'
    )


def render_html_report(report: dict[str, Any], *, max_rows: int = 250) -> str:
    """Render a portable, static, self-contained report with no active scripts.

    The output is intentionally presentation-only. It does not contain cleanup,
    uninstall, command execution or network functionality.
    """
    max_rows = max(1, min(5000, int(max_rows)))
    stats = report.get("stats") or {}
    reclaim = report.get("reclaim_summary") or {}
    health = report.get("audit_health") or {}
    version = str(report.get("version") or "unknown")
    profile = str(report.get("profile") or "unknown")
    root = str(stats.get("root") or "")
    generated = str(stats.get("finished_at") or stats.get("started_at") or "")
    redacted = bool(report.get("privacy_redacted"))

    disposition_labels = {
        "probably_safe_cleanup": "Probably safe cleanup",
        "manual_review": "Needs manual review",
        "intentional_tooling": "Intentional development/security tooling",
        "do_not_touch": "Do not touch",
        "informational": "Informational",
    }
    category_data: dict[str, dict[str, Any]] = {}
    finding_rows = []
    for row in report.get("findings") or []:
        if not isinstance(row, dict):
            continue
        c_group = str(row.get("category_group") or "") or resolve_category_group(str(row.get("category") or ""))
        meta = CATEGORY_GROUPS.get(c_group, {
            "title": c_group.replace("_", " ").title(),
            "icon": "📁",
            "description": "Storage findings requiring assessment.",
        })
        if c_group not in category_data:
            category_data[c_group] = {
                "title": meta.get("title", c_group),
                "icon": meta.get("icon", "📁"),
                "description": meta.get("description", ""),
                "count": 0,
                "total_bytes": 0,
                "reclaim_bytes": 0,
            }
        category_data[c_group]["count"] += 1
        category_data[c_group]["total_bytes"] += int(row.get("size_bytes") or 0)
        category_data[c_group]["reclaim_bytes"] += int(row.get("estimated_reclaimable_bytes") or 0)

        finding_rows.append({
            **row,
            "category_label": f"{meta.get('icon', '📁')} {meta.get('title', c_group)}",
            "disposition_label": disposition_labels.get(str(row.get("disposition") or ""), str(row.get("disposition") or "")),
        })

    cat_cards = []
    for c_id, cinfo in category_data.items():
        reclaim_str = f'<span class="safe">Est. {_bytes(cinfo["reclaim_bytes"])} reclaim</span>' if cinfo["reclaim_bytes"] > 0 else ''
        cat_cards.append(
            f'<div class="cat-card">'
            f'<div class="cat-card-header"><span class="cat-icon">{cinfo["icon"]}</span> <strong>{html.escape(cinfo["title"])}</strong></div>'
            f'<div class="cat-card-size">{_bytes(cinfo["total_bytes"])}</div>'
            f'<p class="cat-card-desc">{html.escape(cinfo["description"])}</p>'
            f'<div class="cat-card-footer"><span>{cinfo["count"]} findings</span>{reclaim_str}</div>'
            f'</div>'
        )
    category_grid_html = f'<section><h2>Storage by category</h2><div class="cat-grid">{"".join(cat_cards)}</div></section>' if cat_cards else ''

    collector_rows = []
    for row in report.get("collectors") or []:
        if not isinstance(row, dict):
            continue
        collector_rows.append({
            **row,
            "status": "Not applicable" if row.get("applicable") is False else "Pass" if row.get("ok") else "Incomplete",
        })

    duplicate_rows = []
    for index, row in enumerate(report.get("duplicates") or [], 1):
        if not isinstance(row, dict):
            continue
        duplicate_rows.append({
            "group": index,
            "size_bytes_each": row.get("size_bytes_each"),
            "reclaimable_bytes": row.get("reclaimable_bytes"),
            "distinct_file_instances": row.get("distinct_file_instances"),
            "sha256": row.get("sha256"),
            "paths": row.get("paths") or [],
            "note": row.get("note") or "",
        })

    notes = "".join(f"<li>{_cell(note, limit=3000)}</li>" for note in report.get("notes") or [])
    if not notes:
        notes = "<li>No report notes were recorded.</li>"

    issues = health.get("issues") or []
    strengths = health.get("strengths") or []
    health_list = "".join(
        f'<li><strong>{_cell(row.get("severity", ""))}</strong> — {_cell(row.get("message", ""), limit=2000)}</li>'
        for row in issues if isinstance(row, dict)
    ) or "<li>No coverage issues were recorded.</li>"
    strength_list = "".join(f"<li>{_cell(item, limit=2000)}</li>" for item in strengths) or "<li>No coverage strengths were recorded.</li>"

    metrics = [
        ("Audit coverage", f"{health.get('coverage_score', '—')} / 100", str(health.get("coverage_grade") or "not scored")),
        ("Scanned namespace", _bytes(stats.get("bytes_seen")), f"{int(stats.get('files_seen') or 0):,} files"),
        ("Non-overlap path potential", _bytes(reclaim.get("path_candidates_nonoverlap_bytes")), "Conservative; not an instruction"),
        ("Free space at scan", _bytes(stats.get("filesystem_free_bytes")), "Point-in-time volume metadata"),
        ("Exact duplicate potential", _bytes(reclaim.get("duplicate_potential_bytes_separate")), "Separate; may overlap paths"),
        ("Application potential", _bytes(reclaim.get("application_potential_bytes_separate")), "Separate; manual review"),
    ]
    metric_html = "".join(
        f'<div class="metric"><span>{html.escape(label)}</span><strong>{html.escape(value)}</strong><small>{html.escape(note)}</small></div>'
        for label, value, note in metrics
    )

    sections = [
        _table(
            "Prioritized findings", finding_rows,
            [
                ("title", "Finding"), ("category_label", "Category"), ("disposition_label", "Disposition"), ("risk", "Risk"),
                ("estimated_reclaimable_bytes", "Estimated reclaim"), ("path", "Path"),
                ("why_it_exists", "Why it exists"), ("recommendation", "Recommendation"), ("removal_risk", "Removal risk"),
            ],
            max_rows=max_rows,
            byte_fields={"estimated_reclaimable_bytes"},
        ),
        _table(
            "Largest directories", report.get("top_directories"),
            [("size_bytes", "Logical size"), ("direct_size_bytes", "Direct size"), ("path", "Path")],
            max_rows=max_rows, byte_fields={"size_bytes", "direct_size_bytes"},
        ),
        _table(
            "Largest files", report.get("top_files"),
            [
                ("size_bytes", "Logical size"), ("allocated_bytes", "Allocated"), ("link_count", "Links"),
                ("is_sparse", "Sparse"), ("is_compressed", "Compressed"), ("path", "Path"),
            ],
            max_rows=max_rows, byte_fields={"size_bytes", "allocated_bytes"},
        ),
        _table(
            "Exact duplicate groups", duplicate_rows,
            [
                ("group", "Group"), ("size_bytes_each", "Each"), ("reclaimable_bytes", "Potential"),
                ("distinct_file_instances", "Distinct instances"), ("sha256", "SHA-256"), ("paths", "Paths"), ("note", "Note"),
            ],
            max_rows=max_rows, byte_fields={"size_bytes_each", "reclaimable_bytes"},
        ),
        _table(
            "Installed applications", report.get("applications"),
            [
                ("name", "Application"), ("version", "Version"), ("publisher", "Publisher"),
                ("estimated_size_bytes", "Estimated size"), ("classification", "Classification"),
                ("install_location", "Install location"), ("note", "Context"),
            ],
            max_rows=max_rows, byte_fields={"estimated_size_bytes"},
        ),
        _table(
            "Application ownership graph", report.get("application_footprints"),
            [
                ("name", "Application"), ("installed_size_bytes", "Installed"), ("related_data_bytes", "Related data"),
                ("ownership_confidence", "Ownership confidence"), ("active_processes", "Active processes"),
                ("related_paths", "Related paths"), ("review_note", "Review note"),
            ],
            max_rows=max_rows, byte_fields={"installed_size_bytes", "related_data_bytes"},
        ),
        _table(
            "Startup entries", report.get("startup"),
            [("name", "Name"), ("source", "Source"), ("risk_hint", "Review signal"), ("target_exists", "Target exists"), ("command", "Command")],
            max_rows=max_rows,
        ),
        _table(
            "Services", report.get("services"),
            [
                ("display_name", "Service"), ("state", "State"), ("start_mode", "Start mode"),
                ("start_name", "Account"), ("risk_hint", "Review signal"), ("path_name", "Command path"),
            ],
            max_rows=max_rows,
        ),
        _table(
            "Scheduled tasks", report.get("scheduled_tasks"),
            [
                ("task_name", "Task"), ("state", "State"), ("hidden", "Hidden"), ("user_id", "User"),
                ("risk_hint", "Review signal"), ("actions", "Actions"),
            ],
            max_rows=max_rows,
        ),
        _table(
            "Active processes", report.get("processes"),
            [
                ("pid", "PID"), ("name", "Process"), ("working_set_bytes", "Working set"),
                ("owner", "Owner"), ("executable_path", "Executable"), ("command_line", "Command line"),
            ],
            max_rows=max_rows, byte_fields={"working_set_bytes"},
        ),
        _table(
            "Binary trust evidence", report.get("binary_trust"),
            [
                ("signature_status", "Signature status"), ("signer_subject", "Signer"),
                ("is_user_writable_location", "User-writable location"), ("source_kinds", "Sources"),
                ("sha256", "SHA-256"), ("path", "Path"), ("note", "Note"),
            ],
            max_rows=max_rows,
        ),
        _table(
            "Owner and ACL summaries", report.get("path_security"),
            [
                ("owner", "Owner"), ("broad_write_detected", "Broad write"), ("broad_write_identities", "Broad-write identities"),
                ("deny_rule_count", "Deny rules"), ("protected_acl", "Protected ACL"), ("path", "Path"), ("error", "Error"),
            ],
            max_rows=max_rows,
        ),
        _table(
            "Collector coverage", collector_rows,
            [("name", "Collector"), ("status", "Status"), ("error", "Error"), ("data", "Summary/evidence")],
            max_rows=max_rows,
        ),
    ]

    privacy_badge = '<span class="badge private">Privacy-redacted copy</span>' if redacted else '<span class="badge warn">Contains local paths and identifiers</span>'
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>ReconSpace audit report</title>
<style>
:root{{color-scheme:dark;--bg:#0b0f17;--surface:#111827;--surface2:#162032;--surface-card:#151e2e;--text:#f1f5f9;--muted:#94a3b8;--border:#263449;--good:#10b981;--good-bg:rgba(16,185,129,0.12);--warn:#f59e0b;--warn-bg:rgba(245,158,11,0.12);--risk:#ef4444;--risk-bg:rgba(239,68,68,0.12);--accent:#3b82f6;--accent-bg:rgba(59,130,246,0.12)}}
*{{box-sizing:border-box}}
body{{margin:0;background:#0b0f17;font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--text);-webkit-font-smoothing:antialiased}}
main{{max-width:1580px;margin:auto;padding:32px 24px}}
header{{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;box-shadow:0 4px 24px rgba(0,0,0,.25)}}
h1{{font-size:28px;font-weight:750;letter-spacing:-.025em;margin:0 0 6px}}
h2{{font-size:18px;font-weight:700;margin:0 0 14px;display:flex;align-items:center;gap:8px}}
h3{{font-size:14px;font-weight:650;margin:12px 0 6px;color:var(--accent)}}
p{{color:var(--muted);margin:0 0 12px}}
.meta{{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}}
.badge{{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(16,185,129,.35);background:var(--good-bg);color:var(--good);padding:5px 11px;border-radius:999px;font-weight:700;font-size:12px}}
.badge.warn{{border-color:rgba(245,158,11,.35);background:var(--warn-bg);color:var(--warn)}}
.badge.private{{border-color:rgba(59,130,246,.35);background:var(--accent-bg);color:#93c5fd}}
.metrics{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-top:20px}}
.metric{{background:var(--surface-card);border:1px solid var(--border);border-radius:12px;padding:14px;min-width:0}}
.metric span{{display:block;color:var(--muted);font-size:12px;font-weight:500}}
.metric strong{{display:block;font-size:20px;font-weight:800;margin:4px 0 2px;color:var(--text);overflow:hidden;text-overflow:ellipsis}}
.metric small{{display:block;color:var(--muted);font-size:11px}}
.cat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-top:14px}}
.cat-card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;display:flex;flex-direction:column;justify-content:space-between;gap:10px}}
.cat-card-header{{font-size:14px;font-weight:700;display:flex;align-items:center;gap:8px}}
.cat-icon{{font-size:18px}}
.cat-card-size{{font-size:20px;font-weight:800;color:var(--good)}}
.cat-card-desc{{font-size:12px;color:var(--muted);margin:0;line-height:1.4}}
.cat-card-footer{{display:flex;justify-content:space-between;align-items:center;border-top:1px dashed var(--border);padding-top:8px;font-size:11.5px;color:var(--muted)}}
section{{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:22px;margin:18px 0;box-shadow:0 4px 18px rgba(0,0,0,.18)}}
.count{{font-size:11.5px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:2px 8px}}
.tablewrap{{overflow:auto;max-height:760px;border:1px solid var(--border);border-radius:10px;background:var(--surface-card)}}
table{{border-collapse:collapse;width:100%;min-width:900px;font-size:13px}}
th{{position:sticky;top:0;background:#162032;color:#94a3b8;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;font-weight:700;border-bottom:1px solid var(--border);z-index:1}}
th,td{{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;max-width:480px;word-break:break-word}}
tr:hover td{{background:rgba(255,255,255,.02)}}
.mono{{font-family:Consolas,ui-monospace,monospace;font-size:12px;color:#cbd5e1}}
.empty,.footnote{{color:var(--muted);font-size:12px}}
.safe{{color:var(--good);font-weight:600}}
.warn{{color:var(--warn);font-weight:600}}
.lists{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
li{{margin:6px 0;color:#cbd5e3;font-size:13px}}
.warning{{border-left:3px solid var(--warn);background:#241d0b;padding:12px 16px;border-radius:9px;color:#fef3c7;font-size:13px}}
footer{{padding:20px 4px;color:var(--muted);font-size:12px}}
@media(max-width:1100px){{.metrics{{grid-template-columns:repeat(3,1fr)}}.lists{{grid-template-columns:1fr}}}}
@media(max-width:700px){{.metrics{{grid-template-columns:1fr}}}}
@media print{{:root{{color-scheme:light}}body{{background:white;color:#111}}main{{max-width:none;padding:0}}header,section{{box-shadow:none;background:white;border-color:#bbb;break-inside:avoid}}p,.empty,.footnote,footer,.metric span,.metric small{{color:#444}}th{{position:static;background:#eee;color:#111}}tr:nth-child(even) td{{background:#f6f6f6}}.tablewrap{{max-height:none;overflow:visible}}}}
</style>
</head>
<body><main>
<header>
<h1>ReconSpace audit report</h1>
<p>Static, portable evidence report. This file contains no scripts, network calls, cleanup controls, uninstall controls, or command-execution capability.</p>
<div class="meta"><span class="badge">READ-ONLY / NO EXECUTION</span>{privacy_badge}<span class="badge">v{html.escape(version)}</span><span class="badge">{html.escape(profile)} profile</span></div>
<p><strong>Root:</strong> <span class="mono">{_cell(root)}</span><br><strong>Completed:</strong> {_cell(generated)}<br><strong>Duration:</strong> {_cell(stats.get('duration_seconds'))} seconds</p>
<div class="metrics">{metric_html}</div>
</header>
{category_grid_html}
<section><h2>Coverage interpretation</h2><p class="warning">{_cell(health.get('interpretation') or 'Coverage is evidence quality, not a system health, malware, cleanliness, or safety score.', limit=3000)}</p><div class="lists"><div><h3>Coverage issues</h3><ul>{health_list}</ul></div><div><h3>Coverage strengths</h3><ul>{strength_list}</ul></div></div></section>
<section><h2>Report notes</h2><ul>{notes}</ul></section>
{''.join(sections)}
<footer>Generated from an explicitly exported ReconSpace report. Review original JSON evidence before making any change. ReconSpace did not perform cleanup.</footer>
</main></body></html>'''


def export_html_report(report: dict[str, Any], destination: str, *, max_rows: int = 250) -> Path:
    """Explicitly write a static HTML report to the caller-selected path."""
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(report, max_rows=max_rows), encoding="utf-8")
    return path
