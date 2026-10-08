from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ai_advisor import (
    AIProviderConfig,
    ai_review_to_json,
    build_advisor_prompt,
    query_ai_advisor,
    render_ai_review_markdown,
)
from .compare import compare_reports, load_report
from .doctor import doctor
from .engine import AuditConfig, PROFILE_DEFAULTS, run_audit
from .exporter import export_csv_bundle, export_html_report
from .plan import plan_json, plan_markdown
from .runner import execute_approved_plan
from .privacy import redact_report
from .query import query_report, query_to_csv, query_to_table
from .report import report_json, report_markdown, write_json
from .rules import BUILTIN_RULE_PACK, load_rule_packs
from .trend import analyze_trend
from .validation import validate_report
from .webapp import serve

MAX_DUPLICATE_MB = 1024 * 1024


def _duplicate_mb(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a whole number of MiB") from exc
    if not 1 <= number <= MAX_DUPLICATE_MB:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_DUPLICATE_MB:,} MiB")
    return number


def _port(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a whole-number TCP port") from exc
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return number


def _progress(p: dict) -> None:
    phase = p.get("phase", "")
    files = p.get("files_seen")
    if files is not None:
        print(
            f"\r[{phase}] {files:,} files | {p.get('directories_seen', 0):,} dirs | {p.get('path', '')[:70]}",
            end="",
            file=sys.stderr,
            flush=True,
        )
    elif phase in {"duplicates", "duplicate_hashing"}:
        stage = p.get("stage")
        if stage:
            print(f"\r[{phase}:{stage}] {p.get('path', '')[:70]}", end="", file=sys.stderr, flush=True)
        else:
            print(f"\r[{phase}] {p.get('done', 0):,}/{p.get('total', 0):,} {p.get('path', '')[:70]}", end="", file=sys.stderr, flush=True)
    elif p.get("item") and p.get("total"):
        print(f"\r[{phase}] [{p.get('done', 0)}/{p.get('total')}] {p.get('item', '').replace('_', ' ')[:50]}", end="", file=sys.stderr, flush=True)
    elif p.get("batch") and p.get("total_batches"):
        print(f"\r[{phase}] [batch {p.get('batch')}/{p.get('total_batches')}] {p.get('detail', '')[:50]}", end="", file=sys.stderr, flush=True)
    elif p.get("detail"):
        print(f"\n[{phase}] {p.get('detail')}", file=sys.stderr, flush=True)
    else:
        print(f"\n[{phase}]", file=sys.stderr, flush=True)


def _write_requested(path: str, content: str) -> None:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    print(destination)


def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="reconspace",
        description="Read-only Windows storage, software, ownership and tooling reconnaissance.",
    )
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Open the local read-only dashboard")
    serve_p.add_argument("--port", type=_port, default=8765)
    serve_p.add_argument("--no-browser", action="store_true")

    scan_p = sub.add_parser("scan", help="Run a terminal audit")
    scan_p.add_argument("--root", default="C:\\")
    scan_p.add_argument("--profile", choices=sorted(PROFILE_DEFAULTS), default="deep")
    scan_p.add_argument("--duplicate-min-mb", type=_duplicate_mb, default=None, help="Override profile duplicate minimum threshold")
    scan_p.add_argument("--duplicate-max-mb", type=_duplicate_mb, default=None, help="Override profile duplicate maximum hash size")
    scan_p.add_argument("--hash-stateful-files", action="store_true", help="Expert opt-in: hash VM/forensic/dump formats for duplicates (heavy I/O)")
    scan_p.add_argument("--no-duplicates", action="store_true", default=False)
    scan_p.add_argument("--no-deep-windows", action="store_true", default=False)
    scan_p.add_argument("--no-processes", action="store_true", default=False, help="Skip active-process context")
    scan_p.add_argument("--no-signatures", action="store_true", default=False, help="Skip local Authenticode inspection")
    scan_p.add_argument("--no-permissions", action="store_true", default=False, help="Skip selected path owner/ACL summaries")
    scan_p.add_argument("--no-prefetch", action="store_true", default=False, help="Skip Windows Prefetch filename/timestamp metadata")
    scan_p.add_argument("--signature-hashes", action="store_true", default=False, help="Also calculate SHA-256 for selected persistence targets (local I/O only)")
    scan_p.add_argument("--exclude", action="append", default=[], help="Explicit path to skip; repeatable. Default: none")
    scan_p.add_argument("--keep", action="append", default=[], help="Protect a path from reclaim accounting while keeping it visible; repeatable")
    scan_p.add_argument("--rule-pack", action="append", default=[], help="Additional metadata-only JSON rule pack; repeatable")
    scan_p.add_argument("--no-builtin-rules", action="store_true", default=False, help="Disable the built-in metadata-only intelligence rules")
    scan_p.add_argument("--json", dest="json_path", help="Explicitly export JSON to this path")
    scan_p.add_argument("--json-stdout", action="store_true", help="Print complete JSON to stdout instead of Markdown")

    compare_p = sub.add_parser("compare", help="Compare two explicitly exported ReconSpace JSON reports")
    compare_p.add_argument("old_report")
    compare_p.add_argument("new_report")
    compare_p.add_argument("--pretty", action="store_true")

    trend_p = sub.add_parser("trend", help="Analyze growth across two or more explicitly exported reports")
    trend_p.add_argument("reports", nargs="+")
    trend_p.add_argument("--top-paths", type=int, default=50)
    trend_p.add_argument("--pretty", action="store_true")
    trend_p.add_argument("--output", help="Explicitly write trend JSON to this path")

    query_p = sub.add_parser("query", help="Filter a report section with the ReconSpace query language")
    query_p.add_argument("report")
    query_p.add_argument("section")
    query_p.add_argument("--where", default="", help='Example: size>1GiB age>90d path:"node_modules"')
    query_p.add_argument("--format", choices=("table", "json", "csv"), default="table")
    query_p.add_argument("--limit", type=int, default=100)
    query_p.add_argument("--sort", default="", help="Field name; prefix with - for descending")
    query_p.add_argument("--columns", default="", help="Comma-separated output columns")
    query_p.add_argument("--output", help="Explicitly write query output to this path")

    rules_p = sub.add_parser("validate-rules", help="Validate a metadata-only JSON rule pack")
    rules_p.add_argument("rule_pack", nargs="?")
    rules_p.add_argument("--builtin", action="store_true", help="Show/validate the built-in pack")
    rules_p.add_argument("--pretty", action="store_true")

    plan_p = sub.add_parser("plan", help="Generate a plan-only approval/review document from an exported report")
    plan_p.add_argument("report")
    plan_p.add_argument("--json", action="store_true", help="Emit plan JSON instead of Markdown")

    doctor_p = sub.add_parser("doctor", help="Run a non-destructive ReconSpace/Windows collector readiness diagnostic")
    doctor_p.add_argument("--root", default="C:\\")
    doctor_p.add_argument("--pretty", action="store_true")

    csv_p = sub.add_parser("export-csv", help="Export CSV tables from an existing ReconSpace JSON report")
    csv_p.add_argument("report")
    csv_p.add_argument("destination")

    html_p = sub.add_parser("export-html", help="Export a static, self-contained, no-script HTML evidence report")
    html_p.add_argument("report")
    html_p.add_argument("output")
    html_p.add_argument("--max-rows", type=int, default=250, help="Maximum rows rendered per section (1-5000)")
    html_p.add_argument("--redact", action="store_true", help="Apply best-effort report redaction before rendering")

    validate_p = sub.add_parser("validate-report", help="Validate the structure and safety enums of an exported ReconSpace JSON report")
    validate_p.add_argument("report")
    validate_p.add_argument("--pretty", action="store_true")

    redact_p = sub.add_parser("redact", help="Create an explicitly requested, best-effort redacted copy of an existing report")
    redact_p.add_argument("report")
    redact_p.add_argument("output")

    exec_plan_p = sub.add_parser("execute-plan", help="Execute approved items from an audited ReconSpace plan manifest")
    exec_plan_p.add_argument("plan", help="Path to approval plan JSON file")
    exec_plan_p.add_argument("--dry-run", action="store_true", default=False, help="Simulate execution without modifying files")
    exec_plan_p.add_argument("--confirm", action="store_true", default=False, help="Explicit confirmation to execute actions")
    exec_plan_p.add_argument("--items", default="", help="Comma-separated item IDs to execute (e.g. RS-0001,RS-0002)")
    exec_plan_p.add_argument("--output", help="Optional path to write JSON execution audit log")

    ai_p = sub.add_parser("ai-review", help="Generate AI audit recommendations and review from an exported report")
    ai_p.add_argument("report", help="Path to exported ReconSpace JSON report")
    ai_p.add_argument("--provider", choices=("openai", "anthropic", "gemini", "ollama", "heuristic", "mock"), default="heuristic", help="AI provider (default: heuristic)")
    ai_p.add_argument("--api-key", default="", help="API key for selected cloud provider (or set via OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)")
    ai_p.add_argument("--model", default="", help="Model identifier override")
    ai_p.add_argument("--endpoint", default="", help="Custom HTTP endpoint override (e.g. for Ollama or LocalAI)")
    ai_p.add_argument("--no-redact", action="store_true", help="Opt out of automatic PII redaction (redaction is ON by default)")
    ai_p.add_argument("--prompt-only", action="store_true", help="Print sanitized prompt without making external API calls")
    ai_p.add_argument("--json", action="store_true", help="Output structured recommendations as JSON")
    ai_p.add_argument("--output", help="Optional path to write output (Markdown or JSON)")

    args = parser.parse_args()
    if (
        args.command == "scan"
        and args.duplicate_min_mb is not None
        and args.duplicate_max_mb is not None
        and args.duplicate_max_mb < args.duplicate_min_mb
    ):
        parser.error("--duplicate-max-mb must be greater than or equal to --duplicate-min-mb")
    if args.command in {None, "serve"}:
        serve("127.0.0.1", getattr(args, "port", 8765), not getattr(args, "no_browser", False))
        return

    if args.command == "doctor":
        print(json.dumps(doctor(args.root), indent=2 if args.pretty else None, ensure_ascii=False))
        return

    if args.command == "validate-report":
        result = validate_report(load_report(args.report))
        print(json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False))
        if not result.get("ok"):
            raise SystemExit(2)
        return

    if args.command == "validate-rules":
        if args.builtin or not args.rule_pack:
            packs = load_rule_packs((), include_builtin=True)
            raw = BUILTIN_RULE_PACK
        else:
            packs = load_rule_packs((args.rule_pack,), include_builtin=False)
            raw = None
        result = {
            "ok": True,
            "packs": [{"name": p.name, "version": p.version, "source": p.source, "rules": len(p.rules), "warnings": p.warnings} for p in packs],
            "builtin_pack": raw if args.builtin else None,
            "execution_capability": False,
        }
        print(json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False))
        return

    if args.command == "redact":
        data = redact_report(load_report(args.report))
        out = Path(args.output).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(out)
        return

    if args.command == "export-csv":
        paths = export_csv_bundle(load_report(args.report), args.destination)
        print("\n".join(str(p) for p in paths))
        return

    if args.command == "export-html":
        data = load_report(args.report)
        if args.redact:
            data = redact_report(data)
        print(export_html_report(data, args.output, max_rows=max(1, min(5000, args.max_rows))))
        return

    if args.command == "compare":
        result = compare_reports(load_report(args.old_report), load_report(args.new_report))
        print(json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False))
        return

    if args.command == "trend":
        result = analyze_trend([load_report(path) for path in args.reports], top_paths=max(1, args.top_paths))
        output = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
        if args.output:
            _write_requested(args.output, output)
        else:
            print(output)
        return

    if args.command == "query":
        result = query_report(load_report(args.report), args.section, args.where, limit=max(0, args.limit), sort=args.sort)
        columns = [x.strip() for x in args.columns.split(",") if x.strip()] or None
        if args.format == "json":
            output = json.dumps(result, indent=2, ensure_ascii=False)
        elif args.format == "csv":
            output = query_to_csv(result, columns)
        else:
            output = query_to_table(result, columns)
        if args.output:
            _write_requested(args.output, output)
        else:
            print(output)
        return

    if args.command == "plan":
        report_data = load_report(args.report)
        print(plan_json(report_data) if args.json else plan_markdown(report_data))
        return

    if args.command == "execute-plan":
        plan_path = Path(args.plan).expanduser().resolve()
        with open(plan_path, "r", encoding="utf-8") as f:
            plan_data = json.load(f)
        approved_ids = [x.strip() for x in args.items.split(",") if x.strip()] or None
        log_res = execute_approved_plan(
            plan_data,
            dry_run=args.dry_run or not args.confirm,
            confirm=args.confirm,
            approved_ids=approved_ids,
        )
        out_str = json.dumps(log_res, indent=2, ensure_ascii=False)
        if args.output:
            _write_requested(args.output, out_str)
        else:
            print(out_str)
        return

    if args.command == "ai-review":
        rep = load_report(args.report)
        if args.prompt_only:
            system_prompt, user_prompt, summary = build_advisor_prompt(rep, redact=not args.no_redact)
            combined = f"--- SYSTEM PROMPT ---\n{system_prompt}\n\n--- USER PROMPT ---\n{user_prompt}\n"
            if args.output:
                _write_requested(args.output, combined)
            else:
                print(combined)
            return

        cfg = AIProviderConfig(
            provider=args.provider,
            api_key=args.api_key,
            model=args.model,
            endpoint=args.endpoint,
        )
        res = query_ai_advisor(rep, config=cfg, redact=not args.no_redact)
        if args.json:
            out_text = json.dumps(ai_review_to_json(res), indent=2, ensure_ascii=False)
        else:
            out_text = render_ai_review_markdown(res)

        if args.output:
            _write_requested(args.output, out_text)
        else:
            print(out_text)
        if not res.ok:
            raise SystemExit(1)
        return

    report = run_audit(
        AuditConfig(
            root=args.root,
            profile=args.profile,
            duplicate_min_mb=args.duplicate_min_mb,
            duplicate_max_mb=args.duplicate_max_mb,
            hash_stateful_files=bool(args.hash_stateful_files),
            scan_duplicates=False if args.no_duplicates else None,
            deep_windows_inventory=False if args.no_deep_windows else None,
            excluded_paths=tuple(args.exclude),
            keep_paths=tuple(args.keep),
            rule_pack_paths=tuple(args.rule_pack),
            use_builtin_rules=not args.no_builtin_rules,
            collect_processes=False if args.no_processes else None,
            verify_signatures=False if args.no_signatures else None,
            collect_path_security=False if args.no_permissions else None,
            collect_prefetch=False if args.no_prefetch else None,
            signature_hashes=True if args.signature_hashes else None,
        ),
        progress=_progress,
    )
    print(file=sys.stderr)
    if args.json_path:
        path = write_json(report, args.json_path)
        print(f"Explicit JSON export written to: {path}", file=sys.stderr)
    print(report_json(report) if args.json_stdout else report_markdown(report))


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    try:
        _main()
    except KeyboardInterrupt:
        print("\nReconSpace audit interrupted by user.", file=sys.stderr)
        raise SystemExit(130) from None
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ReconSpace error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
