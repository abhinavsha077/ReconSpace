from __future__ import annotations

import copy
import os
import re
from typing import Any


_WINDOWS_VOLUME_ROOT = re.compile(r"^[A-Za-z]:[\\/]*$")
_UNC_SHARE_ROOT = re.compile(r"^\\\\[^\\/]+[\\/][^\\/]+[\\/]*$")
_POSIX_ROOT = re.compile(r"^/+$")
_SENSITIVE_VALUE_KEYS = {
    "computername", "computer_name", "hostname", "host_name", "node",
    "username", "user_name", "user", "current_user",
}
_SECRET_OPTION_NAMES = (
    "password", "passwd", "pwd", "token", "access-token", "access_token",
    "api-key", "api_key", "apikey", "secret", "client-secret", "client_secret",
    "private-key", "private_key", "authorization",
)


def _is_bare_root(path: str) -> bool:
    value = str(path or "").strip()
    return bool(_WINDOWS_VOLUME_ROOT.fullmatch(value) or _POSIX_ROOT.fullmatch(value))


def _collect_strings(value: Any, output: list[str], *, limit: int = 25000) -> None:
    if len(output) >= limit:
        return
    if isinstance(value, str):
        output.append(value)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, output, limit=limit)
            if len(output) >= limit:
                break
    elif isinstance(value, dict):
        for item in value.values():
            _collect_strings(item, output, limit=limit)
            if len(output) >= limit:
                break


def _collect_keyed_identifiers(value: Any, output: set[str]) -> None:
    if isinstance(value, list):
        for item in value:
            _collect_keyed_identifiers(item, output)
    elif isinstance(value, dict):
        for key, item in value.items():
            key_normalized = str(key).strip().lower().replace("-", "_")
            if key_normalized in _SENSITIVE_VALUE_KEYS and isinstance(item, str):
                candidate = item.strip()
                if len(candidate) >= 3 and not any(ch in candidate for ch in "\\/"):
                    output.add(candidate)
            _collect_keyed_identifiers(item, output)


def _report_derived_replacements(report: dict[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    strings: list[str] = []
    _collect_strings(report, strings)

    # Profile prefixes are collected before the scan-root replacement so a scan
    # rooted exactly at C:\\Users\\Alice is represented as %USERPROFILE% rather
    # than the less informative <SCAN_ROOT>.
    root = str((report.get("stats") or {}).get("root") or "").strip().rstrip("\\/")

    profile_prefixes: set[str] = set()
    unc_hosts: set[str] = set()
    for text in strings:
        # Works even when the report came from a different machine than the one
        # running redaction; no reliance on the local USERPROFILE is required.
        for match in re.finditer(r"(?i)([A-Z]:[\\/]Users[\\/][^\\/\s\"']+)", text):
            profile_prefixes.add(match.group(1))
        for match in re.finditer(r"(?i)([A-Z]:[\\/]Documents and Settings[\\/][^\\/\s\"']+)", text):
            profile_prefixes.add(match.group(1))
        for match in re.finditer(r"(?i)(/(?:home|Users)/[^/\s\"']+)", text):
            profile_prefixes.add(match.group(1))
        for match in re.finditer(r"\\\\([^\\/\s]+)[\\/]", text):
            unc_hosts.add(match.group(1))

    for prefix in profile_prefixes:
        pairs.append((prefix, "%USERPROFILE%" if re.match(r"(?i)^[A-Z]:", prefix) else "~"))

    # A scan rooted below the volume/filesystem root often contains a project,
    # customer or case name. Preserve useful relative paths while replacing that
    # prefix, unless a more specific profile replacement already covers it.
    if root and not _is_bare_root(root) and root.casefold() not in {x.casefold() for x in profile_prefixes}:
        pairs.append((root, "<SCAN_ROOT>"))

    for host in unc_hosts:
        pairs.append((f"\\\\{host}\\", "\\\\<HOST>\\"))

    identifiers: set[str] = set()
    _collect_keyed_identifiers(report, identifiers)
    for identifier in identifiers:
        pairs.append((identifier, "<LOCAL_ID>"))

    return pairs


def _default_replacements() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    candidates = [
        (os.environ.get("USERPROFILE", ""), "%USERPROFILE%"),
        (os.environ.get("HOME", ""), "~"),
        (os.environ.get("USERNAME", ""), "<USER>"),
        (os.environ.get("COMPUTERNAME", ""), "<COMPUTER>"),
    ]
    for source, replacement in candidates:
        source = str(source or "").strip().rstrip("\\/")
        if source and len(source) >= 3 and not _is_bare_root(source):
            pairs.append((source, replacement))
    return pairs


def _deduplicate_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    output: list[tuple[str, str]] = []
    seen: set[str] = set()
    # Longest first so a complete scan/profile prefix is handled before a user or
    # computer token contained inside it.
    for source, replacement in sorted(pairs, key=lambda x: len(x[0]), reverse=True):
        source = str(source or "")
        if len(source) < 3:
            continue
        key = source.casefold()
        if key in seen:
            continue
        seen.add(key)
        output.append((source, replacement))
    return output


def _replace_case_insensitive(value: str, source: str, replacement: str) -> str:
    # Windows path evidence is case-insensitive. Regex substitution also handles
    # reports produced with casing different from the current environment.
    return re.sub(re.escape(source), lambda _m: replacement, value, flags=re.IGNORECASE)


def _replace_text(value: str, pairs: list[tuple[str, str]]) -> str:
    out = value
    for source, replacement in pairs:
        out = _replace_case_insensitive(out, source, replacement)

    # Last-resort path-segment anonymization catches profiles nested under a
    # nonstandard scan root (for example an offline mounted Windows image).
    out = re.sub(
        r"(?i)([\\/]Users[\\/])([^\\/\s\"']+)",
        lambda m: f"{m.group(1)}<USER>",
        out,
    )
    out = re.sub(
        r"(?i)([\\/]Documents and Settings[\\/])([^\\/\s\"']+)",
        lambda m: f"{m.group(1)}<USER>",
        out,
    )

    # Reports can contain process command lines, task arguments, service command
    # lines and URLs. Remove common secret-bearing forms without trying to parse
    # every application's bespoke syntax. This remains a best-effort sharing aid,
    # not a formal secrecy or anonymization guarantee.
    out = re.sub(
        r"(?i)(\bAuthorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+\-/=]+",
        r"\1<REDACTED_SECRET>",
        out,
    )
    out = re.sub(
        r"(?i)(\bBearer\s+)[A-Za-z0-9._~+\-/=]+",
        r"\1<REDACTED_SECRET>",
        out,
    )
    option_names = "|".join(re.escape(name) for name in _SECRET_OPTION_NAMES)
    out = re.sub(
        rf"(?i)((?:--?|/)(?:{option_names})\s*(?:=|:)\s*)([^\s,;]+)",
        r"\1<REDACTED_SECRET>",
        out,
    )
    out = re.sub(
        rf"(?i)((?:--?|/)(?:{option_names})\s+)([^\s,;]+)",
        r"\1<REDACTED_SECRET>",
        out,
    )
    out = re.sub(
        rf"(?i)(\b(?:{option_names})\b\s*(?:=|:)\s*)([^\s,;]+)",
        r"\1<REDACTED_SECRET>",
        out,
    )
    out = re.sub(
        r"(?i)(://[^:/\s]+:)[^@/\s]+(@)",
        r"\1<REDACTED_SECRET>\2",
        out,
    )
    return out


def redact_report(report: dict[str, Any], extra_replacements: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    """Return a redacted deep copy suitable for sharing.

    This does not mutate the source report. It replaces report-derived scan-root,
    user-profile, hostname and username identifiers, common command-line/URL
    secret forms, and local environment values while retaining sizes, hashes,
    classifications and useful relative paths.
    It is best-effort, not a formal anonymization guarantee.
    """
    pairs = _deduplicate_pairs(
        list(extra_replacements or [])
        + _report_derived_replacements(report)
        + _default_replacements()
    )

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return _replace_text(value, pairs)
        if isinstance(value, list):
            return [walk(x) for x in value]
        if isinstance(value, dict):
            return {str(k): walk(v) for k, v in value.items()}
        return value

    output = walk(copy.deepcopy(report))
    if isinstance(output, dict):
        output["privacy_redacted"] = True
        output["privacy_note"] = (
            "Best-effort report-derived identifier redaction; review before sharing because "
            "application names, filenames, hashes and unrecognized free-form evidence can still be sensitive."
        )
        output["privacy_redaction_summary"] = {
            "replacement_rules_applied": len(pairs),
            "scan_root_prefix_redaction": bool(
                str((report.get("stats") or {}).get("root") or "").strip()
                and not _is_bare_root(str((report.get("stats") or {}).get("root") or "").strip())
            ),
            "common_secret_value_scrubbing": True,
            "formal_anonymization_guarantee": False,
        }
    return output
