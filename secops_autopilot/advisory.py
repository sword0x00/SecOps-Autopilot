"""Verified advisory metadata and version-range evaluation.

Tenable answers "which assets have a finding?" It does not always answer "what
is the fixed version for this runtime branch?" and it does not carry vendor
support status. This module accepts a small JSON advisory record, validates it,
merges it into the normalized vulnerability, and evaluates runtime versions
found in CPE data.

The engine does not fetch advisories itself. A human (or a validation scenario)
supplies the advisory file and its provenance; the engine records the source URL,
retrieval time, and verification status. If the provenance does not say
``verified``, the report says so and the data is treated as unverified.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .errors import ConfigError
from .models import Finding, SourceRef, VulnerabilityRecord
from .util import dedupe, utc_now

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
RANGE_TOKEN_RE = re.compile(r"(<=|>=|<|>|=)?\s*v?([0-9][0-9A-Za-z.\-+]*)")
VERSION_RE = re.compile(r"\d+")


def load_advisory(path: str | Path) -> dict[str, Any]:
    advisory_path = Path(path).expanduser()
    if not advisory_path.is_file():
        raise ConfigError(f"advisory file not found: {advisory_path}")
    try:
        data = json.loads(advisory_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"advisory {advisory_path} is not valid JSON: {exc}") from exc
    validated = validate_advisory(data, source=str(advisory_path))
    validated["_path"] = str(advisory_path)
    return validated


def validate_advisory(data: Any, *, source: str = "advisory") -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must be a JSON object")
    for key in ("id", "title", "source", "url", "affected"):
        if not data.get(key):
            raise ConfigError(f"{source} is missing required field {key!r}")
    if not isinstance(data["affected"], list) or not data["affected"]:
        raise ConfigError(f"{source} must contain a non-empty 'affected' list")
    for index, entry in enumerate(data["affected"]):
        if not isinstance(entry, dict):
            raise ConfigError(f"{source} affected[{index}] must be an object")
        if not entry.get("product") or not entry.get("range"):
            raise ConfigError(
                f"{source} affected[{index}] must have 'product' and 'range'"
            )
    provenance = data.get("provenance") or {}
    if provenance.get("status") == "verified":
        for key in ("source_url", "retrieved_at"):
            if not provenance.get(key):
                raise ConfigError(
                    f"{source} claims verified provenance but has no {key!r}"
                )
    data.setdefault("cve", data["id"] if CVE_RE.match(str(data["id"])) else None)
    data.setdefault("aliases", [])
    data.setdefault("mitigations", [])
    data.setdefault("references", [])
    data.setdefault("provenance", {"status": "provided", "source": source})
    return data


def advisory_cves(advisory: dict[str, Any]) -> set[str]:
    values = [advisory.get("id"), advisory.get("cve"), *(advisory.get("aliases") or [])]
    return {
        str(value).upper()
        for value in values
        if value and str(value).upper().startswith("CVE-")
    }


def merge_advisory(
    record: VulnerabilityRecord, advisory: dict[str, Any]
) -> VulnerabilityRecord:
    """Merge advisory metadata without silently overwriting scanner facts.

    Conflicts are recorded. A verified advisory that names a fixed version is
    enough to set ``patch_available=True`` even when the scanner's plugin flag is
    missing; if the scanner says ``False``, the conflict is preserved for a human.
    """
    if record.id.upper() not in advisory_cves(advisory):
        raise ConfigError(
            f"advisory {advisory.get('id')} does not cover target {record.id}; "
            f"advisory CVEs: {sorted(advisory_cves(advisory)) or 'none'}"
        )
    record.advisory = {
        key: value for key, value in advisory.items() if not key.startswith("_")
    }
    provenance = dict(advisory.get("provenance") or {})
    provenance.setdefault("status", "provided")
    provenance.setdefault("source", advisory.get("source"))
    provenance.setdefault("source_url", advisory.get("url"))
    provenance.setdefault("retrieved_at", utc_now())
    record.provenance = [provenance]

    severity = advisory.get("severity")
    if record.published is None and advisory.get("published"):
        record.published = str(advisory["published"])
    if record.severity_cvss is None and isinstance(severity, (int, float)):
        record.severity_cvss = float(severity)
        record.severity_source = f"advisory:{advisory.get('source')}"
    elif (
        isinstance(severity, (int, float))
        and record.severity_cvss is not None
        and abs(float(severity) - float(record.severity_cvss)) > 0.05
    ):
        record.notes.append(
            "Advisory severity "
            f"{severity} ({advisory.get('severity_system') or 'unspecified system'}) "
            f"differs from scanner severity {record.severity_cvss}; both are retained."
        )

    fixed = [
        {
            "product": entry.get("product"),
            "branch": entry.get("branch"),
            "range": entry.get("range"),
            "fixed": entry.get("fixed"),
            "support": entry.get("support") or "unknown",
            "source": advisory.get("source"),
        }
        for entry in advisory.get("affected") or []
        if entry.get("fixed")
    ]
    record.fixed_versions = fixed
    if fixed:
        if record.patch_available is False:
            record.conflicts.append(
                "Scanner reports no patch, but advisory "
                f"{advisory.get('source')} lists fixed version(s): "
                + ", ".join(str(item["fixed"]) for item in fixed)
            )
        record.patch_available = True
        record.patch_refs = dedupe(
            [
                *record.patch_refs,
                *[
                    f"{item['product']} {item['fixed']}"
                    for item in fixed
                ],
                *[str(ref) for ref in advisory.get("references") or []],
            ]
        )
    record.mitigation_steps = list(advisory.get("mitigations") or [])
    record.aliases = dedupe(
        [*record.aliases, *(advisory.get("aliases") or [])]
    )
    record.sources.append(
        SourceRef(
            type="advisory",
            ref=str(advisory.get("url")),
            note=(
                f"{advisory.get('source')} ({provenance.get('status')}); "
                f"{advisory.get('title')}"
            ),
            retrieved=str(provenance.get("retrieved_at") or utc_now()),
        )
    )
    record.notes.append(
        f"Advisory metadata supplied: {advisory.get('source')} "
        f"[{provenance.get('status')}]. Fixed-version and mitigation statements "
        "are attributed to that source."
    )
    return record


def parse_cpe(cpe: str) -> dict[str, str] | None:
    text = str(cpe or "").strip()
    if not text:
        return None
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")
        if len(parts) < 6:
            return None
        return {
            "part": parts[2],
            "vendor": parts[3].lower(),
            "product": parts[4].lower(),
            "version": parts[5],
        }
    if text.startswith("cpe:/"):
        parts = text[5:].split(":")
        if len(parts) < 3:
            return None
        return {
            "part": parts[0],
            "vendor": parts[1].lower(),
            "product": parts[2].lower(),
            "version": parts[3] if len(parts) > 3 else "",
        }
    return None


def version_key(value: Any) -> tuple[int, ...] | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in {"*", "-"}:
        return None
    core = text.split("+", 1)[0].split("-", 1)[0]
    parts = VERSION_RE.findall(core)
    if not parts:
        return None
    return tuple(int(part) for part in parts[:5])


def compare_versions(left: Any, right: Any) -> int | None:
    left_key, right_key = version_key(left), version_key(right)
    if left_key is None or right_key is None:
        return None
    length = max(len(left_key), len(right_key))
    left_key = left_key + (0,) * (length - len(left_key))
    right_key = right_key + (0,) * (length - len(right_key))
    return (left_key > right_key) - (left_key < right_key)


def version_in_range(version: Any, expression: str | None) -> bool | None:
    if not expression:
        return None
    if version_key(version) is None:
        return None
    tokens = RANGE_TOKEN_RE.findall(str(expression))
    if not tokens:
        return None
    for operator, boundary in tokens:
        comparison = compare_versions(version, boundary)
        if comparison is None:
            return None
        operator = operator or "="
        if operator == ">" and not comparison > 0:
            return False
        if operator == ">=" and not comparison >= 0:
            return False
        if operator == "<" and not comparison < 0:
            return False
        if operator == "<=" and not comparison <= 0:
            return False
        if operator == "=" and comparison != 0:
            return False
    return True


def runtime_matches(
    findings: Iterable[Finding], advisory: dict[str, Any] | None
) -> list[dict[str, Any]]:
    if not advisory:
        return []
    entries = advisory.get("affected") or []
    matches: list[dict[str, Any]] = []
    for finding in findings:
        for cpe in finding.cpe or []:
            parsed = parse_cpe(cpe)
            if not parsed:
                continue
            for entry in entries:
                if not _product_matches(parsed, entry):
                    continue
                in_range = version_in_range(parsed.get("version"), entry.get("range"))
                matches.append(
                    {
                        "asset_uuid": finding.asset.uuid,
                        "cpe": cpe,
                        "product": entry.get("product"),
                        "vendor": entry.get("vendor"),
                        "version": parsed.get("version") or None,
                        "range": entry.get("range"),
                        "fixed": entry.get("fixed") or None,
                        "branch": entry.get("branch"),
                        "support": entry.get("support") or "unknown",
                        "in_range": in_range,
                        "plugin_id": finding.plugin_id,
                        "entry": entry,
                    }
                )
    # Deduplicate identical product/version/entry matches from multiple plugins.
    seen: set[tuple[Any, ...]] = set()
    unique: list[dict[str, Any]] = []
    for item in matches:
        key = (
            item.get("product"),
            item.get("version"),
            item.get("range"),
            item.get("fixed"),
            item.get("plugin_id"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def fixed_version_for_match(match: dict[str, Any]) -> str | None:
    return match.get("fixed")


def advisory_summary(advisory: dict[str, Any] | None) -> dict[str, Any] | None:
    if not advisory:
        return None
    return {
        "id": advisory.get("id"),
        "title": advisory.get("title"),
        "source": advisory.get("source"),
        "url": advisory.get("url"),
        "published": advisory.get("published"),
        "severity": advisory.get("severity"),
        "severity_system": advisory.get("severity_system"),
        "provenance": advisory.get("provenance"),
        "affected_products": sorted(
            {
                str(entry.get("product"))
                for entry in advisory.get("affected") or []
                if entry.get("product")
            }
        ),
        "fixed_versions": [
            entry.get("fixed")
            for entry in advisory.get("affected") or []
            if entry.get("fixed")
        ],
    }


def _product_matches(parsed: dict[str, str], entry: dict[str, Any]) -> bool:
    aliases = {
        str(value).lower()
        for value in (
            entry.get("product"),
            entry.get("cpe_product"),
            *(entry.get("aliases") or []),
        )
        if value
    }
    if parsed.get("product") not in aliases:
        return False
    entry_vendor = str(entry.get("vendor") or "").lower()
    cpe_vendor = str(parsed.get("vendor") or "").lower()
    if entry_vendor and cpe_vendor and entry_vendor not in {cpe_vendor, parsed.get("product")}:
        return False
    return True


__all__ = [
    "load_advisory",
    "validate_advisory",
    "merge_advisory",
    "advisory_cves",
    "advisory_summary",
    "parse_cpe",
    "compare_versions",
    "version_key",
    "version_in_range",
    "runtime_matches",
]
