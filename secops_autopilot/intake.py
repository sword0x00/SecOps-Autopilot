"""Stage 1 — vulnerability intake.

Normalizes a CVE into one record using Tenable's CVE -> plugin mapping and the
per-asset findings. Everything is sourced; nothing is filled in from memory.
"""

from __future__ import annotations

import re
from typing import Any

from .errors import IntakeError
from .models import Finding, PluginHit, SourceRef, VulnerabilityRecord
from .scoring import cisa_known_exploited, exploit_signals
from .util import (
    dedupe,
    extract_kb_refs,
    extract_refs,
    severity_label,
    utc_now,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def normalize_cve(value: str) -> str:
    candidate = (value or "").strip().upper()
    if not CVE_RE.match(candidate):
        raise IntakeError(
            f"{value!r} is not a CVE identifier. Expected the form CVE-YYYY-NNNN."
        )
    return candidate


def _target_findings(cve: str, findings: list[Finding]) -> tuple[list[Finding], int]:
    selected: list[Finding] = []
    excluded = 0
    for finding in findings:
        cves = {item.upper() for item in finding.cve if item}
        if cves and cve not in cves:
            excluded += 1
            continue
        selected.append(finding)
    return selected, excluded


def _max_by(findings: list[Finding], attr: str) -> Finding | None:
    valued = [f for f in findings if getattr(f, attr) is not None]
    if not valued:
        return None
    return max(valued, key=lambda f: getattr(f, attr))


def _severity(findings: list[Finding]) -> tuple[float | None, str, float | None, str | None, float | None, str | None]:
    cvss3 = [f for f in findings if f.cvss3_base is not None]
    if cvss3:
        best = max(cvss3, key=lambda f: f.cvss3_base or 0)
        return (
            best.cvss3_base,
            "tenable:cvss3_base_score",
            best.cvss3_base,
            best.cvss3_vector,
            None,
            None,
        )
    cvss2 = [f for f in findings if f.cvss2_base is not None]
    if cvss2:
        best = max(cvss2, key=lambda f: f.cvss2_base or 0)
        return (
            best.cvss2_base,
            "tenable:cvss_base_score",
            None,
            None,
            best.cvss2_base,
            best.cvss2_vector,
        )
    return None, "unknown", None, None, None, None


def _patch_state(findings: list[Finding]) -> tuple[bool | None, list[str], list[str]]:
    flags = [f.has_patch for f in findings if f.has_patch is not None]
    if any(flags):
        available: bool | None = True
    elif flags and all(flag is False for flag in flags):
        available = False
    else:
        available = None
    refs: list[str] = []
    text_parts: list[str] = []
    for finding in findings:
        text_parts.extend(
            [
                finding.plugin_name,
                finding.solution,
                finding.output,
                finding.synopsis,
                " ".join(finding.see_also),
            ]
        )
    combined = " ".join(text_parts)
    extracted = extract_refs(combined)
    for kind, values in extracted.items():
        if kind == "cve":
            continue
        refs.extend(values)
    refs.extend(extract_kb_refs(combined))
    return available, dedupe(refs), flags


def build_vulnerability(
    cve: str,
    hits: list[PluginHit],
    findings: list[Finding],
    sources: list[SourceRef],
    *,
    date_range: int,
) -> VulnerabilityRecord:
    target = normalize_cve(cve)
    selected, excluded = _target_findings(target, findings)
    severity_cvss, severity_source, cvss3, cvss3_vector, cvss2, cvss2_vector = _severity(selected)
    signals = exploit_signals(selected)
    exploited_flags = [
        f.exploited_by_malware for f in selected if f.exploited_by_malware is not None
    ]
    if exploited_flags:
        exploited_in_wild: bool | None = any(exploited_flags) or any(
            cisa_known_exploited(f) for f in selected
        )
    elif selected:
        exploited_in_wild = None
    else:
        exploited_in_wild = None

    patch_available, patch_refs, patch_flags = _patch_state(selected)
    published_values = [
        f.vuln_publication_date for f in selected if f.vuln_publication_date
    ]
    published = min(published_values) if published_values else None

    top = hits[0] if hits else None
    if top:
        title = top.plugin_name
        title_source = "Tenable plugin name (highest severity / VPR match)"
    elif selected:
        best = max(selected, key=lambda f: (f.severity or 0, f.vpr or 0))
        title = best.plugin_name
        title_source = "Tenable finding plugin name"
    else:
        title = f"{target} (no Tenable plugin match in the selected window)"
        title_source = "CVE identifier only"

    aliases: list[str] = []
    alias_refs = extract_refs(" ".join(hit.plugin_name for hit in hits))
    aliases.extend(alias_refs.get("msrc", []))
    aliases.extend(alias_refs.get("advisory", []))

    products: list[dict[str, Any]] = []
    cpes = dedupe(cpe for finding in selected for cpe in finding.cpe)
    for cpe in cpes:
        plugin_ids = sorted(
            {f.plugin_id for f in selected if cpe in f.cpe}
        )
        products.append(
            {
                "cpe": cpe,
                "plugin_ids": plugin_ids,
                "versions": "unknown — Tenable plugin detection, not an NVD version range",
            }
        )
    if not products:
        families = dedupe(f.family for f in selected)
        for family in families:
            products.append(
                {
                    "family": family,
                    "plugin_ids": sorted(
                        {f.plugin_id for f in selected if f.family == family}
                    ),
                    "versions": "unknown",
                }
            )

    conflicts: list[str] = []
    if True in patch_flags and False in patch_flags:
        conflicts.append(
            "Tenable plugins disagree on patch availability "
            f"({sum(1 for flag in patch_flags if flag)} true / "
            f"{sum(1 for flag in patch_flags if flag is False)} false)."
        )

    notes = [
        f"Tenable workbench window: last {date_range} days.",
        "Severity is recorded as published by Tenable; the pipeline does not "
        "re-score CVSS.",
    ]
    if excluded:
        notes.append(
            f"{excluded} exported finding(s) were excluded because their CVE list did "
            "not contain the target CVE."
        )
    if hits and not selected:
        notes.append(
            "Tenable matched plugins for this CVE, but no per-asset finding was "
            "returned by the export. Exposure is therefore unresolved."
        )
    if len(signals) > 1:
        notes.append("Multiple exploit signals present: " + ", ".join(signals))

    confidence = "high" if selected else "medium" if hits else "low"
    confidence_reason = (
        f"{len(selected)} finding(s) across {len({f.asset.uuid for f in selected})} asset(s)"
        if selected
        else f"{len(hits)} plugin(s) matched, but no finding was exported"
        if hits
        else "no Tenable plugin matched the CVE in the selected window"
    )

    if not sources:
        sources = [
            SourceRef(
                type="tenable",
                ref="workbench:/workbenches/vulnerabilities",
                note="CVE -> plugin mapping",
                retrieved=utc_now(),
            )
        ]

    return VulnerabilityRecord(
        id=target,
        title=title,
        title_source=title_source,
        aliases=dedupe(aliases),
        published=published,
        severity_cvss=severity_cvss,
        severity_source=severity_source,
        cvss3_base=cvss3,
        cvss3_vector=cvss3_vector,
        cvss2_base=cvss2,
        cvss2_vector=cvss2_vector,
        exploited_in_wild=exploited_in_wild,
        exploit_signals=signals,
        patch_available=patch_available,
        patch_refs=patch_refs,
        affected_products=products,
        cpe=list(cpes),
        plugin_hits=hits,
        affected_asset_count=len({f.asset.uuid for f in selected}),
        affected_finding_count=len(selected),
        sources=sources,
        confidence=confidence,
        confidence_reason=confidence_reason,
        conflicts=conflicts,
        notes=notes,
    )


def severity_text(record: VulnerabilityRecord) -> str:
    if record.severity_cvss is None:
        return "unknown"
    return f"{record.severity_cvss:.1f}"


__all__ = ["build_vulnerability", "normalize_cve", "severity_text", "severity_label"]
