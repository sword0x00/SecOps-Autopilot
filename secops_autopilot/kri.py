"""KRI register: deterministic checks for KRI-01 … KRI-07.

The numeric KRI score in ``scoring.py`` answers "how risky is this asset for
this vulnerability?" This module answers a different, auditable question for
each asset: which of the organization's named key risk indicators are detected,
clear, unknown, or not applicable, and on what evidence?

The catalog is data: ``kri_catalog.json`` next to this module. Detection
functions are code, one per detector name.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from .errors import ConfigError
from .models import ControlPosture, KRIDetection, VulnerabilityRecord

DETECTED = "detected"
NOT_DETECTED = "not_detected"
UNKNOWN = "unknown"
NOT_APPLICABLE = "not_applicable"

DEFAULT_CATALOG_PATH = Path(__file__).with_name("kri_catalog.json")

Detector = Callable[
    [dict[str, Any], dict[str, Any], VulnerabilityRecord],
    tuple[str, list[str], dict[str, Any]],
]


def load_catalog(path: str | Path | None = None) -> dict[str, Any]:
    catalog_path = Path(path).expanduser() if path else DEFAULT_CATALOG_PATH
    if not catalog_path.is_file():
        raise ConfigError(f"KRI catalog not found: {catalog_path}")
    try:
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"KRI catalog {catalog_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("kris"), list):
        raise ConfigError(f"KRI catalog {catalog_path} must contain a 'kris' list")
    seen: set[str] = set()
    for item in data["kris"]:
        if not isinstance(item, dict):
            raise ConfigError(f"KRI catalog {catalog_path} contains a non-object entry")
        for key in ("id", "name", "detector", "severity"):
            if not item.get(key):
                raise ConfigError(f"KRI entry missing {key!r}: {item}")
        if item["id"] in seen:
            raise ConfigError(f"duplicate KRI id {item['id']} in {catalog_path}")
        seen.add(item["id"])
        if item["detector"] not in DETECTORS:
            raise ConfigError(
                f"KRI {item['id']} uses unknown detector {item['detector']!r}; "
                f"known detectors: {', '.join(sorted(DETECTORS))}"
            )
    data["_path"] = str(catalog_path)
    return data


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    parts = re.findall(r"\d+", str(value))
    if not parts:
        return None
    return tuple(int(part) for part in parts[:4])


def _compare_versions(installed: str | None, baseline: str | None) -> int | None:
    left, right = _version(installed), _version(baseline)
    if left is None or right is None:
        return None
    length = max(len(left), len(right))
    left = left + (0,) * (length - len(left))
    right = right + (0,) * (length - len(right))
    return (left > right) - (left < right)


def _missing_security_agent(
    ctx: dict[str, Any], params: dict[str, Any], _vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    control: ControlPosture = ctx["control"]
    signals = {
        "Tenable agent": control.agent_present,
        "EDR": control.edr_present,
        "AV": control.av_present,
    }
    present = [name for name, value in signals.items() if value is True]
    missing = [name for name, value in signals.items() if value is False]
    unknown = [name for name, value in signals.items() if value is None]
    detail = {"signals": signals}
    if present:
        return (
            NOT_DETECTED,
            ["Security control present: " + ", ".join(present)],
            detail,
        )
    if len(missing) == len(signals):
        return (
            DETECTED,
            ["No Tenable agent, EDR, or AV presence is recorded."],
            detail,
        )
    return (
        UNKNOWN,
        [
            f"Missing: {', '.join(missing) or 'none'}; "
            f"unknown: {', '.join(unknown) or 'none'}."
        ],
        detail,
    )


def _stale_control_version(
    ctx: dict[str, Any], params: dict[str, Any], _vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    control: ControlPosture = ctx["control"]
    pairs: list[tuple[str, str | None, str | None]] = []
    if control.av_present is not False or control.av_version or control.av_baseline_version:
        pairs.append(("AV", control.av_version, control.av_baseline_version))
    if control.edr_present is not False or control.edr_version or control.edr_baseline_version:
        pairs.append(("EDR", control.edr_version, control.edr_baseline_version))
    if not pairs:
        return NOT_APPLICABLE, ["No AV/EDR is present to compare to a baseline."], {}
    stale: list[str] = []
    unknown: list[str] = []
    clear: list[str] = []
    for label, installed, baseline in pairs:
        comparison = _compare_versions(installed, baseline)
        if comparison is None:
            unknown.append(f"{label}: installed/baseline version is incomplete or unparseable.")
        elif comparison < 0:
            stale.append(f"{label} {installed} < approved baseline {baseline}.")
        else:
            clear.append(f"{label} {installed} >= baseline {baseline}.")
    detail = {"pairs": [{"control": label, "installed": installed, "baseline": baseline} for label, installed, baseline in pairs]}
    if stale:
        return DETECTED, stale + clear, detail
    if unknown:
        return UNKNOWN, unknown + clear, detail
    return NOT_DETECTED, clear, detail


def _stale_threat_feed(
    ctx: dict[str, Any], params: dict[str, Any], _vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    control: ControlPosture = ctx["control"]
    sla = float(params.get("feed_sla_hours") or 24)
    feeds: list[tuple[str, float | None]] = []
    if control.av_present is not False:
        feeds.append(("AV signature", control.av_signature_age_hours))
    if control.edr_present is not False:
        feeds.append(("EDR feed", control.edr_feed_age_hours))
    if not feeds:
        return NOT_APPLICABLE, ["No AV/EDR is present to evaluate feed age."], {}
    stale: list[str] = []
    unknown: list[str] = []
    clear: list[str] = []
    for label, age in feeds:
        if age is None:
            unknown.append(f"{label} age is unknown.")
        elif age > sla:
            stale.append(f"{label} age {age}h exceeds the {sla:g}h SLA.")
        else:
            clear.append(f"{label} age {age}h is within the {sla:g}h SLA.")
    detail = {"sla_hours": sla, "feeds": {label: age for label, age in feeds}}
    if stale:
        return DETECTED, stale + clear, detail
    if unknown:
        return UNKNOWN, unknown + clear, detail
    return NOT_DETECTED, clear, detail


def _detect_only_mode(
    ctx: dict[str, Any], params: dict[str, Any], _vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    control: ControlPosture = ctx["control"]
    monitor = {_norm(item) for item in params.get("monitor_modes", [])}
    prevent = {_norm(item) for item in params.get("prevent_modes", [])}
    modes: list[tuple[str, str | None]] = []
    if control.av_present is not False:
        modes.append(("AV", control.av_mode))
    if control.edr_present is not False:
        modes.append(("EDR", control.edr_mode))
    if control.app_control_mode:
        modes.append(("Application control", control.app_control_mode))
    if not modes:
        return NOT_APPLICABLE, ["No AV/EDR/application-control mode is available."], {}
    detected: list[str] = []
    unknown: list[str] = []
    clear: list[str] = []
    for label, mode in modes:
        value = _norm(mode)
        if not value:
            unknown.append(f"{label} mode is unknown.")
        elif value in monitor:
            detected.append(f"{label} mode={mode!r} is detect-only.")
        elif value in prevent:
            clear.append(f"{label} mode={mode!r} enforces prevention.")
        else:
            unknown.append(f"{label} mode={mode!r} is not in the catalog vocabulary.")
    detail = {
        "modes": {label: mode for label, mode in modes},
        "monitor_modes": sorted(monitor),
        "prevent_modes": sorted(prevent),
    }
    if detected:
        return DETECTED, detected + clear, detail
    if unknown:
        return UNKNOWN, unknown + clear, detail
    return NOT_DETECTED, clear, detail


def _unpatched_exploitable(
    ctx: dict[str, Any], params: dict[str, Any], vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    target = vulnerability.id.upper()
    cves = {str(item).upper() for item in params.get("cves", [])}
    markers = [_norm(item) for item in params.get("name_markers", [])]
    service_markers = [_norm(item) for item in params.get("service_markers", [])]
    matches = []
    for finding in ctx.get("findings") or []:
        text = _norm(
            " ".join(
                [
                    finding.plugin_name,
                    finding.synopsis,
                    finding.description,
                    finding.output,
                ]
            )
        )
        finding_cves = {item.upper() for item in finding.cve}
        cve_match = bool(cves.intersection(finding_cves))
        marker_match = any(marker and marker in text for marker in markers)
        if cve_match or marker_match:
            matches.append(finding)
    if target not in cves and not matches:
        return (
            NOT_APPLICABLE,
            [f"{target} is outside KRI-05 scope ({', '.join(sorted(cves)) or 'no CVEs'})."],
            {"target": target, "scope_cves": sorted(cves)},
        )
    if not matches:
        return (
            NOT_DETECTED,
            ["No MS17-010/SMBv1 finding for this asset in this run."],
            {"target": target},
        )
    evidence = []
    service_evidence = []
    for finding in matches:
        evidence.append(f"Tenable plugin {finding.plugin_id}: {finding.plugin_name}")
        text = _norm(f"{finding.plugin_name} {finding.description} {finding.output}")
        if (
            finding.port == 445
            or _norm(finding.service) == "cifs"
            or any(marker in text for marker in service_markers)
        ):
            service_evidence.append(
                f"SMB service/port evidence on {finding.asset.display_name} (port {finding.port or 'unknown'})."
            )
    if service_evidence:
        evidence.extend(sorted(set(service_evidence)))
        evidence.append("SMBv1 state must be confirmed on the host; the missing MS17-010 patch is confirmed.")
    return (
        DETECTED,
        evidence,
        {
            "target": target,
            "plugin_ids": sorted({finding.plugin_id for finding in matches}),
            "smb_service_evidence": bool(service_evidence),
        },
    )


def _nac_noncompliant(
    ctx: dict[str, Any], params: dict[str, Any], _vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    control: ControlPosture = ctx["control"]
    value = control.nac_compliant
    policy = control.nac_policy or "unknown policy"
    if value is False:
        return (
            DETECTED,
            [f"NAC policy {policy} reports the endpoint as non-compliant."],
            {"nac_compliant": False, "nac_policy": control.nac_policy},
        )
    if value is True:
        return (
            NOT_DETECTED,
            [f"NAC policy {policy} reports the endpoint as compliant."],
            {"nac_compliant": True, "nac_policy": control.nac_policy},
        )
    return (
        UNKNOWN,
        ["NAC compliance is not supplied by an ISE/NAC connector or control inventory."],
        {"nac_compliant": None, "nac_policy": control.nac_policy},
    )


def _active_compromise(
    ctx: dict[str, Any], params: dict[str, Any], _vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    edr = ctx.get("edr_status") or {}
    status = _norm(edr.get("infection_status") or "unknown")
    matches = [str(item) for item in edr.get("behavioral_matches") or []]
    infected = {_norm(item) for item in params.get("infection_values", [])}
    clean = {_norm(item) for item in params.get("clean_values", [])}
    evidence: list[str] = []
    if status in infected:
        evidence.append(f"EDR infection_status={status}.")
    if matches:
        evidence.append("EDR behavioral matches: " + "; ".join(matches) + ".")
    detail = {
        "infection_status": status,
        "behavioral_matches": matches,
        "edr_source": edr.get("source"),
    }
    if evidence:
        return DETECTED, evidence, detail
    if status in clean:
        return NOT_DETECTED, [f"EDR infection_status={status}; no behavioral matches."], detail
    return (
        UNKNOWN,
        [f"EDR infection_status={status}; no behavioral match data."],
        detail,
    )


DETECTORS: dict[str, Detector] = {
    "missing_security_agent": _missing_security_agent,
    "stale_control_version": _stale_control_version,
    "stale_threat_feed": _stale_threat_feed,
    "detect_only_mode": _detect_only_mode,
    "unpatched_exploitable": _unpatched_exploitable,
    "nac_noncompliant": _nac_noncompliant,
    "active_compromise": _active_compromise,
}


def evaluate_kri_register(
    contexts: list[dict[str, Any]],
    vulnerability: VulnerabilityRecord,
    catalog: dict[str, Any],
) -> list[KRIDetection]:
    results: list[KRIDetection] = []
    for ctx in contexts:
        control = ctx.get("control")
        if control is None:
            continue
        asset = ctx["asset"]
        for definition in catalog["kris"]:
            detector = DETECTORS[definition["detector"]]
            try:
                status, evidence, detail = detector(
                    ctx, definition.get("params") or {}, vulnerability
                )
            except Exception as exc:  # a broken detector must not break the run
                status = UNKNOWN
                evidence = [f"detector error: {exc}"]
                detail = {"error": str(exc)}
            evidence = [str(entry).rstrip(" .") for entry in evidence]
            results.append(
                KRIDetection(
                    kri_id=definition["id"],
                    name=definition["name"],
                    status=status,
                    severity=definition.get("severity", UNKNOWN),
                    asset_uuid=asset.uuid,
                    hostname=asset.display_name,
                    evidence=evidence,
                    source="; ".join(definition.get("data_sources") or []),
                    remediation=definition.get("remediation", ""),
                    action=definition.get("action", ""),
                    detail=detail,
                )
            )
    return results


def detection_counts(detections: list[KRIDetection] | list[dict[str, Any]]) -> dict[str, int]:
    counts = {DETECTED: 0, NOT_DETECTED: 0, UNKNOWN: 0, NOT_APPLICABLE: 0}
    for item in detections:
        status = item.status if isinstance(item, KRIDetection) else item.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def detected_kri_ids(
    detections: list[KRIDetection] | list[dict[str, Any]], asset_uuid: str
) -> list[str]:
    ids = set()
    for item in detections:
        if isinstance(item, KRIDetection):
            if item.asset_uuid == asset_uuid and item.status == DETECTED:
                ids.add(item.kri_id)
        else:
            if item.get("asset_uuid") == asset_uuid and item.get("status") == DETECTED:
                ids.add(item.get("kri_id", ""))
    return sorted(item for item in ids if item)


def catalog_summary(catalog: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": catalog.get("name"),
        "version": catalog.get("version"),
        "updated": catalog.get("updated"),
        "path": catalog.get("_path"),
        "count": len(catalog.get("kris") or []),
        "ids": [item.get("id") for item in catalog.get("kris") or []],
    }


__all__ = [
    "DETECTED",
    "NOT_DETECTED",
    "UNKNOWN",
    "NOT_APPLICABLE",
    "DETECTORS",
    "catalog_summary",
    "detection_counts",
    "detected_kri_ids",
    "evaluate_kri_register",
    "load_catalog",
]
