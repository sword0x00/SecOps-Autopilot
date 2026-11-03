"""KRI register: deterministic checks for KRI-01 … KRI-09.

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

from .advisory import runtime_matches
from .errors import ConfigError
from .models import ControlPosture, KRIDetection, VulnerabilityRecord
from .scoring import exploit_signals

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
    """Generic KRI-05: the target vulnerability is still open on this asset.

    The earlier implementation was hard-coded to MS17-010. That made the KRI
    report ``not_applicable`` for every non-Windows CVE, which defeated its
    purpose. The target CVE is now the primary match; legacy name/service
    markers remain available for MS17-010-style evidence enrichment.
    """
    target = vulnerability.id.upper()
    legacy_cves = {
        str(item).upper()
        for item in (params.get("legacy_cves") or params.get("cves") or [])
    }
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
        cve_match = target in finding_cves
        legacy_match = bool(legacy_cves.intersection(finding_cves))
        marker_match = any(marker and marker in text for marker in markers)
        if cve_match or legacy_match or marker_match:
            matches.append(finding)
    if not matches:
        return (
            NOT_APPLICABLE,
            [
                f"{target} is not represented by a finding on this asset; "
                "KRI-05 is not applicable to this asset."
            ],
            {"target": target, "scope_cves": sorted(legacy_cves)},
        )
    open_matches = [
        finding
        for finding in matches
        if str(finding.state or "open").upper() not in {"FIXED", "CLOSED", "RESOLVED"}
    ]
    if not open_matches:
        return (
            NOT_DETECTED,
            [f"All {len(matches)} finding(s) for {target} are closed/fixed in the export."],
            {"target": target, "plugin_ids": sorted({f.plugin_id for f in matches})},
        )

    evidence = [
        f"Tenable plugin {finding.plugin_id}: {finding.plugin_name}"
        for finding in open_matches
    ]
    signals = exploit_signals(open_matches)
    if signals:
        evidence.append("Exploit signals: " + ", ".join(signals) + ".")
    patch_flags = [
        finding.has_patch
        for finding in open_matches
        if finding.has_patch is not None
    ]
    if any(patch_flags):
        evidence.append(
            "A patch is reported available, but the asset still has an open finding."
        )
    elif patch_flags and all(flag is False for flag in patch_flags):
        evidence.append(
            "No patch is reported available; compensating controls are the interim path."
        )
    else:
        evidence.append(
            "Patch availability is unknown in the scanner metadata."
        )
    service_evidence = []
    for finding in open_matches:
        text = _norm(f"{finding.plugin_name} {finding.description} {finding.output}")
        if (
            finding.port in {445, 139}
            or _norm(finding.service) in {"cifs", "smb"}
            or any(marker in text for marker in service_markers)
        ):
            service_evidence.append(
                f"SMB service/port evidence on {finding.asset.display_name} "
                f"(port {finding.port or 'unknown'})."
            )
    if service_evidence:
        evidence.extend(sorted(set(service_evidence)))
        evidence.append(
            "SMBv1 state must be confirmed on the host; the missing patch is confirmed."
        )
    return (
        DETECTED,
        evidence,
        {
            "target": target,
            "plugin_ids": sorted({finding.plugin_id for finding in open_matches}),
            "exploit_signals": signals,
            "patch_available": True if any(patch_flags) else False if patch_flags else None,
            "smb_service_evidence": bool(service_evidence),
        },
    )


def _vulnerable_runtime_version(
    ctx: dict[str, Any], params: dict[str, Any], vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    """KRI-08: installed runtime is below the advisory's fixed version.

    Runtime versions come from the finding's CPE, not from a guess. If the CPE
    is absent or unversioned, the result is ``unknown``. If the advisory does not
    cover the asset's product, the KRI does not apply to that asset.
    """
    advisory = getattr(vulnerability, "advisory", None)
    if not advisory:
        return (
            UNKNOWN,
            [
                "No advisory version metadata is attached; runtime currency "
                "cannot be assessed. Supply --advisory to evaluate KRI-08."
            ],
            {"advisory": None},
        )
    matches = runtime_matches(ctx.get("findings") or [], advisory)
    if not matches:
        return (
            NOT_APPLICABLE,
            [
                "No CPE in the finding set matches an affected product in the "
                f"advisory {advisory.get('id')}."
            ],
            {"advisory": advisory.get("id"), "matches": []},
        )
    detected: list[str] = []
    unknown: list[str] = []
    clear: list[str] = []
    grouped: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    for match in matches:
        grouped.setdefault(
            (str(match.get("product") or "runtime"), match.get("version")), []
        ).append(match)
    for (product, version), group in grouped.items():
        if not version:
            unknown.append(
                f"{product}: CPE does not expose a version; runtime currency is unknown."
            )
            continue
        affecting = [item for item in group if item.get("in_range") is True]
        if affecting:
            chosen = affecting[0]
            fixed = next(
                (item.get("fixed") for item in affecting if item.get("fixed")), None
            )
            branch = chosen.get("branch") or "unknown branch"
            if fixed:
                detected.append(
                    f"{product} {version} is inside affected range "
                    f"{chosen.get('range')}; fixed version is {fixed} "
                    f"(branch {branch})."
                )
            else:
                detected.append(
                    f"{product} {version} is inside affected range "
                    f"{chosen.get('range')}; no vendor fixed version is recorded "
                    f"for branch {branch} (support={chosen.get('support')})."
                )
            continue
        if all(item.get("in_range") is False for item in group):
            clear.append(
                f"{product} {version} is outside all affected ranges in advisory "
                f"{advisory.get('id')}."
            )
            continue
        unknown.append(
            f"{product} {version}: one or more affected ranges could not be "
            "evaluated."
        )
    detail = {
        "advisory": advisory.get("id"),
        "advisory_source": advisory.get("source"),
        "matches": [
            {
                "product": item.get("product"),
                "version": item.get("version"),
                "range": item.get("range"),
                "fixed": item.get("fixed"),
                "branch": item.get("branch"),
                "support": item.get("support"),
                "in_range": item.get("in_range"),
            }
            for item in matches
        ],
    }
    if detected:
        return DETECTED, detected + clear, detail
    if unknown:
        return UNKNOWN, unknown + clear, detail
    return NOT_DETECTED, clear, detail


def _external_exposure(
    ctx: dict[str, Any], params: dict[str, Any], _vulnerability: VulnerabilityRecord
) -> tuple[str, list[str], dict[str, Any]]:
    """KRI-09: the vulnerable service is reachable from an untrusted network.

    The signal is a web port/service on the finding, or a supplied asset
    exposure score. No signal is ``unknown``; an explicit non-web listener with
    no exposure score is ``not_detected`` only when the finding itself carries
    port/service metadata. The engine never infers "internal" from silence.
    """
    ports = {int(item) for item in (params.get("ports") or [80, 443, 8080, 8443, 3000, 8000])}
    services = {_norm(item) for item in (params.get("services") or [])}
    findings = ctx.get("findings") or []
    web: list[str] = []
    non_web: list[str] = []
    for finding in findings:
        service = _norm(finding.service)
        if (
            finding.port in ports
            or service in services
            or "http" in service
            or "https" in service
        ):
            web.append(
                f"Plugin {finding.plugin_id} exposes "
                f"{finding.service or 'a service'} on port {finding.port or 'unknown'}."
            )
        elif finding.port is not None:
            non_web.append(
                f"Plugin {finding.plugin_id} is on non-web port {finding.port} "
                f"({finding.service or 'service unknown'})."
            )
    detail_raw = ctx.get("detail") or {}
    aes = detail_raw.get("aes_score")
    threshold = float(params.get("aes_threshold") or 700)
    detail = {"ports": sorted(ports), "aes_score": aes, "aes_threshold": threshold}
    if web:
        evidence = list(web)
        if isinstance(aes, (int, float)):
            evidence.append(
                f"Asset exposure score {aes} "
                f"({'at/above' if aes >= threshold else 'below'} threshold {threshold:g})."
            )
        return DETECTED, evidence, detail
    if isinstance(aes, (int, float)):
        if aes >= threshold:
            return (
                DETECTED,
                [
                    f"No web listener is recorded on the finding, but the asset "
                    f"exposure score {aes} is at/above the {threshold:g} threshold."
                ],
                detail,
            )
        return (
            NOT_DETECTED,
            [
                f"No web listener is recorded on the finding, and the asset "
                f"exposure score {aes} is below the {threshold:g} threshold."
            ],
            detail,
        )
    if non_web:
        return (
            NOT_DETECTED,
            non_web
            + ["No web listener or asset exposure score is recorded; the finding is not web-exposed."],
            detail,
        )
    return (
        UNKNOWN,
        ["No port, service, or asset exposure score is available; external exposure is unknown."],
        detail,
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
    "vulnerable_runtime_version": _vulnerable_runtime_version,
    "external_exposure": _external_exposure,
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
