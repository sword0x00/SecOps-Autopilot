"""KRI scoring.

Raw CVSS is an input, not the answer. The score combines published severity,
exploit maturity (Tenable VPR when present), asset exposure, asset criticality
(ACR), and the control gap on the asset. Unknowns are excluded and the weights
renormalized; the unknown list travels with the score so a reader can see what
the number does not know.
"""

from __future__ import annotations

from typing import Any

from .models import AssetAssessment, ControlPosture, Finding, RiskScore

WEIGHTS = {
    "severity": 0.35,
    "exploitability": 0.25,
    "exposure": 0.15,
    "control_gap": 0.20,
    "criticality": 0.05,
}

TIER_CRITICAL = 80.0
TIER_HIGH = 65.0
TIER_MEDIUM = 45.0


def tier_for(score: float) -> str:
    if score >= TIER_CRITICAL:
        return "critical"
    if score >= TIER_HIGH:
        return "high"
    if score >= TIER_MEDIUM:
        return "medium"
    return "low"


def cisa_known_exploited(finding: Finding) -> bool:
    for xref in finding.xrefs:
        name = str(xref.get("name") or "").lower()
        value = str(xref.get("value") or "").lower()
        if "cisa" in name and ("known" in name or "exploited" in name):
            return True
        if "cisa-known-exploited" in name:
            return True
        if "known-exploited" in value:
            return True
    for link in finding.see_also:
        if "known-exploited" in link.lower() or "cisa.gov" in link.lower():
            return True
    return False


def severity_component(findings: list[Finding]) -> tuple[float | None, str]:
    cvss3 = [f.cvss3_base for f in findings if f.cvss3_base is not None]
    if cvss3:
        return round(max(cvss3), 2), "tenable:cvss3_base_score"
    cvss2 = [f.cvss2_base for f in findings if f.cvss2_base is not None]
    if cvss2:
        return round(max(cvss2), 2), "tenable:cvss_base_score"
    from .util import severity_baseline

    bands = [severity_baseline(f.severity) for f in findings if f.severity is not None]
    if bands:
        return round(max(bands), 2), "tenable:severity_band"
    return None, "unknown"


def exploit_signals(findings: list[Finding]) -> list[str]:
    signals: list[str] = []
    for finding in findings:
        if finding.exploited_by_malware:
            signals.append("exploited_by_malware")
        if finding.in_the_news:
            signals.append("in_the_news")
        if finding.exploit_framework_metasploit:
            signals.append("metasploit")
        if finding.exploit_available:
            signals.append("exploit_available")
        if cisa_known_exploited(finding):
            signals.append("cisa_known_exploited")
    return sorted(set(signals))


def exploit_component(findings: list[Finding]) -> tuple[float | None, str, list[str]]:
    signals = exploit_signals(findings)
    signal_score: float | None = None
    signal_source = "unknown"
    if "cisa_known_exploited" in signals:
        signal_score, signal_source = 9.8, "signals:cisa_known_exploited"
    elif "exploited_by_malware" in signals:
        signal_score, signal_source = 9.5, "signals:exploited_by_malware"
    elif "metasploit" in signals or "in_the_news" in signals:
        signal_score, signal_source = 8.5, "signals:weaponized"
    elif "exploit_available" in signals:
        signal_score, signal_source = 8.0, "signals:exploit_available"
    vprs = [f.vpr for f in findings if f.vpr is not None]
    if vprs:
        vpr = round(max(vprs), 2)
        if signal_score is not None and signal_score > vpr:
            return signal_score, f"{signal_source}+tenable:vpr={vpr}", signals
        return vpr, "tenable:vpr", signals
    if signal_score is not None:
        return signal_score, signal_source, signals
    flags = [
        f.exploit_available
        for f in findings
        if f.exploit_available is not None
    ]
    if flags and not any(flags):
        return 3.0, "signals:no_public_exploit", signals
    return None, "unknown", signals


def control_gap_score(posture: ControlPosture) -> float:
    gap = 0.0
    if posture.agent_present is False:
        gap += 4.0
    elif posture.agent_present is None:
        gap += 2.5
    else:
        if posture.agent_version is None:
            gap += 0.75
        if posture.agent_feed_age_hours is None:
            gap += 0.75
    if posture.edr_present is False:
        gap += 3.0
    elif posture.edr_present is None:
        gap += 1.25
    if posture.av_present is False:
        gap += 2.5
    elif posture.av_present is None:
        gap += 1.0
    if posture.av_signature_age_hours is not None:
        if posture.av_signature_age_hours > 168:
            gap += 2.0
        elif posture.av_signature_age_hours > 24:
            gap += 1.0
    if posture.edr_feed_age_hours is not None and posture.edr_feed_age_hours > 168:
        gap += 1.0
    if posture.app_control_mode is None:
        gap += 0.5
    if posture.patch_agent_present is None:
        gap += 0.5
    return round(min(10.0, gap), 2)


def normalise_exposure(raw: float | None) -> float | None:
    if raw is None:
        return None
    if raw <= 0:
        return None
    # Tenable AES is 0-1000; some workbench payloads use 0-100.
    value = raw / 100.0 if raw > 100 else raw / 10.0
    return round(min(10.0, max(0.0, value)), 2)


def score_asset(
    asset_uuid: str,
    findings: list[Finding],
    posture: ControlPosture,
    *,
    aes_raw: float | None,
    acr_raw: float | None,
) -> RiskScore:
    posture.control_gap_score = control_gap_score(posture)
    severity, severity_source = severity_component(findings)
    exploitability, exploit_source, signals = exploit_component(findings)
    exposure = normalise_exposure(aes_raw)
    criticality = acr_raw if acr_raw and acr_raw > 0 else None

    components: dict[str, float | None] = {
        "severity": severity,
        "exploitability": exploitability,
        "exposure": exposure,
        "control_gap": posture.control_gap_score,
        "criticality": criticality,
    }
    unknown_components = [key for key, value in components.items() if value is None]
    effective_weights = {
        key: WEIGHTS[key]
        for key, value in components.items()
        if value is not None
    }
    weight_total = sum(effective_weights.values())
    if weight_total <= 0:
        score = 0.0
    else:
        score = (
            sum(
                (components[key] or 0.0) * weight
                for key, weight in effective_weights.items()
            )
            / weight_total
            * 10.0
        )
    score = round(min(100.0, max(0.0, score)), 1)
    known_count = len(effective_weights)
    confidence = "high" if known_count == 5 else "medium" if known_count >= 3 else "low"
    drivers = sorted(
        (
            {
                "component": key,
                "value": value,
                "weight": effective_weights.get(key, 0.0),
                "contribution": round((value or 0.0) * effective_weights.get(key, 0.0) * 10, 1),
            }
            for key, value in components.items()
            if value is not None
        ),
        key=lambda item: item["contribution"],
        reverse=True,
    )
    parts = [
        f"severity={severity if severity is not None else 'unknown'} ({severity_source})",
        f"exploitability={exploitability if exploitability is not None else 'unknown'} ({exploit_source})",
        f"exposure={exposure if exposure is not None else 'unknown'}",
        f"control_gap={posture.control_gap_score}",
        f"criticality={criticality if criticality is not None else 'unknown'}",
    ]
    explanation = (
        f"KRI {score:.1f}/100 ({tier_for(score)}): " + "; ".join(parts) + "."
    )
    if unknown_components:
        explanation += " Excluded unknown components: " + ", ".join(unknown_components) + "."
    if signals:
        explanation += " Exploit signals: " + ", ".join(signals) + "."
    return RiskScore(
        score=score,
        tier=tier_for(score),
        components=components,
        weights=dict(WEIGHTS),
        effective_weights={key: round(value, 4) for key, value in effective_weights.items()},
        raw={
            "cvss3": severity if severity_source == "tenable:cvss3_base_score" else None,
            "cvss2": severity if severity_source == "tenable:cvss_base_score" else None,
            "vpr": exploitability if exploit_source == "tenable:vpr" else None,
            "aes_raw": aes_raw,
            "acr_raw": acr_raw,
        },
        unknown_components=unknown_components,
        confidence=confidence,
        drivers=drivers,
        explanation=explanation,
    )


def build_assessment_summary(assessment: AssetAssessment) -> dict[str, Any]:
    return {
        "asset_uuid": assessment.asset.uuid,
        "hostname": assessment.asset.display_name,
        "kri": assessment.risk.score,
        "tier": assessment.risk.tier,
        "components": assessment.risk.components,
        "unknown_components": assessment.risk.unknown_components,
    }
