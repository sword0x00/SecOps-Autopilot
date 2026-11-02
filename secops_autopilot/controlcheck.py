"""Stage 3 — control posture per asset.

What we can establish from Tenable is narrow: whether the asset carries a
Tenable agent flag, its last scan, and any agent record the API scope exposes.
EDR, AV, signature freshness, and application-control mode come from a control
inventory CSV when one is supplied. Everything else is recorded as unknown with
the reason it is unknown.
"""

from __future__ import annotations

from typing import Any

from .models import AssetRef, ControlPosture, SourceRef
from .scoring import control_gap_score
from .util import utc_now


def _agent_match(
    asset: AssetRef, detail: dict[str, Any], agents: list[dict[str, Any]] | None
) -> tuple[dict[str, Any] | None, str | None]:
    if not agents:
        return None, None
    identifiers = {
        str(value).strip().lower()
        for value in (
            asset.uuid,
            asset.agent_uuid,
            detail.get("agent_name"),
            asset.hostname,
            asset.ipv4,
        )
        if value
    }
    for agent in agents:
        for field in ("id", "name"):
            value = str(agent.get(field) or "").strip().lower()
            if value and value in identifiers:
                return agent, field
    return None, None


def build_control_posture(
    asset: AssetRef,
    detail: dict[str, Any],
    *,
    agent_inventory: list[dict[str, Any]] | None,
    agent_inventory_reason: str | None,
    control_entry: dict[str, Any],
    edr_status: dict[str, Any],
) -> ControlPosture:
    matched_agent, matched_on = _agent_match(asset, detail, agent_inventory)
    agent_present = detail.get("has_agent")
    if agent_present is None and matched_agent is not None:
        agent_present = True
    agent_uuid = asset.agent_uuid or (str(matched_agent.get("id")) if matched_agent and matched_agent.get("id") else None)
    agent_version = matched_agent.get("version") if matched_agent else None
    agent_last_seen = matched_agent.get("last_connect") if matched_agent else None
    agent_status = matched_agent.get("status") if matched_agent else None
    agent_last_scan = detail.get("last_scan")

    edr_present = control_entry.get("edr_present")
    if edr_present is None:
        edr_present = edr_status.get("present")
    edr_vendor = control_entry.get("edr_vendor") or edr_status.get("vendor")
    edr_version = control_entry.get("edr_version") or edr_status.get("version")
    edr_feed_age = (
        control_entry.get("edr_feed_age_hours")
        if control_entry.get("edr_feed_age_hours") is not None
        else edr_status.get("feed_age_hours")
    )
    av_present = control_entry.get("av_present")
    av_vendor = control_entry.get("av_vendor")
    av_signature_age = control_entry.get("av_signature_age_hours")
    app_control_mode = control_entry.get("app_control_mode")
    patch_agent_present = control_entry.get("patch_agent_present")

    source_names = [str(item) for item in (detail.get("sources") or [])]
    source_implies_agent = any("AGENT" in item.upper() for item in source_names)
    unknowns: list[dict[str, str]] = []
    gaps: list[dict[str, str]] = []
    detail_error = detail.get("_error")
    if detail_error:
        unknowns.append(
            {
                "field": "asset_detail",
                "reason": str(detail_error),
                "source": "tenable asset detail",
            }
        )
    if agent_present is None:
        unknowns.append(
            {
                "field": "agent_present",
                "reason": "Tenable asset inventory did not expose has_agent and no agent record matched",
                "source": "tenable asset detail / agent inventory",
            }
        )
        gaps.append(
            {
                "control": "endpoint_agent",
                "status": "unknown",
                "severity": "medium",
                "reason": "Endpoint agent presence could not be established.",
            }
        )
    elif agent_present is False:
        gaps.append(
            {
                "control": "endpoint_agent",
                "status": "absent",
                "severity": "high",
                "reason": "Tenable asset inventory reports has_agent=false.",
            }
        )
        if asset.agent_uuid and source_implies_agent:
            unknowns.append(
                {
                    "field": "agent_flag_conflict",
                    "reason": (
                        f"Asset source {source_names} indicates an agent, and the export "
                        f"carries agent_uuid={asset.agent_uuid}, but /assets reports "
                        "has_agent=false. Reconcile the asset record."
                    ),
                    "source": "tenable asset sources vs /assets",
                }
            )
            gaps.append(
                {
                    "control": "endpoint_agent_record",
                    "status": "conflict",
                    "severity": "medium",
                    "reason": (
                        "Agent-indicating source and has_agent=false disagree; reconcile "
                        "the asset record before trusting either control state."
                    ),
                }
            )
    if agent_present is True and agent_version is None:
        unknowns.append(
            {
                "field": "agent_version",
                "reason": agent_inventory_reason
                or "Tenable agent inventory did not return a matching agent record",
                "source": "tenable /scanners/agents",
            }
        )
        gaps.append(
            {
                "control": "endpoint_agent_health",
                "status": "unknown",
                "severity": "medium",
                "reason": "Agent present, but version and feed health are not exposed.",
            }
        )
    if agent_present is True and agent_status is None:
        unknowns.append(
            {
                "field": "agent_status",
                "reason": agent_inventory_reason
                or "Agent status is not available in this API scope",
                "source": "tenable /scanners/agents",
            }
        )
    if agent_present is not False:
        unknowns.append(
            {
                "field": "agent_feed_age_hours",
                "reason": "Tenable does not expose agent plugin-feed age in this API scope",
                "source": "tenable",
            }
        )
    if edr_present is None:
        unknowns.append(
            {
                "field": "edr_present",
                "reason": control_entry.get("source")
                or "No EDR connector or control inventory row supplied a status.",
                "source": "control inventory / EDR connector",
            }
        )
        gaps.append(
            {
                "control": "edr",
                "status": "unknown",
                "severity": "medium",
                "reason": "EDR presence and health were not established; this is not evidence of absence.",
            }
        )
    elif edr_present is False:
        gaps.append(
            {
                "control": "edr",
                "status": "absent",
                "severity": "high",
                "reason": "Control inventory reports EDR is not present.",
            }
        )
    if av_present is None:
        unknowns.append(
            {
                "field": "av_present",
                "reason": control_entry.get("source")
                or "No AV control inventory row supplied a status.",
                "source": "control inventory",
            }
        )
        gaps.append(
            {
                "control": "antivirus",
                "status": "unknown",
                "severity": "medium",
                "reason": "AV presence and signature freshness were not established.",
            }
        )
    elif av_present is False:
        gaps.append(
            {
                "control": "antivirus",
                "status": "absent",
                "severity": "high",
                "reason": "Control inventory reports AV is not present.",
            }
        )
    if av_present is True and av_signature_age is None:
        unknowns.append(
            {
                "field": "av_signature_age_hours",
                "reason": "AV is present per inventory, but signature age was not supplied.",
                "source": "control inventory",
            }
        )
    if app_control_mode is None:
        unknowns.append(
            {
                "field": "app_control_mode",
                "reason": "Application-control enforcement mode was not supplied by any connector.",
                "source": "control inventory",
            }
        )
        gaps.append(
            {
                "control": "application_control",
                "status": "unknown",
                "severity": "low",
                "reason": "Application-control mode is unknown.",
            }
        )
    if patch_agent_present is None:
        unknowns.append(
            {
                "field": "patch_agent_present",
                "reason": "Patch-management agent presence was not supplied by any connector.",
                "source": "control inventory",
            }
        )
        gaps.append(
            {
                "control": "patch_agent",
                "status": "unknown",
                "severity": "low",
                "reason": "Patch agent presence is unknown.",
            }
        )

    sources = [
        SourceRef(
            type="tenable_asset",
            ref=detail.get("source_ref") or f"/assets/{asset.uuid}",
            note="has_agent, ACR, AES, last scan",
            retrieved=detail.get("retrieved") or utc_now(),
        ),
        SourceRef(
            type="agent_inventory",
            ref="/scanners/agents",
            note=(
                f"matched on {matched_on}"
                if matched_agent
                else agent_inventory_reason or "no matching agent record"
            ),
            retrieved=utc_now(),
        ),
        SourceRef(
            type="control_inventory",
            ref=control_entry.get("source") or "no control inventory",
            note="EDR/AV/signature/application-control fields",
            retrieved=utc_now(),
        ),
        SourceRef(
            type="edr",
            ref=edr_status.get("source") or "no EDR integration",
            note="infection status",
            retrieved=utc_now(),
        ),
    ]

    posture = ControlPosture(
        asset_uuid=asset.uuid,
        agent_present=agent_present,
        agent_uuid=agent_uuid,
        agent_version=agent_version,
        agent_last_seen=agent_last_seen,
        agent_last_scan=agent_last_scan,
        agent_status=agent_status,
        agent_feed_age_hours=None,
        patch_agent_present=patch_agent_present,
        edr_present=edr_present,
        edr_vendor=edr_vendor,
        edr_version=edr_version,
        edr_feed_age_hours=edr_feed_age,
        av_present=av_present,
        av_vendor=av_vendor,
        av_signature_age_hours=av_signature_age,
        app_control_mode=app_control_mode,
        unknowns=unknowns,
        gaps=gaps,
        sources=sources,
    )
    posture.control_gap_score = control_gap_score(posture)
    return posture
