"""Read-only stages: intake through remediation planning.

These stages are deliberately incapable of state change. They can query the
scanner, read inventories, evaluate KRIs, score risk, and build a plan; they
cannot create a ticket, contact the NAC, or submit a patch job. The engine
enforces that separation by invoking only this module before the first approval
gate.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..controlcheck import build_control_posture
from ..errors import ConnectorError
from ..intake import build_vulnerability
from ..kri import (
    catalog_summary,
    detected_kri_ids,
    detection_counts,
    evaluate_kri_register,
)
from ..models import (
    STATUS_AWAITING_TICKET_APPROVAL,
    STATUS_INTAKE_FAILED,
    STATUS_NO_EXPOSURE,
    AssetAssessment,
    AssetRef,
    Finding,
)
from ..remediation import build_plan
from ..scoring import score_asset
from ..util import (
    dedupe,
    extract_kb_refs,
    extract_refs,
    first_nonempty,
    normalize_mac,
    utc_now,
)
from .context import StageContext


def stage_intake(ctx: StageContext) -> str | None:
    wf = ctx.workflow
    run = wf.run
    target_cve = str(run.target.get("value") or "")
    started = utc_now()
    try:
        hits = ctx.source.cve_plugin_hits(target_cve, wf.date_range)
        plugin_ids = [hit.plugin_id for hit in hits if hit.plugin_id]
        findings = (
            ctx.source.findings_for_plugins(plugin_ids, wf.date_range)
            if plugin_ids
            else []
        )
    except ConnectorError as exc:
        ctx.emit(
            "intake",
            {"error": str(exc)},
            summary="Scanner intake failed.",
            status="error",
            started_at=started,
            errors=[str(exc)],
        )
        run.status = STATUS_INTAKE_FAILED
        run.next_actions = [f"Resolve scanner access/scope, then rerun: {exc}"]
        raise

    vulnerability = build_vulnerability(
        target_cve,
        hits,
        findings,
        ctx.source_refs(),
        date_range=wf.date_range,
        advisory=wf.advisory,
    )
    wf.vulnerability = vulnerability
    wf.hits = hits
    wf.findings = findings
    run.vulnerability = vulnerability.to_dict()

    intake_unknowns: list[dict[str, str]] = []
    if vulnerability.confidence != "high":
        intake_unknowns.append(
            {"field": "exposure", "reason": vulnerability.confidence_reason}
        )
    ctx.emit(
        "intake",
        {
            "vulnerability": vulnerability.to_dict(),
            "plugin_hits": [hit.to_dict() for hit in hits],
            "findings_returned": len(findings),
            "cve_filter": target_cve,
            "advisory_provenance": (getattr(vulnerability, "advisory", None) or {}).get(
                "provenance"
            ),
        },
        summary=(
            f"{len(hits)} scanner plugin(s) matched; {len(findings)} finding(s) "
            f"across {vulnerability.affected_asset_count} asset(s)."
        ),
        started_at=started,
        unknowns=intake_unknowns,
    )

    if not hits or not findings:
        ctx.emit(
            "exposure",
            {"assets": [], "reason": "no scanner finding returned"},
            summary="No affected assets were resolved from the scanner.",
            status="skipped",
            started_at=utc_now(),
            source_calls=[],
        )
        run.status = STATUS_NO_EXPOSURE
        run.next_actions = [
            "Confirm the target is in scope for the tenant's scan window, then rerun "
            "with a wider --date-range or supply an advisory/exposure import."
        ]
        return STATUS_NO_EXPOSURE
    return None


def stage_exposure(ctx: StageContext) -> None:
    wf = ctx.workflow
    run = wf.run
    started = utc_now()
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in wf.findings:
        groups[finding.asset.uuid].append(finding)

    agent_inventory, agent_reason = ctx.agent_inventory()
    contexts: list[dict[str, Any]] = []
    detail_errors: list[dict[str, str]] = []
    for asset_uuid, group in groups.items():
        detail, detail_error = ctx.asset_detail(asset_uuid)
        if detail_error:
            detail_errors.append({"asset_uuid": asset_uuid, "error": detail_error})
        asset = _merge_asset(group[0].asset, detail)
        owner = ctx.owners.lookup(asset)
        contexts.append(
            {
                "asset": asset,
                "findings": group,
                "detail": detail,
                "detail_error": detail_error,
                "owner": owner,
            }
        )
    contexts.sort(
        key=lambda item: (
            max((f.severity or 0) for f in item["findings"]),
            max((f.vpr or 0) for f in item["findings"]),
        ),
        reverse=True,
    )

    truncated: list[str] = []
    if len(contexts) > wf.max_assets:
        truncated = [item["asset"].uuid for item in contexts[wf.max_assets :]]
        contexts = contexts[: wf.max_assets]
    wf.contexts = contexts
    wf.run.options["agent_inventory_available"] = agent_inventory is not None
    wf.run.options["agent_inventory_reason"] = agent_reason

    exposure_unknowns: list[dict[str, str]] = []
    for item in contexts:
        if item["owner"].owner == "unknown":
            exposure_unknowns.append(
                {
                    "field": f"owner:{item['asset'].display_name}",
                    "reason": item["owner"].source,
                }
            )
    if truncated:
        exposure_unknowns.append(
            {
                "field": "assets_truncated",
                "reason": (
                    f"{len(truncated)} asset(s) omitted by --max-assets; ids: "
                    + ", ".join(truncated[:10])
                ),
            }
        )
    ctx.emit(
        "exposure",
        {
            "assets": [
                {
                    "asset": item["asset"].to_dict(),
                    "owner": item["owner"].to_dict(),
                    "findings": len(item["findings"]),
                    "plugin_ids": sorted({f.plugin_id for f in item["findings"]}),
                    "detail_error": item["detail_error"],
                }
                for item in contexts
            ],
            "agent_inventory_available": agent_inventory is not None,
            "agent_inventory_reason": agent_reason,
            "truncated_assets": truncated,
        },
        summary=(
            f"{len(contexts)} asset(s) exposed; "
            f"{sum(1 for item in contexts if item['owner'].owner == 'unknown')} "
            "without an owner mapping."
        ),
        started_at=started,
        unknowns=exposure_unknowns,
    )


def stage_control_check(ctx: StageContext) -> None:
    wf = ctx.workflow
    started = utc_now()
    agent_inventory, agent_reason = ctx.agent_inventory()
    control_unknowns: list[dict[str, str]] = []
    for item in wf.contexts:
        edr_status = ctx.edr.status(
            item["asset"].uuid, item["asset"].display_name
        )
        control_entry = ctx.controls.lookup(item["asset"])
        control = build_control_posture(
            item["asset"],
            item["detail"],
            agent_inventory=agent_inventory,
            agent_inventory_reason=agent_reason,
            control_entry=control_entry,
            edr_status=edr_status,
        )
        item["control"] = control
        item["control_entry"] = control_entry
        item["edr_status"] = edr_status
        for unknown in control.unknowns:
            control_unknowns.append(
                {
                    "field": f"{item['asset'].display_name}:{unknown.get('field')}",
                    "reason": unknown.get("reason", ""),
                }
            )
    ctx.emit(
        "control_check",
        {
            "assets": [
                {
                    "asset": item["asset"].to_dict(),
                    "control": item["control"].to_dict(),
                    "edr_status": item["edr_status"],
                }
                for item in wf.contexts
            ],
            "agent_inventory_available": agent_inventory is not None,
            "agent_inventory_reason": agent_reason,
        },
        summary=(
            f"Agent present on {sum(1 for item in wf.contexts if item['control'].agent_present is True)} "
            f"of {len(wf.contexts)}; absent on "
            f"{sum(1 for item in wf.contexts if item['control'].agent_present is False)}; "
            f"unknown on {sum(1 for item in wf.contexts if item['control'].agent_present is None)}; "
            f"{sum(1 for item in wf.contexts if any(u.get('field') == 'agent_flag_conflict' for u in item['control'].unknowns))} "
            "with a conflicting agent record. EDR/AV/feed details are unknown unless "
            "a control inventory supplied them."
        ),
        started_at=started,
        unknowns=control_unknowns,
    )


def stage_kri_register(ctx: StageContext) -> None:
    wf = ctx.workflow
    run = wf.run
    assert wf.vulnerability is not None
    started = utc_now()
    detections = evaluate_kri_register(wf.contexts, wf.vulnerability, wf.catalog)
    run.kri_detections = [detection.to_dict() for detection in detections]
    for item in wf.contexts:
        item["kri_ids"] = detected_kri_ids(run.kri_detections, item["asset"].uuid)
    counts = detection_counts(detections)
    register_unknowns = [
        {
            "field": f"{detection.kri_id} on {detection.hostname}",
            "reason": "; ".join(detection.evidence),
        }
        for detection in detections
        if detection.status == "unknown"
    ]
    ctx.emit(
        "kri_register",
        {
            "catalog": catalog_summary(wf.catalog),
            "counts": counts,
            "detections": run.kri_detections,
        },
        summary=(
            f"{len(detections)} KRI evaluation(s) across {len(wf.contexts)} asset(s): "
            f"{counts['detected']} detected, {counts['not_detected']} clear, "
            f"{counts['unknown']} unknown, {counts['not_applicable']} not applicable."
        ),
        started_at=started,
        unknowns=register_unknowns,
    )


def stage_risk_scoring(ctx: StageContext) -> None:
    wf = ctx.workflow
    run = wf.run
    started = utc_now()
    assessments: list[AssetAssessment] = []
    for item in wf.contexts:
        risk = score_asset(
            item["asset"].uuid,
            item["findings"],
            item["control"],
            aes_raw=item["detail"].get("aes_score"),
            acr_raw=item["detail"].get("acr_score"),
        )
        item["risk"] = risk
        assessments.append(_assessment(item))
    assessments.sort(key=lambda assessment: assessment.risk.score, reverse=True)
    wf.assessments = assessments
    run.exposure = [assessment.to_dict() for assessment in assessments]
    run.risk_queue = [
        {
            "asset_uuid": assessment.asset.uuid,
            "hostname": assessment.asset.display_name,
            "kri": assessment.risk.score,
            "tier": assessment.risk.tier,
            "components": assessment.risk.components,
            "confidence": assessment.risk.confidence,
            "unknown_components": assessment.risk.unknown_components,
        }
        for assessment in assessments
    ]
    ctx.emit(
        "kri_scoring",
        {
            "method": (
                "weighted blend of published severity, exploitability (VPR or "
                "exploit signals), exposure (AES), control gap, and criticality "
                "(ACR); unknown components excluded and weights renormalized"
            ),
            "weights": assessments[0].risk.weights if assessments else {},
            "queue": run.risk_queue,
        },
        summary=(
            f"Ranked {len(assessments)} asset(s): "
            + ", ".join(
                f"{sum(1 for a in assessments if a.risk.tier == tier)} {tier}"
                for tier in ("critical", "high", "medium", "low")
                if any(a.risk.tier == tier for a in assessments)
            )
            + "."
        ),
        started_at=started,
    )


def stage_planning(ctx: StageContext) -> None:
    wf = ctx.workflow
    run = wf.run
    assert wf.vulnerability is not None
    started = utc_now()
    plan = build_plan(
        wf.vulnerability,
        wf.assessments,
        isolate_threshold=ctx.settings.isolate_threshold,
    )
    run.plan = plan.to_dict()
    run.status = STATUS_AWAITING_TICKET_APPROVAL
    run.next_actions = [
        f"Approve ticketing-system ticket creation: secops approve --run {run.run_id} "
        f'--gate ticket --approver "<name>"'
    ]
    ctx.emit(
        "remediation_planning",
        plan.to_dict(),
        summary=(
            f"Patch available: {_bool_text(plan.patch_path.get('available'))}; "
            f"{len(plan.compensating_controls)} compensating control(s); "
            f"{sum(1 for item in plan.per_asset if item.containment_recommended)} "
            "containment candidate(s)."
        ),
        started_at=started,
        unknowns=[
            {
                "field": "patch_prerequisites",
                "reason": (
                    "Tenable plugin metadata does not carry prerequisites, "
                    "rollback, or effort. Advisory fixed versions do not imply "
                    "the asset's patch window or reboot requirements."
                ),
            }
        ],
    )


# -- helpers ------------------------------------------------------------


def _assessment(item: dict[str, Any]) -> AssetAssessment:
    findings: list[Finding] = item["findings"]
    flags = [finding.has_patch for finding in findings if finding.has_patch is not None]
    if any(flags):
        patch_available: bool | None = True
    elif flags and all(flag is False for flag in flags):
        patch_available = False
    else:
        patch_available = None
    refs: list[str] = []
    for finding in findings:
        combined = " ".join(
            [
                finding.plugin_name,
                finding.solution,
                finding.output,
                finding.synopsis,
            ]
        )
        extracted = extract_refs(combined)
        for kind, values in extracted.items():
            if kind != "cve":
                refs.extend(values)
        refs.extend(extract_kb_refs(combined))
    detail = item["detail"] or {}
    return AssetAssessment(
        asset=item["asset"],
        owner=item["owner"],
        findings=findings,
        control=item["control"],
        risk=item["risk"],
        plugin_ids=sorted({f.plugin_id for f in findings}),
        max_severity=_max_optional([f.severity for f in findings]),
        max_cvss3=_max_optional([f.cvss3_base for f in findings]),
        max_cvss2=_max_optional([f.cvss2_base for f in findings]),
        max_vpr=_max_optional([f.vpr for f in findings]),
        patch_available=patch_available,
        patch_refs=dedupe(refs),
        workarounds=[],
        aes_raw=detail.get("aes_score"),
        aes_normalized=item["risk"].components.get("exposure"),
        acr_raw=detail.get("acr_score"),
        last_seen=detail.get("last_seen") or item["asset"].last_seen,
        last_scan=detail.get("last_scan"),
        detail_source=detail.get("source_ref") or item["detail_error"] or "scanner export",
        kri_ids=list(item.get("kri_ids") or []),
    )


def _merge_asset(base: AssetRef, detail: dict[str, Any]) -> AssetRef:
    return AssetRef(
        uuid=detail.get("asset_uuid") or base.uuid,
        hostname=first_nonempty(detail.get("hostname"), base.hostname),
        fqdn=first_nonempty(
            (detail.get("fqdn") or [None])[0]
            if isinstance(detail.get("fqdn"), list)
            else detail.get("fqdn"),
            base.fqdn,
        ),
        netbios=first_nonempty(base.netbios, base.hostname),
        ipv4=first_nonempty(
            (detail.get("ipv4") or [None])[0]
            if isinstance(detail.get("ipv4"), list)
            else detail.get("ipv4"),
            base.ipv4,
        ),
        mac=normalize_mac(detail.get("mac")) or base.mac,
        os=detail.get("os") or base.os,
        agent_uuid=first_nonempty(base.agent_uuid, detail.get("agent_name")),
        last_seen=first_nonempty(detail.get("last_seen"), base.last_seen),
        network_id=base.network_id,
    )


def _max_optional(values: list[Any]) -> Any:
    present = [value for value in values if value is not None]
    return max(present) if present else None


def _bool_text(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


# (contract id, stage function) in execution order.
READ_ONLY_STAGES = (
    ("intake", stage_intake),
    ("exposure", stage_exposure),
    ("control_check", stage_control_check),
    ("kri_register", stage_kri_register),
    ("kri_scoring", stage_risk_scoring),
    ("remediation_planning", stage_planning),
)


__all__ = [
    "READ_ONLY_STAGES",
    "stage_intake",
    "stage_exposure",
    "stage_control_check",
    "stage_kri_register",
    "stage_risk_scoring",
    "stage_planning",
]
