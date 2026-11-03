"""Markdown and self-contained HTML evidence reports.

The report is the human-readable face of the run. It is generated from the same
records the engine writes, so it cannot claim anything the run did not record.
"""

from __future__ import annotations

import html
import json
from typing import Any

from .models import STAGE_LABELS, RunState
from .util import UNKNOWN

STATUS_TEXT = {
    "initialized": "Initialized",
    "intake_failed": "Intake failed",
    "stage_failed": "A pipeline stage failed",
    "no_exposure_found": "No exposure found",
    "awaiting_ticket_approval": "Awaiting Human Approval to create the ticketing-system ticket",
    "awaiting_remediation_approval": "Ticket created; awaiting infosec Human Approval",
    "remediation_rejected": "Remediation rejected by infosec",
    "approved_for_containment": "Remediation Human-Approved; containment pending",
    "containment_executed": "Containment executed",
    "awaiting_verification": "Awaiting verification",
    "verified_remediated": "Remediated and verified",
    "verification_open": "Verification complete with open items",
    "escalated": "Escalated (legacy status)",
    "restored": "Restored to production",
    "complete": "Complete",
}

TIER_ORDER = ["critical", "high", "medium", "low"]


def _text(value: Any, default: str = UNKNOWN) -> str:
    if value is None or value == "":
        return default
    return str(value)


def _md(value: Any) -> str:
    return _text(value).replace("|", "\\|").replace("\n", " ")


def _html(value: Any) -> str:
    return html.escape(_text(value))


def _bool(value: Any, yes: str = "present", no: str = "absent") -> str:
    if value is True:
        return yes
    if value is False:
        return no
    return "unknown"


def _score(value: Any) -> str:
    return f"{value:.1f}" if isinstance(value, (int, float)) else "unknown"


def _age(value: Any) -> str:
    return f"{value}h" if isinstance(value, (int, float)) else "unknown"


def _asset_name(asset: dict[str, Any]) -> str:
    return (
        asset.get("hostname")
        or asset.get("fqdn")
        or asset.get("netbios")
        or asset.get("ipv4")
        or asset.get("uuid")
        or "unknown asset"
    )


def _plan_asset(plan: dict[str, Any], uuid: str) -> dict[str, Any]:
    for item in plan.get("per_asset") or []:
        if item.get("asset_uuid") == uuid:
            return item
    return {}


def _unknowns(run: RunState) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for stage, record in (run.stages or {}).items():
        for item in record.get("unknowns") or []:
            if isinstance(item, dict):
                field = item.get("field") or item.get("what") or "value"
                reason = item.get("reason") or item.get("detail") or ""
                line = f"{stage}: {field} — {reason}"
            else:
                line = f"{stage}: {item}"
            if line not in seen:
                seen.add(line)
                out.append(line)
    return out


def _coverage(run: RunState) -> list[tuple[str, str, str]]:
    exposure = run.exposure or []
    control_known = bool(exposure) and all(
        (a.get("control") or {}).get("agent_present") is not None for a in exposure
    )
    health_known = bool(exposure) and all(
        (a.get("control") or {}).get("agent_version") is not None for a in exposure
    )
    edr_known = bool(exposure) and all(
        (a.get("control") or {}).get("edr_present") is not None for a in exposure
    )
    plan = run.plan or {}
    ticket = run.ticket or {}
    containment = run.containment or []
    patch_execution = run.patch_execution or {}
    verification = run.verification or {}
    return [
        (
            "1. Agents & controls installed on endpoints and servers",
            "covered" if control_known and edr_known else "partial" if exposure else "unknown",
            "Control posture and KRI register sections — Tenable agent flag; EDR/AV when an inventory CSV is supplied.",
        ),
        (
            "2. Latest version, signature feed, and application-control modes",
            "covered"
            if health_known
            else "partial"
            if any((a.get("control") or {}).get("agent_version") for a in exposure)
            else "unknown",
            "Control posture and KRI register sections — version/feed/mode where the API or inventory exposes it; otherwise unknown with a reason.",
        ),
        (
            "3. Compensating controls / workarounds, ticketing-system ticket, infosec approval, team routing",
            "covered"
            if plan.get("compensating_controls") and ticket.get("status") in {"APPROVED", "IN_PROGRESS", "RESOLVED"}
            else "partial"
            if plan.get("compensating_controls")
            else "pending",
            "Remediation plan, ticket, and approval ledger sections.",
        ),
        (
            "4. Ticketing → NAC isolation → patch/AV → restore or infected EDR escalation",
            "covered"
            if verification and (containment or patch_execution or not plan.get("per_asset"))
            else "partial"
            if containment or patch_execution or ticket
            else "pending",
            "Ticket, containment, remediation execution, and verification sections; "
            "KRI-06/KRI-07 drive containment, the infection branch is explicit.",
        ),
        (
            "5. Waiting for action",
            "covered",
            "Run status, next actions, and approval ledger.",
        ),
        (
            "6. Reporting",
            "covered" if run.artifacts.get("markdown") else "partial",
            "This report plus stage records and the SHA-256 manifest.",
        ),
    ]


KRI_STATUS_LABELS = {
    "detected": "detected",
    "not_detected": "clear",
    "unknown": "unknown",
    "not_applicable": "n/a",
}


def _kri_ids(detections: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {str(item.get("kri_id")) for item in detections if item.get("kri_id")},
        key=lambda item: (len(item), item),
    )


def _kri_matrix(detections: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    matrix: dict[str, dict[str, dict[str, Any]]] = {}
    for item in detections:
        matrix.setdefault(str(item.get("asset_uuid")), {})[
            str(item.get("kri_id"))
        ] = item
    return matrix


def _kri_summary(
    detections: list[dict[str, Any]], ids: list[str]
) -> list[dict[str, Any]]:
    rows = []
    for kri_id in ids:
        items = [item for item in detections if item.get("kri_id") == kri_id]
        counts = {
            "detected": sum(1 for item in items if item.get("status") == "detected"),
            "not_detected": sum(1 for item in items if item.get("status") == "not_detected"),
            "unknown": sum(1 for item in items if item.get("status") == "unknown"),
            "not_applicable": sum(1 for item in items if item.get("status") == "not_applicable"),
        }
        first = items[0] if items else {}
        rows.append(
            {
                "id": kri_id,
                "name": first.get("name", ""),
                "action": first.get("action", ""),
                **counts,
            }
        )
    return rows


def _kri_status_label(status: Any) -> str:
    return KRI_STATUS_LABELS.get(str(status), str(status))


# -- Markdown -----------------------------------------------------------


def render_markdown(run: RunState) -> str:
    data = run.to_dict()
    v = data.get("vulnerability") or {}
    plan = data.get("plan") or {}
    exposure = data.get("exposure") or []
    containment = data.get("containment") or []
    verification = data.get("verification") or {}
    ticket = data.get("ticket") or {}
    truth = data.get("truthfulness") or {}
    source = data.get("source") or {}
    lines: list[str] = []
    add = lines.append

    add("# SecOps Autopilot — Evidence Report")
    add("")
    add(f"**Run:** `{run.run_id}`  ")
    add(f"**Created:** {run.created_at}  ")
    add(f"**Status:** {STATUS_TEXT.get(run.status, run.status)} (`{run.status}`)  ")
    add(f"**Target:** {run.target.get('value')}  ")
    add(f"**Data source:** {source.get('product') or source.get('name') or 'unknown'}")
    add("")
    live_reads = bool(truth.get("live_reads"))
    add(
        "> **Read this first.** "
        + (
            "Scanner reads in this run are live."
            if live_reads
            else "Scanner reads in this run are **simulated fixtures**; no scanner was contacted."
        )
        + " Ticketing, NAC, EDR and patch-management actions are **file-backed "
        "simulations** unless the run explicitly records a live connector. "
        "No host was patched by this engine; patch jobs are submissions, not "
        "proof of remediation."
    )
    add("")

    add("## 1. Executive summary")
    add("")
    if v:
        add(
            f"**{v.get('id')} — {v.get('title')}**  \n"
            f"CVSS: {_score(v.get('severity_cvss'))} ({v.get('severity_source')}); "
            f"exploited in wild: {_bool(v.get('exploited_in_wild'), 'yes', 'no')}; "
            f"patch available: {_bool(v.get('patch_available'), 'yes', 'no')}."
        )
        add("")
        if v.get("exploit_signals"):
            add("Exploit signals: " + ", ".join(v["exploit_signals"]) + ".")
            add("")
    if exposure:
        tiers = {tier: 0 for tier in TIER_ORDER}
        for asset in exposure:
            tier = (asset.get("risk") or {}).get("tier") or "unknown"
            tiers[tier] = tiers.get(tier, 0) + 1
        summary_bits = [
            f"{tiers[tier]} {tier}" for tier in TIER_ORDER if tiers.get(tier)
        ]
        if tiers.get("unknown"):
            summary_bits.append(f"{tiers['unknown']} unknown")
        add(f"**{len(exposure)} affected asset(s):** " + ", ".join(summary_bits) + ".")
        add("")
    add(f"**Next action:** {(data.get('next_actions') or ['none'])[0]}")
    add("")

    add("## 2. Data provenance and truthfulness")
    add("")
    add(f"- Tenable source: `{source.get('name')}` — {source.get('product')}")
    add(f"- Base URL: `{source.get('base_url')}`")
    add(f"- User-Agent: `{source.get('user_agent')}`")
    add(f"- Read window: last {data.get('options', {}).get('date_range', UNKNOWN)} days")
    add(
        "- Verification scan-age limit: "
        f"{(data.get('options') or {}).get('verification_max_scan_age_hours', UNKNOWN)} hours"
    )
    add(f"- Live Tenable reads: {truth.get('live_reads', UNKNOWN)}")
    control_plane = truth.get("control_plane") or {}
    for name, snapshot in control_plane.items():
        if isinstance(snapshot, dict):
            add(
                f"- {name}: {snapshot.get('product') or snapshot.get('name')} "
                f"(live={snapshot.get('live')}, simulated={snapshot.get('simulated')})"
            )
    catalog = (data.get("options") or {}).get("kri_catalog") or {}
    if catalog:
        add(
            f"- KRI catalog: {_md(catalog.get('name'))} "
            f"v{_md(catalog.get('version'))} — {catalog.get('count')} definitions"
        )
    advisory = v.get("advisory") or {}
    if advisory:
        provenance = advisory.get("provenance") or {}
        add(
            f"- Advisory: {_md(advisory.get('source'))} "
            f"[{_md(provenance.get('status', 'provided'))}] — "
            f"{_md(advisory.get('url'))}"
        )
        if provenance.get("retrieved_at"):
            add(f"- Advisory retrieved: {_md(provenance.get('retrieved_at'))}")
    if truth.get("advisory"):
        add(f"- Advisory provenance: {_md(json.dumps(truth['advisory'], sort_keys=True))}")
    add("")

    add("## 3. Stage timeline")
    add("")
    add("| Stage | Method | Kind | Gate | Status | Finished | Summary | Record |")
    add("|---|---|---|---|---|---|---|---|")
    for stage, record in (data.get("stages") or {}).items():
        contract = record.get("contract") or {}
        add(
            f"| {_md(STAGE_LABELS.get(stage, record.get('name') or stage))} | "
            f"{_md(contract.get('methodology_stage'))} | {_md(contract.get('kind'))} | "
            f"{_md(contract.get('approval_gate') or '—')} | {_md(record.get('status'))} | "
            f"{_md(record.get('finished_at'))} | {_md(record.get('summary'))} | "
            f"`{_md(record.get('data_ref'))}` |"
        )
    add("")

    add("## 4. Intake")
    add("")
    if v:
        add("| Field | Value | Source |")
        add("|---|---|---|")
        add(f"| CVE | {_md(v.get('id'))} | input |")
        add(f"| Title | {_md(v.get('title'))} | {_md(v.get('title_source'))} |")
        add(f"| Published | {_md(v.get('published'))} | scanner findings / advisory |")
        add(f"| CVSS | {_md(_score(v.get('severity_cvss')))} | {_md(v.get('severity_source'))} |")
        add(f"| CVSS v3 vector | {_md(v.get('cvss3_vector'))} | Tenable |")
        add(f"| CVSS v2 vector | {_md(v.get('cvss2_vector'))} | Tenable |")
        add(f"| Exploited in wild | {_md(_bool(v.get('exploited_in_wild'), 'yes', 'no'))} | Tenable signals |")
        add(f"| Patch available | {_md(_bool(v.get('patch_available'), 'yes', 'no'))} | Tenable plugin flags |")
        add(f"| Aliases | {_md(', '.join(v.get('aliases') or []) or UNKNOWN)} | Tenable references |")
        add(f"| Confidence | {_md(v.get('confidence'))} — {_md(v.get('confidence_reason'))} | engine |")
        if advisory:
            provenance = advisory.get("provenance") or {}
            fixed = v.get("fixed_versions") or []
            add(
                f"| Advisory source | {_md(advisory.get('source'))} | "
                f"{_md(provenance.get('status', 'provided'))} |"
            )
            add(
                f"| Advisory URL | {_md(advisory.get('url'))} | "
                f"retrieved {_md(provenance.get('retrieved_at', UNKNOWN))} |"
            )
            add(
                f"| Advisory fixed versions | "
                f"{_md(', '.join(str(item.get('fixed')) for item in fixed) or UNKNOWN)} | "
                "advisory affected ranges |"
            )
            add(
                f"| Advisory mitigations | {len(v.get('mitigation_steps') or [])} | "
                "advisory, unverified in this environment |"
            )
        add("")
        if v.get("patch_refs"):
            add("Patch references found in Tenable text: " + ", ".join(v["patch_refs"]) + ".")
            add("")
        if v.get("conflicts"):
            add("**Source conflicts**")
            add("")
            for conflict in v["conflicts"]:
                add(f"- {conflict}")
            add("")
        if v.get("notes"):
            add("**Intake notes**")
            add("")
            for note in v["notes"]:
                add(f"- {note}")
            add("")

    add("## 5. Exposure")
    add("")
    if exposure:
        add("| Asset | Address | MAC | OS | Owner | Agent | EDR | AV | KRI | Tier |")
        add("|---|---|---|---|---|---|---|---|---|---|")
        for asset in exposure:
            ref = asset.get("asset") or {}
            control = asset.get("control") or {}
            risk = asset.get("risk") or {}
            owner = asset.get("owner") or {}
            add(
                f"| {_md(_asset_name(ref))} | {_md(ref.get('ipv4'))} | {_md(ref.get('mac'))} | "
                f"{_md((ref.get('os') or [UNKNOWN])[0])} | {_md(owner.get('owner'))} | "
                f"{_md(_bool(control.get('agent_present')))} | {_md(_bool(control.get('edr_present')))} | "
                f"{_md(_bool(control.get('av_present')))} | {_md(_score(risk.get('score')))} | "
                f"{_md(risk.get('tier'))} |"
            )
        add("")
    else:
        add("No affected assets were resolved.")
        add("")

    add("## 6. Control posture")
    add("")
    if exposure:
        add("| Asset | Agent | Agent version | Agent feed age | EDR | EDR vendor | AV | AV signature age | App control | Patch agent | Gap /10 |")
        add("|---|---|---|---|---|---|---|---|---|---|---|")
        for asset in exposure:
            ref = asset.get("asset") or {}
            control = asset.get("control") or {}
            add(
                f"| {_md(_asset_name(ref))} | {_md(_bool(control.get('agent_present')))} | "
                f"{_md(control.get('agent_version'))} | {_md(_age(control.get('agent_feed_age_hours')))} | "
                f"{_md(_bool(control.get('edr_present')))} | {_md(control.get('edr_vendor'))} | "
                f"{_md(_bool(control.get('av_present')))} | {_md(_age(control.get('av_signature_age_hours')))} | "
                f"{_md(control.get('app_control_mode'))} | {_md(_bool(control.get('patch_agent_present')))} | "
                f"{_md(_score(control.get('control_gap_score')))} |"
            )
        add("")
        gaps = [
            (asset, item)
            for asset in exposure
            for item in ((asset.get("control") or {}).get("gaps") or [])
        ]
        if gaps:
            add("**Control gaps**")
            add("")
            for asset, gap in gaps:
                add(
                    f"- **{_asset_name(asset.get('asset') or {})}** — "
                    f"{gap.get('severity', 'unknown')}: {gap.get('reason')}"
                )
            add("")

    add("## 7. KRI register")
    add("")
    detections = data.get("kri_detections") or []
    if detections:
        kri_ids = _kri_ids(detections)
        kri_summary = _kri_summary(detections, kri_ids)
        matrix = _kri_matrix(detections)
        status_counts = {
            status: sum(1 for item in detections if item.get("status") == status)
            for status in ("detected", "not_detected", "unknown", "not_applicable")
        }
        add(
            f"**{len(kri_ids)} KRI definitions on {len(matrix)} asset(s).** "
            f"Detected {status_counts['detected']}, "
            f"clear {status_counts['not_detected']}, "
            f"unknown {status_counts['unknown']}, "
            f"n/a {status_counts['not_applicable']}."
        )
        add("")
        add("| KRI | Name | Detected | Clear | Unknown | N/A | Action |")
        add("|---|---|---|---|---|---|---|")
        for row in kri_summary:
            add(
                f"| {_md(row['id'])} | {_md(row['name'])} | {row['detected']} | "
                f"{row['not_detected']} | {row['unknown']} | "
                f"{row['not_applicable']} | {_md(row['action'])} |"
            )
        add("")
        add("### Per-asset KRI matrix")
        add("")
        add("| Asset | " + " | ".join(kri_ids) + " |")
        add("|---|" + "|".join(["---"] * len(kri_ids)) + "|")
        for asset_uuid, cells in matrix.items():
            hostname = next(iter(cells.values())).get("hostname", asset_uuid)
            row = [f"| {_md(hostname)} |"]
            for kri_id in kri_ids:
                status = (cells.get(kri_id) or {}).get("status")
                row.append(f" {_md(_kri_status_label(status))} |")
            add("".join(row))
        add("")
        detected_items = [
            item for item in detections if item.get("status") == "detected"
        ]
        if detected_items:
            add("### Detected KRI evidence")
            add("")
            for item in detected_items:
                evidence = "; ".join(item.get("evidence") or []).rstrip(" .")
                add(
                    f"- **{_md(item.get('kri_id'))} {_md(item.get('name'))}** on "
                    f"`{_md(item.get('hostname'))}` — {_md(evidence)}. "
                    f"Action: {_md(item.get('action'))}"
                )
            add("")
        else:
            add("No KRI was detected as present.")
            add("")
    else:
        add("No KRI register was recorded in this run.")
        add("")

    add("## 8. KRI scoring")
    add("")
    add(
        "The score is a weighted blend of severity, exploitability, exposure, control "
        "gap, and asset criticality. Unknown components are excluded and the remaining "
        "weights renormalized; the unknown list is part of the score."
    )
    add("")
    if exposure:
        add("| Asset | KRI | Tier | Severity | Exploitability | Exposure | Control gap | Criticality | Confidence |")
        add("|---|---|---|---|---|---|---|---|---|")
        for asset in exposure:
            risk = asset.get("risk") or {}
            comp = risk.get("components") or {}
            add(
                f"| {_md(_asset_name(asset.get('asset') or {}))} | {_md(_score(risk.get('score')))} | "
                f"{_md(risk.get('tier'))} | {_md(_score(comp.get('severity')))} | "
                f"{_md(_score(comp.get('exploitability')))} | {_md(_score(comp.get('exposure')))} | "
                f"{_md(_score(comp.get('control_gap')))} | {_md(_score(comp.get('criticality')))} | "
                f"{_md(risk.get('confidence'))} |"
            )
        add("")

    add("## 9. Remediation plan")
    add("")
    if plan:
        patch = plan.get("patch_path") or {}
        add(f"- Patch available: **{_bool(patch.get('available'), 'yes', 'no')}**")
        add(f"- Patch references: {_md(', '.join(patch.get('patch_refs') or []) or UNKNOWN)}")
        fixed_versions = patch.get("fixed_versions") or []
        if fixed_versions:
            add(
                "- Advisory fixed versions: "
                + ", ".join(
                    f"{item.get('product')} {item.get('fixed')} "
                    f"({item.get('branch') or 'branch unknown'}, "
                    f"{item.get('support') or 'support unknown'})"
                    for item in fixed_versions
                )
            )
        targets = patch.get("target_versions_by_asset") or {}
        if targets:
            add(
                "- Verified target versions by asset: "
                + ", ".join(f"{uuid}={version}" for uuid, version in targets.items())
            )
        add(f"- Prerequisites: {_md(patch.get('prerequisites_note') or UNKNOWN)}")
        add(f"- Rollback: {_md(patch.get('rollback') or UNKNOWN)}")
        add(f"- Plan SHA-256: `{plan.get('plan_sha256')}`")
        add("")
        controls = plan.get("compensating_controls") or []
        if controls:
            add("### Compensating controls")
            add("")
            add("| Type | Rationale | Coverage | Limitations | Verified | Reference |")
            add("|---|---|---|---|---|---|")
            for control in controls:
                add(
                    f"| {_md(control.get('type'))} | {_md(control.get('rationale'))} | "
                    f"{_md(control.get('coverage'))} | {_md(control.get('limitations'))} | "
                    f"{_md(control.get('verified'))} | {_md(control.get('reference'))} |"
                )
            add("")
        workarounds = plan.get("workarounds") or []
        if workarounds:
            add("### Workarounds")
            add("")
            for item in workarounds:
                add(
                    f"- {item.get('action')} — scope: {item.get('scope')}; "
                    f"verified: {item.get('verified', False)}; "
                    f"source: {item.get('source', UNKNOWN)}"
                    + (
                        f"; limitations: {item.get('limitations')}"
                        if item.get("limitations")
                        else ""
                    )
                )
            add("")
        add("### Per-asset path")
        add("")
        add("| Asset | Path | Runtime | Target version | Containment candidate | Reason | Owner |")
        add("|---|---|---|---|---|---|---|")
        for item in plan.get("per_asset") or []:
            add(
                f"| {_md(item.get('hostname'))} | {_md(item.get('path'))} | "
                f"{_md(item.get('runtime_product'))} {_md(item.get('runtime_version'))} | "
                f"{_md(item.get('target_version'))} | "
                f"{_md(_bool(item.get('containment_recommended'), 'yes', 'no'))} | "
                f"{_md(item.get('containment_reason') or item.get('reason'))} | "
                f"{_md(item.get('owner'))} / {_md(item.get('owner_team'))} |"
            )
        add("")
        if plan.get("notes"):
            add("**Plan notes**")
            add("")
            for note in plan["notes"]:
                add(f"- {note}")
            add("")

    add("## 10. Ticket and approvals")
    add("")
    if ticket:
        add(
            f"Ticket **{ticket.get('ticket_id')}** ({ticket.get('system')}) — "
            f"status **{ticket.get('status')}**; priority {ticket.get('priority')}; "
            f"simulated={ticket.get('simulated')}."
        )
        add("")
    if data.get("approvals"):
        add("| Gate | Decision | Approver | Recorded | Plan SHA-256 | Action |")
        add("|---|---|---|---|---|---|")
        for approval in data["approvals"]:
            add(
                f"| {_md(approval.get('gate'))} | {_md(approval.get('decision'))} | "
                f"{_md(approval.get('approver'))} | {_md(approval.get('recorded_at'))} | "
                f"`{_md(approval.get('plan_sha256'))}` | {_md(approval.get('action_taken'))} |"
            )
        add("")
    else:
        add("No approval has been recorded. The run is read-only.")
        add("")

    add("## 11. Containment")
    add("")
    if containment:
        add("| Event | Asset | MAC | Action | Status | Policy | VLAN | Approver | Simulated | Reason |")
        add("|---|---|---|---|---|---|---|---|---|---|")
        for event in containment:
            add(
                f"| {_md(event.get('event_id'))} | {_md(event.get('hostname'))} | {_md(event.get('mac'))} | "
                f"{_md(event.get('action'))} | {_md(event.get('status'))} | {_md(event.get('policy'))} | "
                f"{_md(event.get('vlan'))} | {_md(event.get('approver'))} | {_md(event.get('simulated'))} | "
                f"{_md(event.get('reason'))} |"
            )
        add("")
    else:
        add("No containment action has been executed. Containment requires an approval.")
        add("")

    add("## 12. Remediation execution")
    add("")
    patch_execution = data.get("patch_execution") or {}
    if patch_execution:
        add(
            f"Connector: **{_md(patch_execution.get('connector') or UNKNOWN)}**; "
            f"status: **{_md(patch_execution.get('status') or UNKNOWN)}**; "
            f"simulated: **{_md(patch_execution.get('simulated'))}**; "
            f"submitted: {patch_execution.get('submitted', 0)}; "
            f"skipped: {len(patch_execution.get('skipped') or [])}."
        )
        add("")
        jobs = patch_execution.get("jobs") or []
        if jobs:
            add("| Job | Asset | Package | Current | Target | Status | Touched host |")
            add("|---|---|---|---|---|---|---|")
            for job in jobs:
                add(
                    f"| {_md(job.get('job_id'))} | {_md(job.get('hostname'))} | "
                    f"{_md(job.get('package'))} | {_md(job.get('current_version'))} | "
                    f"{_md(job.get('target_version'))} | {_md(job.get('status'))} | "
                    f"{_md(job.get('touched_host'))} |"
                )
            add("")
        skipped = patch_execution.get("skipped") or []
        if skipped:
            add("**Skipped jobs (no invented target version):**")
            add("")
            for item in skipped:
                add(f"- {_md(item.get('hostname'))} — {_md(item.get('reason'))}")
            add("")
        add(
            "A submitted job is not a remediation claim. Verification below is the "
            "only accepted evidence that the vulnerability is gone."
        )
        add("")
    else:
        add("No patch execution has been recorded. A plan is not an execution.")
        add("")

    add("## 13. Verification and recovery")
    add("")
    if verification:
        add(
            f"Method: {_md(verification.get('method'))}; "
            f"remediated: {verification.get('remediated_count')}; "
            f"still affected: {verification.get('still_affected_count')}; "
            f"unknown: {verification.get('unknown_count')}; "
            f"infection: {_md(verification.get('infection_status'))}."
        )
        add("")
        add("| Asset | Before | After | Status | Infection | Last scan | Scan age (h) | Fresh | Containment |")
        add("|---|---|---|---|---|---|---|---|---|")
        for item in verification.get("assets") or []:
            evidence = item.get("evidence") or {}
            add(
                f"| {_md(item.get('hostname'))} | {_md(item.get('before_affected'))} | "
                f"{_md(item.get('after_affected'))} | {_md(item.get('status'))} | "
                f"{_md(item.get('infection_status'))} | {_md(item.get('last_scan'))} | "
                f"{_md(evidence.get('scan_age_hours'))} | {_md(evidence.get('scan_fresh'))} | "
                f"{_md(item.get('contained'))} |"
            )
        add("")
        if verification.get("new_affected_assets"):
            add("**New assets appeared during verification**")
            add("")
            for item in verification["new_affected_assets"]:
                add(f"- {item.get('hostname') or item.get('asset_uuid')} ({item.get('ipv4') or UNKNOWN})")
            add("")
        if verification.get("notes"):
            for note in verification["notes"]:
                add(f"- {note}")
            add("")
    else:
        add("Verification has not run. Absence of a verification record is not a fix.")
        add("")

    add("## 14. Open questions and unknowns")
    add("")
    unknowns = _unknowns(run)
    if unknowns:
        for item in unknowns:
            add(f"- {item}")
    else:
        add("No unknowns were recorded in this run.")
    add("")
    if data.get("next_actions"):
        add("**Next actions**")
        add("")
        for action in data["next_actions"]:
            add(f"- {action}")
        add("")

    add("## 15. KRI coverage")
    add("")
    add("| KRI requirement | Status | Where |")
    add("|---|---|---|")
    for requirement, status, where in _coverage(run):
        add(f"| {_md(requirement)} | {_md(status)} | {_md(where)} |")
    add("")

    add("## 16. Evidence integrity")
    add("")
    add("Stage records:")
    add("")
    for stage, record in (data.get("stages") or {}).items():
        add(f"- `{record.get('data_ref')}` — {STAGE_LABELS.get(stage, record.get('name'))}")
    add("")
    add(
        "Hashes are in `manifest.json` and `manifest.sha256`. Verify with: "
        f"`secops evidence --run {run.run_id} --verify`."
    )
    add("")

    add("## 17. What this run did not do")
    add("")
    add("- It did not deliver or reboot a host, or execute a patch on an endpoint.")
    add("- It did not execute containment without a recorded approval.")
    add("- It did not claim a compensating control is verified.")
    add("- It did not claim a host is clean without an EDR signal; unknown remains unknown.")
    add("- It did not invent asset owners, agent versions, feed ages, or patch schedules.")
    if (data.get("truthfulness") or {}).get("limits"):
        add("")
        for limit in data["truthfulness"]["limits"]:
            add(f"- {limit}")
    add("")
    return "\n".join(lines)


# -- HTML ---------------------------------------------------------------

_CSS = """
:root{--bg:#f4f6f8;--panel:#ffffff;--panel-2:#fafbfc;--text:#171a21;--muted:#5b6472;
--line:#dde2e8;--accent:#0b5cad;--critical:#b42318;--high:#b54708;--medium:#8a6d00;
--low:#067647;--unknown:#667085;--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.1);}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--panel:#161b22;--panel-2:#1b2129;
--text:#e6edf3;--muted:#9aa4b2;--line:#2a313b;--accent:#6cb6ff;--critical:#ff7b72;
--high:#f0a35e;--medium:#e3c95c;--low:#56d364;--unknown:#8b949e;
--shadow:0 1px 2px rgba(0,0,0,.4);}}
*{box-sizing:border-box}html{color-scheme:light dark}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 18px 64px}
header{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;justify-content:space-between;margin-bottom:22px}
h1{font-size:26px;line-height:1.2;margin:0 0 6px;letter-spacing:-.02em}
h2{font-size:19px;margin:0 0 14px;letter-spacing:-.01em}
h3{font-size:15px;margin:18px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.sub{color:var(--muted);font-size:13.5px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:5px 11px;
font-size:12.5px;font-weight:600;background:var(--panel);white-space:nowrap}
.pill.critical{color:var(--critical);border-color:color-mix(in srgb,var(--critical) 40%,var(--line))}
.pill.high{color:var(--high);border-color:color-mix(in srgb,var(--high) 40%,var(--line))}
.pill.medium{color:var(--medium);border-color:color-mix(in srgb,var(--medium) 40%,var(--line))}
.pill.low{color:var(--low);border-color:color-mix(in srgb,var(--low) 40%,var(--line))}
.pill.unknown{color:var(--unknown)}
.callout{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--line);
border-left:4px solid var(--accent);border-radius:10px;padding:15px 17px;margin:16px 0 22px;
box-shadow:var(--shadow)}
.callout strong{color:var(--text)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 24px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 15px;box-shadow:var(--shadow)}
.tile .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.tile .value{font-size:27px;font-weight:700;line-height:1.2;margin-top:4px}
.tile .note{font-size:12.5px;color:var(--muted);margin-top:3px}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;
margin:0 0 18px;box-shadow:var(--shadow)}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13.5px;min-width:620px}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--panel-2);font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
code{background:var(--panel-2);border:1px solid var(--line);border-radius:5px;padding:1px 5px;word-break:break-word}
.kri{display:flex;align-items:center;gap:8px;min-width:120px}
.kri-summary td:first-child,.kri-summary th:first-child,
.kri-matrix td:first-child,.kri-matrix th:first-child{white-space:nowrap}
.bar{flex:1;height:7px;background:var(--panel-2);border:1px solid var(--line);border-radius:999px;overflow:hidden;min-width:52px}
.bar span{display:block;height:100%;background:var(--accent)}
.bar span.critical{background:var(--critical)}.bar span.high{background:var(--high)}
.bar span.medium{background:var(--medium)}.bar span.low{background:var(--low)}
.kri b{font-variant-numeric:tabular-nums;min-width:34px;text-align:right}
.badge{display:inline-block;border-radius:6px;padding:2px 7px;font-size:11.5px;font-weight:600;
background:var(--panel-2);border:1px solid var(--line);color:var(--muted)}
.badge.critical{color:var(--critical)}.badge.high{color:var(--high)}
.badge.medium{color:var(--medium)}.badge.low{color:var(--low)}
ul{margin:8px 0 0;padding-left:22px}li{margin:4px 0}
details{margin:8px 0}summary{cursor:pointer;color:var(--accent)}
.footer{color:var(--muted);font-size:12.5px;margin-top:26px;text-align:center}
@media print{body{background:#fff}.wrap{max-width:none;padding:0}
section,.tile,.callout{box-shadow:none;break-inside:avoid}header{break-after:avoid}}
"""

def render_executive_summary(run: RunState) -> str:
    """One-page management report generated for every finalized run."""
    data = run.to_dict()
    v = data.get("vulnerability") or {}
    exposure = data.get("exposure") or []
    plan = data.get("plan") or {}
    detections = data.get("kri_detections") or []
    approvals = data.get("approvals") or []
    containment = data.get("containment") or []
    patch = data.get("patch_execution") or {}
    verification = data.get("verification") or {}
    truth = data.get("truthfulness") or {}
    source = data.get("source") or {}

    tier_counts = {tier: 0 for tier in TIER_ORDER}
    for asset in exposure:
        tier = (asset.get("risk") or {}).get("tier") or "unknown"
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    kri_counts = {
        status: sum(1 for item in detections if item.get("status") == status)
        for status in ("detected", "not_detected", "unknown", "not_applicable")
    }
    kri_detected = {
        kri_id: sum(
            1
            for item in detections
            if item.get("kri_id") == kri_id and item.get("status") == "detected"
        )
        for kri_id in sorted({str(item.get("kri_id")) for item in detections})
    }
    plan_items = plan.get("per_asset") or []
    path_counts = {
        path: sum(1 for item in plan_items if item.get("path") == path)
        for path in ("patch", "compensate", "isolate")
    }
    target_assets = sum(1 for item in plan_items if item.get("target_version"))
    containment_candidates = sum(
        1 for item in plan_items if item.get("containment_recommended")
    )
    isolated = sum(1 for item in containment if item.get("status") == "isolated")
    blocked = sum(1 for item in containment if item.get("status") == "blocked")
    failed = sum(1 for item in containment if item.get("status") == "failed")
    restored = sum(
        1
        for item in containment
        if item.get("action") == "restore" and item.get("status") == "restored"
    )
    unknown_total = sum(
        len(record.get("unknowns") or [])
        for record in (data.get("stages") or {}).values()
    )
    top_assets = sorted(
        exposure,
        key=lambda item: (item.get("risk") or {}).get("score") or 0,
        reverse=True,
    )[:5]

    lines: list[str] = []
    add = lines.append
    add("# Executive summary for management")
    add("")
    add(f"**Vulnerability:** {_md(v.get('id') or run.target.get('value'))} — {_md(v.get('title'))}")
    add(f"**Run:** `{run.run_id}`  ")
    add(f"**Status:** {STATUS_TEXT.get(run.status, run.status)} (`{run.status}`)  ")
    add(f"**Source:** {_md(source.get('product') or source.get('name'))} "
        f"(live reads: {_md(truth.get('live_reads'))})  ")
    add(f"**Created / updated:** {_md(run.created_at)} / {_md(run.updated_at)}")
    add("")
    add("## Bottom line")
    add("")
    if exposure:
        add(
            f"{len(exposure)} affected asset(s): "
            + ", ".join(f"{tier_counts[tier]} {tier}" for tier in TIER_ORDER if tier_counts.get(tier))
            + f". KRI register: {kri_counts['detected']} detected, "
            f"{kri_counts['unknown']} unknown, {kri_counts['not_detected']} clear, "
            f"{kri_counts['not_applicable']} not applicable."
        )
    else:
        add("No affected assets were resolved; no remediation decision is supported.")
    add(
        f"Remediation plan: {path_counts['patch']} patch, "
        f"{path_counts['compensate']} compensate, {path_counts['isolate']} isolate; "
        f"verified target version on {target_assets} asset(s). "
        f"Containment candidates: {containment_candidates}."
    )
    if containment:
        add(
            f"Containment executed: {isolated} isolated, {blocked} blocked, {failed} failed; "
            f"{restored} restored after verification."
        )
    if patch:
        add(
            f"Patch execution: {patch.get('status')} — "
            f"{patch.get('submitted', 0)} submitted, "
            f"{len(patch.get('skipped') or [])} skipped; "
            f"simulated={patch.get('simulated')}."
        )
    if verification:
        add(
            f"Verification: {verification.get('remediated_count', 0)} remediated, "
            f"{verification.get('still_affected_count', 0)} still affected, "
            f"{verification.get('unknown_count', 0)} unknown; "
            f"infection status: {verification.get('infection_status', 'unknown')}."
        )
    add("")
    add("## Numbers at a glance")
    add("")
    add("| Metric | Value |")
    add("|---|---|")
    rows = [
        ("Affected assets", len(exposure)),
        ("Critical / high / medium / low", f"{tier_counts['critical']} / {tier_counts['high']} / {tier_counts['medium']} / {tier_counts['low']}"),
        ("KRI detected / clear / unknown / n/a", f"{kri_counts['detected']} / {kri_counts['not_detected']} / {kri_counts['unknown']} / {kri_counts['not_applicable']}"),
        ("Plan paths patch / compensate / isolate", f"{path_counts['patch']} / {path_counts['compensate']} / {path_counts['isolate']}"),
        ("Assets with a verified target version", target_assets),
        ("Containment candidates", containment_candidates),
        ("Containment isolated / blocked / failed", f"{isolated} / {blocked} / {failed}"),
        ("Restored after verification", restored),
        ("Patch jobs submitted / skipped", f"{patch.get('submitted', 0)} / {len(patch.get('skipped') or [])}"),
        ("Verification remediated / still affected / unknown", f"{verification.get('remediated_count', 0)} / {verification.get('still_affected_count', 0)} / {verification.get('unknown_count', 0)}"),
        ("Approval gates recorded", len(approvals)),
        ("Explicit unknown fields recorded", unknown_total),
    ]
    for label, value in rows:
        add(f"| {label} | {value} |")
    add("")
    add("## Risk and control insights")
    add("")
    if top_assets:
        add("**Highest-risk assets**")
        add("")
        add("| Asset | KRI score | Tier | Owner |")
        add("|---|---|---|---|")
        for asset in top_assets:
            ref = asset.get("asset") or {}
            add(
                f"| {_md(_asset_name(ref))} | {_md(_score((asset.get('risk') or {}).get('score')))} | "
                f"{_md((asset.get('risk') or {}).get('tier'))} | "
                f"{_md((asset.get('owner') or {}).get('owner'))} |"
            )
        add("")
    detected_bits = ", ".join(
        f"{kri_id} x{count}" for kri_id, count in kri_detected.items() if count
    )
    add(f"- **KRI detections:** {detected_bits or 'none'}.")
    add(
        f"- **Control confidence:** {kri_counts['unknown']} KRI evaluation(s) are unknown. "
        "Unknown is not clear; a control gap or missing connector is driving the gap."
    )
    add(
        f"- **Remediation readiness:** {target_assets} of {len(plan_items)} planned asset(s) "
        "have a verified target version. A patch gate will skip the rest."
    )
    add(
        f"- **Containment and recovery:** {isolated} isolated, {blocked} blocked; "
        f"{restored} restored. Restore is only eligible after fresh verification and no infection."
    )
    add("")
    add("## Decisions and next actions")
    add("")
    actions = data.get("next_actions") or []
    if actions:
        for action in actions:
            add(f"- {action}")
    else:
        add("- No pending action is recorded.")
    add("")
    add("## What this report does not prove")
    add("")
    add("- It does not prove that a patch was delivered or that a host was rebooted.")
    add("- It does not turn an unknown control state into a clear state.")
    add("- It does not prove real-world exploitability beyond the scanner's claim.")
    if not truth.get("live_reads"):
        add("- This run used simulated scanner/control-plane fixtures; the report is not production evidence.")
    add("")
    add("## Evidence")
    add("")
    add(f"- Markdown report: `report.md`")
    add(f"- HTML report: `report.html`")
    add(f"- SHA-256 manifest: `manifest.json` / `manifest.sha256`")
    add(f"- Run directory: `runs/{run.run_id}/`")
    add("")
    return "\n".join(lines)


def _h(value: Any) -> str:
    return html.escape(_text(value))


def _tier_badge(tier: Any) -> str:
    name = str(tier or "unknown").lower()
    return f'<span class="badge {html.escape(name)}">{html.escape(name)}</span>'


def _kri_badge(status: Any) -> str:
    kind = {
        "detected": "critical",
        "not_detected": "low",
        "unknown": "unknown",
        "not_applicable": "unknown",
    }.get(str(status), "unknown")
    return (
        f'<span class="badge {kind}">'
        f"{_h(_kri_status_label(status))}</span>"
    )


def _kri_cell(score: Any, tier: Any) -> str:
    value = float(score) if isinstance(score, (int, float)) else 0.0
    pct = max(0.0, min(100.0, value))
    kind = str(tier or "unknown").lower()
    return (
        f'<div class="kri"><div class="bar"><span class="{html.escape(kind)}" '
        f'style="width:{pct:.1f}%"></span></div><b>{pct:.1f}</b></div>'
    )


def _table(
    headers: list[str],
    rows: list[list[str]],
    *,
    raw: bool = False,
    class_name: str = "",
) -> str:
    head = "".join(f"<th>{_h(header)}</th>" for header in headers)
    body = []
    for row in rows:
        cells = []
        for cell in row:
            cells.append(f"<td>{cell if raw else _h(cell)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    cls = f' class="{html.escape(class_name)}"' if class_name else ""
    return (
        f'<div class="table-wrap"><table{cls}><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def _section(title: str, body: str, anchor: str) -> str:
    return f'<section id="{html.escape(anchor)}"><h2>{_h(title)}</h2>{body}</section>'


def render_html(run: RunState) -> str:
    data = run.to_dict()
    v = data.get("vulnerability") or {}
    plan = data.get("plan") or {}
    exposure = data.get("exposure") or []
    containment = data.get("containment") or []
    verification = data.get("verification") or {}
    ticket = data.get("ticket") or {}
    truth = data.get("truthfulness") or {}
    source = data.get("source") or {}

    tiers = {tier: 0 for tier in TIER_ORDER}
    for asset in exposure:
        tier = (asset.get("risk") or {}).get("tier", "low")
        tiers[tier] = tiers.get(tier, 0) + 1
    contained = sum(1 for event in containment if event.get("status") == "isolated")
    remediated = int(verification.get("remediated_count") or 0)
    riskiest = max(
        exposure,
        key=lambda item: (item.get("risk") or {}).get("score") or 0,
        default=None,
    )

    status = str(run.status)
    status_class = (
        "critical"
        if status in {"escalated", "remediation_rejected", "stage_failed"}
        else "high"
        if "awaiting" in status
        else "low"
        if status in {"verified_remediated", "restored", "complete"}
        else "unknown"
    )

    live_reads = bool(truth.get("live_reads"))
    callout = (
        '<div class="callout">'
        "<strong>Read this first.</strong> "
        + (
            "Scanner reads in this run are live."
            if live_reads
            else "Scanner reads in this run are <strong>simulated fixtures</strong>; "
            "no scanner was contacted."
        )
        + " Ticketing, NAC, EDR and patch-management actions are file-backed "
        "simulations unless the run records a live connector. No host was patched "
        "by this engine; patch jobs are submissions, not proof of remediation."
        "</div>"
    )

    headline = v.get("title") or "Vulnerability run"
    if len(headline) > 118:
        headline = headline[:115].rstrip() + "…"
    head = f"""
<header>
  <div>
    <div class="sub">SecOps Autopilot · evidence report</div>
    <h1><span class="mono">{_h(v.get('id') or run.target.get('value'))}</span> — {_h(headline)}</h1>
    <div class="sub mono">{_h(run.run_id)} · created {_h(run.created_at)} · source {_h(source.get('name'))}</div>
  </div>
  <div><span class="pill {status_class}">{_h(STATUS_TEXT.get(status, status))}</span></div>
</header>
"""
    detected_kri = sum(
        1
        for item in (data.get("kri_detections") or [])
        if item.get("status") == "detected"
    )
    tiles = f"""
<div class="grid">
  <div class="tile"><div class="label">Affected assets</div><div class="value">{len(exposure)}</div><div class="note">{tiers.get('critical',0)} critical · {tiers.get('high',0)} high KRI</div></div>
  <div class="tile"><div class="label">KRI detections</div><div class="value">{detected_kri}</div><div class="note">KRI-01 … KRI-09</div></div>
  <div class="tile"><div class="label">Top KRI</div><div class="value">{_score((riskiest or {}).get('risk', {}).get('score')).replace('.0','')}</div><div class="note">{_h((riskiest or {}).get('asset', {}).get('hostname') or '—')}</div></div>
  <div class="tile"><div class="label">Contained</div><div class="value">{contained}</div><div class="note">approval-gated NAC events</div></div>
  <div class="tile"><div class="label">Verified remediated</div><div class="value">{remediated}</div><div class="note">from a fresh Tenable query</div></div>
  <div class="tile"><div class="label">Patch path</div><div class="value" style="font-size:18px">{_h('available' if (plan.get('patch_path') or {}).get('available') is True else 'unknown' if (plan.get('patch_path') or {}).get('available') is None else 'none')}</div><div class="note">{_h(', '.join((plan.get('patch_path') or {}).get('patch_refs') or [])[:80] or 'no reference found')}</div></div>
  <div class="tile"><div class="label">Ticket</div><div class="value" style="font-size:18px">{_h(ticket.get('status') or 'not created')}</div><div class="note">{_h(ticket.get('ticket_id') or 'approval pending')}</div></div>
</div>
"""

    provenance_rows = [
        ["Tenable source", f"{source.get('name')} — {source.get('product')}"],
        ["Base URL", source.get("base_url")],
        ["User-Agent", source.get("user_agent")],
        ["Window", f"last {data.get('options', {}).get('date_range', UNKNOWN)} days"],
        [
            "Verification scan-age limit",
            f"{(data.get('options') or {}).get('verification_max_scan_age_hours', UNKNOWN)} hours",
        ],
        ["Live Tenable reads", str(truth.get("live_reads", UNKNOWN))],
    ]
    for name, snapshot in (truth.get("control_plane") or {}).items():
        if isinstance(snapshot, dict):
            provenance_rows.append(
                [
                    name,
                    f"{snapshot.get('product') or snapshot.get('name')} · live={snapshot.get('live')} · simulated={snapshot.get('simulated')}",
                ]
            )
    catalog = (data.get("options") or {}).get("kri_catalog") or {}
    if catalog:
        provenance_rows.append(
            [
                "KRI catalog",
                f"{catalog.get('name')} v{catalog.get('version')} · {catalog.get('count')} definitions",
            ]
        )
    advisory = v.get("advisory") or {}
    if advisory:
        provenance_rows.append(
            [
                "Advisory",
                f"{advisory.get('source')} "
                f"[{(advisory.get('provenance') or {}).get('status', 'provided')}] · "
                f"{advisory.get('url')}",
            ]
        )
    provenance = _table(["Item", "Value"], provenance_rows)

    timeline_rows = []
    for stage, record in (data.get("stages") or {}).items():
        contract = record.get("contract") or {}
        timeline_rows.append(
            [
                STAGE_LABELS.get(stage, record.get("name") or stage),
                contract.get("methodology_stage"),
                contract.get("kind"),
                contract.get("approval_gate") or "—",
                record.get("status"),
                record.get("finished_at"),
                record.get("summary"),
                record.get("data_ref"),
            ]
        )
    timeline = _table(
        ["Stage", "Method", "Kind", "Gate", "Status", "Finished", "Summary", "Record"],
        timeline_rows,
    )

    intake_rows = [
        ["CVE", v.get("id"), "input"],
        ["Title", v.get("title"), v.get("title_source")],
        ["Published", v.get("published"), "scanner findings / advisory"],
        ["CVSS", _score(v.get("severity_cvss")), v.get("severity_source")],
        ["CVSS v3 vector", v.get("cvss3_vector"), "Tenable"],
        ["CVSS v2 vector", v.get("cvss2_vector"), "Tenable"],
        ["Exploited in wild", _bool(v.get("exploited_in_wild"), "yes", "no"), "Tenable signals"],
        ["Patch available", _bool(v.get("patch_available"), "yes", "no"), "Tenable plugin flags"],
        ["Aliases", ", ".join(v.get("aliases") or []) or UNKNOWN, "Tenable references"],
        ["Confidence", f"{v.get('confidence')} — {v.get('confidence_reason')}", "engine"],
    ]
    if advisory:
        provenance_meta = advisory.get("provenance") or {}
        fixed = v.get("fixed_versions") or []
        intake_rows.extend(
            [
                [
                    "Advisory source",
                    advisory.get("source"),
                    provenance_meta.get("status", "provided"),
                ],
                [
                    "Advisory URL",
                    advisory.get("url"),
                    f"retrieved {provenance_meta.get('retrieved_at', UNKNOWN)}",
                ],
                [
                    "Advisory fixed versions",
                    ", ".join(str(item.get("fixed")) for item in fixed) or UNKNOWN,
                    "advisory affected ranges",
                ],
                [
                    "Advisory mitigations",
                    str(len(v.get("mitigation_steps") or [])),
                    "advisory, unverified in this environment",
                ],
            ]
        )
    intake = _table(["Field", "Value", "Source"], intake_rows)
    if v.get("conflicts"):
        intake += "<h3>Source conflicts</h3><ul>" + "".join(
            f"<li>{_h(item)}</li>" for item in v["conflicts"]
        ) + "</ul>"
    if v.get("notes"):
        intake += "<h3>Intake notes</h3><ul>" + "".join(
            f"<li>{_h(item)}</li>" for item in v["notes"]
        ) + "</ul>"

    exposure_rows = []
    control_rows = []
    kri_rows = []
    for asset in exposure:
        ref = asset.get("asset") or {}
        control = asset.get("control") or {}
        risk = asset.get("risk") or {}
        owner = asset.get("owner") or {}
        exposure_rows.append(
            [
                _asset_name(ref),
                ref.get("ipv4"),
                ref.get("mac"),
                (ref.get("os") or [UNKNOWN])[0],
                owner.get("owner"),
                _bool(control.get("agent_present")),
                _bool(control.get("edr_present")),
                _bool(control.get("av_present")),
                _score(risk.get("score")),
                risk.get("tier"),
            ]
        )
        control_rows.append(
            [
                _asset_name(ref),
                _bool(control.get("agent_present")),
                control.get("agent_version"),
                _age(control.get("agent_feed_age_hours")),
                _bool(control.get("edr_present")),
                control.get("edr_vendor"),
                _bool(control.get("av_present")),
                _age(control.get("av_signature_age_hours")),
                control.get("app_control_mode"),
                _bool(control.get("patch_agent_present")),
                _score(control.get("control_gap_score")),
            ]
        )
        components = risk.get("components") or {}
        kri_rows.append(
            [
                _h(_asset_name(ref)),
                _kri_cell(risk.get("score"), risk.get("tier")),
                _h(risk.get("tier")),
                _h(_score(components.get("severity"))),
                _h(_score(components.get("exploitability"))),
                _h(_score(components.get("exposure"))),
                _h(_score(components.get("control_gap"))),
                _h(_score(components.get("criticality"))),
                _h(risk.get("confidence")),
            ]
        )
    exposure_table = _table(
        ["Asset", "Address", "MAC", "OS", "Owner", "Agent", "EDR", "AV", "KRI", "Tier"],
        exposure_rows,
    ) if exposure_rows else "<p>No affected assets were resolved.</p>"
    control_table = _table(
        ["Asset", "Agent", "Version", "Feed age", "EDR", "EDR vendor", "AV", "Sig age", "App mode", "Patch agent", "Gap /10"],
        control_rows,
    ) if control_rows else "<p>No control posture recorded.</p>"
    kri_table = _table(
        ["Asset", "KRI", "Tier", "Severity", "Exploitability", "Exposure", "Control gap", "Criticality", "Confidence"],
        kri_rows,
        raw=True,
    ) if kri_rows else "<p>No KRI scores.</p>"
    gaps_html = ""
    gaps = [
        (asset, item)
        for asset in exposure
        for item in ((asset.get("control") or {}).get("gaps") or [])
    ]
    if gaps:
        gaps_html = "<h3>Control gaps</h3><ul>" + "".join(
            f"<li><strong>{_h(_asset_name(asset.get('asset') or {}))}</strong> — "
            f"{_h(gap.get('severity', 'unknown'))}: {_h(gap.get('reason'))}</li>"
            for asset, gap in gaps
        ) + "</ul>"

    detections = data.get("kri_detections") or []
    if detections:
        kri_ids = _kri_ids(detections)
        summary_rows = _kri_summary(detections, kri_ids)
        matrix = _kri_matrix(detections)
        status_counts = {
            status: sum(1 for item in detections if item.get("status") == status)
            for status in ("detected", "not_detected", "unknown", "not_applicable")
        }
        kri_html = (
            f"<p><strong>{len(kri_ids)} KRI definitions on {len(matrix)} asset(s).</strong> "
            f"Detected {status_counts['detected']}, clear {status_counts['not_detected']}, "
            f"unknown {status_counts['unknown']}, n/a {status_counts['not_applicable']}.</p>"
        )
        kri_html += _table(
            ["KRI", "Name", "Detected", "Clear", "Unknown", "N/A", "Action"],
            [
                [
                    row["id"],
                    row["name"],
                    row["detected"],
                    row["not_detected"],
                    row["unknown"],
                    row["not_applicable"],
                    row["action"],
                ]
                for row in summary_rows
            ],
            class_name="kri-summary",
        )
        matrix_rows = []
        for asset_uuid, cells in matrix.items():
            hostname = next(iter(cells.values())).get("hostname", asset_uuid)
            matrix_rows.append(
                [_h(hostname)]
                + [
                    _kri_badge((cells.get(kri_id) or {}).get("status"))
                    for kri_id in kri_ids
                ]
            )
        kri_html += "<h3>Per-asset KRI matrix</h3>" + _table(
            ["Asset"] + kri_ids, matrix_rows, raw=True, class_name="kri-matrix"
        )
        detected_items = [
            item for item in detections if item.get("status") == "detected"
        ]
        if detected_items:
            kri_html += "<h3>Detected KRI evidence</h3><ul>" + "".join(
                f"<li><strong>{_h(item.get('kri_id'))} {_h(item.get('name'))}</strong> "
                f"on <code>{_h(item.get('hostname'))}</code> — "
                f"{_h('; '.join(item.get('evidence') or []).rstrip(' .'))}. "
                f"Action: {_h(item.get('action'))}</li>"
                for item in detected_items
            ) + "</ul>"
        else:
            kri_html += "<p>No KRI was detected as present.</p>"
    else:
        kri_html = "<p>No KRI register was recorded in this run.</p>"

    plan_html = ""
    if plan:
        patch = plan.get("patch_path") or {}
        plan_html += (
            f"<p><strong>Patch available:</strong> {_h(_bool(patch.get('available'), 'yes', 'no'))}<br>"
            f"<strong>References:</strong> {_h(', '.join(patch.get('patch_refs') or []) or UNKNOWN)}<br>"
            + (
                "<strong>Advisory fixed versions:</strong> "
                + _h(
                    ", ".join(
                        f"{item.get('product')} {item.get('fixed')} "
                        f"({item.get('branch') or 'branch unknown'}, "
                        f"{item.get('support') or 'support unknown'})"
                        for item in patch.get("fixed_versions") or []
                    )
                )
                + "<br>"
                if patch.get("fixed_versions")
                else ""
            )
            + (
                "<strong>Verified target versions:</strong> "
                + _h(
                    ", ".join(
                        f"{uuid}={version}"
                        for uuid, version in (
                            patch.get("target_versions_by_asset") or {}
                        ).items()
                    )
                )
                + "<br>"
                if patch.get("target_versions_by_asset")
                else ""
            )
            + f"<strong>Prerequisites:</strong> {_h(patch.get('prerequisites_note') or UNKNOWN)}<br>"
            f"<strong>Rollback:</strong> {_h(patch.get('rollback') or UNKNOWN)}<br>"
            f"<strong>Plan SHA-256:</strong> <code>{_h(plan.get('plan_sha256'))}</code></p>"
        )
        controls = plan.get("compensating_controls") or []
        if controls:
            plan_html += "<h3>Compensating controls</h3>" + _table(
                ["Type", "Rationale", "Coverage", "Limitations", "Verified", "Reference"],
                [
                    [
                        item.get("type"),
                        item.get("rationale"),
                        item.get("coverage"),
                        item.get("limitations"),
                        str(item.get("verified")),
                        item.get("reference"),
                    ]
                    for item in controls
                ],
            )
        if plan.get("workarounds"):
            plan_html += "<h3>Workarounds</h3><ul>" + "".join(
                f"<li>{_h(item.get('action'))} — scope: {_h(item.get('scope'))}; verified: false.</li>"
                for item in plan["workarounds"]
            ) + "</ul>"
        plan_html += "<h3>Per-asset path</h3>" + _table(
            ["Asset", "Path", "Runtime", "Target", "Containment", "Reason", "Owner"],
            [
                [
                    item.get("hostname"),
                    item.get("path"),
                    f"{item.get('runtime_product') or UNKNOWN} "
                    f"{item.get('runtime_version') or ''}".strip(),
                    item.get("target_version") or UNKNOWN,
                    _bool(item.get("containment_recommended"), "yes", "no"),
                    item.get("containment_reason") or item.get("reason"),
                    f"{item.get('owner')} / {item.get('owner_team')}",
                ]
                for item in plan.get("per_asset") or []
            ],
        )
        if plan.get("notes"):
            plan_html += "<h3>Plan notes</h3><ul>" + "".join(
                f"<li>{_h(note)}</li>" for note in plan["notes"]
            ) + "</ul>"

    ticket_html = ""
    if ticket:
        ticket_html += (
            f"<p>Ticket <strong>{_h(ticket.get('ticket_id'))}</strong> "
            f"({_h(ticket.get('system'))}) — status <strong>{_h(ticket.get('status'))}</strong>; "
            f"priority {_h(ticket.get('priority'))}; simulated={_h(ticket.get('simulated'))}.</p>"
        )
    if data.get("approvals"):
        ticket_html += _table(
            ["Gate", "Decision", "Approver", "Recorded", "Plan SHA-256", "Action"],
            [
                [
                    item.get("gate"),
                    item.get("decision"),
                    item.get("approver"),
                    item.get("recorded_at"),
                    item.get("plan_sha256"),
                    item.get("action_taken"),
                ]
                for item in data["approvals"]
            ],
        )
    else:
        ticket_html += "<p>No approval has been recorded. The run is read-only.</p>"

    containment_html = _table(
        ["Event", "Asset", "MAC", "Action", "Status", "Policy", "VLAN", "Approver", "Simulated", "Reason"],
        [
            [
                item.get("event_id"),
                item.get("hostname"),
                item.get("mac"),
                item.get("action"),
                item.get("status"),
                item.get("policy"),
                item.get("vlan"),
                item.get("approver"),
                item.get("simulated"),
                item.get("reason"),
            ]
            for item in containment
        ],
    ) if containment else "<p>No containment action has been executed.</p>"

    patch_execution = data.get("patch_execution") or {}
    if patch_execution:
        patch_execution_html = (
            f"<p>Connector <strong>{_h(patch_execution.get('connector') or UNKNOWN)}</strong> · "
            f"status <strong>{_h(patch_execution.get('status') or UNKNOWN)}</strong> · "
            f"simulated <strong>{_h(patch_execution.get('simulated'))}</strong> · "
            f"submitted {_h(patch_execution.get('submitted', 0))} · "
            f"skipped {len(patch_execution.get('skipped') or [])}.</p>"
        )
        jobs = patch_execution.get("jobs") or []
        if jobs:
            patch_execution_html += _table(
                ["Job", "Asset", "Package", "Current", "Target", "Status", "Touched host"],
                [
                    [
                        item.get("job_id"),
                        item.get("hostname"),
                        item.get("package"),
                        item.get("current_version"),
                        item.get("target_version"),
                        item.get("status"),
                        item.get("touched_host"),
                    ]
                    for item in jobs
                ],
            )
        if patch_execution.get("skipped"):
            patch_execution_html += "<h3>Skipped jobs (no invented target version)</h3><ul>" + "".join(
                f"<li>{_h(item.get('hostname'))} — {_h(item.get('reason'))}</li>"
                for item in patch_execution["skipped"]
            ) + "</ul>"
        patch_execution_html += (
            "<p>A submitted job is not a remediation claim. Verification is the "
            "only accepted evidence that the vulnerability is gone.</p>"
        )
    else:
        patch_execution_html = "<p>No patch execution has been recorded. A plan is not an execution.</p>"

    verification_html = ""
    if verification:
        verification_html += (
            f"<p>Method: <code>{_h(verification.get('method'))}</code> · "
            f"remediated {verification.get('remediated_count')} · "
            f"still affected {verification.get('still_affected_count')} · "
            f"unknown {verification.get('unknown_count')} · "
            f"infection {_h(verification.get('infection_status'))}.</p>"
        )
        verification_html += _table(
            ["Asset", "Before", "After", "Status", "Infection", "Last scan", "Scan age (h)", "Fresh", "Containment"],
            [
                [
                    item.get("hostname"),
                    str(item.get("before_affected")),
                    str(item.get("after_affected")),
                    item.get("status"),
                    item.get("infection_status"),
                    item.get("last_scan"),
                    (item.get("evidence") or {}).get("scan_age_hours"),
                    (item.get("evidence") or {}).get("scan_fresh"),
                    str(item.get("contained")),
                ]
                for item in verification.get("assets") or []
            ],
        )
        if verification.get("new_affected_assets"):
            verification_html += "<h3>New assets appeared during verification</h3><ul>" + "".join(
                f"<li>{_h(item.get('hostname') or item.get('asset_uuid'))} "
                f"({_h(item.get('ipv4') or UNKNOWN)})</li>"
                for item in verification["new_affected_assets"]
            ) + "</ul>"
        if verification.get("notes"):
            verification_html += "<ul>" + "".join(
                f"<li>{_h(note)}</li>" for note in verification["notes"]
            ) + "</ul>"
    else:
        verification_html = "<p>Verification has not run. Absence of a verification record is not a fix.</p>"

    unknown_items = _unknowns(run)
    unknowns_html = (
        "<ul>" + "".join(f"<li>{_h(item)}</li>" for item in unknown_items) + "</ul>"
        if unknown_items
        else "<p>No unknowns were recorded in this run.</p>"
    )
    if data.get("next_actions"):
        unknowns_html += "<h3>Next actions</h3><ul>" + "".join(
            f"<li>{_h(action)}</li>" for action in data["next_actions"]
        ) + "</ul>"

    coverage_html = _table(
        ["KRI requirement", "Status", "Where"],
        [[item[0], item[1], item[2]] for item in _coverage(run)],
    )

    stage_files = "".join(
        f"<li><code>{_h(record.get('data_ref'))}</code> — "
        f"{_h(STAGE_LABELS.get(stage, record.get('name')))}</li>"
        for stage, record in (data.get("stages") or {}).items()
    )
    evidence_html = (
        f"<ul>{stage_files}</ul>"
        "<p>Hashes are recorded in <code>manifest.json</code> and "
        "<code>manifest.sha256</code>. Verify with "
        f"<code>secops evidence --run {_h(run.run_id)} --verify</code>.</p>"
    )

    limits = "".join(
        f"<li>{_h(item)}</li>" for item in (truth.get("limits") or [])
    )
    not_done = """
<ul>
  <li>It did not deliver or reboot a host, or execute a patch on an endpoint.</li>
  <li>It did not execute containment without a recorded approval.</li>
  <li>It did not claim a compensating control is verified.</li>
  <li>It did not claim a host is clean without an EDR signal; unknown remains unknown.</li>
  <li>It did not invent asset owners, agent versions, feed ages, patch targets, or patch schedules.</li>
  {limits}
</ul>
""".format(limits=limits)

    body = [
        head,
        callout,
        tiles,
        _section("Data provenance and truthfulness", provenance, "provenance"),
        _section("Stage timeline", timeline, "timeline"),
        _section("Intake", intake, "intake"),
        _section("Exposure", exposure_table, "exposure"),
        _section("Control posture", control_table + gaps_html, "controls"),
        _section("KRI register", kri_html, "kri-register"),
        _section(
            "KRI scoring",
            "<p>The score blends severity, exploitability, exposure, control gap, and asset "
            "criticality. Unknown components are excluded and the remaining weights "
            "renormalized; the unknown list is part of the score.</p>" + kri_table,
            "kri",
        ),
        _section("Remediation plan", plan_html or "<p>No plan yet.</p>", "plan"),
        _section("Ticket and approvals", ticket_html, "ticket"),
        _section("Containment", containment_html, "containment"),
        _section("Remediation execution", patch_execution_html, "patch-execution"),
        _section("Verification and recovery", verification_html, "verification"),
        _section("Open questions and unknowns", unknowns_html, "unknowns"),
        _section("KRI coverage", coverage_html, "coverage"),
        _section("Evidence integrity", evidence_html, "evidence"),
        _section("What this run did not do", not_done, "limits"),
        f'<div class="footer">SecOps Autopilot · {_h(run.run_id)} · '
        "generated from the run records; no external assets loaded.</div>",
    ]
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>SecOps Autopilot — {_h(run.run_id)}</title>"
        f"<style>{_CSS}</style></head><body><div class=\"wrap\">"
        + "".join(body)
        + "</div></body></html>"
    )
