"""Stage 6 — ticketing and infosec approval.

Both actions are state-changing and reachable only through ``Pipeline.approve``
with the matching gate and a non-empty approver. The ticket is bound to the
plan SHA-256; the infosec decision is recorded separately so a ticket update
cannot be mistaken for remediation approval.
"""

from __future__ import annotations

from collections import defaultdict

from ..errors import ConnectorError, StateError
from ..models import (
    GATE_REMEDIATION,
    GATE_TICKET,
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_AWAITING_REMEDIATION_APPROVAL,
    STATUS_AWAITING_TICKET_APPROVAL,
    STATUS_REMEDIATION_REJECTED,
)
from ..util import utc_now
from .context import StageContext


def approve_ticket(ctx: StageContext, approver: str, note: str):
    run = ctx.workflow.run
    if run.status != STATUS_AWAITING_TICKET_APPROVAL:
        raise StateError(f"ticket creation is not pending (status: {run.status})")
    plan = run.plan or {}
    vulnerability = run.vulnerability or {}
    tiers: dict[str, int] = defaultdict(int)
    for asset in run.exposure or []:
        tiers[(asset.get("risk") or {}).get("tier", "unknown")] += 1
    owners_known = sum(
        1
        for asset in run.exposure or []
        if (asset.get("owner") or {}).get("owner") not in (None, "unknown")
    )
    payload = {
        "run_id": run.run_id,
        "vulnerability_id": vulnerability.get("id"),
        "title": vulnerability.get("title"),
        "priority": _priority(tiers),
        "asset_count": len(run.exposure or []),
        "kri_tiers": dict(tiers),
        "plan_sha256": plan.get("plan_sha256"),
        "evidence_ref": str(ctx.store.run_dir(run.run_id)),
        "owner_summary": {
            "known": owners_known,
            "unknown": len(run.exposure or []) - owners_known,
        },
        "summary": (
            f"{vulnerability.get('id')} affects {len(run.exposure or [])} asset(s); "
            f"containment candidates: "
            f"{sum(1 for item in plan.get('per_asset') or [] if item.get('containment_recommended'))}. "
            "Infosec approval is required before containment or patch execution."
        ),
    }
    started = utc_now()
    try:
        ticket = ctx.ticketing.create_ticket(payload)
    except ConnectorError as exc:
        ctx.emit(
            "ticket",
            {"error": str(exc), "payload": payload},
            summary="Ticketing-system ticket creation failed.",
            status="error",
            started_at=started,
            errors=[str(exc)],
        )
        raise
    run.ticket = ticket
    ctx.record_approval(
        run,
        gate=GATE_TICKET,
        decision="approve",
        approver=approver,
        note=note,
        action_taken="Ticketing-system ticket created",
        result_ref=str(ticket.get("ticket_id")),
    )
    run.status = STATUS_AWAITING_REMEDIATION_APPROVAL
    run.next_actions = [
        f"Record infosec remediation approval: secops approve --run {run.run_id} "
        f'--gate remediation --approver "<infosec approver>"'
    ]
    ctx.emit(
        "ticket",
        {"ticket": ticket, "payload": payload},
        summary=(
            f"Ticket {ticket.get('ticket_id')} created as "
            f"{ticket.get('status')}; awaiting infosec remediation approval."
        ),
        started_at=started,
    )
    return run


def approve_remediation(
    ctx: StageContext, approver: str, note: str, *, reject: bool
):
    run = ctx.workflow.run
    if run.status != STATUS_AWAITING_REMEDIATION_APPROVAL:
        raise StateError(
            f"remediation approval is not pending (status: {run.status})"
        )
    ticket = run.ticket or {}
    ticket_id = ticket.get("ticket_id")
    if not ticket_id:
        raise StateError("run has no ticket to approve")
    started = utc_now()
    if reject:
        updated = ctx.ticketing.reject_ticket(ticket_id, approver, note)
        run.ticket = updated
        ctx.record_approval(
            run,
            gate=GATE_REMEDIATION,
            decision="reject",
            approver=approver,
            note=note,
            action_taken="Ticketing-system ticket rejected; no containment or patch executed",
            result_ref=str(ticket_id),
        )
        run.status = STATUS_REMEDIATION_REJECTED
        run.next_actions = [
            "Remediation rejected. Revise the plan or compensating controls and "
            "start a new run; containment and patch execution will not occur."
        ]
        ctx.emit(
            "remediation_approval",
            {"ticket": updated, "decision": "reject"},
            summary=f"Infosec rejected remediation on ticket {ticket_id}.",
            started_at=started,
        )
        return run
    updated = ctx.ticketing.approve_ticket(ticket_id, approver, note)
    run.ticket = updated
    ctx.record_approval(
        run,
        gate=GATE_REMEDIATION,
        decision="approve",
        approver=approver,
        note=note,
        action_taken=(
            "Infosec approved remediation plan; containment and patch execution "
            "may now be authorized"
        ),
        result_ref=str(ticket_id),
    )
    run.status = STATUS_APPROVED_FOR_CONTAINMENT
    run.next_actions = [
        f"Authorize containment: secops approve --run {run.run_id} "
        f'--gate containment --approver "<name>"',
        f"Authorize patch submission: secops approve --run {run.run_id} "
        f'--gate patch --approver "<name>"',
    ]
    ctx.emit(
        "remediation_approval",
        {"ticket": updated, "decision": "approve"},
        summary=f"Infosec approved remediation on ticket {ticket_id}.",
        started_at=started,
    )
    return run


def _priority(tiers: dict[str, int]) -> str:
    if tiers.get("critical"):
        return "P1"
    if tiers.get("high"):
        return "P2"
    if tiers.get("medium"):
        return "P3"
    return "P4"


__all__ = ["approve_ticket", "approve_remediation"]
