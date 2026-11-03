"""Stage 9/10 — approved restore after verification.

Recovery is deliberately narrower than verification. Only an asset with a
``remediated`` verification result and no infection signal is eligible. A new
exposure during verification keeps the run open even if every original asset was
restored. Restore is a separate approval gate, not an automatic consequence of a
green verification result.
"""

from __future__ import annotations

from typing import Any

from ..errors import ConnectorError, StateError
from ..models import (
    GATE_RESTORE,
    STATUS_ESCALATED,
    STATUS_RESTORED,
    STATUS_VERIFICATION_OPEN,
    STATUS_VERIFIED,
)
from ..util import utc_now
from .context import StageContext

ELIGIBLE_FOR_RESTORE = {
    STATUS_VERIFIED,
    STATUS_VERIFICATION_OPEN,
    STATUS_ESCALATED,
}


def execute_restore(ctx: StageContext, approver: str, note: str):
    run = ctx.workflow.run
    if run.status not in ELIGIBLE_FOR_RESTORE:
        raise StateError(
            f"restore is only valid after verification (status: {run.status})"
        )
    verification = run.verification or {}
    remediated = {
        item.get("asset_uuid")
        for item in verification.get("assets") or []
        if item.get("status") == "remediated"
        and item.get("infection_status") != "infected"
    }
    isolated = [
        event
        for event in run.containment or []
        if event.get("action") == "quarantine" and event.get("status") == "isolated"
    ]
    eligible = [event for event in isolated if event.get("asset_uuid") in remediated]
    if not eligible:
        raise StateError(
            "no contained asset has verified remediation; isolation is retained"
        )
    started = utc_now()
    restored = failed = 0
    ticket_id = str((run.ticket or {}).get("ticket_id") or "")
    for event in eligible:
        try:
            restored_event = ctx.nac.restore(
                asset_uuid=event.get("asset_uuid"),
                hostname=event.get("hostname"),
                mac=event.get("mac"),
                reason="verification confirmed remediation",
                approver=approver,
                ticket_id=ticket_id,
            )
            restored += 1
        except ConnectorError as exc:
            restored_event = {
                "event_id": f"RESTORE-FAILED-{len(run.containment) + 1:03d}",
                "asset_uuid": event.get("asset_uuid"),
                "hostname": event.get("hostname"),
                "mac": event.get("mac"),
                "action": "restore",
                "status": "failed",
                "policy": "",
                "vlan": None,
                "timestamp": utc_now(),
                "approver": approver,
                "ticket_id": ticket_id,
                "connector": getattr(ctx.nac, "name", "unknown"),
                "simulated": not getattr(ctx.nac, "live", False),
                "reason": str(exc),
            }
            failed += 1
        run.containment.append(restored_event)
    ctx.record_approval(
        run,
        gate=GATE_RESTORE,
        decision="approve",
        approver=approver,
        note=note,
        action_taken=f"NAC restore executed: {restored} restored, {failed} failed",
    )
    ctx.update_ticket(
        run,
        {
            "status": "RESOLVED" if not remaining_isolated(run) else "IN_PROGRESS",
            "note": f"Restore approved by {approver}: {restored} restored, {failed} failed.",
        },
    )
    new_exposure = bool((run.verification or {}).get("new_affected_assets"))
    if remaining_isolated(run) or new_exposure:
        run.status = STATUS_VERIFICATION_OPEN
        run.next_actions = [
            "Some isolated assets are not verified remediated, or new exposure "
            "appeared during verification; isolation or escalation remains."
        ]
    else:
        run.status = STATUS_RESTORED
        run.next_actions = ["Run complete. Evidence package is finalized."]
    ctx.emit(
        "recovery",
        {
            "eligible_events": eligible,
            "restored": restored,
            "failed": failed,
            "remaining_isolated": remaining_isolated(run),
        },
        summary=f"Restore executed: {restored} restored, {failed} failed.",
        started_at=started,
    )
    return run


def remaining_isolated(run: Any) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for event in run.containment or []:
        mac = event.get("mac") or event.get("asset_uuid")
        if not mac:
            continue
        latest[str(mac)] = event
    return [event for event in latest.values() if event.get("status") == "isolated"]


__all__ = ["execute_restore", "remaining_isolated", "ELIGIBLE_FOR_RESTORE"]
