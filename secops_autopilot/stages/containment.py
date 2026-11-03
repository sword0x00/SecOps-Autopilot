"""Stage 7 — approved network containment through the NAC.

The engine never guesses an endpoint identity. The NAC solution is keyed on a MAC
address; an asset without one produces a ``blocked`` record with the reason and
a manual-containment next action. Every event carries the approver, ticket, connector,
and simulation flag.
"""

from __future__ import annotations

from typing import Any

from ..errors import ConnectorError, StateError
from ..models import (
    GATE_CONTAINMENT,
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_AWAITING_VERIFICATION,
    ContainmentEvent,
)
from ..util import normalize_mac, utc_now
from .context import StageContext


def execute_containment(ctx: StageContext, approver: str, note: str):
    run = ctx.workflow.run
    if run.status != STATUS_APPROVED_FOR_CONTAINMENT:
        raise StateError(f"containment is not authorized (status: {run.status})")
    plan = run.plan or {}
    ticket_id = str((run.ticket or {}).get("ticket_id") or "")
    by_uuid = {
        (asset.get("asset") or {}).get("uuid"): asset for asset in run.exposure or []
    }
    started = utc_now()
    events: list[dict[str, Any]] = []
    isolated = blocked = failed = 0
    for index, item in enumerate(plan.get("per_asset") or [], start=1):
        if not item.get("containment_recommended"):
            continue
        asset_uuid = str(item.get("asset_uuid") or "")
        asset = by_uuid.get(asset_uuid) or {}
        ref = asset.get("asset") or {}
        mac = normalize_mac(ref.get("mac"))
        hostname = item.get("hostname") or ref.get("hostname") or asset_uuid
        reason = item.get("containment_reason") or "high KRI / control gap"
        if not mac:
            event = ContainmentEvent(
                event_id=f"BLOCKED-{index:03d}",
                asset_uuid=asset_uuid,
                hostname=str(hostname),
                mac=None,
                action="quarantine",
                status="blocked",
                policy=ctx.settings.quarantine_policy,
                vlan=None,
                timestamp=utc_now(),
                approver=approver,
                ticket_id=ticket_id,
                connector=getattr(ctx.nac, "name", "unknown"),
                simulated=not getattr(ctx.nac, "live", False),
                reason=(
                    "No MAC address is recorded for this asset; the NAC solution cannot "
                    "identify the endpoint. Manual containment or asset inventory enrichment "
                    "is required."
                ),
            ).to_dict()
            blocked += 1
        else:
            try:
                event = ctx.nac.quarantine(
                    asset_uuid=asset_uuid,
                    hostname=str(hostname),
                    mac=mac,
                    policy=ctx.settings.quarantine_policy,
                    vlan=ctx.settings.remediation_vlan,
                    reason=str(reason),
                    approver=approver,
                    ticket_id=ticket_id,
                )
                isolated += 1
            except ConnectorError as exc:
                event = {
                    "event_id": f"FAILED-{index:03d}",
                    "asset_uuid": asset_uuid,
                    "hostname": str(hostname),
                    "mac": mac,
                    "action": "quarantine",
                    "status": "failed",
                    "policy": ctx.settings.quarantine_policy,
                    "vlan": None,
                    "timestamp": utc_now(),
                    "approver": approver,
                    "ticket_id": ticket_id,
                    "connector": getattr(ctx.nac, "name", "unknown"),
                    "simulated": not getattr(ctx.nac, "live", False),
                    "reason": str(exc),
                }
                failed += 1
        events.append(event)
        run.containment.append(event)
    ctx.record_approval(
        run,
        gate=GATE_CONTAINMENT,
        decision="approve",
        approver=approver,
        note=note,
        action_taken=(
            f"NAC containment attempted: {isolated} isolated, {blocked} blocked, "
            f"{failed} failed"
        ),
    )
    ctx.update_ticket(
        run,
        {
            "status": "IN_PROGRESS",
            "note": (
                f"Containment approved by {approver}: {isolated} isolated, "
                f"{blocked} blocked (no MAC), {failed} failed."
            ),
        },
    )
    run.status = STATUS_AWAITING_VERIFICATION
    run.next_actions = [
        f"Run verification: secops verify --run {run.run_id}",
    ]
    if blocked:
        run.next_actions.append(
            "Assets without a MAC address could not be NAC-isolated; assign an "
            "owner and contain manually."
        )
    ctx.emit(
        "containment",
        {
            "events": events,
            "summary": {
                "isolated": isolated,
                "blocked": blocked,
                "failed": failed,
            },
            "policy": ctx.settings.quarantine_policy,
            "vlan": ctx.settings.remediation_vlan,
        },
        summary=(
            f"Containment executed: {isolated} isolated, {blocked} blocked (no MAC), "
            f"{failed} failed."
        ),
        started_at=started,
        unknowns=(
            [
                {
                    "field": "nac_identity",
                    "reason": "The NAC solution keys on MAC; assets without a MAC are blocked, not guessed.",
                }
            ]
            if blocked
            else []
        ),
    )
    return run


__all__ = ["execute_containment"]
