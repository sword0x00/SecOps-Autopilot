"""Stage 8 — approved remediation execution.

This stage submits patch jobs; it does not patch hosts. The default connector is
file-backed, labels every job ``simulated``, and records ``touched_host=false``.
A job submission is an audit event, not a remediation claim. The only
remediation evidence the engine accepts is a fresh scanner read in the next
stage.

Jobs are built from the advisory's fixed version for the asset's runtime. If
the advisory cannot name a fixed version for that branch, the job is skipped and
the reason is recorded; the engine does not invent a target version.
"""

from __future__ import annotations

from typing import Any

from ..errors import ConnectorError, StateError
from ..models import (
    GATE_PATCH,
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_AWAITING_VERIFICATION,
    STATUS_VERIFICATION_OPEN,
)
from ..util import utc_now
from .context import StageContext

ALLOWED_STATUSES = {
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_AWAITING_VERIFICATION,
    STATUS_VERIFICATION_OPEN,
}


def execute_patch(ctx: StageContext, approver: str, note: str):
    run = ctx.workflow.run
    if run.status not in ALLOWED_STATUSES:
        raise StateError(
            "patch execution requires remediation approval "
            f"(status: {run.status})"
        )
    if run.patch_execution and run.patch_execution.get("status") in {
        "submitted",
        "not_submitted",
    }:
        run.add_event(
            "patch_execution_idempotent",
            "Patch execution was already recorded; no duplicate jobs were submitted.",
            submitted=run.patch_execution.get("submitted"),
        )
        return run

    plan = run.plan or {}
    ticket_id = str((run.ticket or {}).get("ticket_id") or "")
    started = utc_now()
    jobs: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for item in plan.get("per_asset") or []:
        if item.get("path") != "patch":
            continue
        target_version = item.get("target_version")
        job = {
            "asset_uuid": item.get("asset_uuid"),
            "hostname": item.get("hostname"),
            "package": item.get("package") or item.get("runtime_product"),
            "current_version": item.get("runtime_version"),
            "target_version": target_version,
            "reason": item.get("reason"),
        }
        if not target_version:
            skipped.append(
                {
                    **job,
                    "reason": (
                        "No advisory fixed version applies to this asset's runtime "
                        "branch; no patch job was submitted."
                    ),
                }
            )
            continue
        jobs.append(job)

    if not jobs:
        run.patch_execution = {
            "status": "not_submitted",
            "connector": getattr(ctx.patch, "name", "unknown"),
            "simulated": not getattr(ctx.patch, "live", False),
            "submitted": 0,
            "skipped": skipped,
            "approved_by": approver,
            "approved_at": utc_now(),
            "reason": "No patchable asset had a verified target version.",
        }
        ctx.record_approval(
            run,
            gate=GATE_PATCH,
            decision="approve",
            approver=approver,
            note=note,
            action_taken="Patch gate approved; no job submitted (no verified target version)",
        )
        _next_actions(ctx)
        ctx.emit(
            "patch_execution",
            run.patch_execution,
            summary=(
                "Patch execution recorded no jobs: no patchable asset had a "
                "verified target version."
            ),
            status="skipped",
            started_at=started,
            unknowns=[
                {"field": "patch_target_version", "reason": item["reason"]}
                for item in skipped[:10]
            ],
        )
        return run

    try:
        receipt = ctx.patch.submit(
            run_id=run.run_id,
            ticket_id=ticket_id,
            jobs=jobs,
            approver=approver,
        )
    except ConnectorError as exc:
        run.patch_execution = {
            "status": "failed",
            "connector": getattr(ctx.patch, "name", "unknown"),
            "simulated": not getattr(ctx.patch, "live", False),
            "submitted": 0,
            "skipped": skipped,
            "approved_by": approver,
            "approved_at": utc_now(),
            "error": str(exc),
        }
        ctx.emit(
            "patch_execution",
            run.patch_execution,
            summary="Patch management connector failed; no job is claimed submitted.",
            status="error",
            started_at=started,
            errors=[str(exc)],
        )
        raise

    run.patch_execution = {
        **receipt,
        "status": "submitted",
        "approved_by": approver,
        "approved_at": utc_now(),
        "ticket_id": ticket_id,
        "skipped": skipped,
    }
    ctx.record_approval(
        run,
        gate=GATE_PATCH,
        decision="approve",
        approver=approver,
        note=note,
        action_taken=(
            f"Patch jobs submitted to {receipt.get('connector')}: "
            f"{len(jobs)} job(s); simulated={receipt.get('simulated')}"
        ),
    )
    _next_actions(ctx)
    ctx.emit(
        "patch_execution",
        run.patch_execution,
        summary=(
            f"Submitted {len(jobs)} patch job(s) to {receipt.get('connector')}; "
            f"simulated={receipt.get('simulated')}. No host is reported patched."
        ),
        started_at=started,
        unknowns=(
            [
                {"field": "patch_target_version", "reason": item["reason"]}
                for item in skipped[:10]
            ]
            if skipped
            else []
        ),
    )
    return run


def _next_actions(ctx: StageContext) -> None:
    run = ctx.workflow.run
    actions: list[str] = []
    if run.status == STATUS_APPROVED_FOR_CONTAINMENT:
        actions.append(
            f"Authorize containment: secops approve --run {run.run_id} "
            f'--gate containment --approver "<name>"'
        )
    actions.append(f"Run verification: secops verify --run {run.run_id}")
    run.next_actions = actions


__all__ = ["execute_patch", "ALLOWED_STATUSES"]
