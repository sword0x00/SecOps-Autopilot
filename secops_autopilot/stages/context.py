"""Execution context shared by stage functions.

A stage receives one object with the run state, the connectors, and the small
set of helpers that must behave consistently across stages (stage records,
approval records, ticket updates). Keeping those helpers here is what
makes a stage independently testable and stops every new stage from growing its
own slightly different audit trail.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..config import Settings
from ..connectors.base import EDRConnector, NACConnector, TicketingConnector, VulnerabilitySource
from ..connectors.patch import PatchConnector
from ..controls import ControlInventory, OwnerDirectory
from ..errors import ConnectorError
from ..models import (
    Approval,
    AssetAssessment,
    Finding,
    PluginHit,
    RunState,
    VulnerabilityRecord,
)
from ..store import RunStore
from ..util import utc_now
from .contracts import StageContract, contract_for


@dataclass
class Workflow:
    """Mutable state shared by the read-only stages of one run."""

    run: RunState
    catalog: dict[str, Any]
    date_range: int
    max_assets: int
    advisory: dict[str, Any] | None = None
    vulnerability: VulnerabilityRecord | None = None
    hits: list[PluginHit] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    contexts: list[dict[str, Any]] = field(default_factory=list)
    assessments: list[AssetAssessment] = field(default_factory=list)


class StageContext:
    def __init__(
        self,
        settings: Settings,
        source: VulnerabilitySource,
        store: RunStore,
        ticketing: TicketingConnector,
        nac: NACConnector,
        edr: EDRConnector,
        patch: PatchConnector,
        workflow: Workflow,
        *,
        owners: OwnerDirectory | None = None,
        controls: ControlInventory | None = None,
    ) -> None:
        self.settings = settings
        self.source = source
        self.store = store
        self.ticketing = ticketing
        self.nac = nac
        self.edr = edr
        self.patch = patch
        self.workflow = workflow
        self.owners = owners or OwnerDirectory()
        self.controls = controls or ControlInventory()
        self.contract: StageContract | None = None
        self.attempt = 1
        self._started_monotonic = time.monotonic()

    # -- stage lifecycle -------------------------------------------------

    def begin(self, contract: StageContract, *, attempt: int = 1) -> None:
        self.contract = contract
        self.attempt = attempt
        self._started_monotonic = time.monotonic()

    def emit(
        self,
        stage: str,
        payload: dict[str, Any],
        *,
        summary: str,
        status: str = "complete",
        started_at: str | None = None,
        unknowns: list[dict[str, str]] | None = None,
        errors: list[str] | None = None,
        source_calls: list[dict[str, Any]] | None = None,
    ):
        contract = self.contract if self.contract and self.contract.id == stage else contract_for(stage)
        duration_ms = round((time.monotonic() - self._started_monotonic) * 1000, 1)
        return self.store.write_stage(
            self.workflow.run,
            stage,
            payload,
            summary=summary,
            status=status,
            started_at=started_at,
            unknowns=unknowns,
            errors=errors,
            source_calls=source_calls if source_calls is not None else self.source_calls(),
            contract=contract.to_dict(),
            attempt=self.attempt,
            duration_ms=duration_ms,
        )

    # -- source helpers ---------------------------------------------------

    def source_calls(self) -> list[dict[str, Any]]:
        http = getattr(self.source, "http", None)
        return list(getattr(http, "calls", []) or [])

    def asset_detail(self, asset_uuid: str) -> tuple[dict[str, Any], str | None]:
        try:
            return self.source.asset_detail(asset_uuid), None
        except ConnectorError as exc:
            return {}, str(exc)

    def agent_inventory(self) -> tuple[list[dict[str, Any]] | None, str | None]:
        try:
            return self.source.agent_inventory()
        except ConnectorError as exc:
            return None, str(exc)

    def source_refs(self) -> list[Any]:
        if hasattr(self.source, "last_workbench") and hasattr(self.source, "last_exports"):
            from ..connectors.tenable_vm import source_refs_for_vm

            return source_refs_for_vm(self.source)  # type: ignore[arg-type]
        return []

    # -- audit helpers ----------------------------------------------------

    def record_approval(
        self,
        run: RunState,
        *,
        gate: str,
        decision: str,
        approver: str,
        note: str,
        action_taken: str,
        result_ref: str | None = None,
    ) -> None:
        approval = Approval(
            gate=gate,
            decision=decision,
            approver=approver,
            note=note,
            recorded_at=utc_now(),
            plan_sha256=str((run.plan or {}).get("plan_sha256") or ""),
            action_taken=action_taken,
            result_ref=result_ref,
        )
        run.approvals.append(approval.to_dict())
        run.add_event(
            "approval",
            f"{gate} {decision} by {approver}: {action_taken}",
            gate=gate,
            decision=decision,
            result_ref=result_ref,
        )

    def update_ticket(self, run: RunState, fields: dict[str, Any]) -> None:
        ticket = run.ticket or {}
        ticket_id = ticket.get("ticket_id")
        if not ticket_id:
            return
        try:
            run.ticket = self.ticketing.update_ticket(ticket_id, fields)
        except ConnectorError as exc:
            run.add_event(
                "ticket_update_failed",
                f"Could not update ticket {ticket_id}: {exc}",
            )

    def truthfulness(self) -> dict[str, Any]:
        return {
            "live_reads": bool(getattr(self.source, "live", False)),
            "control_plane": {
                "ticketing": _snapshot(self.ticketing),
                "nac": _snapshot(self.nac),
                "edr": _snapshot(self.edr),
                "patch": _snapshot(self.patch),
            },
            "limits": [
                "Scanner findings are point-in-time; verification requires a post-remediation rescan.",
                "The engine does not exploit, patch, reboot, or execute on endpoints.",
                "Asset owners, control health, and patch schedules are unknown unless "
                "a asset inventory/control inventory or a live connector supplies them.",
                "A submitted patch job is not evidence that a host was patched; "
                "verification is a fresh scanner read.",
            ],
        }


def _snapshot(connector: Any) -> dict[str, Any]:
    if hasattr(connector, "public_snapshot"):
        return connector.public_snapshot()
    return {
        "name": getattr(connector, "name", "unknown"),
        "live": getattr(connector, "live", False),
        "simulated": getattr(connector, "simulated", not getattr(connector, "live", False)),
    }


__all__ = ["Workflow", "StageContext"]
