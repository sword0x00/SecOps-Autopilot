"""Pipeline facade over explicit stages.

The public API is unchanged: ``run`` is read-only, ``approve`` is the only route
to a state change, and ``verify`` is a fresh read. The implementation now lives
in ``secops_autopilot.stages``: each stage has a contract, the read-only chain is
physically separated from the action stages, and the evidence record carries the
contract that authorized the stage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import Settings
from .connectors.base import EDRConnector, NACConnector, TicketingConnector, VulnerabilitySource
from .connectors.patch import PatchConnector, build_patch
from .controls import ControlInventory, OwnerDirectory
from .errors import ApprovalError, ConnectorError, StateError
from .intake import normalize_cve
from .kri import catalog_summary, load_catalog
from .models import (
    GATE_CONTAINMENT,
    GATE_PATCH,
    GATE_REMEDIATION,
    GATE_RESTORE,
    GATE_TICKET,
    STATUS_STAGE_FAILED,
    RunState,
)
from .remediation import plan_digest
from .scoring import tier_for
from .stages.containment import execute_containment
from .stages.context import StageContext, Workflow
from .stages.contracts import contract_for
from .stages.patch_execution import execute_patch
from .stages.recovery import execute_restore, remaining_isolated
from .stages.readonly import READ_ONLY_STAGES
from .stages.ticketing import approve_remediation, approve_ticket
from .stages.verification import execute_verification
from .store import RunStore
from .util import utc_now


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        source: VulnerabilitySource,
        store: RunStore,
        ticketing: TicketingConnector,
        nac: NACConnector,
        edr: EDRConnector,
        *,
        owners: OwnerDirectory | None = None,
        controls: ControlInventory | None = None,
        kri_catalog_path: str | Path | None = None,
        patch: PatchConnector | None = None,
    ) -> None:
        self.settings = settings
        self.source = source
        self.store = store
        self.ticketing = ticketing
        self.nac = nac
        self.edr = edr
        self.patch = patch or build_patch(settings.state_dir)
        self.owners = owners or OwnerDirectory()
        self.controls = controls or ControlInventory()
        self.kri_catalog_path = kri_catalog_path

    # -- context construction --------------------------------------------

    def _workflow(
        self,
        run: RunState,
        *,
        date_range: int | None = None,
        max_assets: int | None = None,
        advisory: dict[str, Any] | None = None,
    ) -> Workflow:
        return Workflow(
            run=run,
            catalog=load_catalog(self.kri_catalog_path),
            date_range=int(date_range or self.settings.date_range),
            max_assets=int(max_assets or 200),
            advisory=advisory,
        )

    def _context(self, workflow: Workflow) -> StageContext:
        return StageContext(
            self.settings,
            self.source,
            self.store,
            self.ticketing,
            self.nac,
            self.edr,
            self.patch,
            workflow,
            owners=self.owners,
            controls=self.controls,
        )

    # -- read-only pipeline ----------------------------------------------

    def run(
        self,
        cve: str,
        *,
        date_range: int | None = None,
        max_assets: int | None = None,
        advisory: dict[str, Any] | None = None,
    ) -> RunState:
        target_cve = normalize_cve(cve)
        date_range = int(date_range or self.settings.date_range)
        max_assets = int(max_assets or 200)
        catalog = load_catalog(self.kri_catalog_path)
        target = {"type": "cve", "value": target_cve}
        options = {
            "date_range": date_range,
            "max_assets": max_assets,
            "isolate_threshold": self.settings.isolate_threshold,
            "owners_inventory": str(self.owners.path) if self.owners.path else None,
            "controls_inventory": str(self.controls.path) if self.controls.path else None,
            "kri_catalog": catalog_summary(catalog),
            "source": self.source.name,
            "advisory": advisory.get("id") if advisory else None,
            "verification_max_scan_age_hours": self.settings.verification_max_scan_age_hours,
        }
        run = self.store.create(target, options, self.source.public_snapshot())
        workflow = self._workflow(
            run,
            date_range=date_range,
            max_assets=max_assets,
            advisory=advisory,
        )
        ctx = self._context(workflow)
        run.truthfulness = ctx.truthfulness()
        run.truthfulness["kri_catalog"] = catalog_summary(catalog)
        if advisory:
            run.truthfulness["advisory"] = advisory.get("provenance") or {
                "status": "provided",
                "source": advisory.get("source"),
            }
        self.store.save(run)

        for stage_id, stage_fn in READ_ONLY_STAGES:
            ctx.begin(contract_for(stage_id))
            try:
                halt = stage_fn(ctx)
            except ConnectorError:
                self._finalize(
                    run,
                    status="error",
                    summary="Evidence package finalized after a connector error.",
                )
                raise
            except Exception as exc:  # a stage failure must leave evidence
                if stage_id not in run.stages:
                    ctx.emit(
                        stage_id,
                        {"error": str(exc), "exception": type(exc).__name__},
                        summary=f"Stage {stage_id} failed unexpectedly.",
                        status="error",
                        errors=[str(exc)],
                    )
                run.add_event(
                    "stage_error",
                    f"Stage {stage_id} failed: {exc}",
                    stage=stage_id,
                    exception=type(exc).__name__,
                )
                run.status = STATUS_STAGE_FAILED
                run.next_actions = [
                    f"Stage {stage_id} failed: {exc}. Fix the input/connector and "
                    "start a new run; no state change was authorized."
                ]
                self._finalize(
                    run,
                    status="error",
                    summary=f"Evidence package finalized after stage {stage_id} failed.",
                )
                raise
            if halt:
                self._finalize(run)
                return run

        self._finalize(run)
        return run

    # -- approval gates ---------------------------------------------------

    def approve(
        self,
        run_id: str,
        gate: str,
        approver: str,
        note: str = "",
        *,
        reject: bool = False,
    ) -> RunState:
        approver = (approver or "").strip()
        if not approver:
            raise ApprovalError("an approver name is required for every state change")
        run = self.store.load(run_id)
        if not run.plan:
            raise StateError("run has no remediation plan to approve")
        self._assert_plan_integrity(run)
        workflow = self._workflow(run)
        ctx = self._context(workflow)
        try:
            if gate == GATE_TICKET:
                ctx.begin(contract_for("ticket"))
                approve_ticket(ctx, approver, note)
            elif gate == GATE_REMEDIATION:
                ctx.begin(contract_for("remediation_approval"))
                approve_remediation(ctx, approver, note, reject=reject)
            elif gate == GATE_CONTAINMENT:
                ctx.begin(contract_for("containment"))
                execute_containment(ctx, approver, note)
            elif gate == GATE_PATCH:
                ctx.begin(contract_for("patch_execution"))
                execute_patch(ctx, approver, note)
            elif gate == GATE_RESTORE:
                ctx.begin(contract_for("recovery"))
                execute_restore(ctx, approver, note)
            else:
                raise StateError(f"unknown approval gate: {gate!r}")
        except ConnectorError:
            self._finalize(
                run,
                status="error",
                summary="Evidence package finalized after a connector error.",
            )
            raise
        self._finalize(run)
        return run

    # -- verification -----------------------------------------------------

    def verify(self, run_id: str) -> RunState:
        run = self.store.load(run_id)
        workflow = self._workflow(run)
        ctx = self._context(workflow)
        ctx.begin(contract_for("verification"))
        try:
            execute_verification(ctx)
        except ConnectorError:
            self._finalize(
                run,
                status="error",
                summary="Evidence package finalized after a connector error.",
            )
            raise
        self._finalize(run)
        return run

    # -- evidence ---------------------------------------------------------

    def _finalize(
        self,
        run: RunState,
        *,
        status: str = "complete",
        summary: str = "Evidence package finalized.",
    ) -> None:
        """Record the evidence stage, then write reports and the manifest.

        The contract for ``evidence`` existed before this method; without this
        record a reader saw every operational stage but no evidence stage. The
        stage is written before ``RunStore.finalize`` so it is included in the
        artifact manifest.
        """
        contract = contract_for("evidence")
        self.store.write_stage(
            run,
            "evidence",
            {
                "run_status": run.status,
                "stage_count": len(run.stages) + 1,
                "report": "report.md",
                "manifest": "manifest.json",
            },
            summary=summary,
            status=status,
            started_at=utc_now(),
            contract=contract.to_dict(),
            duration_ms=0.0,
            source_calls=[],
        )
        self.store.finalize(run)

    # -- integrity --------------------------------------------------------

    def _assert_plan_integrity(self, run: RunState) -> None:
        plan = run.plan or {}
        expected = plan.get("plan_sha256")
        actual = plan_digest(plan)
        if not expected or expected != actual:
            raise ApprovalError(
                "remediation plan hash mismatch; the plan changed after it was recorded. "
                "Start a new run or re-plan before approving."
            )


__all__ = ["Pipeline", "remaining_isolated", "tier_for"]
