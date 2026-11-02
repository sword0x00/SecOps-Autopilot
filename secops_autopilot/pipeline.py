"""The orchestration engine.

Read-only stages run immediately. Every state-changing stage is reachable only
through ``approve`` with an explicit gate and approver, and the approval record
binds to the remediation plan's SHA-256.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .config import Settings
from .connectors.base import EDRConnector, ITSMConnector, NACConnector, VulnerabilitySource
from .connectors.siem import SimulatedSIEM
from .controlcheck import build_control_posture
from .controls import ControlInventory, OwnerDirectory
from .errors import ApprovalError, ConnectorError, SecOpsError, StateError
from .intake import build_vulnerability, normalize_cve
from .models import (
    GATE_CONTAINMENT,
    GATE_REMEDIATION,
    GATE_RESTORE,
    GATE_TICKET,
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_AWAITING_REMEDIATION_APPROVAL,
    STATUS_AWAITING_TICKET_APPROVAL,
    STATUS_AWAITING_VERIFICATION,
    STATUS_CONTAINMENT_EXECUTED,
    STATUS_ESCALATED,
    STATUS_INTAKE_FAILED,
    STATUS_NO_EXPOSURE,
    STATUS_REMEDIATION_REJECTED,
    STATUS_RESTORED,
    STATUS_VERIFICATION_OPEN,
    STATUS_VERIFIED,
    Approval,
    AssetAssessment,
    AssetRef,
    ContainmentEvent,
    Finding,
    VerificationAsset,
    VerificationResult,
)
from .remediation import build_plan, plan_digest
from .scoring import score_asset, tier_for
from .store import RunStore
from .util import (
    dedupe,
    extract_kb_refs,
    extract_refs,
    first_nonempty,
    normalize_mac,
    utc_now,
)

ELIGIBLE_FOR_VERIFICATION = {
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_CONTAINMENT_EXECUTED,
    STATUS_AWAITING_VERIFICATION,
    STATUS_VERIFIED,
    STATUS_VERIFICATION_OPEN,
    STATUS_RESTORED,
}


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        source: VulnerabilitySource,
        store: RunStore,
        itsm: ITSMConnector,
        nac: NACConnector,
        edr: EDRConnector,
        siem: SimulatedSIEM,
        *,
        owners: OwnerDirectory | None = None,
        controls: ControlInventory | None = None,
    ) -> None:
        self.settings = settings
        self.source = source
        self.store = store
        self.itsm = itsm
        self.nac = nac
        self.edr = edr
        self.siem = siem
        self.owners = owners or OwnerDirectory()
        self.controls = controls or ControlInventory()

    # -- read-only pipeline --------------------------------------------

    def run(
        self,
        cve: str,
        *,
        date_range: int | None = None,
        max_assets: int | None = None,
    ) -> Any:
        target_cve = normalize_cve(cve)
        date_range = int(date_range or self.settings.date_range)
        max_assets = int(max_assets or 200)
        target = {"type": "cve", "value": target_cve}
        options = {
            "date_range": date_range,
            "max_assets": max_assets,
            "isolate_threshold": self.settings.isolate_threshold,
            "owners_inventory": str(self.owners.path) if self.owners.path else None,
            "controls_inventory": str(self.controls.path) if self.controls.path else None,
            "source": self.source.name,
        }
        run = self.store.create(target, options, self.source.public_snapshot())
        run.truthfulness = self._truthfulness()
        self.store.save(run)

        started = utc_now()
        try:
            hits = self.source.cve_plugin_hits(target_cve, date_range)
            plugin_ids = [hit.plugin_id for hit in hits if hit.plugin_id]
            findings = (
                self.source.findings_for_plugins(plugin_ids, date_range)
                if plugin_ids
                else []
            )
        except ConnectorError as exc:
            self.store.write_stage(
                run,
                "intake",
                {"error": str(exc)},
                summary="Tenable intake failed.",
                status="error",
                started_at=started,
                errors=[str(exc)],
                source_calls=self._calls(),
            )
            run.status = STATUS_INTAKE_FAILED
            run.next_actions = [
                f"Resolve Tenable access/scope, then rerun: {exc}",
            ]
            self.store.finalize(run)
            raise

        vulnerability = build_vulnerability(
            target_cve,
            hits,
            findings,
            self._source_refs(),
            date_range=date_range,
        )
        run.vulnerability = vulnerability.to_dict()
        intake_unknowns = []
        if vulnerability.confidence != "high":
            intake_unknowns.append(
                {
                    "field": "exposure",
                    "reason": vulnerability.confidence_reason,
                }
            )
        self.store.write_stage(
            run,
            "intake",
            {
                "vulnerability": vulnerability.to_dict(),
                "plugin_hits": [hit.to_dict() for hit in hits],
                "findings_returned": len(findings),
                "cve_filter": target_cve,
            },
            summary=(
                f"{len(hits)} Tenable plugin(s) matched; {len(findings)} finding(s) "
                f"across {vulnerability.affected_asset_count} asset(s)."
            ),
            started_at=started,
            unknowns=intake_unknowns,
            source_calls=self._calls(),
        )
        if not hits or not findings:
            self.store.write_stage(
                run,
                "exposure",
                {"assets": [], "reason": "no Tenable finding returned"},
                summary="No affected assets were resolved from Tenable.",
                status="skipped",
                started_at=utc_now(),
                source_calls=self._calls(),
            )
            run.status = STATUS_NO_EXPOSURE
            run.next_actions = [
                "Confirm the CVE is in scope for the tenant's scan window, then rerun "
                "with a wider --date-range.",
            ]
            self.store.finalize(run)
            return run

        # -- stage 2: group findings into assets -----------------------
        started = utc_now()
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            groups[finding.asset.uuid].append(finding)
        agent_inventory, agent_reason = self._agent_inventory()
        contexts: list[dict[str, Any]] = []
        detail_errors: list[dict[str, str]] = []
        for asset_uuid, group in groups.items():
            detail, detail_error = self._asset_detail(asset_uuid)
            if detail_error:
                detail_errors.append({"asset_uuid": asset_uuid, "error": detail_error})
            asset = self._merge_asset(group[0].asset, detail)
            owner = self.owners.lookup(asset)
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
        if len(contexts) > max_assets:
            truncated = [item["asset"].uuid for item in contexts[max_assets:]]
            contexts = contexts[:max_assets]
        exposure_unknowns = []
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
                    "reason": f"{len(truncated)} asset(s) omitted by --max-assets; ids: "
                    + ", ".join(truncated[:10]),
                }
            )
        self.store.write_stage(
            run,
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
            source_calls=self._calls(),
        )

        # -- stage 3: control posture ---------------------------------
        started = utc_now()
        control_unknowns: list[dict[str, str]] = []
        for item in contexts:
            edr_status = self.edr.status(
                item["asset"].uuid, item["asset"].display_name
            )
            control_entry = self.controls.lookup(item["asset"])
            control = build_control_posture(
                item["asset"],
                item["detail"],
                agent_inventory=agent_inventory,
                agent_inventory_reason=agent_reason,
                control_entry=control_entry,
                edr_status=edr_status,
            )
            item["control"] = control
            item["edr_status"] = edr_status
            for unknown in control.unknowns:
                control_unknowns.append(
                    {
                        "field": f"{item['asset'].display_name}:{unknown.get('field')}",
                        "reason": unknown.get("reason", ""),
                    }
                )
        self.store.write_stage(
            run,
            "control_check",
            {
                "assets": [
                    {
                        "asset": item["asset"].to_dict(),
                        "control": item["control"].to_dict(),
                        "edr_status": item["edr_status"],
                    }
                    for item in contexts
                ],
                "agent_inventory_available": agent_inventory is not None,
                "agent_inventory_reason": agent_reason,
            },
            summary=(
                f"Agent present on {sum(1 for item in contexts if item['control'].agent_present is True)} "
                f"of {len(contexts)}; absent on "
                f"{sum(1 for item in contexts if item['control'].agent_present is False)}; "
                f"unknown on {sum(1 for item in contexts if item['control'].agent_present is None)}; "
                f"{sum(1 for item in contexts if any(u.get('field') == 'agent_flag_conflict' for u in item['control'].unknowns))} "
                "with a conflicting agent record. EDR/AV/feed details are unknown unless "
                "a control inventory supplied them."
            ),
            started_at=started,
            unknowns=control_unknowns,
            source_calls=self._calls(),
        )

        # -- stage 4: KRI scoring -------------------------------------
        started = utc_now()
        assessments: list[AssetAssessment] = []
        for item in contexts:
            risk = score_asset(
                item["asset"].uuid,
                item["findings"],
                item["control"],
                aes_raw=item["detail"].get("aes_score"),
                acr_raw=item["detail"].get("acr_score"),
            )
            item["risk"] = risk
            assessments.append(self._assessment(item))
        assessments.sort(key=lambda assessment: assessment.risk.score, reverse=True)
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
        self.store.write_stage(
            run,
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
            source_calls=self._calls(),
        )

        # -- alerts ----------------------------------------------------
        started = utc_now()
        new_alerts = 0
        for assessment in assessments:
            if assessment.risk.tier in {"critical", "high"}:
                self._emit_alert(
                    run,
                    severity=assessment.risk.tier,
                    code="HIGH_KRI_EXPOSURE",
                    message=(
                        f"{target_cve} on {assessment.asset.display_name}: "
                        f"KRI {assessment.risk.score:.1f} ({assessment.risk.tier})"
                    ),
                    assets=[assessment.asset.uuid],
                )
                new_alerts += 1
        self.store.write_stage(
            run,
            "alerting",
            {"alerts": run.alerts},
            summary=(
                f"{new_alerts} high/critical KRI alert(s) sent to the simulated SIEM sink."
                if new_alerts
                else "No alert threshold was crossed."
            ),
            status="complete" if new_alerts else "skipped",
            started_at=started,
            unknowns=[
                {
                    "field": "siem_delivery",
                    "reason": "No SIEM connector is configured; alerts are file-backed.",
                }
            ]
            if new_alerts
            else [],
        )

        # -- stage 5: remediation plan --------------------------------
        started = utc_now()
        plan = build_plan(
            vulnerability,
            assessments,
            isolate_threshold=self.settings.isolate_threshold,
        )
        run.plan = plan.to_dict()
        run.status = STATUS_AWAITING_TICKET_APPROVAL
        run.next_actions = [
            f"Approve ITSM ticket creation: secops approve --run {run.run_id} "
            f"--gate ticket --approver \"<name>\""
        ]
        self.store.write_stage(
            run,
            "remediation",
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
                    "reason": "Tenable plugin metadata does not carry prerequisites, "
                    "rollback, or effort.",
                }
            ],
        )
        self.store.finalize(run)
        return run

    # -- approval gates -------------------------------------------------

    def approve(
        self,
        run_id: str,
        gate: str,
        approver: str,
        note: str = "",
        *,
        reject: bool = False,
    ) -> Any:
        approver = (approver or "").strip()
        if not approver:
            raise ApprovalError("an approver name is required for every state change")
        run = self.store.load(run_id)
        if not run.plan:
            raise StateError("run has no remediation plan to approve")
        self._assert_plan_integrity(run)
        if gate == GATE_TICKET:
            return self._approve_ticket(run, approver, note)
        if gate == GATE_REMEDIATION:
            return self._approve_remediation(run, approver, note, reject=reject)
        if gate == GATE_CONTAINMENT:
            return self._approve_containment(run, approver, note)
        if gate == GATE_RESTORE:
            return self._approve_restore(run, approver, note)
        raise StateError(f"unknown approval gate: {gate!r}")

    def _approve_ticket(self, run: Any, approver: str, note: str) -> Any:
        if run.status != STATUS_AWAITING_TICKET_APPROVAL:
            raise StateError(
                f"ticket creation is not pending (status: {run.status})"
            )
        plan = run.plan or {}
        vulnerability = run.vulnerability or {}
        tiers: dict[str, int] = defaultdict(int)
        for asset in run.exposure or []:
            tiers[(asset.get("risk") or {}).get("tier", "unknown")] += 1
        owners_known = sum(
            1 for asset in run.exposure or []
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
            "evidence_ref": str(self.store.run_dir(run.run_id)),
            "owner_summary": {
                "known": owners_known,
                "unknown": len(run.exposure or []) - owners_known,
            },
            "summary": (
                f"{vulnerability.get('id')} affects {len(run.exposure or [])} asset(s); "
                f"containment candidates: "
                f"{sum(1 for item in plan.get('per_asset') or [] if item.get('containment_recommended'))}. "
                "Infosec approval is required before containment."
            ),
        }
        started = utc_now()
        try:
            ticket = self.itsm.create_ticket(payload)
        except ConnectorError as exc:
            self.store.write_stage(
                run,
                "ticket",
                {"error": str(exc), "payload": payload},
                summary="ITSM ticket creation failed.",
                status="error",
                started_at=started,
                errors=[str(exc)],
            )
            raise
        run.ticket = ticket
        self._record_approval(
            run,
            gate=GATE_TICKET,
            decision="approve",
            approver=approver,
            note=note,
            action_taken="ITSM ticket created",
            result_ref=str(ticket.get("ticket_id")),
        )
        run.status = STATUS_AWAITING_REMEDIATION_APPROVAL
        run.next_actions = [
            f"Record infosec remediation approval: secops approve --run {run.run_id} "
            f"--gate remediation --approver \"<infosec approver>\""
        ]
        self.store.write_stage(
            run,
            "ticket",
            {"ticket": ticket, "payload": payload},
            summary=(
                f"Ticket {ticket.get('ticket_id')} created as "
                f"{ticket.get('status')}; awaiting infosec remediation approval."
            ),
            started_at=started,
        )
        self.store.finalize(run)
        return run

    def _approve_remediation(
        self, run: Any, approver: str, note: str, *, reject: bool
    ) -> Any:
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
            updated = self.itsm.reject_ticket(ticket_id, approver, note)
            run.ticket = updated
            self._record_approval(
                run,
                gate=GATE_REMEDIATION,
                decision="reject",
                approver=approver,
                note=note,
                action_taken="ITSM ticket rejected; no containment executed",
                result_ref=str(ticket_id),
            )
            run.status = STATUS_REMEDIATION_REJECTED
            run.next_actions = [
                "Remediation rejected. Revise the plan or compensating controls and "
                "start a new run; containment will not execute."
            ]
            self.store.write_stage(
                run,
                "remediation_approval",
                {"ticket": updated, "decision": "reject"},
                summary=f"Infosec rejected remediation on ticket {ticket_id}.",
                started_at=started,
            )
            self.store.finalize(run)
            return run
        updated = self.itsm.approve_ticket(ticket_id, approver, note)
        run.ticket = updated
        self._record_approval(
            run,
            gate=GATE_REMEDIATION,
            decision="approve",
            approver=approver,
            note=note,
            action_taken="Infosec approved remediation plan; containment may now be authorized",
            result_ref=str(ticket_id),
        )
        run.status = STATUS_APPROVED_FOR_CONTAINMENT
        run.next_actions = [
            f"Authorize containment: secops approve --run {run.run_id} "
            f"--gate containment --approver \"<name>\""
        ]
        self.store.write_stage(
            run,
            "remediation_approval",
            {"ticket": updated, "decision": "approve"},
            summary=f"Infosec approved remediation on ticket {ticket_id}.",
            started_at=started,
        )
        self.store.finalize(run)
        return run

    def _approve_containment(self, run: Any, approver: str, note: str) -> Any:
        if run.status != STATUS_APPROVED_FOR_CONTAINMENT:
            raise StateError(
                f"containment is not authorized (status: {run.status})"
            )
        plan = run.plan or {}
        ticket_id = str((run.ticket or {}).get("ticket_id") or "")
        by_uuid = {
            (asset.get("asset") or {}).get("uuid"): asset
            for asset in run.exposure or []
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
                    policy=self.settings.quarantine_policy,
                    vlan=None,
                    timestamp=utc_now(),
                    approver=approver,
                    ticket_id=ticket_id,
                    connector=getattr(self.nac, "name", "unknown"),
                    simulated=not getattr(self.nac, "live", False),
                    reason=(
                        "No MAC address is recorded for this asset; ISE ANC cannot "
                        "identify the endpoint. Manual containment or CMDB enrichment "
                        "is required."
                    ),
                ).to_dict()
                blocked += 1
            else:
                try:
                    event = self.nac.quarantine(
                        asset_uuid=asset_uuid,
                        hostname=str(hostname),
                        mac=mac,
                        policy=self.settings.quarantine_policy,
                        vlan=self.settings.remediation_vlan,
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
                        "policy": self.settings.quarantine_policy,
                        "vlan": None,
                        "timestamp": utc_now(),
                        "approver": approver,
                        "ticket_id": ticket_id,
                        "connector": getattr(self.nac, "name", "unknown"),
                        "simulated": not getattr(self.nac, "live", False),
                        "reason": str(exc),
                    }
                    failed += 1
            events.append(event)
            run.containment.append(event)
            self._emit_alert(
                run,
                severity="high" if event.get("status") == "isolated" else "medium",
                code="CONTAINMENT_ACTION",
                message=(
                    f"{event.get('action')} {event.get('status')} for "
                    f"{event.get('hostname')} ({event.get('mac') or 'no MAC'})"
                ),
                assets=[asset_uuid],
            )
        self._record_approval(
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
        self._update_ticket(
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
        self.store.write_stage(
            run,
            "containment",
            {
                "events": events,
                "summary": {
                    "isolated": isolated,
                    "blocked": blocked,
                    "failed": failed,
                },
                "policy": self.settings.quarantine_policy,
                "vlan": self.settings.remediation_vlan,
            },
            summary=(
                f"Containment executed: {isolated} isolated, {blocked} blocked (no MAC), "
                f"{failed} failed."
            ),
            started_at=started,
            unknowns=[
                {
                    "field": "nac_identity",
                    "reason": "ISE ANC keys on MAC; assets without a MAC are blocked, not guessed.",
                }
            ]
            if blocked
            else [],
        )
        self.store.finalize(run)
        return run

    def _approve_restore(self, run: Any, approver: str, note: str) -> Any:
        if run.status not in {STATUS_VERIFIED, STATUS_VERIFICATION_OPEN, STATUS_ESCALATED}:
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
                restored_event = self.nac.restore(
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
                    "connector": getattr(self.nac, "name", "unknown"),
                    "simulated": not getattr(self.nac, "live", False),
                    "reason": str(exc),
                }
                failed += 1
            run.containment.append(restored_event)
        self._record_approval(
            run,
            gate=GATE_RESTORE,
            decision="approve",
            approver=approver,
            note=note,
            action_taken=f"NAC restore executed: {restored} restored, {failed} failed",
        )
        self._update_ticket(
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
        self.store.write_stage(
            run,
            "restore",
            {
                "eligible_events": eligible,
                "restored": restored,
                "failed": failed,
                "remaining_isolated": remaining_isolated(run),
            },
            summary=f"Restore executed: {restored} restored, {failed} failed.",
            started_at=started,
        )
        self.store.finalize(run)
        return run

    # -- verification ---------------------------------------------------

    def verify(self, run_id: str) -> Any:
        run = self.store.load(run_id)
        if run.status not in ELIGIBLE_FOR_VERIFICATION:
            raise StateError(
                f"verification requires remediation approval (status: {run.status})"
            )
        vulnerability = run.vulnerability or {}
        cve = vulnerability.get("id")
        date_range = int((run.options or {}).get("date_range") or self.settings.date_range)
        started = utc_now()
        try:
            hits = self.source.cve_plugin_hits(cve, date_range)
            ids = [hit.plugin_id for hit in hits if hit.plugin_id]
            findings = (
                self.source.findings_for_plugins(ids, date_range) if ids else []
            )
        except ConnectorError as exc:
            result = VerificationResult(
                started_at=started,
                finished_at=utc_now(),
                method=f"{self.source.name}: CVE -> plugin -> per-asset findings",
                date_range=date_range,
                assets=[
                    VerificationAsset(
                        asset_uuid=(asset.get("asset") or {}).get("uuid", ""),
                        hostname=(asset.get("asset") or {}).get("hostname")
                        or (asset.get("asset") or {}).get("uuid", ""),
                        before_affected=True,
                        after_affected=None,
                        status="unknown",
                        last_scan=asset.get("last_scan"),
                        last_found=None,
                        evidence={"error": str(exc)},
                        infection_status="unknown",
                        contained=any(
                            event.get("asset_uuid") == (asset.get("asset") or {}).get("uuid")
                            and event.get("status") == "isolated"
                            for event in run.containment or []
                        ),
                    )
                    for asset in run.exposure or []
                ],
                new_affected_assets=[],
                remediated_count=0,
                still_affected_count=0,
                unknown_count=len(run.exposure or []),
                infection_status="unknown",
                notes=[
                    "Verification query failed. No remediation claim is made.",
                    str(exc),
                ],
            )
            run.verification = result.to_dict()
            run.status = STATUS_VERIFICATION_OPEN
            run.next_actions = [f"Resolve Tenable access and rerun verification: {exc}"]
            self.store.write_stage(
                run,
                "verification",
                result.to_dict(),
                summary="Verification could not query Tenable; result recorded as unknown.",
                status="error",
                started_at=started,
                errors=[str(exc)],
                source_calls=self._calls(),
            )
            self.store.finalize(run)
            raise

        target_findings = [
            finding
            for finding in findings
            if not finding.cve or cve in {item.upper() for item in finding.cve}
        ]
        current_by_identity: dict[str, Finding] = {}
        current_assets: dict[str, AssetRef] = {}
        for finding in target_findings:
            for key in _identity_keys(finding.asset):
                current_by_identity[key] = finding
            current_assets[finding.asset.uuid] = finding.asset

        before_uuids = {
            (asset.get("asset") or {}).get("uuid") for asset in run.exposure or []
        }
        verification_assets: list[VerificationAsset] = []
        for asset in run.exposure or []:
            ref = AssetRef(**{
                key: value
                for key, value in (asset.get("asset") or {}).items()
                if key
                in {
                    "uuid",
                    "hostname",
                    "fqdn",
                    "netbios",
                    "ipv4",
                    "mac",
                    "os",
                    "agent_uuid",
                    "last_seen",
                    "network_id",
                }
            })
            keys = _identity_keys(ref)
            matches: list[Finding] = []
            for key in keys:
                candidate = current_by_identity.get(key)
                if candidate is not None and not any(candidate is item for item in matches):
                    matches.append(candidate)
            matched = (
                max(matches, key=lambda item: item.last_found or "")
                if matches
                else None
            )
            after_affected = matched is not None
            last_found = matched.last_found if matched else None
            detail, _ = self._asset_detail(ref.uuid)
            edr_status = self.edr.status(ref.uuid, ref.display_name)
            infection = str(edr_status.get("infection_status") or "unknown")
            contained = any(
                event.get("asset_uuid") == ref.uuid
                and event.get("action") == "quarantine"
                and event.get("status") == "isolated"
                for event in run.containment or []
            )
            if infection == "infected":
                handoff = self.edr.handoff(
                    ref.uuid,
                    ref.display_name,
                    {
                        "run_id": run.run_id,
                        "cve": cve,
                        "kri": (asset.get("risk") or {}).get("score"),
                        "contained": contained,
                        "edr": edr_status,
                    },
                )
                run.add_event(
                    "soc_handoff",
                    f"EDR reports infection on {ref.display_name}; SOC case created.",
                    case_id=handoff.get("case_id"),
                )
                self._emit_alert(
                    run,
                    severity="critical",
                    code="EDR_INFECTION",
                    message=(
                        f"EDR reports infection on {ref.display_name}; do not restore. "
                        f"SOC case {handoff.get('case_id')}."
                    ),
                    assets=[ref.uuid],
                )
            status = "remediated" if not after_affected else "not_remediated"
            verification_assets.append(
                VerificationAsset(
                    asset_uuid=ref.uuid,
                    hostname=ref.display_name,
                    before_affected=True,
                    after_affected=after_affected,
                    status=status,
                    last_scan=detail.get("last_scan") if detail else asset.get("last_scan"),
                    last_found=last_found,
                    evidence={
                        "matched_plugin_ids": sorted(
                            {finding.plugin_id for finding in matches}
                        ),
                        "last_found": last_found,
                        "last_scan": detail.get("last_scan") if detail else asset.get("last_scan"),
                        "identity_keys_checked": len(keys),
                    },
                    infection_status=infection,
                    contained=contained,
                )
            )

        new_assets = [
            {
                "asset_uuid": asset.uuid,
                "hostname": asset.display_name,
                "ipv4": asset.ipv4,
                "mac": asset.mac,
            }
            for asset_uuid, asset in current_assets.items()
            if asset_uuid not in before_uuids
        ]
        remediated_count = sum(1 for item in verification_assets if item.status == "remediated")
        still_affected = sum(1 for item in verification_assets if item.status == "not_remediated")
        unknown_count = sum(1 for item in verification_assets if item.status == "unknown")
        infection_status = (
            "infected"
            if any(item.infection_status == "infected" for item in verification_assets)
            else "unknown"
            if any(item.infection_status == "unknown" for item in verification_assets)
            else "none_reported"
        )
        notes = [
            "Verification re-queries Tenable for the CVE's plugin set. A finding that "
            "disappears after a rescan is the remediation evidence; absence from a stale "
            "scan is not.",
            "No EDR signal means infection status remains unknown; it is never reported as clean.",
        ]
        if new_assets:
            notes.append(
                f"{len(new_assets)} asset(s) appeared during verification and were not in "
                "the original exposure set."
            )
        result = VerificationResult(
            started_at=started,
            finished_at=utc_now(),
            method=f"{self.source.name}: CVE -> plugin -> per-asset findings",
            date_range=date_range,
            assets=verification_assets,
            new_affected_assets=new_assets,
            remediated_count=remediated_count,
            still_affected_count=still_affected,
            unknown_count=unknown_count,
            infection_status=infection_status,
            notes=notes,
        )
        run.verification = result.to_dict()

        for item in verification_assets:
            if item.status == "not_remediated":
                self._emit_alert(
                    run,
                    severity="high",
                    code="VERIFICATION_FAILED",
                    message=(
                        f"{cve} is still present on {item.hostname}; remediation not "
                        "confirmed."
                    ),
                    assets=[item.asset_uuid],
                )
        for asset in new_assets:
            self._emit_alert(
                run,
                severity="medium",
                code="NEW_EXPOSURE_DURING_VERIFICATION",
                message=(
                    f"New affected asset during verification: "
                    f"{asset.get('hostname')} ({asset.get('ipv4')})"
                ),
                assets=[asset.get("asset_uuid")],
            )

        if infection_status == "infected":
            run.status = STATUS_ESCALATED
        elif (
            remediated_count == len(verification_assets)
            and unknown_count == 0
            and not new_assets
        ):
            run.status = STATUS_VERIFIED
        else:
            run.status = STATUS_VERIFICATION_OPEN

        if run.status == STATUS_VERIFIED:
            run.next_actions = [
                f"Restore contained assets: secops approve --run {run.run_id} "
                f"--gate restore --approver \"<name>\"",
            ]
            self._update_ticket(
                run,
                {
                    "status": "RESOLVED",
                    "note": "Tenable re-query no longer reports the CVE on the affected assets.",
                },
            )
        else:
            run.next_actions = [
                "Escalate the still-affected assets to their owners; keep NAC isolation "
                "in place until a fresh Tenable query clears them.",
            ]
            if new_assets:
                run.next_actions.append(
                    "New affected assets appeared during verification; scope and "
                    "remediate them before closing the ticket."
                )
            self._update_ticket(
                run,
                {
                    "status": "IN_PROGRESS",
                    "note": (
                        f"Verification: {remediated_count} remediated, "
                        f"{still_affected} still affected, {unknown_count} unknown, "
                        f"{len(new_assets)} new."
                    ),
                },
            )
        self.store.write_stage(
            run,
            "verification",
            result.to_dict(),
            summary=(
                f"Verification: {remediated_count} remediated, {still_affected} still "
                f"affected, {unknown_count} unknown; infection {infection_status}."
            ),
            started_at=started,
            source_calls=self._calls(),
        )
        self.store.finalize(run)
        return run

    # -- helpers --------------------------------------------------------

    def _assessment(self, item: dict[str, Any]) -> AssetAssessment:
        findings: list[Finding] = item["findings"]
        flags = [finding.has_patch for finding in findings if finding.has_patch is not None]
        if any(flags):
            patch_available: bool | None = True
        elif flags and all(flag is False for flag in flags):
            patch_available = False
        else:
            patch_available = None
        refs = []
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
            detail_source=detail.get("source_ref") or item["detail_error"] or "tenable export",
        )

    def _merge_asset(self, base: AssetRef, detail: dict[str, Any]) -> AssetRef:
        return AssetRef(
            uuid=detail.get("asset_uuid") or base.uuid,
            hostname=first_nonempty(detail.get("hostname"), base.hostname),
            fqdn=first_nonempty(
                (detail.get("fqdn") or [None])[0] if isinstance(detail.get("fqdn"), list) else detail.get("fqdn"),
                base.fqdn,
            ),
            netbios=first_nonempty(base.netbios, base.hostname),
            ipv4=first_nonempty(
                (detail.get("ipv4") or [None])[0] if isinstance(detail.get("ipv4"), list) else detail.get("ipv4"),
                base.ipv4,
            ),
            mac=normalize_mac(detail.get("mac")) or base.mac,
            os=detail.get("os") or base.os,
            agent_uuid=first_nonempty(base.agent_uuid, detail.get("agent_name")),
            last_seen=first_nonempty(detail.get("last_seen"), base.last_seen),
            network_id=base.network_id,
        )

    def _asset_detail(self, asset_uuid: str) -> tuple[dict[str, Any], str | None]:
        try:
            return self.source.asset_detail(asset_uuid), None
        except ConnectorError as exc:
            return {}, str(exc)

    def _agent_inventory(self) -> tuple[list[dict[str, Any]] | None, str | None]:
        try:
            return self.source.agent_inventory()
        except ConnectorError as exc:
            return None, str(exc)

    def _source_refs(self) -> list[Any]:
        if hasattr(self.source, "last_workbench") and hasattr(self.source, "last_exports"):
            from .connectors.tenable_vm import source_refs_for_vm

            return source_refs_for_vm(self.source)  # type: ignore[arg-type]
        return []

    def _calls(self) -> list[dict[str, Any]]:
        http = getattr(self.source, "http", None)
        return list(getattr(http, "calls", []) or [])

    def _truthfulness(self) -> dict[str, Any]:
        return {
            "live_reads": bool(getattr(self.source, "live", False)),
            "control_plane": {
                "itsm": _snapshot(self.itsm),
                "nac": _snapshot(self.nac),
                "edr": _snapshot(self.edr),
                "siem": _snapshot(self.siem),
            },
            "limits": [
                "Tenable findings are point-in-time; verification requires a post-remediation rescan.",
                "No exploit validation, patching, or endpoint execution is performed.",
                "Asset owners, EDR/AV health, and patch schedules are unknown unless "
                "an inventory CSV or a live connector supplies them.",
            ],
        }

    def _assert_plan_integrity(self, run: Any) -> None:
        plan = run.plan or {}
        expected = plan.get("plan_sha256")
        actual = plan_digest(plan)
        if not expected or expected != actual:
            raise ApprovalError(
                "remediation plan hash mismatch; the plan changed after it was recorded. "
                "Start a new run or re-plan before approving."
            )

    def _record_approval(
        self,
        run: Any,
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

    def _update_ticket(self, run: Any, fields: dict[str, Any]) -> None:
        ticket = run.ticket or {}
        ticket_id = ticket.get("ticket_id")
        if not ticket_id:
            return
        try:
            updated = self.itsm.update_ticket(ticket_id, fields)
            run.ticket = updated
        except ConnectorError as exc:
            run.add_event(
                "ticket_update_failed",
                f"Could not update ticket {ticket_id}: {exc}",
            )

    def _emit_alert(
        self,
        run: Any,
        *,
        severity: str,
        code: str,
        message: str,
        assets: list[str],
    ) -> dict[str, Any]:
        alert = {
            "at": utc_now(),
            "run_id": run.run_id,
            "severity": severity,
            "code": code,
            "message": message,
            "assets": assets,
            "destination": "simulated SIEM sink",
        }
        try:
            receipt = self.siem.send(alert)
            alert.update(receipt)
        except SecOpsError as exc:
            alert["delivery_error"] = str(exc)
        run.alerts.append(alert)
        run.add_event("alert", message, code=code, severity=severity)
        return alert


def _snapshot(connector: Any) -> dict[str, Any]:
    if hasattr(connector, "public_snapshot"):
        return connector.public_snapshot()
    return {
        "name": getattr(connector, "name", "unknown"),
        "live": getattr(connector, "live", False),
        "simulated": getattr(connector, "simulated", not getattr(connector, "live", False)),
    }


def _identity_keys(asset: AssetRef) -> list[str]:
    keys = []
    for value in (
        asset.uuid,
        normalize_mac(asset.mac),
        asset.ipv4,
        asset.hostname,
        asset.fqdn,
        asset.netbios,
    ):
        if value:
            keys.append(str(value).strip().lower())
    return dedupe(keys)


def _priority(tiers: dict[str, int]) -> str:
    if tiers.get("critical"):
        return "P1"
    if tiers.get("high"):
        return "P2"
    if tiers.get("medium"):
        return "P3"
    return "P4"


def _max_optional(values: list[Any]) -> Any:
    present = [value for value in values if value is not None]
    return max(present) if present else None


def _bool_text(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def remaining_isolated(run: Any) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for event in run.containment or []:
        mac = event.get("mac") or event.get("asset_uuid")
        if not mac:
            continue
        latest[str(mac)] = event
    return [
        event for event in latest.values() if event.get("status") == "isolated"
    ]


__all__ = ["Pipeline", "remaining_isolated", "tier_for"]
