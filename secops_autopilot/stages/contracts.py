"""Declarative stage contracts.

Each entry states what the stage consumes, what it produces, whether it can
change state, and whether it is safe to retry automatically. The engine checks
the read-only flag before invoking state-changing connectors; the evidence
record carries the contract so an auditor can confirm that a stage was allowed
to do what it did.

The ``methodology_stage`` field maps the implementation to the ten operating
stages in ``SecOps_Autopilot_Stages(1).docx.md``. Stages 9 and 10 of that
document are deliberately merged into ``verification`` + ``recovery`` here:
verification is a fresh read, recovery is the separately approved restore.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class StageContract:
    id: str
    name: str
    order: int
    methodology_stage: int
    kind: str  # read | state | evidence
    requires: tuple[str, ...]
    produces: tuple[str, ...]
    approval_gate: str | None = None
    retryable: bool = False
    idempotent: bool = False
    description: str = ""
    side_effects: tuple[str, ...] = ()

    @property
    def read_only(self) -> bool:
        """True when the stage cannot change an asset or control-plane state.

        A read-only stage may still write evidence or escalation records; those
        side effects are declared in ``side_effects`` and are not containment or
        remediation.
        """
        return self.kind == "read"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["read_only"] = self.read_only
        return data


CONTRACTS: tuple[StageContract, ...] = (
    StageContract(
        id="intake",
        name="Risk intake",
        order=10,
        methodology_stage=1,
        kind="read",
        requires=("target", "source"),
        produces=("vulnerability",),
        retryable=True,
        description=(
            "Normalize the target CVE/advisory, map it to scanner plugins and "
            "findings, merge verified advisory metadata, and record confidence."
        ),
    ),
    StageContract(
        id="exposure",
        name="Exposure and asset resolution",
        order=20,
        methodology_stage=2,
        kind="read",
        requires=("vulnerability",),
        produces=("exposure",),
        retryable=True,
        description=(
            "Group findings by asset, enrich inventory details, resolve owners "
            "and criticality, and record unresolved or truncated exposure."
        ),
    ),
    StageContract(
        id="control_check",
        name="Security control check",
        order=30,
        methodology_stage=3,
        kind="read",
        requires=("exposure",),
        produces=("control_posture",),
        retryable=True,
        description=(
            "Resolve Tenable agent, EDR/AV, feed, mode, NAC posture, and patch "
            "agent state per asset. Unavailable telemetry is recorded as unknown."
        ),
    ),
    StageContract(
        id="kri_register",
        name="KRI identification",
        order=40,
        methodology_stage=4,
        kind="read",
        requires=("control_posture", "vulnerability"),
        produces=("kri_detections",),
        retryable=False,
        description=(
            "Evaluate every configured KRI on every affected asset. A detector "
            "error is recorded as unknown for that asset, never as clear."
        ),
    ),
    StageContract(
        id="kri_scoring",
        name="Risk scoring",
        order=50,
        methodology_stage=4,
        kind="read",
        requires=("kri_detections", "control_posture"),
        produces=("risk_queue",),
        retryable=False,
        description=(
            "Blend severity, exploitability, exposure, control gap, and asset "
            "criticality; renormalize around unknown components and emit a queue."
        ),
    ),
    StageContract(
        id="remediation_planning",
        name="Remediation and workaround selection",
        order=70,
        methodology_stage=5,
        kind="read",
        requires=("risk_queue", "vulnerability"),
        produces=("plan",),
        retryable=False,
        description=(
            "Select the patch path from verified fixed versions, otherwise "
            "select compensating controls matched to the exploit mechanism. "
            "Every control is unverified until tested."
        ),
    ),
    StageContract(
        id="ticket",
        name="Ticket creation",
        order=80,
        methodology_stage=6,
        kind="state",
        requires=("plan",),
        produces=("ticket", "approvals"),
        approval_gate="ticket",
        idempotent=True,
        description=(
            "Create the ticketing-system ticket after the ticket gate is approved and bind "
            "it to the remediation plan SHA-256 and evidence reference."
        ),
    ),
    StageContract(
        id="remediation_approval",
        name="Infosec remediation approval",
        order=90,
        methodology_stage=6,
        kind="state",
        requires=("ticket", "plan"),
        produces=("approvals",),
        approval_gate="remediation",
        idempotent=False,
        description=(
            "Record the infosec decision on the remediation plan. Rejection "
            "blocks every later state change; approval authorizes containment "
            "and patch execution."
        ),
    ),
    StageContract(
        id="containment",
        name="Network containment",
        order=100,
        methodology_stage=7,
        kind="state",
        requires=("approvals", "plan", "exposure"),
        produces=("containment",),
        approval_gate="containment",
        idempotent=True,
        description=(
            "Apply the approved NAC quarantine to containment candidates. An "
            "asset without a MAC is recorded blocked, never guessed."
        ),
    ),
    StageContract(
        id="patch_execution",
        name="Remediation execution",
        order=110,
        methodology_stage=8,
        kind="state",
        requires=("approvals", "plan", "vulnerability"),
        produces=("patch_execution",),
        approval_gate="patch",
        idempotent=True,
        description=(
            "Submit the approved patch jobs to the patch-management connector "
            "with the advisory fixed version per asset. The default connector "
            "is file-backed and labels jobs simulated."
        ),
    ),
    StageContract(
        id="verification",
        name="Verification and recovery — verification",
        order=120,
        methodology_stage=9,
        kind="read",
        requires=("patch_execution", "exposure"),
        produces=("verification",),
        retryable=True,
        description=(
            "Re-query the vulnerability source for the target CVE, compare "
            "identity keys against the original exposure set, and re-check EDR. "
            "A stale scan is not evidence of a fix."
        ),
    ),
    StageContract(
        id="recovery",
        name="Verification and recovery — restore",
        order=130,
        methodology_stage=9,
        kind="state",
        requires=("verification",),
        produces=("restore",),
        approval_gate="restore",
        idempotent=True,
        description=(
            "Restore only assets with a fresh remediation result and no "
            "infection signal, after the separate restore gate. Everything "
            "else stays isolated or escalates."
        ),
    ),
    StageContract(
        id="evidence",
        name="Evidence and compliance",
        order=140,
        methodology_stage=10,
        kind="evidence",
        requires=("stages",),
        produces=("report", "manifest"),
        idempotent=True,
        description=(
            "Write the Markdown and HTML reports and the SHA-256 manifest over "
            "every artifact in the run directory."
        ),
        side_effects=("evidence_files",),
    ),
)

STAGE_BY_ID = {contract.id: contract for contract in CONTRACTS}


def contract_for(stage_id: str) -> StageContract:
    try:
        return STAGE_BY_ID[stage_id]
    except KeyError as exc:
        raise KeyError(f"unknown stage contract: {stage_id!r}") from exc


__all__ = ["CONTRACTS", "STAGE_BY_ID", "StageContract", "contract_for"]
