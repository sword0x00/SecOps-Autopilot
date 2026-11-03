"""Domain models and run-state schema.

Every stage writes one of these records. The run state is plain JSON on disk so
an auditor can replay the decision chain without trusting the tool that wrote
it. Unknown values are represented by ``None`` plus an explicit reason in the
owning record — never by a plausible default.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .util import UNKNOWN, utc_now

# Run lifecycle. State-changing steps are only reachable through an approval.
STATUS_INTAKE_FAILED = "intake_failed"
STATUS_STAGE_FAILED = "stage_failed"
STATUS_NO_EXPOSURE = "no_exposure_found"
STATUS_AWAITING_TICKET_APPROVAL = "awaiting_ticket_approval"
STATUS_AWAITING_REMEDIATION_APPROVAL = "awaiting_remediation_approval"
STATUS_REMEDIATION_REJECTED = "remediation_rejected"
STATUS_APPROVED_FOR_CONTAINMENT = "approved_for_containment"
STATUS_CONTAINMENT_EXECUTED = "containment_executed"
STATUS_AWAITING_VERIFICATION = "awaiting_verification"
STATUS_VERIFIED = "verified_remediated"
STATUS_VERIFICATION_OPEN = "verification_open"
STATUS_ESCALATED = "escalated"
STATUS_RESTORED = "restored"
STATUS_COMPLETE = "complete"

TERMINAL_STATUSES = {
    STATUS_NO_EXPOSURE,
    STATUS_REMEDIATION_REJECTED,
    STATUS_RESTORED,
    STATUS_COMPLETE,
    STATUS_ESCALATED,
}

GATE_TICKET = "ticket"
GATE_REMEDIATION = "remediation"
GATE_CONTAINMENT = "containment"
GATE_PATCH = "patch"
GATE_RESTORE = "restore"

STAGE_LABELS = {
    "intake": "Intake",
    "exposure": "Exposure",
    "control_check": "Control check",
    "kri_register": "KRI register",
    "kri_scoring": "KRI scoring",
    "remediation": "Remediation planning",
    "remediation_planning": "Remediation planning",
    "ticket": "Ticket",
    "remediation_approval": "Remediation approval",
    "containment": "Containment",
    "patch_execution": "Remediation execution",
    "verification": "Verification and recovery — verification",
    "restore": "Verification and recovery — restore",
    "recovery": "Verification and recovery — restore",
    "evidence": "Evidence",
}


class _Serializable:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SourceRef(_Serializable):
    type: str
    ref: str
    retrieved: str = field(default_factory=utc_now)
    note: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssetRef(_Serializable):
    uuid: str
    hostname: str | None = None
    fqdn: str | None = None
    netbios: str | None = None
    ipv4: str | None = None
    mac: str | None = None
    os: list[str] = field(default_factory=list)
    agent_uuid: str | None = None
    last_seen: str | None = None
    network_id: str | None = None

    @property
    def display_name(self) -> str:
        return self.hostname or self.fqdn or self.netbios or self.ipv4 or self.uuid

    def identity(self) -> str:
        return self.uuid or self.mac or self.ipv4 or self.display_name


@dataclass
class Finding(_Serializable):
    plugin_id: int
    plugin_name: str
    family: str
    severity: int | None
    asset: AssetRef
    source: str
    cvss3_base: float | None = None
    cvss2_base: float | None = None
    cvss3_vector: str | None = None
    cvss2_vector: str | None = None
    vpr: float | None = None
    epss: float | None = None
    cve: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)
    xrefs: list[dict[str, Any]] = field(default_factory=list)
    exploit_available: bool | None = None
    exploited_by_malware: bool | None = None
    exploited_by_nessus: bool | None = None
    exploit_framework_metasploit: bool | None = None
    in_the_news: bool | None = None
    has_patch: bool | None = None
    has_workaround: bool | None = None
    vuln_publication_date: str | None = None
    patch_publication_date: str | None = None
    solution: str = ""
    synopsis: str = ""
    description: str = ""
    see_also: list[str] = field(default_factory=list)
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    output: str = ""
    first_found: str | None = None
    last_found: str | None = None
    state: str | None = None
    scan_id: str | None = None


@dataclass
class PluginHit(_Serializable):
    plugin_id: int
    plugin_name: str
    family: str
    severity: int | None
    asset_count: int
    finding_count: int | None = None
    cvss3_base: float | None = None
    cvss2_base: float | None = None
    vpr: float | None = None
    state: str | None = None


@dataclass
class VulnerabilityRecord(_Serializable):
    id: str
    title: str
    title_source: str
    aliases: list[str] = field(default_factory=list)
    published: str | None = None
    severity_cvss: float | None = None
    severity_source: str = UNKNOWN
    cvss3_base: float | None = None
    cvss3_vector: str | None = None
    cvss2_base: float | None = None
    cvss2_vector: str | None = None
    exploited_in_wild: bool | None = None
    exploit_signals: list[str] = field(default_factory=list)
    patch_available: bool | None = None
    patch_refs: list[str] = field(default_factory=list)
    affected_products: list[dict[str, Any]] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)
    plugin_hits: list[PluginHit] = field(default_factory=list)
    affected_asset_count: int = 0
    affected_finding_count: int = 0
    sources: list[SourceRef] = field(default_factory=list)
    confidence: str = UNKNOWN
    confidence_reason: str = ""
    conflicts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    advisory: dict[str, Any] | None = None
    fixed_versions: list[dict[str, Any]] = field(default_factory=list)
    mitigation_steps: list[dict[str, Any]] = field(default_factory=list)
    provenance: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ControlPosture(_Serializable):
    asset_uuid: str
    agent_present: bool | None = None
    agent_uuid: str | None = None
    agent_version: str | None = None
    agent_last_seen: str | None = None
    agent_last_scan: str | None = None
    agent_status: str | None = None
    agent_feed_age_hours: float | None = None
    patch_agent_present: bool | None = None
    edr_present: bool | None = None
    edr_vendor: str | None = None
    edr_version: str | None = None
    edr_baseline_version: str | None = None
    edr_feed_age_hours: float | None = None
    edr_mode: str | None = None
    edr_behavioral_matches: list[str] = field(default_factory=list)
    av_present: bool | None = None
    av_vendor: str | None = None
    av_version: str | None = None
    av_baseline_version: str | None = None
    av_signature_age_hours: float | None = None
    av_mode: str | None = None
    app_control_mode: str | None = None
    nac_compliant: bool | None = None
    nac_policy: str | None = None
    unknowns: list[dict[str, str]] = field(default_factory=list)
    gaps: list[dict[str, str]] = field(default_factory=list)
    sources: list[SourceRef] = field(default_factory=list)
    control_gap_score: float = 0.0


@dataclass
class KRIDetection(_Serializable):
    kri_id: str
    name: str
    status: str
    severity: str
    asset_uuid: str
    hostname: str
    evidence: list[str]
    source: str
    remediation: str
    action: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskScore(_Serializable):
    score: float
    tier: str
    components: dict[str, float | None]
    weights: dict[str, float]
    effective_weights: dict[str, float]
    raw: dict[str, float | None]
    unknown_components: list[str]
    confidence: str
    drivers: list[dict[str, Any]]
    explanation: str


@dataclass
class OwnerInfo(_Serializable):
    owner: str = UNKNOWN
    team: str = UNKNOWN
    email: str | None = None
    source: str = "no asset inventory mapping configured"
    match: str | None = None


@dataclass
class AssetAssessment(_Serializable):
    asset: AssetRef
    owner: OwnerInfo
    findings: list[Finding]
    control: ControlPosture
    risk: RiskScore
    plugin_ids: list[int]
    max_severity: int | None
    max_cvss3: float | None
    max_cvss2: float | None
    max_vpr: float | None
    patch_available: bool | None
    patch_refs: list[str]
    workarounds: list[str]
    aes_raw: float | None
    aes_normalized: float | None
    acr_raw: float | None
    last_seen: str | None
    last_scan: str | None
    detail_source: str
    kri_ids: list[str] = field(default_factory=list)


@dataclass
class CompensatingControl(_Serializable):
    type: str
    rationale: str
    rule_ref: str
    verified: bool
    verification_method: str
    coverage: str
    limitations: str
    reference: str
    applies_to: str


@dataclass
class AssetPlan(_Serializable):
    asset_uuid: str
    hostname: str
    path: str
    reason: str
    patch_refs: list[str]
    containment_recommended: bool
    containment_reason: str
    owner: str
    owner_team: str
    kri_score: float
    kri_tier: str
    kri_ids: list[str] = field(default_factory=list)
    runtime_product: str | None = None
    runtime_version: str | None = None
    target_version: str | None = None
    package: str | None = None


@dataclass
class RemediationPlan(_Serializable):
    vulnerability_id: str
    patch_path: dict[str, Any]
    compensating_controls: list[CompensatingControl]
    workarounds: list[dict[str, Any]]
    per_asset: list[AssetPlan]
    approval_required: bool
    generated_at: str
    plan_sha256: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class Ticket(_Serializable):
    ticket_id: str
    system: str
    status: str
    created_at: str
    run_id: str
    vulnerability_id: str
    plan_sha256: str
    priority: str
    owner_summary: dict[str, int]
    evidence_ref: str
    approved_by: str | None = None
    approved_at: str | None = None
    approval_note: str | None = None
    simulated: bool = True


@dataclass
class Approval(_Serializable):
    gate: str
    decision: str
    approver: str
    note: str
    recorded_at: str
    plan_sha256: str
    action_taken: str
    result_ref: str | None = None


@dataclass
class ContainmentEvent(_Serializable):
    event_id: str
    asset_uuid: str
    hostname: str
    mac: str | None
    action: str
    status: str
    policy: str
    vlan: str | None
    timestamp: str
    approver: str
    ticket_id: str
    connector: str
    simulated: bool
    reason: str


@dataclass
class VerificationAsset(_Serializable):
    asset_uuid: str
    hostname: str
    before_affected: bool
    after_affected: bool | None
    status: str
    last_scan: str | None
    last_found: str | None
    evidence: dict[str, Any]
    infection_status: str
    contained: bool


@dataclass
class VerificationResult(_Serializable):
    started_at: str
    finished_at: str
    method: str
    date_range: int
    assets: list[VerificationAsset]
    new_affected_assets: list[dict[str, Any]]
    remediated_count: int
    still_affected_count: int
    unknown_count: int
    infection_status: str
    notes: list[str]


@dataclass
class StageRecord(_Serializable):
    stage: str
    name: str
    status: str
    started_at: str
    finished_at: str | None = None
    summary: str = ""
    data_ref: str | None = None
    unknowns: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_calls: list[dict[str, Any]] = field(default_factory=list)
    contract: dict[str, Any] = field(default_factory=dict)
    attempt: int = 1
    duration_ms: float | None = None


@dataclass
class RunState(_Serializable):
    run_id: str
    created_at: str
    updated_at: str
    status: str
    target: dict[str, Any]
    options: dict[str, Any]
    source: dict[str, Any]
    vulnerability: dict[str, Any] | None = None
    exposure: list[dict[str, Any]] = field(default_factory=list)
    kri_detections: list[dict[str, Any]] = field(default_factory=list)
    risk_queue: list[dict[str, Any]] = field(default_factory=list)
    plan: dict[str, Any] | None = None
    ticket: dict[str, Any] | None = None
    approvals: list[dict[str, Any]] = field(default_factory=list)
    containment: list[dict[str, Any]] = field(default_factory=list)
    patch_execution: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    next_actions: list[str] = field(default_factory=list)
    truthfulness: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def new(
        cls,
        run_id: str,
        target: dict[str, Any],
        options: dict[str, Any],
        source: dict[str, Any],
    ) -> "RunState":
        now = utc_now()
        return cls(
            run_id=run_id,
            created_at=now,
            updated_at=now,
            status="initialized",
            target=target,
            options=options,
            source=source,
        )

    def add_event(self, kind: str, message: str, **fields: Any) -> None:
        event = {"at": utc_now(), "kind": kind, "message": message}
        event.update(fields)
        self.events.append(event)
        self.updated_at = utc_now()
