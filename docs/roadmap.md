# Implementation roadmap

This roadmap is ordered by risk reduction per unit of effort. It distinguishes
what is implemented and tested now from what is planned. Dates are intentionally
omitted; the project is not resourced against a calendar in this repository.

## Current position

| Capability | Status | Evidence |
|---|---|---|
| Stage-contract architecture; read-only/state separation | **Implemented and tested** | `secops_autopilot/stages/`, `tests/test_stage_contracts.py` |
| Advisory metadata, fixed versions, version-range evaluation | **Implemented and tested** | `secops_autopilot/advisory.py`, `tests/test_advisory.py` |
| Generic KRI-05; KRI-08 runtime currency; KRI-09 external exposure | **Implemented and tested** | `kri.py`, `kri_catalog.json`, `tests/test_kri.py`, `tests/test_advisory.py` |
| Patch execution stage with Human Approval condition and simulated connector | **Implemented and tested** | `stages/patch_execution.py`, `connectors/patch.py` |
| Scan-freshness guard (stale scan is unknown, not a fix) | **Implemented and tested** | `stages/verification.py`, `tests/test_flow.py` |
| Evidence reports with advisory provenance, contracts, patch jobs | **Implemented and tested** | `report.py`, generated `report.md`/`report.html` |
| Live Tenable Vulnerability Management path | **Implemented and live-tested previously** | `docs/tenable-integration.md` |
| Live Cisco ISE ERS; Tenable Security Center | **Implemented, not live-validated in this environment** | code labels and `doctor` output |
| Live ticketing system, EDR, patch manager | **Not implemented; simulated defaults** | `connectors/` labels |

## Phase 1 — Architecture and reporting (complete)

**Goal:** make the engine testable and extensible before adding more live
connectors.

Delivered:

1. Stage contracts with kind, order, gate, retryability, and idempotency.
2. Read-only stage modules separated from state-changing modules.
3. Patch execution connector/stage and `patch` approval gate.
4. Advisory JSON schema, provenance validation, version ranges, and fixed
   versions.
5. Generic KRI-05 plus KRI-08/09.
6. Executive summary generated for every run, plus a live-batch management
   report in Markdown, HTML, and PDF.
7. Report/CLI support for advisory provenance, contracts, target versions, and
   patch jobs.
8. Scan-freshness guard: no fix claim from a stale or missing scan timestamp.

**Acceptance criteria (met):**

- Existing 40 tests still pass; new tests cover advisory, contracts, patch
  gating, and the executive-summary output (62 tests total).
- A read-only run records no ticket, containment, or patch job.
- Every state-changing stage requires its gate and a non-empty approver.
- A patch job without a verified target version is skipped, not guessed.

## Phase 2 — Production control-plane connectors (next)

**Goal:** replace the most consequential simulations with live adapters while
keeping the engine's evidence labels truthful.

| Workstream | Effort | Depends on | Acceptance criteria |
|---|---|---|---|
| ServiceNow/Jira ticketing adapter | M | ticket payload contract | Create/update/reject ticket; idempotency key; live flag and API errors recorded |
| Cisco ISE ERS live validation | M | lab ISE + ANC policy | Quarantine/restore against a lab endpoint; `simulated=False`; blocked/MAC behavior unchanged |
| Patch manager adapter (Intune/SCCM/Ansible/Tanium) | L | chosen product API | Submit job with target version; poll status; never report `patched` without scanner verification |
| EDR/AV control-plane adapter | L | EDR API scope | Presence/version/feed/mode/infection per asset; explicit unknown for missing fields |
| Tenable Security Center live validation | M | SC appliance | Same CVE/asset/verification behavior as VM; adapter note updated |

**Exit criteria:** at least a ticketing system + one patch manager + one EDR source are live in
a lab; the report truthfully labels every connector; the live batch report still
renders in Markdown, HTML, and PDF with live connectors.

## Phase 3 — Scale and automation

| Workstream | Effort | Acceptance criteria |
|---|---|---|
| Batch CVE queue | M | One command accepts a CVE list/export; per-CVE runs; no cross-run state leakage |
| Scheduler and SLA timers | M | Poll scanner feeds; create runs on new critical advisories; flag when a gate ages |
| asset inventory/owner sync | M | Scheduled inventory refresh; owner/team confidence recorded; no guessed owner |
| Multi-tenant profiles | M | Per-tenant credentials/scope; no artifact cross-contamination; redaction tested |
| RBAC / approval signatures | L | Gate approver identity verified against an IdP; separation-of-duties policy configurable |
| Resume/replay | S | A failed read-only stage can be retried without duplicating state; state-changing stages remain one-shot |

**Exit criteria:** a 50-CVE batch runs unattended through planning, stops at the
correct gates, and produces one verifiable evidence package per CVE. SLA
dashboard shows gate age and unknown rate.

## Phase 4 — Assurance and operations

| Workstream | Effort | Acceptance criteria |
|---|---|---|
| Scanner freshness check | S | **Implemented in Phase 1**; harden with tenant-specific scan SLA and reporting |
| Evidence retention/WORM | M | Manifest + external timestamp/immutable store; retention policy enforced |
| Safe exploit-validation hook | L | Optional, isolated, authorized lab-only validation; never runs in production by default |
| Chaos/error injection tests | S | Connector timeout, partial NAC failure, partial patch success, corrupt state, and plan tampering each produce the documented branch |
| KRI calibration | M | KRI weights/thresholds reviewed against historical runs; no unknown-as-clear regressions |
| Metrics/reporting | S | Stage success, unknown rate, containment blocks, verification failures exported |

**Exit criteria:** the engine can be operated by a team that did not write it,
with documented on-call runbooks and measurable SLOs.

## Backlog (prioritized)

1. **Live patch manager adapter** — the largest remaining simulation risk.
2. **ServiceNow/Jira adapter** — makes the ticket gate operationally real.
3. **EDR control-plane adapter** — closes the largest control-posture unknown.
4. **Batch/scheduler** — turns a per-CVE tool into a queue-driven service.
5. **RBAC/approval signatures** — required before broad production use.
6. **Evidence retention** — required for audit programs.
7. **KRI calibration** — after enough real runs exist to tune thresholds.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Advisory metadata is wrong or stale | Wrong patch target | Provenance required; conflicts preserved; the report cites sources; human approval |
| CPE lacks runtime version | KRI-08 unknown | Record unknown; do not infer from plugin text; owner confirms |
| Scanner finding is stale | False fix | Fresh-read verification plus scan-freshness guard (stale/absent timestamp = unknown); tenant-specific SLA in Phase 4 |
| Patch job accepted but host unchanged | False remediation | Patch job is never evidence; scanner re-query is the only fix evidence |
| NAC identity missing | Uncontained asset | Blocked record + manual containment; never guess MAC |
| Simulated connector mistaken for live | False assurance | `live`/`simulated` labels in every record and report; doctor output; report legend |
| Batch run cross-contamination | Wrong tenant/asset | Per-run state dirs; multi-tenant isolation tests in Phase 3 |
| Approval bypass | Unauthorized state change | Plan SHA binding; gate checks; tests for each gate; RBAC in Phase 3 |

## Definition of done for a production release

- All 62 unit/integration tests pass in CI; the live batch report renders in all three formats.
- At least one live ticketing system, one live patch manager, and one live EDR source are
  exercised in a lab.
- Scanner freshness guard is implemented.
- Evidence retention and approval identity are implemented.
- Runbook and rollback procedures are reviewed by SecOps and Infosec.
- A tabletop exercise covers: patch failure, verification failure, infection,
  missing MAC, and plan tampering.
