# Not-running inventory — final live re-run

**Date:** 2026-11-03  
**Run:** 9 focus CVEs processed (from 56 discovered PHP/Node.js CVEs), live Tenable read-only  
**Result:** 9/9 runs stopped at `awaiting_ticket_approval`; 0 errors; 0 target versions; 9/9 manifests verified; 293 explicit unknown fields.

This inventory is about **what did not execute in the final batch**, not a claim
that the code is broken. Some functions are approval-gated, some are CLI-only,
some are documentation, and some are intentionally removed.

## 1. Functions that did run

- `Pipeline.run`
- `stage_intake`, `stage_exposure`, `stage_control_check`,
  `stage_kri_register`, `stage_risk_scoring`, `stage_planning`
- `Pipeline._finalize`
- `RunStore.create`, `save`, `write_stage`, `write_reports`, `finalize`,
  `verify_manifest`
- `TenableVMClient.cve_plugin_hits`, `findings_for_plugins`, `asset_detail`,
  `agent_inventory`, `public_snapshot`
- `build_control_posture`, `evaluate_kri_register`, `score_asset`, `build_plan`
- `render_markdown`, `render_html`, `render_executive_summary`
- `_render_executive_summary`, `_write_executive_formats` (Markdown, HTML, PDF)
- `SimulatedEDR.status`, `public_snapshot` (status was `unknown`)
- `scripts/live_php_node_batch.py`

## 2. Approval-gated functions not run

These are intentionally unreachable without a recorded human approval:

| Function | File | Why it did not run |
|---|---|---|
| `Pipeline.approve` | `secops_autopilot/pipeline.py` | No gate approval |
| `Pipeline.verify` | `secops_autopilot/pipeline.py` | Requires remediation approval |
| `Pipeline._assert_plan_integrity` | `secops_autopilot/pipeline.py` | Only called by `approve` |
| `approve_ticket` | `stages/ticketing.py` | `ticket` gate not approved |
| `approve_remediation` | `stages/ticketing.py` | `remediation` gate not approved |
| `execute_containment` | `stages/containment.py` | `containment` gate not approved |
| `execute_patch` | `stages/patch_execution.py` | `patch` gate not approved; 0 targets |
| `execute_verification` | `stages/verification.py` | Requires remediation approval |
| `execute_restore` | `stages/recovery.py` | Requires verification and `restore` approval |

This is the correct safety behavior. They are not "dead"; they are the
state-changing half of the workflow.

## 3. Connector functions not run

| Connector | Not run | Why |
|---|---|---|
| `TenableSCClient` | All methods | Security Center not configured |
| `CiscoISEAdapter` | All methods | ISE not configured |
| `SimulatedTicketingSystem` | `create_ticket`, `approve_ticket`, `reject_ticket`, `update_ticket`, `get_ticket` | No ticket gate |
| `SimulatedNAC` | `quarantine`, `restore` | No containment gate |
| `SimulatedPatchManager` | `submit` | No patch gate |
| `SimulatedEDR` | No handoff exists | EDR handoff was removed |
| `JsonState` | `update` | No simulated state mutation; only `read` for EDR status |
| `TenableVMClient` | `health`, `tenant_summary` | CLI-only; the batch calls Pipeline directly |
| `RunStore` | `load`, `list_runs` | Batch creates/finalizes; it does not reload/list |
| `StageContext` | `record_approval`, `update_ticket` | No approval action |

`public_snapshot` methods for the simulated ticketing, NAC, EDR, and patch
connectors did run through `truthfulness`; they are not state-changing.

## 4. CLI commands not run by the batch

The batch calls `Pipeline` directly, so none of these CLI entry points ran in the
final re-run:

`cmd_doctor`, `cmd_inventory`, `cmd_run`, `cmd_status`, `cmd_approve`,
`cmd_verify`, `cmd_report`, `cmd_evidence`, `cmd_runs`, `cmd_stages`.

Some were exercised earlier in the session, but not by the final batch. They are
still valid entry points.

## 5. Scripts not run

| Script | Status |
|---|---|
| `scripts/live_php_node_batch.py` | **Ran** |
| `python3 -m unittest discover -s tests` | Not run by the batch; separately **62 tests pass** |

## 6. Skills and agent not invoked

These are Claude Code instruction assets; the Python batch does not load them:

- `SKILL.md`
- `skills/vuln-intake/SKILL.md`
- `skills/remediation-planning/SKILL.md`
- `.claude/agents/secops-autopilot.md`

The final batch was **script-driven**, not agent/skill-driven. The files still
install and describe the workflow, but they did not execute during the batch.
`CLAUDE.md` is loaded by Claude Code as context, not by the engine.

## 7. Markdown files not read by the engine

The Python engine reads **no Markdown files**. All of these are human/Claude
Code documentation or generated output:

**Project docs**

- `README.md`, `CLAUDE.md`, `SECURITY.md`, `SKILL.md`
- `docs/architecture.md`, `docs/kri-catalog.md`, `docs/kri-model.md`,
  `docs/roadmap.md`, `docs/security-and-safety.md`, `docs/tenable-integration.md`
- `playbooks/vuln-to-verified-fix.md`
- `skills/vuln-intake/SKILL.md`, `skills/remediation-planning/SKILL.md`
- `.claude/agents/secops-autopilot.md`
- `examples/README.md`, `reports/README.md`
- `submission/README.md`, `submission/secops-autopilot.md`
- `SecOps_Autopilot_Stages(1).docx.md` (source methodology input)

**Generated output**

- `reports/live-php-node-executive-summary.md` — consolidated management report
- `reports/live-php-node-executive-summary.html` — same report, HTML
- `reports/live-php-node-executive-summary.pdf` — same report, 5-page PDF
- `reports/live-php-node-phase-validation.md`
- `reports/live-php-node-assessment.md`
- `reports/executive-summaries/*.md` (9 run summaries)
- Per-run `report.md` / `executive-summary.md` (the `runs/` folder was removed
  after the batch; the retained copies are in `reports/executive-summaries/`)

## 8. Static helpers with no caller in the current source

These definitions appear unused by application code and tests; they may still be
useful as public helpers:

- `intake.severity_text`
- `util.write_json`
- `util.relative_age_hours`
- `report._plan_asset`
- `OwnerDirectory.public_snapshot`
- `ControlInventory.public_snapshot`
- `TenableHTTP.public_call_log`

## 9. Removed/deleted code

- `secops_autopilot/connectors/siem.py` — deleted.
- `stage_alerting` / notification phase — removed.
- `EDRConnector.handoff` and `SimulatedEDR.handoff` — removed.
- SOC/SIEM/ITSM terminology — removed from source and docs.
- CMDB terminology — replaced with **asset inventory**.
- The only remaining `alert` token is the AV/EDR monitor-mode vocabulary value
  in `kri_catalog.json`; it is a control mode, not a notification function.

## 10. What is important vs not important

**Important gaps**

1. Ticket, approval, containment, patch, verification, and restore never ran.
2. Zero target versions; patch submission would skip every job.
3. Control telemetry is absent: agent inventory 403, no EDR/AV inventory.
4. PHP CVE/PAN-OS mapping needs verification.
5. CVE-2026-111497 is an OS Brotli exposure across 15 assets, not just Node.js.
6. Discovery is capped at the 5,000-entry workbench limit.

**Not important for this batch**

- Demo and KRI-demo scripts, and the separate validation scenario pack, were
  removed from the repository; there is nothing left to run.
- Human documentation was not read by the engine; it is for operators/reviewers.
- 44 older/duplicate OS-package CVEs returned by the same discovery query were
  excluded from this pass; they remain in the tenant.
- CVE-2026-105483, 106070, and 106071 were not returned by this tenant
  discovery; there is nothing to run for them here.
