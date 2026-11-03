---
name: secops-autopilot
description: "Carry an identified vulnerability from intake to a verified, evidenced fix. Use when a CVE, vendor advisory, zero-day report, or scanner export needs to be traced to the endpoints and servers it affects, checked against applied security controls, scored by real risk, remediated or compensated, contained through NAC, patch-submitted, and closed out with audit evidence. Triggers on: SecOps Autopilot, vulnerability to fix, patch verification, affected assets for CVE, KRI, compensating control, NAC quarantine, remediation evidence, advisory fixed version."
---

# SecOps Autopilot

Take a vulnerability the team already knows about and drive it to a verified fix
— without making anyone stitch together six consoles or chase an asset owner by
hand.

The engine in this repository does the work. Use the `secops` CLI rather than
re-implementing scanner queries or containment actions in ad-hoc shell.

## Core rules

These are not negotiable, and they hold at every stage:

1. **No state change without approval.** Ticket creation, NAC quarantine, patch
   submission, and VLAN restore require a human approval recorded in the run.
   Read and plan freely; act only on approval.
2. **Record what you did not learn.** Unknown owner, agent version, runtime
   version, EDR state, patch target, or feed age is written as `unknown` with a
   reason. A guessed value in an audit record is worse than a gap.
3. **One record per stage.** Each stage emits a structured record with its
   contract. Stages chain by consuming the previous record, so any run can be
   replayed and audited.
4. **A patch job is not a fix.** Submission is an execution record. Only a fresh
   scanner read plus an EDR infection check verifies remediation.
5. **Evidence is the deliverable.** The fix matters, but the defensible record of
   how the fix was verified is what the team keeps.

## Usage

```bash
secops doctor
secops inventory
secops stages
secops run --cve CVE-2017-0144
secops run --cve CVE-2026-109618 --advisory advisory.json
```

`run` is read-only. It stops at `awaiting_ticket_approval` and prints the next
command. The state-changing gates are:

```bash
secops approve --run <RUN_ID> --gate ticket --approver "<name>"
secops approve --run <RUN_ID> --gate remediation --approver "<infosec approver>"
secops approve --run <RUN_ID> --gate containment --approver "<name>"
secops approve --run <RUN_ID> --gate patch --approver "<patch approver>"
secops verify --run <RUN_ID>
secops approve --run <RUN_ID> --gate restore --approver "<name>"
secops report --run <RUN_ID> --format html --verify
```

Restore is refused unless a fresh scanner query shows the CVE is gone on that
asset, EDR has not reported an infection, and the asset was actually isolated.
Patch submission is refused without the remediation approval and a verified
target version.

## The pipeline

| # | Stage | Engine | Emits |
|---|---|---|---|
| 1 | Intake | `Pipeline.run` | Normalized CVE record + advisory provenance + plugin hits |
| 2 | Exposure | `Pipeline.run` | Affected assets with owner where available |
| 3 | Control check | `Pipeline.run` | Per-asset agent/EDR/AV/NAC/patch posture and unknowns |
| 4 | KRI register + scoring | `Pipeline.run` | Per-asset KRI-01 … KRI-09 matrix plus transparent 0–100 score |
| 5 | Remediation | `Pipeline.run` | Patch path, target versions, compensating controls, workarounds |
| 6 | Ticket | `approve --gate ticket` then `--gate remediation` | Ticket and approval ledger |
| 7 | Containment | `approve --gate containment` | NAC event or blocked record |
| 8 | Remediation execution | `approve --gate patch` | Patch jobs with per-asset target versions; simulated by default |
| 9 | Verification + recovery | `verify` then `approve --gate restore` | Verified fix, open items, or infection escalation; restore events |
| 10 | Evidence | `report` / every stage | JSON, Markdown, HTML, SHA-256 manifest |

Read-only stages 1–5 and the verification read run unattended. Ticket creation,
containment, patch submission, and restore cannot.

## KRI register

The engine evaluates nine named KRIs from
`secops_autopilot/kri_catalog.json` on every affected asset:

KRI-01 missing security agent, KRI-02 stale control version, KRI-03 stale threat
feed, KRI-04 detect-only mode, KRI-05 unresolved exploitable target CVE, KRI-06
NAC non-compliant, KRI-07 active compromise, KRI-08 vulnerable runtime version,
KRI-09 externally exposed vulnerable service.

Each is `detected`, `not_detected`, `unknown`, or `not_applicable`, with evidence
and an action. `unknown` is never treated as clear. KRI-06 and KRI-07 propose
containment regardless of the numeric score; KRI-07 forces isolation and blocks
restore. KRI-08 reads the runtime product/version from CPE and the advisory's
affected range; KRI-09 uses web port/service or asset exposure score. Use
`--controls` for EDR/AV/baseline/NAC fields, `--advisory` for fixed versions and
mitigations, and `--kri-catalog` to customize thresholds.

## When the user asks for a CVE

1. Run `secops run --cve <CVE>`; add `--advisory <file>` when a vendor advisory
   with affected ranges/fixed versions is available.
2. Summarize:
   - affected asset count and KRI tiers,
   - KRI-08 runtime/fixed-version evidence and any unsupported branch,
   - the patch path, target versions, and compensating controls,
   - the unknowns and why they are unknown,
   - containment candidates and any blocked identities.
3. Ask for explicit approval for the first state change. Do not create a ticket,
   contact the NAC, or submit a patch job without it.
4. After each gate, summarize what changed and what the next gate authorizes.
5. If verification is available, run it; do not call a patch job or a stale scan
   a fix.

If the run reports `no_exposure_found`, do not proceed to remediation. Widen the
date window, confirm the tenant scope, or supply a scanner export.

## What the engine will not do

- Invent an owner, agent version, feed age, EDR state, runtime version, patch
  target, patch prerequisite, or rollback step.
- Quarantine an asset with no MAC address. It records a blocked event instead.
- Claim a compensating control is verified without a test.
- Claim a host is clean because no EDR signal exists.
- Claim a patch job or a ticket is a verified fix.
- Treat a stale scan as evidence of remediation.
- Restore an infected or unverified isolated host.

## Configuration

- Tenable keys: `.env` or environment; see `.env.example`.
- Optional owner asset inventory: `--owners examples/owners.example.csv`.
- Optional EDR/AV inventory: `--controls examples/controls.example.csv`.
- Advisory metadata: `--advisory <json>`; provenance is required for a
  `verified` claim.
- Live Cisco ISE: set `ISE_URL`, `ISE_USERNAME`, `ISE_PASSWORD`. The adapter is
  implemented from the documented ERS API but is not live-validated here.
- Security Center: set `TENABLE_SC_URL`, `TENABLE_SC_ACCESS_KEY`,
  `TENABLE_SC_SECRET_KEY`, and run with `--source sc`.
- Patch management is simulated; a live adapter implements the same
  `PatchConnector` interface.

## Related

- `README.md` — quickstart, architecture, limitations.
- `docs/architecture.md` — gap analysis, stage contracts, state machine, error model.
- `docs/roadmap.md` — production connector and hardening plan.
- `docs/tenable-integration.md` — endpoints, filters, scope limits.
- `docs/kri-catalog.md` — KRI rules and examples.
- `docs/kri-model.md` — scoring formula and containment policy.
- `docs/security-and-safety.md` — approval and evidence model.
- `.claude/agents/secops-autopilot.md` — orchestrator agent.
- `playbooks/vuln-to-verified-fix.md` — end-to-end workflow.

## Status

Implemented. The Tenable Vulnerability Management path is live-tested; the
Security Center and Cisco ISE adapters are documented-API implementations that
are explicitly marked not live-validated. Ticketing, EDR, and patch management
default to file-backed simulators. Live PHP/Node.js batch reports and per-run
management summaries are under `reports/`.
