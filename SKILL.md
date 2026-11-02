---
name: secops-autopilot
description: "Carry an identified vulnerability from intake to a verified, evidenced fix. Use when a CVE, vendor advisory, zero-day report, or scanner export needs to be traced to the endpoints and servers it affects, checked against applied security controls, scored by real risk, remediated or compensated, contained through NAC, and closed out with audit evidence. Triggers on: SecOps Autopilot, vulnerability to fix, patch verification, affected assets for CVE, KRI, compensating control, NAC quarantine, remediation evidence."
---

# SecOps Autopilot

Take a vulnerability the team already knows about and drive it to a verified fix
— without making anyone stitch together six consoles or chase an asset owner by
hand.

The engine in this repository does the work. Use the `secops` CLI rather than
re-implementing Tenable queries or containment actions in ad-hoc shell.

## Core rules

These are not negotiable, and they hold at every stage:

1. **No state change without approval.** Ticket creation, NAC quarantine, patch
   push, and VLAN restore require a human approval recorded in the run. Read and
   plan freely; act only on approval.
2. **Record what you did not learn.** Unknown owner, unknown agent version,
   unreadable feed — write `unknown` and flag it. A guessed value in an audit
   record is worse than a gap.
3. **One record per stage.** Each stage emits a structured record. Stages chain
   by consuming the previous record, so any run can be replayed and audited.
4. **Evidence is the deliverable.** The fix matters, but the defensible record of
   how the fix was verified is what the team keeps.

## Usage

```bash
secops doctor
secops inventory
secops run --cve CVE-2017-0144
```

`run` is read-only. It stops at `awaiting_ticket_approval` and prints the next
command. The state-changing gates are:

```bash
secops approve --run <RUN_ID> --gate ticket --approver "<name>"
secops approve --run <RUN_ID> --gate remediation --approver "<infosec approver>"
secops approve --run <RUN_ID> --gate containment --approver "<name>"
secops verify --run <RUN_ID>
secops report --run <RUN_ID> --format html --verify
```

Restore is a fourth gate and is refused unless a fresh Tenable query shows the
CVE is gone and EDR has not reported an infection.

## The pipeline

| # | Stage | Engine | Emits |
|---|---|---|---|
| 1 | Intake | `Pipeline.run` | Normalized CVE record with Tenable plugin hits |
| 2 | Exposure | `Pipeline.run` | Affected assets with owner where available |
| 3 | Control check | `Pipeline.run` | Per-asset agent/EDR/AV posture and unknowns |
| 4 | KRI scoring | `Pipeline.run` | Transparent 0–100 score and ranked queue |
| 5 | Remediation | `Pipeline.run` | Patch path, compensating controls, workarounds |
| 6 | Ticket | `approve --gate ticket` then `--gate remediation` | Ticket and approval ledger |
| 7 | Containment | `approve --gate containment` | ISE ANC event or blocked record |
| 8 | Verification | `verify` | Verified fix, open items, or SOC escalation |
| 9 | Evidence | `report` / every stage | JSON, Markdown, HTML, SHA-256 manifest |

Read-only stages 1–5 run unattended. Stages 6–8 cannot.

## When the user asks for a CVE

1. Run `secops run --cve <CVE>`.
2. Summarize:
   - affected asset count and KRI tiers,
   - the patch path and any compensating controls,
   - the unknowns and why they are unknown,
   - the containment candidates and any blocked identities.
3. Ask for explicit approval for the first state change. Do not create a ticket
   or contact the NAC without it.
4. After each gate, summarize what changed and what the next gate authorizes.

If the run reports `no_exposure_found`, do not proceed to remediation. Widen the
date window or confirm the tenant scope.

## What the engine will not do

- Invent an owner, agent version, feed age, EDR state, patch prerequisite, or
  rollback step.
- Quarantine an asset with no MAC address. It records a blocked event instead.
- Claim a compensating control is verified without a test.
- Claim a host is clean because no EDR signal exists.
- Treat a ticket or a stale scan as a verified fix.

## Configuration

- Tenable keys: `.env` or environment; see `.env.example`.
- Optional owner CMDB: `--owners examples/owners.example.csv`.
- Optional EDR/AV inventory: `--controls examples/controls.example.csv`.
- Live Cisco ISE: set `ISE_URL`, `ISE_USERNAME`, `ISE_PASSWORD`. The adapter is
  implemented from the documented ERS API but is not live-validated here.
- Security Center: set `TENABLE_SC_URL`, `TENABLE_SC_ACCESS_KEY`,
  `TENABLE_SC_SECRET_KEY`, and run with `--source sc`.

## Related

- `README.md` — full quickstart, architecture, limitations.
- `docs/tenable-integration.md` — endpoints, filters, scope limits.
- `docs/kri-model.md` — scoring formula and containment policy.
- `docs/security-and-safety.md` — approval and evidence model.
- `docs/demo-script.md` — five-minute demonstration.
- `.claude/agents/secops-autopilot.md` — orchestrator agent.
- `playbooks/vuln-to-verified-fix.md` — end-to-end workflow.

## Status

Implemented. The Tenable Vulnerability Management path is live-tested; the
Security Center and Cisco ISE adapters are documented-API implementations that
are explicitly marked not live-validated. ITSM, EDR, and SIEM default to
file-backed simulators.
