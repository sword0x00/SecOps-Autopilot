---
name: "SecOps Autopilot"
author: "sword0x00"
github_url: "https://github.com/sword0x00/SecOps-Autopilot"
description: "Carry a Tenable finding through exposure, KRI scoring, approval-gated containment, and verified remediation evidence."
license: "MIT"
tier: "contributed"
tags:
  - tenable
  - vulnerability-management
  - kri
  - remediation
  - nac
  - audit-evidence
  - security-operations
  - claude-code
domains:
  - vulnerability-management
  - security-operations
integrations:
  - Tenable
date_added: 2026-11-02
contribution_agreement_date: "REPLACE_WITH_ACTUAL_ISO8601_ACCEPTANCE_TIME"
compatible_platforms:
  - Claude Code
invocation: "secops-autopilot"
---

# SecOps Autopilot

SecOps Autopilot is a Claude Code skill for the work that starts after a scanner
produces a finding: deciding which endpoints and servers are actually exposed,
checking whether the controls that should protect them are present and healthy,
ranking the real risk, planning a patch or a compensating control, opening the
right ticket, isolating what cannot wait, and proving the fix afterward.

It is an orchestration layer, not another scanner. It takes an existing CVE or
Tenable finding and drives one run to a defensible close.

## The workflow it replaces

A SecOps analyst typically moves through six consoles: the vulnerability
scanner, the asset inventory for ownership, the EDR console for agent health, the patch
portal, the NAC, and the ticketing system. The handoffs are manual, the evidence is
scattered, and the same asset is often chased twice.

This skill makes that chain one recorded run with explicit approval gates. Each
stage emits a structured record. The run can be replayed from its records.

## What is live

- **Tenable Vulnerability Management** is integrated and validated against a
  Tenable lab tenant: CVE-to-plugin mapping, per-asset findings export, asset
  detail, ACR/AES, agent flags, and an explicit probe for agent inventory scope.
- **Tenable Security Center** has an adapter following the documented `/rest`
  API (`analysis` with `vulndetails`, asset detail, agent inventory). It is
  marked not live-tested because no SC appliance was available in the lab.
- **Cisco ISE** has an ERS ANC adapter for quarantine/clear. It activates only
  when credentials are configured and records that it is not live-validated.
- Ticketing, EDR, and patch management default to file-backed simulators so the approval and
  evidence flow can be demonstrated without changing production state. Every
  simulated action is labelled as simulated.

The Tenable integration sends the required descriptive `User-Agent` on every
request and records it in the evidence snapshot.

## KRI coverage

The run handles the seven KRI requirements directly:

1. Which agents and controls are installed — Tenable `has_agent`, agent records
   where the API scope permits, EDR/AV from an optional control inventory.
2. Version, signature feed, and application-control mode — recorded when a
   connector exposes them; otherwise `unknown` with the exact reason.
3. Compensating controls and workarounds, a ticketing-system ticket, infosec approval, and
   owner routing — remediation plan, ticket, approval ledger, optional owners CSV.
4. Ticketing → NAC isolation → patch submission → restore or EDR escalation —
   the approval-gated containment, remediation execution, and verification stages.
5. Run events — high KRI, containment, verification failure, and infection records.
6. Waiting for action — run status, explicit next actions, approval ledger.
7. Reporting — per-stage JSON, Markdown and HTML reports, SHA-256 manifest.

On top of the narrative, the engine emits a per-asset **KRI register** for
KRI-01 … KRI-09: missing security agent, stale control version, stale threat
feed, detect-only mode, unresolved exploitable target CVE, NAC non-compliant
posture, active compromise, vulnerable runtime version, and externally exposed
vulnerable service. Every result is `detected`, `not_detected` (clear),
`unknown`, or `not_applicable`, with evidence. `unknown` is never treated as
clear. KRI-06 and KRI-07 route to containment regardless of the numeric score;
KRI-07 forces isolation; restore still requires verified remediation and Human
Approval. KRI-08 selects the exact
advisory fixed version from CPE; KRI-09 prioritizes web-exposed assets.
Thresholds and scope live in an editable JSON catalog.

## Safety properties

- Read-only until the first Human Approval. `run` never creates a ticket, touches the
  NAC, or submits a patch job.
- Five Human Approval conditions: ticket creation, infosec remediation Human
  Approval, containment, patch submission, and restore. Restore requires
  verified remediation.
- Every Human Approval binds to the remediation plan's SHA-256. A changed plan
  invalidates the Human Approval.
- An asset without a MAC address is recorded as blocked for NAC containment, not
  guessed.
- A patch job is only submitted when the advisory names a fixed version for the
  asset's runtime branch; otherwise the job is skipped with a reason.
- Unknown owner, agent version, runtime version, fixed version, feed age, EDR
  state, AV state, patch prerequisites, and rollback stay unknown with a reason.
  The engine never invents them.
- Verification is a fresh Tenable query. A stale scan or a disappeared asset is
  not treated as a fix. EDR infection status is recorded as evidence.

## Quickstart

```bash
git clone https://github.com/sword0x00/SecOps-Autopilot.git
cd SecOps-Autopilot
python3 -m pip install -e .
cp .env.example .env && chmod 600 .env
# set the Tenable API key pair and a contact in TENABLE_USER_AGENT

secops doctor
secops run --cve CVE-2017-0144
secops approve --run <RUN_ID> --gate ticket --approver "Your Name"
secops approve --run <RUN_ID> --gate remediation --approver "Infosec Approver"
secops approve --run <RUN_ID> --gate containment --approver "SecOps Lead"
secops approve --run <RUN_ID> --gate patch --approver "Patch Approver"
secops verify --run <RUN_ID>
secops report --run <RUN_ID> --format html --verify
```

The report includes the KRI arithmetic, the control gaps, the unverified
compensating controls, the approval ledger, the containment events, the patch
jobs, the verification result, and the list of things the run did not do.

## Limitations

- The Security Center and Cisco ISE adapters are implemented from the documented
  APIs but are not live-validated in this environment.
- The default ticketing/NAC/EDR/patch connectors are simulators, clearly labelled.
- Asset owners, EDR/AV health, and runtime versions require a asset inventory/control
  inventory export or versioned CPE; without them they are unknown.
- The engine does not deliver or execute a patch on an endpoint. It plans, gates,
  contains through the configured NAC, submits patch jobs through the configured
  connector, and verifies through Tenable.
- KRI weights are defaults, not a universal truth. They are visible in the score
  breakdown so a team can tune and defend them.

## Repository and license

The engine, skills, agent, playbook, tests, and documentation are in the linked
repository. The control-plane detections use the example inventories and are
asserted by `tests/test_kri_examples.py` with no tenant. Live PHP/Node.js
management reports are under `reports/`. MIT licensed. No credentials are stored
in the repository; local credentials belong in a git-ignored `.env`.
