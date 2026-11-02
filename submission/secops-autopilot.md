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
scanner, the CMDB for ownership, the EDR console for agent health, the patch
portal, the NAC, and the ITSM tool. The handoffs are manual, the evidence is
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
- ITSM, EDR, and SIEM default to file-backed simulators so the approval and
  evidence flow can be demonstrated without changing production state. Every
  simulated action is labelled as simulated.

The Tenable integration sends the required descriptive `User-Agent` on every
request and records it in the evidence snapshot.

## KRI coverage

The run handles the seven KRI concerns directly:

1. Which agents and controls are installed — Tenable `has_agent`, agent records
   where the API scope permits, EDR/AV from an optional control inventory.
2. Version, signature feed, and application-control mode — recorded when a
   connector exposes them; otherwise `unknown` with the exact reason.
3. Compensating controls and workarounds, an ITSM ticket, infosec approval, and
   owner routing — remediation plan, ticket, approval ledger, optional owners CSV.
4. Ticketing → NAC isolation → patch/AV → restore or EDR/SOC handoff — the
   approval-gated containment and verification stages.
5. Alert — high KRI, containment, verification failure, and infection records.
6. Waiting for action — run status, explicit next actions, approval ledger.
7. Reporting — per-stage JSON, Markdown and HTML reports, SHA-256 manifest.

On top of the narrative, the engine emits a per-asset **KRI register** for
KRI-01 … KRI-07: missing security agent, stale control version, stale threat
feed, detect-only mode, unpatched MS17-010 host, NAC non-compliant posture, and
active compromise. Every result is `detected`, `not_detected` (clear),
`unknown`, or `not_applicable`, with evidence. `unknown` is never treated as
clear. KRI-06 and KRI-07 route to containment regardless of the numeric score;
KRI-07 forces isolation, alerts SOC, and blocks restore. Thresholds and scope
live in an editable JSON catalog.

## Safety properties

- Read-only until the first approval. `run` never creates a ticket or touches the
  NAC.
- Three approval gates: ticket creation, infosec remediation approval, and
  containment. Restore is a fourth gate and requires verified remediation.
- Every approval binds to the remediation plan's SHA-256. A changed plan
  invalidates the approval.
- An asset without a MAC address is recorded as blocked for NAC containment, not
  guessed or silently dropped.
- Unknown owner, agent version, feed age, EDR state, AV state, patch
  prerequisites, and rollback stay unknown with a reason. The engine never
  invents them.
- Verification is a fresh Tenable query. A stale scan or a disappeared asset is
  not treated as a fix. If EDR reports an infection, the asset is not restored
  and a SOC handoff is recorded.

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
secops verify --run <RUN_ID>
secops report --run <RUN_ID> --format html --verify
```

The report includes the KRI arithmetic, the control gaps, the unverified
compensating controls, the approval ledger, the containment events, the
verification result, and the list of things the run did not do.

## Limitations

- The Security Center and Cisco ISE adapters are implemented from the documented
  APIs but are not live-validated in this environment.
- The default ITSM/NAC/EDR/SIEM connectors are simulators, clearly labelled.
- Asset owners and EDR/AV health require a CMDB/control inventory export; without
  one they are unknown.
- The engine does not patch or execute on endpoints. It plans, gates, contains
  through the configured NAC, and verifies through Tenable.
- KRI weights are defaults, not a universal truth. They are visible in the score
  breakdown so a team can tune and defend them.

## Repository and license

The engine, skills, agent, playbook, tests, and documentation are in the linked
repository. A deterministic `scripts/kri_demo.py` shows all seven detections
with the example inventories and no tenant. MIT licensed. No credentials are stored in the repository; local
credentials belong in a git-ignored `.env`.
