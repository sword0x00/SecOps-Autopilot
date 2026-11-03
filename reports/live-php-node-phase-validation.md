# Live PHP/Node.js phase validation

**Generated:** 2026-11-03T21:40:14Z  
**Source:** tenable_vm — https://cloud.tenable.com (live=True)  
**Window:** last 3650 days  
**CVEs attempted:** 9  
**Scope:** focused-latest (9 CVEs)

## Scope and safety

This batch runs the read-only stages only: intake, exposure, control check, KRI register, scoring, remediation planning, and evidence. It does not approve ticket, containment, patch, or restore gates.

## Per-CVE results

| CVE | Status | Assets | KRI detected/unknown | Plan | Target versions | Errors |
|---|---|---|---|---|---|---|
| CVE-2026-105481 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-105482 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106069 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106072 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106073 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106074 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-109618 | awaiting_ticket_approval | 2 (pa-820.lab.tenablesecurity.com, rhel9) | 4/12 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-109619 | awaiting_ticket_approval | 2 (pa-820.lab.tenablesecurity.com, rhel9) | 4/12 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-111497 | awaiting_ticket_approval | 15 (freebsd14, rhel10, oraclelinux10, ol9, rhel8, oraclelinux8.target.tenablesecurity.com, rhel9, win11, tpm-u2604, tpm-rocky9, debian12, tpm-deb13, deb13, freebsd13, tap-tnabl-lnx01) | 24/90 | 14edbfe0-f977-4234-83ee-8a9624225b0f=patch, 2a89cb2f-fe1f-4ca5-b9d0-3027ea18236b=patch, 45295f4d-d8fc-44ef-b5b3-116d28407f42=patch, 5101c8c8-a841-4f16-9bec-0bfa5defb241=patch, 6c1ffce8-2c1e-4953-9a29-5b76388d3c8b=patch, 94cb18cb-5bff-44aa-927c-0934dae00541=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch, 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch, a1ebd2da-f81c-45db-b1ce-8574686d6297=patch, ab8890fa-0951-4ffa-89bc-aa0fd190e6c3=patch, ddfb5ea0-f4f5-4ebf-b284-f249ac7fa3ff=patch, 5172a7cb-94f0-41bc-b830-69085afbab88=patch, 5bc962b1-c379-459f-a959-d6f5e4a0868d=patch, edde7440-0479-498b-9fef-ccfb890e81c5=patch, df36192f-8f04-49de-aac9-a4f06722277e=patch | — | — |

## Phase validation

| Phase | Complete | Skipped | Not run | Error | Assessment |
|---|---|---|---|---|---|
| intake | 9 | 0 | 0 | 0 | Runs live; no match yields `no_exposure_found`. |
| exposure | 9 | 0 | 0 | 0 | Runs live; assets are only those returned by Tenable. |
| control_check | 9 | 0 | 0 | 0 | Runs; agent inventory is 403, so agent version/feed are unknown. |
| kri_register | 9 | 0 | 0 | 0 | Runs; KRI-08 is unknown unless an advisory was supplied. |
| kri_scoring | 9 | 0 | 0 | 0 | Runs; unknown components are excluded and reported. |
| remediation_planning | 9 | 0 | 0 | 0 | Runs; target versions require advisory metadata. |
| ticket | 0 | 0 | 9 | 0 | Not run: approval gate. |
| remediation_approval | 0 | 0 | 9 | 0 | Not run: approval gate. |
| containment | 0 | 0 | 9 | 0 | Not run: approval gate and simulated NAC. |
| patch_execution | 0 | 0 | 9 | 0 | Not run: approval gate and simulated patch connector. |
| verification | 0 | 0 | 9 | 0 | Not run: requires remediation approval / post-remediation state. |
| recovery | 0 | 0 | 9 | 0 | Not run: requires verification and restore approval. |
| evidence | 9 | 0 | 0 | 0 | Runs; report and manifest written. |

## Issues and gaps

- No intake/exposure errors in this batch.
- **Evidence manifests:** all generated run manifests verified OK

- **Agent inventory 403:** live Tenable scope cannot read `/scanners/agents`; agent version/feed are recorded as unknown, not guessed.
- **No EDR/AV control connector:** KRI-01/02/03/04/06/07 remain unknown unless a control inventory or live connector is supplied.
- **Advisory coverage:** only the CVEs with files in `validation/advisories/` get KRI-08 fixed-version evaluation and patch targets. Others have no target.
- **Advisory without target version:** CVE-2026-109618, CVE-2026-109619, CVE-2026-111497. The advisory was attached, but the finding CPE did not expose a matching runtime/product version, so the engine refused to invent a target.
- **Patch-gate impact:** 0 target versions across the batch; a patch gate would record no jobs. Package/version enrichment is required.
- **Gated phases:** ticket, containment, patch execution, verification, and restore did not run because no human approval was recorded. This is by design.
- **Simulated control plane:** ticketing, NAC, EDR, and patch are file-backed unless a live connector is configured.

## Per-run evidence

- `CVE-2026-105481` — `20261103T213526Z-CVE-2026-105481-79f20c` — `None`
- `CVE-2026-105482` — `20261103T213531Z-CVE-2026-105482-6bfded` — `None`
- `CVE-2026-106069` — `20261103T213536Z-CVE-2026-106069-d6e675` — `None`
- `CVE-2026-106072` — `20261103T213541Z-CVE-2026-106072-4903f8` — `None`
- `CVE-2026-106073` — `20261103T213546Z-CVE-2026-106073-e25a41` — `None`
- `CVE-2026-106074` — `20261103T213550Z-CVE-2026-106074-26891a` — `None`
- `CVE-2026-109618` — `20261103T213555Z-CVE-2026-109618-3d12a8` — `None`
- `CVE-2026-109619` — `20261103T213601Z-CVE-2026-109619-099c81` — `None`
- `CVE-2026-111497` — `20261103T213607Z-CVE-2026-111497-74fcdb` — `None`
