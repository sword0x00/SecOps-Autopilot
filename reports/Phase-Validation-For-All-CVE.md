# Phase validation for all CVEs

**Generated:** 2026-11-05T17:50:24Z  
**Source:** tenable_vm — https://cloud.tenable.com (live=True)  
**Window:** last 3650 days  
**CVEs attempted:** 61  
**Scope:** 61 CVE runs — 56 discovered from PHP/Node.js plugin findings plus 5 added high-profile CVEs

## Scope and safety

This batch runs the read-only stages only: intake, exposure, control check, KRI register, scoring, remediation planning, and evidence. It does not approve ticket, containment, patch, or restore gates.

## Per-CVE results

| CVE | Status | Assets | KRI detected/unknown | Plan | Target versions | Errors |
|---|---|---|---|---|---|---|
| CVE-2017-0144 | awaiting_ticket_approval | 2 (HYPERVDC, sql2016) | 4/14 | 229a7f48-dc96-4fab-9a98-b99d8dfa9b52=patch, 3aa0a03e-353c-4000-ba62-b2a9132fde49=patch | — | — |
| CVE-2020-1472 | awaiting_ticket_approval | 5 (dc1, sql2016, sql2019, win2019, win2016) | 10/35 | 305977f2-acb6-441f-b34c-8cbb1df1a55d=patch, 3aa0a03e-353c-4000-ba62-b2a9132fde49=patch, 525ade79-1c06-4e2e-9129-da5ccc3d2836=patch, b97e5974-1024-4a2f-a48f-7aadd33ff06d=patch, e0897915-4240-46f8-ad3a-ab5effe6f5ce=patch | — | — |
| CVE-2021-26855 | no_exposure_found | 0 (—) | 0/0 | — | — | — |
| CVE-2021-44228 | awaiting_ticket_approval | 1 (dc1) | 2/7 | 305977f2-acb6-441f-b34c-8cbb1df1a55d=patch | — | — |
| CVE-2023-4966 | no_exposure_found | 0 (—) | 0/0 | — | — | — |
| CVE-2024-36137 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2025-14177 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2025-14178 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-105481 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-105482 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106069 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106072 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106073 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-106074 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-109618 | awaiting_ticket_approval | 2 (pa-820.lab.tenablesecurity.com, rhel9) | 4/14 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-109619 | awaiting_ticket_approval | 2 (pa-820.lab.tenablesecurity.com, rhel9) | 4/14 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-111497 | awaiting_ticket_approval | 15 (oraclelinux8.target.tenablesecurity.com, rhel8, rhel9, rhel10, oraclelinux10, ol9, deb13, win11, tpm-u2604, tpm-rocky9, debian12, tpm-deb13, freebsd14, freebsd13, tap-tnabl-lnx01) | 23/104 | 94cb18cb-5bff-44aa-927c-0934dae00541=patch, 6c1ffce8-2c1e-4953-9a29-5b76388d3c8b=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch, 2a89cb2f-fe1f-4ca5-b9d0-3027ea18236b=patch, 45295f4d-d8fc-44ef-b5b3-116d28407f42=patch, 5101c8c8-a841-4f16-9bec-0bfa5defb241=patch, 5bc962b1-c379-459f-a959-d6f5e4a0868d=patch, 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch, a1ebd2da-f81c-45db-b1ce-8574686d6297=patch, ab8890fa-0951-4ffa-89bc-aa0fd190e6c3=patch, ddfb5ea0-f4f5-4ebf-b284-f249ac7fa3ff=patch, 5172a7cb-94f0-41bc-b830-69085afbab88=patch, 14edbfe0-f977-4234-83ee-8a9624225b0f=patch, edde7440-0479-498b-9fef-ccfb890e81c5=patch, df36192f-8f04-49de-aac9-a4f06722277e=patch | — | — |
| CVE-2026-14355 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-17543 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-21637 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-21710 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-21711 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-21712 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-21713 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-21714 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-21715 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-21717 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-29786 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-31802 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48615 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48617 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48618 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48619 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48928 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48930 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48931 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48933 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48934 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48935 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48936 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-48937 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-56846 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-56847 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-56848 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-56850 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-58039 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-58040 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-58041 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-58042 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-58043 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-58044 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-58045 | awaiting_ticket_approval | 1 (win11) | 2/7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | — | — |
| CVE-2026-6722 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-6735 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-7258 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-7259 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-7260 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-7261 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-7262 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-7568 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |
| CVE-2026-91765 | awaiting_ticket_approval | 1 (rhel9) | 2/7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | — | — |

## Phase validation

| Phase | Complete | Skipped | Not run | Error | Assessment |
|---|---|---|---|---|---|
| intake | 61 | 0 | 0 | 0 | Runs live; no match yields `no_exposure_found`. |
| exposure | 59 | 2 | 0 | 0 | Runs live; assets are only those returned by Tenable. |
| control_check | 59 | 0 | 2 | 0 | Runs; agent inventory is 403, so agent version/feed are unknown. |
| kri_register | 59 | 0 | 2 | 0 | Runs; KRI-08 is unknown unless an advisory was supplied. |
| kri_scoring | 59 | 0 | 2 | 0 | Runs; unknown components are excluded and reported. |
| remediation_planning | 59 | 0 | 2 | 0 | Runs; target versions require advisory metadata. |
| ticket | 0 | 0 | 61 | 0 | Not run: approval gate. |
| remediation_approval | 0 | 0 | 61 | 0 | Not run: approval gate. |
| containment | 0 | 0 | 61 | 0 | Not run: approval gate and simulated NAC. |
| patch_execution | 0 | 0 | 61 | 0 | Not run: approval gate and simulated patch connector. |
| verification | 0 | 0 | 61 | 0 | Not run: requires remediation approval / post-remediation state. |
| recovery | 0 | 0 | 61 | 0 | Not run: requires verification and restore approval. |
| evidence | 61 | 0 | 0 | 0 | Runs; report and manifest written. |

## Issues and gaps

- CVE-2021-26855: no_exposure_found
- CVE-2023-4966: no_exposure_found
- **Evidence manifests:** all generated run manifests verified OK

- **Agent inventory 403:** live Tenable scope cannot read `/scanners/agents`; agent version/feed are recorded as unknown, not guessed.
- **No EDR/AV control connector:** KRI-01/02/03/04/06/07 remain unknown unless a control inventory or live connector is supplied.
- **Advisory coverage:** only the CVEs with files in `validation/advisories/` get KRI-08 fixed-version evaluation and patch targets. Others have no target.
- **Patch-gate impact:** 0 target versions across the batch; a patch gate would record no jobs. Package/version enrichment is required.
- **Gated phases:** ticket, containment, patch execution, verification, and restore did not run because no human approval was recorded. This is by design.
- **Simulated control plane:** ticketing, NAC, EDR, and patch are file-backed unless a live connector is configured.

## Per-run evidence

- `CVE-2017-0144` — `20261105T174241Z-CVE-2017-0144-26c6aa` — `runs/20261105T174241Z-CVE-2017-0144-26c6aa/report.html`
- `CVE-2020-1472` — `20261105T174251Z-CVE-2020-1472-7049ae` — `runs/20261105T174251Z-CVE-2020-1472-7049ae/report.html`
- `CVE-2021-26855` — `20261105T174302Z-CVE-2021-26855-5af798` — `runs/20261105T174302Z-CVE-2021-26855-5af798/report.html`
- `CVE-2021-44228` — `20261105T174306Z-CVE-2021-44228-2b7433` — `runs/20261105T174306Z-CVE-2021-44228-2b7433/report.html`
- `CVE-2023-4966` — `20261105T174315Z-CVE-2023-4966-2aa3b0` — `runs/20261105T174315Z-CVE-2023-4966-2aa3b0/report.html`
- `CVE-2024-36137` — `20261105T173717Z-CVE-2024-36137-54140a` — `runs/20261105T173717Z-CVE-2024-36137-54140a/report.html`
- `CVE-2025-14177` — `20261105T173722Z-CVE-2025-14177-3b09a8` — `runs/20261105T173722Z-CVE-2025-14177-3b09a8/report.html`
- `CVE-2025-14178` — `20261105T173727Z-CVE-2025-14178-e146c5` — `runs/20261105T173727Z-CVE-2025-14178-e146c5/report.html`
- `CVE-2026-105481` — `20261105T173733Z-CVE-2026-105481-ea95ef` — `runs/20261105T173733Z-CVE-2026-105481-ea95ef/report.html`
- `CVE-2026-105482` — `20261105T173739Z-CVE-2026-105482-479826` — `runs/20261105T173739Z-CVE-2026-105482-479826/report.html`
- `CVE-2026-106069` — `20261105T173744Z-CVE-2026-106069-377788` — `runs/20261105T173744Z-CVE-2026-106069-377788/report.html`
- `CVE-2026-106072` — `20261105T173749Z-CVE-2026-106072-41b8af` — `runs/20261105T173749Z-CVE-2026-106072-41b8af/report.html`
- `CVE-2026-106073` — `20261105T173754Z-CVE-2026-106073-958c87` — `runs/20261105T173754Z-CVE-2026-106073-958c87/report.html`
- `CVE-2026-106074` — `20261105T173800Z-CVE-2026-106074-a0ea66` — `runs/20261105T173800Z-CVE-2026-106074-a0ea66/report.html`
- `CVE-2026-109618` — `20261105T173805Z-CVE-2026-109618-21cb14` — `runs/20261105T173805Z-CVE-2026-109618-21cb14/report.html`
- `CVE-2026-109619` — `20261105T173812Z-CVE-2026-109619-835291` — `runs/20261105T173812Z-CVE-2026-109619-835291/report.html`
- `CVE-2026-111497` — `20261105T173818Z-CVE-2026-111497-8c91aa` — `runs/20261105T173818Z-CVE-2026-111497-8c91aa/report.html`
- `CVE-2026-14355` — `20261105T173832Z-CVE-2026-14355-030a58` — `runs/20261105T173832Z-CVE-2026-14355-030a58/report.html`
- `CVE-2026-17543` — `20261105T173837Z-CVE-2026-17543-552316` — `runs/20261105T173837Z-CVE-2026-17543-552316/report.html`
- `CVE-2026-21637` — `20261105T173843Z-CVE-2026-21637-8e6a2e` — `runs/20261105T173843Z-CVE-2026-21637-8e6a2e/report.html`
- `CVE-2026-21710` — `20261105T173848Z-CVE-2026-21710-fd6213` — `runs/20261105T173848Z-CVE-2026-21710-fd6213/report.html`
- `CVE-2026-21711` — `20261105T173854Z-CVE-2026-21711-f14904` — `runs/20261105T173854Z-CVE-2026-21711-f14904/report.html`
- `CVE-2026-21712` — `20261105T173859Z-CVE-2026-21712-c606d8` — `runs/20261105T173859Z-CVE-2026-21712-c606d8/report.html`
- `CVE-2026-21713` — `20261105T173905Z-CVE-2026-21713-62a4c8` — `runs/20261105T173905Z-CVE-2026-21713-62a4c8/report.html`
- `CVE-2026-21714` — `20261105T173910Z-CVE-2026-21714-41c475` — `runs/20261105T173910Z-CVE-2026-21714-41c475/report.html`
- `CVE-2026-21715` — `20261105T173915Z-CVE-2026-21715-016e54` — `runs/20261105T173915Z-CVE-2026-21715-016e54/report.html`
- `CVE-2026-21717` — `20261105T173920Z-CVE-2026-21717-7743a5` — `runs/20261105T173920Z-CVE-2026-21717-7743a5/report.html`
- `CVE-2026-29786` — `20261105T173926Z-CVE-2026-29786-23f612` — `runs/20261105T173926Z-CVE-2026-29786-23f612/report.html`
- `CVE-2026-31802` — `20261105T173931Z-CVE-2026-31802-a74ffd` — `runs/20261105T173931Z-CVE-2026-31802-a74ffd/report.html`
- `CVE-2026-48615` — `20261105T173937Z-CVE-2026-48615-fb19ed` — `runs/20261105T173937Z-CVE-2026-48615-fb19ed/report.html`
- `CVE-2026-48617` — `20261105T173942Z-CVE-2026-48617-7135ba` — `runs/20261105T173942Z-CVE-2026-48617-7135ba/report.html`
- `CVE-2026-48618` — `20261105T173948Z-CVE-2026-48618-e52c2c` — `runs/20261105T173948Z-CVE-2026-48618-e52c2c/report.html`
- `CVE-2026-48619` — `20261105T173953Z-CVE-2026-48619-735983` — `runs/20261105T173953Z-CVE-2026-48619-735983/report.html`
- `CVE-2026-48928` — `20261105T173958Z-CVE-2026-48928-8b6679` — `runs/20261105T173958Z-CVE-2026-48928-8b6679/report.html`
- `CVE-2026-48930` — `20261105T174003Z-CVE-2026-48930-11de42` — `runs/20261105T174003Z-CVE-2026-48930-11de42/report.html`
- `CVE-2026-48931` — `20261105T174009Z-CVE-2026-48931-518dbc` — `runs/20261105T174009Z-CVE-2026-48931-518dbc/report.html`
- `CVE-2026-48933` — `20261105T174014Z-CVE-2026-48933-34e215` — `runs/20261105T174014Z-CVE-2026-48933-34e215/report.html`
- `CVE-2026-48934` — `20261105T174020Z-CVE-2026-48934-34ff46` — `runs/20261105T174020Z-CVE-2026-48934-34ff46/report.html`
- `CVE-2026-48935` — `20261105T174026Z-CVE-2026-48935-d4eceb` — `runs/20261105T174026Z-CVE-2026-48935-d4eceb/report.html`
- `CVE-2026-48936` — `20261105T174031Z-CVE-2026-48936-4b4c61` — `runs/20261105T174031Z-CVE-2026-48936-4b4c61/report.html`
- `CVE-2026-48937` — `20261105T174036Z-CVE-2026-48937-ba7ee8` — `runs/20261105T174036Z-CVE-2026-48937-ba7ee8/report.html`
- `CVE-2026-56846` — `20261105T174042Z-CVE-2026-56846-254f98` — `runs/20261105T174042Z-CVE-2026-56846-254f98/report.html`
- `CVE-2026-56847` — `20261105T174047Z-CVE-2026-56847-ce7c89` — `runs/20261105T174047Z-CVE-2026-56847-ce7c89/report.html`
- `CVE-2026-56848` — `20261105T174052Z-CVE-2026-56848-fe2803` — `runs/20261105T174052Z-CVE-2026-56848-fe2803/report.html`
- `CVE-2026-56850` — `20261105T174057Z-CVE-2026-56850-138c62` — `runs/20261105T174057Z-CVE-2026-56850-138c62/report.html`
- `CVE-2026-58039` — `20261105T174102Z-CVE-2026-58039-cc86d0` — `runs/20261105T174102Z-CVE-2026-58039-cc86d0/report.html`
- `CVE-2026-58040` — `20261105T174108Z-CVE-2026-58040-e69e91` — `runs/20261105T174108Z-CVE-2026-58040-e69e91/report.html`
- `CVE-2026-58041` — `20261105T174112Z-CVE-2026-58041-02cdbe` — `runs/20261105T174112Z-CVE-2026-58041-02cdbe/report.html`
- `CVE-2026-58042` — `20261105T174118Z-CVE-2026-58042-ba1339` — `runs/20261105T174118Z-CVE-2026-58042-ba1339/report.html`
- `CVE-2026-58043` — `20261105T174123Z-CVE-2026-58043-794354` — `runs/20261105T174123Z-CVE-2026-58043-794354/report.html`
- `CVE-2026-58044` — `20261105T174128Z-CVE-2026-58044-0c90c7` — `runs/20261105T174128Z-CVE-2026-58044-0c90c7/report.html`
- `CVE-2026-58045` — `20261105T174133Z-CVE-2026-58045-444e0e` — `runs/20261105T174133Z-CVE-2026-58045-444e0e/report.html`
- `CVE-2026-6722` — `20261105T174138Z-CVE-2026-6722-c587d3` — `runs/20261105T174138Z-CVE-2026-6722-c587d3/report.html`
- `CVE-2026-6735` — `20261105T174143Z-CVE-2026-6735-341e0e` — `runs/20261105T174143Z-CVE-2026-6735-341e0e/report.html`
- `CVE-2026-7258` — `20261105T174148Z-CVE-2026-7258-4657ea` — `runs/20261105T174148Z-CVE-2026-7258-4657ea/report.html`
- `CVE-2026-7259` — `20261105T174153Z-CVE-2026-7259-245a98` — `runs/20261105T174153Z-CVE-2026-7259-245a98/report.html`
- `CVE-2026-7260` — `20261105T174159Z-CVE-2026-7260-3bc621` — `runs/20261105T174159Z-CVE-2026-7260-3bc621/report.html`
- `CVE-2026-7261` — `20261105T174204Z-CVE-2026-7261-814893` — `runs/20261105T174204Z-CVE-2026-7261-814893/report.html`
- `CVE-2026-7262` — `20261105T174209Z-CVE-2026-7262-ac7e58` — `runs/20261105T174209Z-CVE-2026-7262-ac7e58/report.html`
- `CVE-2026-7568` — `20261105T174215Z-CVE-2026-7568-d6fab5` — `runs/20261105T174215Z-CVE-2026-7568-d6fab5/report.html`
- `CVE-2026-91765` — `20261105T174220Z-CVE-2026-91765-6f97bf` — `runs/20261105T174220Z-CVE-2026-91765-6f97bf/report.html`
