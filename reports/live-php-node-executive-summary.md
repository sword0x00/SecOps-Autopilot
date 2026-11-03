# Executive summary for management — live PHP/Node.js batch

**Generated:** 2026-11-03T21:40:14Z  
**Source:** tenable_vm — https://cloud.tenable.com (live=True)  
**Scope:** 9 CVEs discovered from PHP/Node.js plugin findings  
**Safety:** read-only; no ticket, containment, patch, or restore executed.

## Bottom line

9 CVEs were processed with 0 errors. All runs stopped at the ticket gate. 16 unique assets were returned; 0 of 25 asset plans had a verified target version.

## Numbers at a glance

| Metric | Value |
|---|---|
| CVEs run | 9 |
| Runs with errors | 0 |
| No-exposure runs | 0 |
| Runs awaiting ticket approval | 9 |
| Unique assets | 16 |
| Asset appearances | 25 |
| Asset max tiers critical / high / medium / low / unknown | 16 / 0 / 0 / 0 / 0 |
| KRI detected / clear / unknown / n/a | 44 / 7 / 156 / 18 |
| Plan paths patch / compensate / isolate | 25 / 0 / 0 |
| Asset plans with a verified target version | 0 |
| Containment candidates | 25 |
| Containment isolated / blocked / failed / restored | 0 / 0 / 0 / 0 |
| Patch jobs submitted / skipped | 0 / 0 |
| Verification remediated / still affected / unknown | 0 / 0 / 0 |
| Infection status counts | not_run=9 |
| Approval gates recorded | 0 |
| Explicit unknown fields | 293 |
| Evidence manifests verified | 9/9 |

## All CVEs

| CVE | Status | Assets | KRI detected / unknown | Plan paths | Target | Advisory |
|---|---|---|---|---|---|---|
| CVE-2026-105481 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-105482 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106069 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106072 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106073 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106074 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-109618 | awaiting_ticket_approval | 2: pa-820.lab.tenablesecurity.com, rhel9 | 4 / 12 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | yes |
| CVE-2026-109619 | awaiting_ticket_approval | 2: pa-820.lab.tenablesecurity.com, rhel9 | 4 / 12 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | yes |
| CVE-2026-111497 | awaiting_ticket_approval | 15: freebsd14, rhel10, oraclelinux10, ol9, rhel8, oraclelinux8.target.tenablesecurity.com, rhel9, win11, tpm-u2604, tpm-rocky9, debian12, tpm-deb13, deb13, freebsd13, tap-tnabl-lnx01 | 24 / 90 | 14edbfe0-f977-4234-83ee-8a9624225b0f=patch, 2a89cb2f-fe1f-4ca5-b9d0-3027ea18236b=patch, 45295f4d-d8fc-44ef-b5b3-116d28407f42=patch, 5101c8c8-a841-4f16-9bec-0bfa5defb241=patch, 6c1ffce8-2c1e-4953-9a29-5b76388d3c8b=patch, 94cb18cb-5bff-44aa-927c-0934dae00541=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch, 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch, a1ebd2da-f81c-45db-b1ce-8574686d6297=patch, ab8890fa-0951-4ffa-89bc-aa0fd190e6c3=patch, ddfb5ea0-f4f5-4ebf-b284-f249ac7fa3ff=patch, 5172a7cb-94f0-41bc-b830-69085afbab88=patch, 5bc962b1-c379-459f-a959-d6f5e4a0868d=patch, edde7440-0479-498b-9fef-ccfb890e81c5=patch, df36192f-8f04-49de-aac9-a4f06722277e=patch | 0 | yes |

## All assets

| Asset | Address | MAC | Owner | CVEs | Max KRI | Tier |
|---|---|---|---|---|---|---|
| win11 | 172.26.48.31 | 00:50:56:a6:ce:31 | unknown | 7: CVE-2026-105481, CVE-2026-105482, CVE-2026-106069, CVE-2026-106072, CVE-2026-106073, CVE-2026-106074, CVE-2026-111497 | 85.5 | critical |
| rhel9 | 172.26.48.55 | 00:50:56:a6:f0:98 | unknown | 3: CVE-2026-109618, CVE-2026-109619, CVE-2026-111497 | 85.6 | critical |
| pa-820.lab.tenablesecurity.com | 172.26.0.22 | e8:98:6d:a9:d5:00 | unknown | 2: CVE-2026-109618, CVE-2026-109619 | 88.2 | critical |
| deb13 | 172.26.48.35 | 00:50:56:a6:19:46 | unknown | 1: CVE-2026-111497 | 83.9 | critical |
| debian12 | 172.26.48.15 | 00:50:56:a6:3d:5d | unknown | 1: CVE-2026-111497 | 84.9 | critical |
| freebsd13 | 172.26.48.25 | 00:50:56:a6:9c:32 | unknown | 1: CVE-2026-111497 | 82.6 | critical |
| freebsd14 | 172.26.48.21 | 00:50:56:a6:e7:68 | unknown | 1: CVE-2026-111497 | 86.1 | critical |
| ol9 | 172.26.48.34 | 00:50:56:a6:56:2a | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| oraclelinux10 | 172.26.48.19 | 00:50:56:a6:c2:7b | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| oraclelinux8.target.tenablesecurity.com | 172.26.48.17 | 00:50:56:a6:a5:7b | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| rhel10 | 172.26.48.11 | 00:50:56:a6:e4:cd | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| rhel8 | 172.26.48.57 | 00:50:56:a6:3b:23 | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| tap-tnabl-lnx01 | 10.100.213.231 | 00:50:56:a1:1f:21 | unknown | 1: CVE-2026-111497 | 80.6 | critical |
| tpm-deb13 | 10.238.64.115 | 10:66:6a:0c:e6:f2 | unknown | 1: CVE-2026-111497 | 84.6 | critical |
| tpm-rocky9 | 10.238.64.129 | 10:66:6a:78:fa:f4 | unknown | 1: CVE-2026-111497 | 85.1 | critical |
| tpm-u2604 | 10.238.64.120 | 10:66:6a:7b:9e:98 | unknown | 1: CVE-2026-111497 | 85.1 | critical |

## KRI coverage

| KRI | Name | Detected | Clear | Unknown | N/A |
|---|---|---|---|---|---|
| KRI-01 | Missing security agent | 0 | 1 | 24 | 0 |
| KRI-02 | Stale control version | 0 | 0 | 25 | 0 |
| KRI-03 | Stale threat feeds | 0 | 0 | 25 | 0 |
| KRI-04 | Detect-only mode | 0 | 0 | 25 | 0 |
| KRI-05 | Unresolved exploitable vulnerability | 25 | 0 | 0 | 0 |
| KRI-06 | NAC non-compliant posture | 0 | 0 | 25 | 0 |
| KRI-07 | Active compromise | 0 | 0 | 25 | 0 |
| KRI-08 | Vulnerable runtime version | 0 | 0 | 7 | 18 |
| KRI-09 | Externally exposed vulnerable service | 19 | 6 | 0 | 0 |

## Phase validation

| Phase | Complete | Skipped | Not run | Error |
|---|---|---|---|---|
| containment | 0 | 0 | 9 | 0 |
| control_check | 9 | 0 | 0 | 0 |
| evidence | 9 | 0 | 0 | 0 |
| exposure | 9 | 0 | 0 | 0 |
| intake | 9 | 0 | 0 | 0 |
| kri_register | 9 | 0 | 0 | 0 |
| kri_scoring | 9 | 0 | 0 | 0 |
| patch_execution | 0 | 0 | 9 | 0 |
| recovery | 0 | 0 | 9 | 0 |
| remediation_approval | 0 | 0 | 9 | 0 |
| remediation_planning | 9 | 0 | 0 | 0 |
| ticket | 0 | 0 | 9 | 0 |
| verification | 0 | 0 | 9 | 0 |

## Insights

**Largest asset concentrations**

| Asset | CVEs | Max KRI | Tier |
|---|---|---|---|
| win11 | 7 | 85.5 | critical |
| rhel9 | 3 | 85.6 | critical |
| pa-820.lab.tenablesecurity.com | 2 | 88.2 | critical |
| freebsd14 | 1 | 86.1 | critical |
| rhel10 | 1 | 85.6 | critical |
| oraclelinux10 | 1 | 85.6 | critical |
| ol9 | 1 | 85.6 | critical |
| rhel8 | 1 | 85.6 | critical |

- **No target versions:** the batch produced 0 targets. Patch submission would skip every job until package/runtime versions are enriched.
- **Advisory without target:** CVE-2026-109618, CVE-2026-109619, CVE-2026-111497 had advisory metadata but no CPE-matched target version.
- **Control confidence:** KRI-02/03/04/06/07 are unknown on every asset; agent inventory is out of scope and no EDR/AV inventory was supplied.
- **Scope is broader than Node.js:** CVE-2026-111497 matched OS Brotli packages across 15 assets, not only the Node.js host.
- **Scanner mapping needs review:** the PHP CVEs also matched a PAN-OS plugin; verify the CVE/plugin association.
- **Discovery is capped:** the workbench query returned the requested 5,000-entry limit; paginate before calling the list exhaustive.

## Decisions required

1. Fix runtime/package version enrichment before approving any patch gate.
2. Supply an asset inventory/control connector to reduce unknown KRIs.
3. Review the PAN-OS PHP mapping and the 15-asset Brotli scope.
4. Select a pilot asset and approve ticket → containment → patch → verification with a named approver.

## Evidence

- `reports/live-php-node-phase-validation.md` — per-CVE and phase detail
- `reports/live-php-node-phase-validation.json` — machine-readable results
- `reports/live-php-node-assessment.md` — issue analysis and priorities
- `reports/executive-summaries/<run-id>.md` — one management summary per run
