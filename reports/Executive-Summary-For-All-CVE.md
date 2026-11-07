# Executive summary for management — all CVE scan

**Generated:** 2026-11-05T17:50:24Z  
**Source:** tenable_vm — https://cloud.tenable.com (live=True)  
**Scope:** 61 CVE runs — 56 discovered from PHP/Node.js plugin findings plus 5 added high-profile CVEs  
**Safety:** read-only; no ticket, containment, patch, or restore executed.

## Bottom line

61 CVEs were processed with 0 errors. 2 had no Tenable plugin match; 59 stopped at the ticket gate. 22 unique assets were returned; 0 of 80 asset plans had a verified target version.

## Numbers at a glance

| Metric | Value |
|---|---|
| CVEs run | 61 |
| Runs with errors | 0 |
| No-exposure runs | 2 |
| Runs awaiting ticket approval | 59 |
| Unique assets | 22 |
| Asset appearances | 80 |
| Asset max tiers critical / high / medium / low / unknown | 22 / 0 / 0 / 0 / 0 |
| KRI detected / clear / unknown / n/a | 153 / 8 / 559 / 0 |
| Plan paths patch / compensate / isolate | 80 / 0 / 0 |
| Asset plans with a verified target version | 0 |
| Containment candidates | 56 |
| Containment isolated / blocked / failed / restored | 0 / 0 / 0 / 0 |
| Patch jobs submitted / skipped | 0 / 0 |
| Verification remediated / still affected / unknown | 0 / 0 / 0 |
| Infection status counts | not_run=61 |
| Approval gates recorded | 0 |
| Explicit unknown fields | 1023 |
| Evidence manifests verified | 61/61 |

## All CVEs

| CVE | Status | Assets | KRI detected / unknown | Plan paths | Target | Advisory |
|---|---|---|---|---|---|---|
| CVE-2017-0144 | awaiting_ticket_approval | 2: HYPERVDC, sql2016 | 4 / 14 | 229a7f48-dc96-4fab-9a98-b99d8dfa9b52=patch, 3aa0a03e-353c-4000-ba62-b2a9132fde49=patch | 0 | no |
| CVE-2020-1472 | awaiting_ticket_approval | 5: dc1, sql2016, sql2019, win2019, win2016 | 10 / 35 | 305977f2-acb6-441f-b34c-8cbb1df1a55d=patch, 3aa0a03e-353c-4000-ba62-b2a9132fde49=patch, 525ade79-1c06-4e2e-9129-da5ccc3d2836=patch, b97e5974-1024-4a2f-a48f-7aadd33ff06d=patch, e0897915-4240-46f8-ad3a-ab5effe6f5ce=patch | 0 | no |
| CVE-2021-26855 | no_exposure_found | 0: — | 0 / 0 | — | 0 | no |
| CVE-2021-44228 | awaiting_ticket_approval | 1: dc1 | 2 / 7 | 305977f2-acb6-441f-b34c-8cbb1df1a55d=patch | 0 | no |
| CVE-2023-4966 | no_exposure_found | 0: — | 0 / 0 | — | 0 | no |
| CVE-2024-36137 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2025-14177 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2025-14178 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-105481 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-105482 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106069 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106072 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106073 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-106074 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-109618 | awaiting_ticket_approval | 2: pa-820.lab.tenablesecurity.com, rhel9 | 4 / 14 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-109619 | awaiting_ticket_approval | 2: pa-820.lab.tenablesecurity.com, rhel9 | 4 / 14 | 0dd7c0c4-4487-484f-995c-01c4d09a2bb0=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-111497 | awaiting_ticket_approval | 15: oraclelinux8.target.tenablesecurity.com, rhel8, rhel9, rhel10, oraclelinux10, ol9, deb13, win11, tpm-u2604, tpm-rocky9, debian12, tpm-deb13, freebsd14, freebsd13, tap-tnabl-lnx01 | 23 / 104 | 94cb18cb-5bff-44aa-927c-0934dae00541=patch, 6c1ffce8-2c1e-4953-9a29-5b76388d3c8b=patch, e577a0de-9d56-4a22-9a59-7cf0ad038913=patch, 2a89cb2f-fe1f-4ca5-b9d0-3027ea18236b=patch, 45295f4d-d8fc-44ef-b5b3-116d28407f42=patch, 5101c8c8-a841-4f16-9bec-0bfa5defb241=patch, 5bc962b1-c379-459f-a959-d6f5e4a0868d=patch, 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch, a1ebd2da-f81c-45db-b1ce-8574686d6297=patch, ab8890fa-0951-4ffa-89bc-aa0fd190e6c3=patch, ddfb5ea0-f4f5-4ebf-b284-f249ac7fa3ff=patch, 5172a7cb-94f0-41bc-b830-69085afbab88=patch, 14edbfe0-f977-4234-83ee-8a9624225b0f=patch, edde7440-0479-498b-9fef-ccfb890e81c5=patch, df36192f-8f04-49de-aac9-a4f06722277e=patch | 0 | no |
| CVE-2026-14355 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-17543 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-21637 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-21710 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-21711 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-21712 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-21713 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-21714 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-21715 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-21717 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-29786 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-31802 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48615 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48617 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48618 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48619 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48928 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48930 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48931 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48933 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48934 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48935 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48936 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-48937 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-56846 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-56847 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-56848 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-56850 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-58039 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-58040 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-58041 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-58042 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-58043 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-58044 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-58045 | awaiting_ticket_approval | 1: win11 | 2 / 7 | 60ff70f2-2b94-40c4-88f5-d846aa5b141a=patch | 0 | no |
| CVE-2026-6722 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-6735 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-7258 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-7259 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-7260 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-7261 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-7262 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-7568 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |
| CVE-2026-91765 | awaiting_ticket_approval | 1: rhel9 | 2 / 7 | e577a0de-9d56-4a22-9a59-7cf0ad038913=patch | 0 | no |

## All assets

| Asset | Address | MAC | Owner | CVEs | Max KRI | Tier |
|---|---|---|---|---|---|---|
| win11 | 172.26.48.31 | 00:50:56:a6:ce:31 | unknown | 41: CVE-2024-36137, CVE-2026-105481, CVE-2026-105482, CVE-2026-106069, CVE-2026-106072, CVE-2026-106073, CVE-2026-106074, CVE-2026-111497, CVE-2026-21637, CVE-2026-21710, CVE-2026-21711, CVE-2026-21712, CVE-2026-21713, CVE-2026-21714, CVE-2026-21715, CVE-2026-21717, CVE-2026-29786, CVE-2026-31802, CVE-2026-48615, CVE-2026-48617, CVE-2026-48618, CVE-2026-48619, CVE-2026-48928, CVE-2026-48930, CVE-2026-48931, CVE-2026-48933, CVE-2026-48934, CVE-2026-48935, CVE-2026-48936, CVE-2026-48937, CVE-2026-56846, CVE-2026-56847, CVE-2026-56848, CVE-2026-56850, CVE-2026-58039, CVE-2026-58040, CVE-2026-58041, CVE-2026-58042, CVE-2026-58043, CVE-2026-58044, CVE-2026-58045 | 85.5 | critical |
| rhel9 | 172.26.48.55 | 00:50:56:a6:f0:98 | unknown | 16: CVE-2025-14177, CVE-2025-14178, CVE-2026-109618, CVE-2026-109619, CVE-2026-111497, CVE-2026-14355, CVE-2026-17543, CVE-2026-6722, CVE-2026-6735, CVE-2026-7258, CVE-2026-7259, CVE-2026-7260, CVE-2026-7261, CVE-2026-7262, CVE-2026-7568, CVE-2026-91765 | 87.1 | critical |
| dc1 | 172.26.48.10 | 00:50:56:bd:27:47 | unknown | 2: CVE-2020-1472, CVE-2021-44228 | 92.7 | critical |
| pa-820.lab.tenablesecurity.com | 172.26.0.22 | e8:98:6d:a9:d5:00 | unknown | 2: CVE-2026-109618, CVE-2026-109619 | 88.2 | critical |
| sql2016 | 172.26.48.14 | 00:50:56:a6:54:f9 | unknown | 2: CVE-2017-0144, CVE-2020-1472 | 84.7 | critical |
| HYPERVDC | 172.26.0.60 | unknown | unknown | 1: CVE-2017-0144 | 86.8 | critical |
| deb13 | 172.26.48.35 | 00:50:56:a6:19:46 | unknown | 1: CVE-2026-111497 | 85.5 | critical |
| debian12 | 172.26.48.15 | 00:50:56:a6:3d:5d | unknown | 1: CVE-2026-111497 | 84.9 | critical |
| freebsd13 | 172.26.48.25 | 00:50:56:a6:9c:32 | unknown | 1: CVE-2026-111497 | 82.6 | critical |
| freebsd14 | 172.26.48.21 | 00:50:56:a6:e7:68 | unknown | 1: CVE-2026-111497 | 83.2 | critical |
| ol9 | 172.26.48.34 | 00:50:56:a6:56:2a | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| oraclelinux10 | 172.26.48.19 | 00:50:56:a6:c2:7b | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| oraclelinux8.target.tenablesecurity.com | 172.26.48.17 | 00:50:56:a6:a5:7b | unknown | 1: CVE-2026-111497 | 89.9 | critical |
| rhel10 | 172.26.48.11 | 00:50:56:a6:e4:cd | unknown | 1: CVE-2026-111497 | 85.6 | critical |
| rhel8 | 172.26.48.57 | 00:50:56:a6:3b:23 | unknown | 1: CVE-2026-111497 | 87.1 | critical |
| sql2019 | 172.26.48.45 | 00:50:56:a6:f4:7e | unknown | 1: CVE-2020-1472 | 82.9 | critical |
| tap-tnabl-lnx01 | 10.100.213.231 | 00:50:56:a1:1f:21 | unknown | 1: CVE-2026-111497 | 80.6 | critical |
| tpm-deb13 | 10.238.64.115 | 10:66:6a:0c:e6:f2 | unknown | 1: CVE-2026-111497 | 84.6 | critical |
| tpm-rocky9 | 10.238.64.129 | 10:66:6a:78:fa:f4 | unknown | 1: CVE-2026-111497 | 85.1 | critical |
| tpm-u2604 | 10.238.64.120 | 10:66:6a:7b:9e:98 | unknown | 1: CVE-2026-111497 | 85.1 | critical |
| win2016 | 172.26.48.145 | 00:50:56:a6:5b:a1 | unknown | 1: CVE-2020-1472 | 82.9 | critical |
| win2019 | 172.26.48.38 | 00:50:56:a6:63:6f | unknown | 1: CVE-2020-1472 | 82.9 | critical |

## KRI coverage

| KRI | Name | Detected | Clear | Unknown | N/A |
|---|---|---|---|---|---|
| KRI-01 | Missing security agent | 0 | 1 | 79 | 0 |
| KRI-02 | Stale control version | 0 | 0 | 80 | 0 |
| KRI-03 | Stale threat feeds | 0 | 0 | 80 | 0 |
| KRI-04 | Detect-only mode | 0 | 0 | 80 | 0 |
| KRI-05 | Unresolved exploitable vulnerability | 80 | 0 | 0 | 0 |
| KRI-06 | NAC non-compliant posture | 0 | 0 | 80 | 0 |
| KRI-07 | Active compromise | 0 | 0 | 80 | 0 |
| KRI-08 | Vulnerable runtime version | 0 | 0 | 80 | 0 |
| KRI-09 | Externally exposed vulnerable service | 73 | 7 | 0 | 0 |

## Phase validation

| Phase | Complete | Skipped | Not run | Error |
|---|---|---|---|---|
| containment | 0 | 0 | 61 | 0 |
| control_check | 59 | 0 | 2 | 0 |
| evidence | 61 | 0 | 0 | 0 |
| exposure | 59 | 2 | 0 | 0 |
| intake | 61 | 0 | 0 | 0 |
| kri_register | 59 | 0 | 2 | 0 |
| kri_scoring | 59 | 0 | 2 | 0 |
| patch_execution | 0 | 0 | 61 | 0 |
| recovery | 0 | 0 | 61 | 0 |
| remediation_approval | 0 | 0 | 61 | 0 |
| remediation_planning | 59 | 0 | 2 | 0 |
| ticket | 0 | 0 | 61 | 0 |
| verification | 0 | 0 | 61 | 0 |

## Insights

**Largest asset concentrations**

| Asset | CVEs | Max KRI | Tier |
|---|---|---|---|
| win11 | 41 | 85.5 | critical |
| rhel9 | 16 | 87.1 | critical |
| dc1 | 2 | 92.7 | critical |
| pa-820.lab.tenablesecurity.com | 2 | 88.2 | critical |
| sql2016 | 2 | 84.7 | critical |
| oraclelinux8.target.tenablesecurity.com | 1 | 89.9 | critical |
| rhel8 | 1 | 87.1 | critical |
| HYPERVDC | 1 | 86.8 | critical |

- **No target versions:** the batch produced 0 targets. Patch submission would skip every job until package/runtime versions are enriched.
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

- `reports/Phase-Validation-For-All-CVE.md` — per-CVE and phase detail
- `reports/Phase-Validation-For-All-CVE.json` — machine-readable results
- `reports/Executive-Summary-For-All-CVE.md` / `.html` / `.pdf` — this summary
- `runs/<run-id>/executive-summary.md` — one management summary per run
