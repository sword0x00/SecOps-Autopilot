# Live PHP/Node.js assessment — phase validation and issues

**Generated:** 2026-11-03T21:40Z  
**Source:** Tenable Vulnerability Management (`https://cloud.tenable.com`)  
**Window:** last 3650 days  
**Scope:** 9 focus CVEs processed from 56 PHP/Node.js CVEs returned by discovery  
**Read-only:** no ticket, containment, patch, or restore was approved or executed.

Companion report: `reports/live-php-node-phase-validation.md` (per-CVE table and
phase matrix). The consolidated management view is
`reports/live-php-node-executive-summary.md` (also `.html` and `.pdf`); per-run
summaries are in `reports/executive-summaries/<run-id>.md`.

## Final results

| Metric | Result |
|---|---|
| CVEs processed | 9 |
| Runs completed without error | 9 |
| Runs stopped at `awaiting_ticket_approval` | 9 |
| No-exposure runs | 0 |
| Unique assets returned | 16 |
| Asset appearances | 25 |
| Evidence manifests verified | 9/9 |
| Evidence stage recorded | 9/9 |
| Target versions produced | **0/25 asset plans** |
| Explicit unknown fields | 293 |

The tenant's actual asset set returned by Tenable was used; no asset was
assumed. The largest concentrations were `win11` (7 CVEs), `rhel9` (3), and
`pa-820.lab.tenablesecurity.com` (2). The remaining 13 assets each appeared for
one CVE, all the Brotli library finding CVE-2026-111497.

## Phase validation

| Phase | Runs complete | Not run | Verdict |
|---|---|---|---|
| Intake | 9 | 0 | Working live |
| Exposure | 9 | 0 | Working live; assets are API-returned only |
| Control check | 9 | 0 | Working, but control telemetry is mostly unknown |
| KRI register | 9 | 0 | Working; KRI-08 is unknown/not applicable |
| Risk scoring | 9 | 0 | Working; unknown components are excluded and reported |
| Remediation planning | 9 | 0 | Working; target versions are missing |
| Ticket | 0 | 9 | Approval gate; not run |
| Infosec remediation approval | 0 | 9 | Approval gate; not run |
| Containment | 0 | 9 | Approval gate; not run |
| Patch execution | 0 | 9 | Approval gate; no target versions |
| Verification | 0 | 9 | Requires remediation approval |
| Recovery/restore | 0 | 9 | Requires verification and restore approval |
| Evidence | 9 | 0 | Working; reports and manifests verified |

The separate notification phase and the previous external-monitoring concepts were removed. Escalation and infection are recorded as run events; they are no longer a separate phase.

## Important issues

### 1. Zero target versions — patch execution would submit no jobs

All 9 runs produced a plan, but **none produced a target version** for any of
the 25 asset plans. Three runs had advisory metadata:

- CVE-2026-109618
- CVE-2026-109619
- CVE-2026-111497

Even those produced no target version. The reason is evidence-based, not a
guess:

- PHP findings on `rhel9` carry RHEL package CPEs (for example
  `p-cpe:/a:redhat:enterprise_linux:php-cli`) without a PHP runtime version.
- The PHP CVEs also matched a PAN-OS plugin on `pa-820`, whose CPE carries the
  PAN-OS OS version, not a PHP version.
- The Node.js finding on `win11` carries a CPE with no version field.
- KRI-08 results: **7 unknown, 18 not applicable, 0 detected**. KRI-08 cannot
  compare a runtime version it does not have.

Consequence: `approve --gate patch` would record `not_submitted` and skip every
job. The engine correctly refuses to invent a target, but the operator gets no
exact remediation version. The next engine improvement should parse package and
fixed versions from scanner output (`Remote package installed` /
`Should be`, PAN-OS `Fixed version`) into a structured target, with the same
"unknown if absent" rule.

### 2. Control-plane blindness

- Tenable agent inventory returned HTTP 403 `Insufficient scope`.
- No EDR/AV control inventory was supplied.
- KRI results: KRI-01 24 unknown / 1 clear; KRI-02, KRI-03, KRI-04, KRI-06, and
  KRI-07 are unknown on all 25 asset appearances.
- The 9 runs contain 293 unknown stage fields in total.

This is the largest operational gap. The engine is behaving correctly by
recording unknowns, but the risk score and containment decisions cannot reflect
control posture until a live control connector or inventory is supplied.

### 3. Tenable CVE-to-plugin mapping anomaly

CVE-2026-109618 and CVE-2026-109619 are PHP advisories, but Tenable returned
Palo Alto Networks plugin 371596 with these CVEs on `pa-820`, alongside RHEL PHP
plugins on `rhel9`. The CVE list on the PAN-OS finding explicitly contains both
PHP CVEs. This may be a Tenable plugin metadata mapping issue, a bundled PHP
component in PAN-OS, or a false association. It should not be silently treated as
a PHP runtime finding. Verify the plugin/CVE mapping before ticketing or
containment; the engine is reporting the scanner's claim, not validating it.

### 4. Node.js CVE-2026-111497 is broader than Node.js

CVE-2026-111497 (Brotli out-of-bounds write) returned **15 assets**, not only
`win11`; `rhel9` is among them. The matches include FreeBSD, RHEL, Oracle Linux,
Ubuntu, Debian, Rocky, and other OS Brotli packages. Only `win11` also matched
the Node.js plugin; its Node CPE has no version. The remediation scope is
therefore library/OS package scope, not Node-only. KRI-08 cannot assess the OS
package versions from the current advisory's Node.js ranges.

### 5. Discovery is capped at 5,000 workbench entries

The discovery query returned exactly 5,000 vulnerabilities, the requested limit,
and 56 PHP/Node.js CVEs. This pass processed the 9 focus CVEs only. That focus
set is not proof that no additional PHP/Node.js findings exist. Use pagination
or a family-filtered export for an exhaustive inventory.

### 6. No state-changing phase was exercised

Ticket creation, approval, containment, patch submission, verification, and
restore were not run because no human approval was recorded. The ticketing, NAC,
EDR, and patch connectors are simulated. This is by design, not a defect.

## Not running / lower priority

**Not running by design**

- Ticket and infosec approval gates.
- Containment and patch submission.
- Verification and restore/recovery.
- Live ticketing, NAC, EDR, and patch-management integrations.
- The removed notification phase; there is no external notification sink.

**Lower priority for this pass**

- 44 older/duplicate OS-package CVEs returned by the same discovery query were
  deliberately excluded from this pass. They remain in the tenant and are not
  evidence of safety.
- CVE-2026-105483, CVE-2026-106070, and CVE-2026-106071 were not returned by this
  tenant discovery; there is nothing to remediate for them here.
- Duplicate CVEs across multiple plugins (for example the two RHEL PHP RHSAs)
  are not separate exposures; deduplicate by CVE and asset before ticketing.

## Recommended next actions

1. Enrich target versions from scanner package/fixed-version output; re-run the
   three advisory CVEs and confirm nonzero targets.
2. Supply a control inventory or live EDR/AV connector and re-run the batch to
   replace the unknown control KRIs.
3. Verify the PAN-OS mapping for the PHP CVEs before using those assets in a
   ticket.
4. Paginate discovery so the 5,000-entry cap cannot hide PHP/Node.js findings.
5. Pick one approved pilot asset (for example `rhel9` for the RHEL PHP CVEs) and
   exercise the ticket → containment → patch → verification → restore gates with
   a named approver. That is the only way to validate phases 6–9 live.

## Verified vs simulated

| Claim | Status |
|---|---|
| 9 intake, exposure, control, KRI, scoring, planning, and evidence phases ran against the live tenant | **Verified** |
| 16 assets and all 9 processed CVEs are exactly what the API returned in this query | **Verified for this query** |
| Evidence manifests and evidence stage | **Verified** |
| Target versions, control posture, current EDR/AV state | **Not available / unknown** |
| Ticket, containment, patch delivery, verification, restore | **Not run** |
| Engine regression coverage (unit and integration suite) | **62 tests pass**; the previous separate validation scenario pack was removed |

## Reproduce

```bash
python3 scripts/live_php_node_batch.py \
  --cves CVE-2026-105481,CVE-2026-105482,CVE-2026-106069,CVE-2026-106072,CVE-2026-106073,CVE-2026-106074,CVE-2026-109618,CVE-2026-109619,CVE-2026-111497 \
  --date-range 3650 --out reports
python3 -m unittest discover -s tests -v
```
