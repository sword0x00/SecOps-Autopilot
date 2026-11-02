# Five-minute demo script

This is a live Tenable demo. The control plane (ITSM/NAC/EDR/SIEM) is simulated
and labelled as such. No patch is pushed and no real endpoint is isolated.

## Before the room

```bash
python3 -m pip install -e .
secops doctor
```

Expected: `Workbench read: True`; `Agent inventory: unknown` with the reason
`Insufficient scope`. Say the quiet part out loud: this is a real scope limit,
and the engine records it instead of inventing an agent version.

## 0. Show the KRI register without a tenant (20s, optional)

```bash
python3 scripts/kri_demo.py
```

This prints the DC01 / WS-FIN-042 / WS-MKT-011 matrix and the two synthetic
MS17-010 hosts. It is deterministic and makes no network calls. Use it if the
live tenant does not have a control inventory that matches the demo hosts.

## 1. Tenant context (30s)

```bash
secops inventory
```

Point out assets returned, Tenable agent coverage, severity distribution, and the
top plugins. This is the "what are we working with" view.

## 2. The read-only pipeline (90s)

```bash
secops run --cve CVE-2017-0144
```

Walk the table:

- Two affected Windows servers.
- Both critical KRI despite CVSS 8.8, because VPR is 9.9, the exploit is
  weaponized, and the control posture is absent/unknown.
- One asset has a MAC address; one does not.
- Patch path: KB4013389 / KB4013429 / MS17-010.
- The KRI register: KRI-05 (unpatched MS17-010) is detected on both hosts.
  KRI-01/02/03/04/06 are unknown without a control inventory; KRI-07 is unknown
  without an EDR signal. Say plainly that unknown is not clear.
- The run stopped at `awaiting_ticket_approval`. Nothing has changed.

The full KRI matrix is in the report. To exercise all seven detections with the
synthetic DC01 / WS-FIN-042 / WS-MKT-011 examples:

```bash
python3 -m unittest tests.test_kri -v
python3 -m unittest tests.test_flow.FlowTest.test_kri_07_detected_forces_isolation_and_soc_handoff -v
```

Optional: add the example inventories to show owner and EDR enrichment:

```bash
secops run --cve CVE-2017-0144 \
  --owners examples/owners.example.csv \
  --controls examples/controls.example.csv
```

## 3. Ticket + infosec approval (45s)

```bash
secops approve --run <RUN_ID> --gate ticket --approver "Demo Operator"
secops approve --run <RUN_ID> --gate remediation --approver "Infosec Approver" \
  --note "Approved for containment pending patch"
```

Point out that the approval record includes the plan SHA-256. Try to approve a
different plan and the engine refuses.

## 4. Containment (45s)

```bash
secops approve --run <RUN_ID> --gate containment --approver "SecOps Lead"
```

Expected: one `isolated` event for the asset with a MAC, one `blocked` event for
the asset without one. This is the honest behavior: ISE ANC cannot quarantine an
endpoint it cannot identify.

## 5. Verification (60s)

```bash
secops verify --run <RUN_ID>
```

Expected on the lab tenant: both assets are still affected because no patch was
applied. The run becomes `verification_open`, keeps isolation in place, and emits
verification-failure alerts. This is the point: the tool does not claim a fix
from a stale scan or from the act of opening a ticket.

Restore is refused:

```bash
secops approve --run <RUN_ID> --gate restore --approver "SecOps Lead"
# error: no contained asset has verified remediation; isolation is retained
```

The verified/restored branch is exercised by the automated test suite with a fake
source whose findings disappear after remediation:

```bash
python3 -m unittest tests.test_flow.FlowTest.test_verified_branch_restores_after_explicit_approval -v
```

### Optional: show the EDR/SOC branch

Copy the example EDR status into the local simulated state before verification:

```bash
cp examples/edr_status.example.json .state/edr_status.json
secops verify --run <RUN_ID>
```

Expected: the asset is `infected`, the run becomes `escalated_to_soc`, a SOC
case is created in `.state/edr_cases.json`, and restore is refused even though
the Tenable finding disappeared. The automated equivalent is:

```bash
python3 -m unittest tests.test_flow.FlowTest.test_edr_infection_escalates_and_blocks_restore -v
```

## 6. Evidence (45s)

```bash
secops report --run <RUN_ID> --format html --verify
```

Open the HTML report. Point to:

- the live-vs-simulated banner,
- the stage timeline,
- control gaps and unknowns,
- the KRI register matrix and detected evidence,
- the KRI component table,
- the approval ledger with the plan hash,
- the blocked-containment reason,
- the verification result,
- the SHA-256 manifest.

## Closing line

"The scanner tells us what is exposed. The agent tells us what is actually
protected. The KRI tells us what matters. The approval gates keep us from turning
a demo into an incident. And the evidence package is the thing the auditor
actually keeps."

## If the tenant has no findings for the CVE

Choose another CVE from a fresh export or run against a fixture:

```bash
python3 -m unittest discover -s tests -v
```

The tests use a stable fake source and exercise the same pipeline, including the
verified/restore branch and the blocked-containment branch.
