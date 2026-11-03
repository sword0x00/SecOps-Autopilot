# Playbook — Vulnerability to verified fix

**Purpose:** move one identified vulnerability (CVE, vendor advisory, zero-day
report, or scanner export) from intake to a verified, evidenced fix without
bypassing human authorization or inventing missing facts.

**Applies to:** an affected asset fleet visible to the configured scanner. The
engine is an orchestration layer, not a scanner and not an exploit framework.

**Entry criteria**

- A target identifier (`CVE-YYYY-NNNN`) and a scanner/tenant scope.
- For runtime-specific remediation: an advisory JSON with affected ranges,
  fixed versions, and provenance (see `examples/` for an advisory JSON example).
- Optional but recommended: owner CSV, control inventory CSV, and a patch
  management connector.

**Exit criteria**

- The target is no longer reported by a fresh scanner read on every affected
  asset, or the remaining assets are explicitly open/escalated.
- Every containment, patch submission, and restore has a recorded Human Approval.
- The evidence manifest verifies, and the report labels live vs simulated data.

## Roles

| Role | Responsibility | Human Approval condition |
|---|---|---|
| SecOps operator | Runs intake through planning, prepares evidence, coordinates owners | — |
| Asset owner | Confirms business context, patch window, and rollback | Consulted |
| Infosec approver | Accepts the remediation plan and compensating controls | `remediation` |
| SecOps lead | Authorizes containment and restore | `containment`, `restore` |
| Patch approver | Authorizes patch job submission | `patch` |

No single person should be required for every gate in production. The CLI does
not enforce separation of duties; that is an organizational control. The
evidence records each Human Approval decision.

## Stage map

The source methodology has eleven stages; stages 9 and 10 are merged here as
**Verification and recovery** because a verification result must not
automatically release a quarantined host. The implementation has ten operating
stages plus an evidence stage.

### Stage 1 — Risk intake

**Input:** CVE, advisory JSON, scanner tenant.

**Actions**

1. Normalize the CVE; reject malformed identifiers.
2. Query the scanner for the CVE → plugin mapping and per-asset findings.
3. Merge advisory metadata if supplied. Preserve conflicts; do not overwrite
   scanner facts silently.
4. Record confidence, source references, and advisory provenance.

**Output/evidence:** normalized vulnerability record, plugin hits, finding count,
advisory provenance, source-call log.

**Failure branch**

- No plugin/finding: status `no_exposure_found`; do not proceed to remediation.
  Confirm scope/window or supply an exposure import.
- Scanner auth/scope error: status `intake_failed`; no state change.

**Command:** `secops run --cve <CVE> [--advisory <file>]`

### Stage 2 — Exposure and asset resolution

**Actions**

1. Group findings by asset; enrich with asset detail.
2. Resolve owner/team from the asset inventory export; record `unknown` when no row matches.
3. Apply `--max-assets`; record every truncated asset ID.
4. Preserve asset identity keys (UUID, MAC, IPv4, hostnames) for verification.

**Output/evidence:** affected assets with source, owner, criticality, confidence,
and explicit unknowns.

### Stage 3 — Security control check

**Actions**

1. Read the Tenable agent flag and any agent record the API scope exposes.
2. Merge EDR/AV presence, versions, feed age, mode, NAC posture, and patch-agent
   presence from the control inventory or a live connector.
3. Record every unavailable field as `unknown` with the reason and source.
4. Compute a control-gap score from the known and unknown state.

**Output/evidence:** per-asset `ControlPosture`, gaps, unknowns, sources.

**Rule:** a missing EDR signal is not evidence that the host is clean.

### Stage 4 — KRI identification and risk scoring

**Actions**

1. Evaluate KRI-01 … KRI-09 on every affected asset.
2. Treat `unknown` as unknown, never as clear.
3. Score each asset from severity, exploitability, exposure, control gap, and
   criticality; renormalize around unknown components.
4. Record high/critical exposure and KRI-07 in the run events.

**Output/evidence:** per-asset KRI matrix, score, tier, drivers, unknown
components, run events.

**Key decisions**

- KRI-06 (NAC non-compliant) or KRI-07 (active compromise) propose containment.
- KRI-07 forces isolation; restore still requires verified remediation and Human Approval.
- KRI-08 detects a runtime below the advisory fixed version, including an
  unsupported branch with no vendor fix.
- KRI-09 detects web exposure or an asset exposure score above threshold.

### Stage 5 — Remediation and workaround selection

**Actions**

1. For each asset, parse the runtime product/version from CPE and select the
   advisory fixed version for that branch.
2. If a fixed version exists: path `patch`, record the exact target version.
3. If the branch has no vendor fix: path `compensate`; record that the target is
   unknown and why.
4. If the asset is actively compromised: path `isolate`.
5. Select compensating controls matched to the exploit mechanism. Every control
   is `verified: false` until tested in the target environment.
6. Bind the plan to a SHA-256.

**Output/evidence:** patch path with target versions, per-asset plan, controls,
workarounds, provenance, plan hash.

**Rule:** never invent a patch target. If the advisory cannot name a fixed
version for the asset's branch, the plan says so and the patch stage submits no
job.

### Stage 6 — Human Approval and ticketing

**Human Approval condition — `ticket`:** create the ticketing-system ticket, bound to the plan SHA and evidence
reference. The ticket summary includes asset count, KRI tiers, owner coverage,
and containment candidates.

**Human Approval condition — `remediation`:** the infosec approver accepts or rejects the plan.
Rejection is terminal for the run and blocks containment and patch execution.

**Output/evidence:** ticket ID/status, Human Approval ledger with approver, time, plan
SHA, action taken.

### Stage 7 — Containment

**Human Approval condition — `containment`:** authorized only after remediation Human Approval.

**Actions**

1. For every asset the plan marks as a containment candidate:
   - MAC present: quarantine through the NAC solution connector (live NAC
     solution or simulator).
   - MAC absent: record `blocked` with the reason; do not guess an identity.
2. Record the Human Approval (approver name), ticket, policy, VLAN, connector, and `simulated` flag.
3. Record every containment action in the run.
4. Update the ticket to in-progress.

**Do not:** contain an asset with no recorded Human Approval, or treat a blocked
identity as contained.

### Stage 8 — Remediation execution

**Human Approval condition — `patch`:** authorized after remediation Human Approval; can run before or
after containment.

**Actions**

1. Build jobs only for assets on the `patch` path with a verified target version.
2. Submit jobs to the patch connector with run ID, ticket ID, current version,
   target version, and the Human Approval record.
3. Record submitted/skipped/failed jobs; label simulated jobs explicitly.
4. Record that a job was submitted, not that a host was patched.

**Output/evidence:** patch execution record, per-job status, skipped jobs with
reasons, Human Approval ledger entry.

**Rule:** a submitted job is not remediation evidence. Only a fresh scanner read
in stage 9 closes the finding.

### Stage 9 — Verification and recovery

**Verification (read-only):**

1. Re-query the scanner for the CVE's plugin set.
2. Match assets on every identity key; a finding that remains means
   `not_remediated`.
3. Record the EDR infection status in the verification evidence; it does not
   create a separate escalation branch.
4. Record new assets that appeared during verification; they keep the run open.
5. A missing finding after a fresh rescan is the fix evidence. A stale scan is
   not.

**Recovery (Human Approval condition `restore`):**

1. Eligible assets: verification status `remediated` and an active quarantine
   event.
2. Restore through the NAC; record each event.
3. Keep isolation for every other asset; keep the run open if anything remains
   affected or new exposure appeared.

**Output/evidence:** verification result per asset, infection status, restore
events, final status.

### Stage 10 — Evidence and compliance

1. Write Markdown and HTML reports from the run records.
2. Hash every artifact into `manifest.json` / `manifest.sha256`.
3. Verify with `secops evidence --run <id> --verify`.
4. Retain the run directory according to the organization's evidence retention
   policy. The manifest detects modification; it is not a WORM store.

## Gate matrix

| Human Approval condition | Authorizes | Required state | Cannot be bypassed by |
|---|---|---|---|
| `ticket` | ticketing-system ticket creation | plan exists and hash matches | a direct connector call from the operator |
| `remediation` | containment and patch eligibility | ticket exists, plan hash matches | editing the plan (hash mismatch) |
| `containment` | NAC quarantine | remediation Human Approval recorded | ticket status alone |
| `patch` | patch job submission | remediation Human Approval recorded | a plan without a verified target version |
| `restore` | NAC restore | fresh verification and isolated event | a green verification alone |

## Decision tree

```
Target finding present?
  no  -> no_exposure_found; confirm scope. Stop.
  yes -> control posture + KRI
         KRI-07 active compromise?
           yes -> isolate path; contain, remediate, verify.
           no  -> advisory fixed version for this runtime branch?
                    yes -> patch path; submit Human-Approved job; verify.
                    no  -> patch target unknown -> compensate path;
                           WAF/IPS/firewall controls; verify or escalate.
         KRI-06 NAC non-compliant or risk >= threshold?
           yes -> containment candidate; gate; MAC required.
```

## Failure and escalation branches

| Condition | Action | Run status |
|---|---|---|
| Scanner auth/scope failure | Stop; fix access; rerun | `intake_failed` |
| No finding in window | Widen window or confirm scope; do not remediate | `no_exposure_found` |
| Unsupported runtime branch | Compensate + migration plan; no invented patch target | `awaiting_ticket_approval` → later |
| No MAC for containment | Record blocked; manual containment/asset inventory enrichment | containment continues for others |
| Patch connector failure | Record failed jobs; do not claim submission | patch stage error |
| Verification still affected | Keep isolation; escalate to owner | `verification_open` |
| New asset during verification | Keep run open; scope new asset | `verification_open` |
| Plan edited after Human Approval | Reject every gate; re-plan | unchanged |
| Evidence manifest mismatch | Treat the package as untrusted; investigate | evidence failure |

## Evidence checklist per run

- [ ] normalized vulnerability + advisory provenance (verified/provided)
- [ ] affected assets with owner/confidence and truncation record
- [ ] per-asset control posture with explicit unknowns
- [ ] KRI matrix (detected/clear/unknown/n/a) and score drivers
- [ ] remediation plan + plan SHA-256 + target versions
- [ ] ticket ID and Human Approval ledger (all gates)
- [ ] containment events including blocked identities
- [ ] patch execution jobs including skipped jobs and simulation flag
- [ ] fresh verification results and EDR infection status
- [ ] restore events and remaining-isolated list
- [ ] report Markdown/HTML and verified SHA-256 manifest

## Testing and reporting

- `python3 -m unittest discover -s tests -v` covers contracts, advisory version
  ranges, KRI behavior, Human Approval gating, patch idempotency, reporting, and
  executive-summary generation (62 tests).
- `scripts/live_php_node_batch.py` runs the live read-only batch and writes the
  consolidated management report in Markdown, HTML, and PDF.
- The reports label live scanner reads and simulated control-plane connectors.
  Do not present a simulated connector action as production proof.

## What this playbook will not do

- Invent an owner, agent version, feed age, EDR state, patch target, or rollback.
- Quarantine an asset with no MAC.
- Claim a compensating control is verified without a test.
- Claim a host is clean because no EDR signal exists.
- Treat a ticket, a patch submission, or a stale scan as a verified fix.
- Restore an unverified host.
