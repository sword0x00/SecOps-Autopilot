# Security and safety model

SecOps Autopilot is designed to be safe to run against a production Tenable
tenant before any control-plane write is authorized.

## Read-only by default

`secops run` performs:

- Tenable reads: session, workbench CVE query, findings export, asset detail,
  agent inventory probe.
- Local writes: a run directory under `runs/` and simulated state under
  `.state/`.

It does **not** create a ticket, contact the NAC, submit a patch job, restart a
host, or change an endpoint. The run stops at `awaiting_ticket_approval` and
prints the next command.

## Approval gates

| Gate | What it authorizes | Preconditions |
|---|---|---|
| `ticket` | Create the ticketing-system ticket | A completed plan and an approver name |
| `remediation` | Infosec approval of the plan; enables containment and patch submission | An existing ticket |
| `containment` | Cisco ISE ANC quarantine | Remediation approved |
| `patch` | Submit patch jobs to the patch-management connector | Remediation approved; a verified target version per asset |
| `restore` | Return verified-remediated assets to production | Fresh verification shows remediation; a separate approver |

A rejection at the remediation gate moves the run to `remediation_rejected` and
makes containment and patch submission impossible. There is no override flag.

## Plan integrity

The remediation plan is canonicalized and hashed. Every approval stores:

- the gate and decision,
- the approver and timestamp,
- the plan SHA-256,
- the action taken and its result reference.

Before a ticket, containment, patch submission, or restore action, the engine
recomputes the plan hash. A modified plan invalidates the approval and raises an
error. This is covered by a test.

## No invented facts

The engine records `unknown` with a reason for:

- asset owner (no asset inventory mapping),
- agent version/status/feed age (API scope),
- EDR/AV presence and signature age (no inventory),
- application-control mode (no inventory),
- runtime product/version (no versioned CPE),
- fixed version/patch target (advisory cannot name a fix for the branch),
- patch prerequisites, rollback, and effort (not in scanner/advisory metadata),
- EDR status (baseline control evidence; no EDR signal).

It does not turn `has_agent=false` into "EDR absent"; those are different
controls. It does not turn a missing EDR signal into "clean." It does not turn a
MAC-less asset into a quarantinable endpoint. It does not turn an unsupported
runtime branch into a patch target.

## Containment safety

- Only assets marked `containment_recommended` in the approved plan are touched.
- An asset without a MAC address is recorded as `blocked`. ISE ANC cannot
  identify it; a human must contain it manually or enrich the asset identity.
- The simulated ISE adapter writes only to `.state/nac.json`.
- The real Cisco ISE adapter is off unless `ISE_URL`, `ISE_USERNAME`, and
  `ISE_PASSWORD` are configured. It issues documented ERS ANC apply/clear calls
  and records `validated: false` because it has not been exercised against a live
  ISE deployment here.
- Restore only applies to assets whose fresh Tenable query no longer reports the
  CVE. EDR status is recorded as baseline evidence and does not change restore
  eligibility.

## Patch execution safety

- Jobs are built only for assets on the approved `patch` path with a target
  version supplied by the advisory for that runtime branch.
- An asset with no verified target version is recorded in `skipped` with the
  reason; no job is submitted.
- The default patch connector is file-backed. It writes `.state/patch.json`,
  records `simulated: true`, `touched_host: false`, and never reports `patched`.
- A live adapter must set `live: true` and `simulated: false` only when it
  actually contacted the patch-management system. Even then, submission is not
  remediation evidence.
- A patch connector failure is recorded as a failed execution; the engine does
  not automatically retry a consequential submission.
- Verification remains the only accepted evidence of a fix. A queued, accepted,
  or "successful" patch job does not close the finding.

## Verification honesty

A Tenable finding disappearing after a rescan is evidence. The engine records the
verification query, the date window, the per-asset last scan, whether the asset
was contained, and the EDR baseline status. An absent finding is only accepted when `last_scan` is
within `SECOPS_VERIFICATION_MAX_SCAN_AGE_HOURS` (default 72h); a stale or missing
timestamp is `unknown` and records a `verification_scan_stale` event. If the query fails,
every asset is `unknown` and the run says so; it does not report a fix. A stale
scan, a submitted patch job, or a ticket update is not evidence of remediation.

## Secret handling

- Credentials live in `.env` (mode 0600, git-ignored) or the process
  environment.
- The HTTP transport logs only method, path, status, and duration. It never logs
  headers.
- Every artifact write passes through the redactor for the configured access and
  secret keys.
- Tests assert that access keys, secret keys, and `X-ApiKeys` never appear under
  `runs/`.
- `.env.example` contains placeholders only.

Before publishing or submitting the repository, run:

```bash
git grep -nE 'accessKey=|secretKey=|TENABLE_(ACCESS|SECRET)_KEY=.+' || true
git log --all -p | grep -E 'f568|8f02|c78c|5ac2' || true
```

The lab credentials supplied for the competition must never be committed.

## Evidence integrity

`manifest.json` and `manifest.sha256` hash every artifact except the manifest
itself. `secops evidence --run <id> --verify-only` recomputes each hash and reports
mismatches, missing files, and unlisted files.

## Operator responsibilities

- Confirm the Tenable tenant and asset scope before running.
- Keep the `.env` file out of backups that are not access-controlled.
- Review the plan, compensating controls, target versions, and unknowns before
  approving.
- Treat the simulated ticketing/NAC/EDR/patch records as a demonstration of the
  control flow, not as production actions.
- Confirm that a patch target is correct for the asset's runtime branch before
  approving the patch gate; the engine will not invent one.
- For a real ISE deployment, test the ANC policy and the restore path in a lab
  first; the adapter is marked unvalidated.
