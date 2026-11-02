# Security and safety model

SecOps Autopilot is designed to be safe to run against a production Tenable
tenant before any control-plane write is authorized.

## Read-only by default

`secops run` performs:

- Tenable reads: session, workbench CVE query, findings export, asset detail,
  agent inventory probe.
- Local writes: a run directory under `runs/` and simulated state under
  `.state/`.

It does **not** create a ticket, contact the NAC, push a patch, restart a host, or
change an endpoint. The run stops at `awaiting_ticket_approval` and prints the
next command.

## Approval gates

| Gate | What it authorizes | Preconditions |
|---|---|---|
| `ticket` | Create the ITSM ticket | A completed plan and an approver name |
| `remediation` | Infosec approval of the plan; enables containment | An existing ticket |
| `containment` | Cisco ISE ANC quarantine | Remediation approved |
| `restore` | Return verified-remediated assets to production | Fresh verification shows remediation; separate approver |

A rejection at the remediation gate moves the run to `remediation_rejected` and
makes containment impossible. There is no override flag.

## Plan integrity

The remediation plan is canonicalized and hashed. Every approval stores:

- the gate and decision,
- the approver and timestamp,
- the plan SHA-256,
- the action taken and its result reference.

Before a ticket, containment, or restore action, the engine recomputes the plan
hash. A modified plan invalidates the approval and raises an error. This is
covered by a test.

## No invented facts

The engine records `unknown` with a reason for:

- asset owner (no CMDB mapping),
- agent version/status/feed age (API scope),
- EDR/AV presence and signature age (no inventory),
- application-control mode (no inventory),
- patch prerequisites, rollback, and effort (not in Tenable metadata),
- infection status (no EDR signal).

It does not turn `has_agent=false` into "EDR absent"; those are different
controls. It does not turn a missing EDR signal into "clean." It does not turn a
MAC-less asset into a quarantinable endpoint.

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
  CVE and whose EDR status is not `infected`.

## Verification honesty

A Tenable finding disappearing after a rescan is evidence. The engine records the
verification query, the date window, the per-asset last scan, and whether the
asset was contained. If the query fails, every asset is `unknown` and the run
says so; it does not report a fix.

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
- Review the plan, compensating controls, and unknowns before approving.
- Treat the simulated ITSM/NAC/SIEM/EDR records as a demonstration of the control
  flow, not as production actions.
- For a real ISE deployment, test the ANC policy and the restore path in a lab
  first; the adapter is marked unvalidated.
