# Security policy

## Reporting a vulnerability

Do not open a public issue for a security vulnerability. Use GitHub's private
security advisory flow for this repository:

`Security` → `Advisories` → `Report a vulnerability`

Include:

- the affected version or commit,
- the component (`connectors/`, `pipeline.py`, `store.py`, CLI, report),
- reproduction steps,
- impact, especially any path that could bypass an approval gate or write a
  credential to an artifact.

## Scope

This project orchestrates other security products. The most important issues are:

- a state-changing action reachable without an approval record,
- a credential or API key written to a run artifact, report, or log,
- a plan-integrity bypass,
- a containment action applied to an asset that was not approved,
- a verification or evidence record that claims more than the data supports.

## Handling secrets

- Never commit `.env`, `runs/`, `.state/`, or `.cache/`.
- Use a dedicated Tenable API key with the minimum scope needed.
- Rotate the key if it is exposed.
- The repository's tests assert that configured access/secret keys and
  `X-ApiKeys` do not appear under `runs/`.

## Simulated connectors

ITSM, NAC, EDR, and SIEM default to file-backed simulators. They are not a
security boundary and must not be treated as production control planes. The
Cisco ISE adapter is implemented from the documented ERS API but has not been
validated against a live ISE deployment in this repository.
