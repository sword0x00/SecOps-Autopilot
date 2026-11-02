# SecOps Autopilot

Carries a vulnerability from detection to a verified, evidenced fix across the tools a SecOps team already runs.

## What this repo is

An orchestration layer, not another scanner. It takes an already-identified vulnerability (CVE, vendor advisory, zero-day report, scanner export) and drives it through:

1. **Intake** — normalize the vulnerability into one record
2. **Exposure** — find which endpoints and servers are actually affected
3. **Control check** — confirm agent/EDR/AV presence, versions, feeds, and modes
4. **KRI scoring** — rank by real risk, not raw CVSS
5. **Remediation** — patch path plus compensating controls (IPS/SIEM/WAF/firewall)
6. **Ticket** — ITSM ticket with owner, evidence, and infosec approval gate
7. **Containment** — NAC (Cisco ISE) isolates non-compliant devices to a remediation VLAN
8. **Verification** — re-check after patch; restore if compliant, hand to EDR/SOC if infected
9. **Evidence** — audit-ready record of every decision and action

## Layout

```
CLAUDE.md                        you are here
README.md                        quickstart, architecture, limitations
SKILL.md                         entry point for the /secops-autopilot skill
pyproject.toml                   package + `secops` console script
secops_autopilot/
  cli.py                         doctor, inventory, run, approve, verify, report, evidence
  pipeline.py                    stage orchestration and approval gates
  intake.py  scoring.py          stage 1 and stage 4 logic
  remediation.py                 stage 5 patch/control planning
  controlcheck.py                stage 3 posture and unknowns
  store.py  report.py            evidence store, Markdown/HTML reports
  connectors/
    tenable_vm.py                live Tenable Vulnerability Management
    tenable_sc.py                Tenable Security Center adapter (not live-validated)
    itsm.py  nac.py  edr.py      simulated by default; ISE ERS adapter included
    siem.py  http.py             alert sink and shared HTTP transport
skills/
  vuln-intake/SKILL.md           vulnerability normalization
  remediation-planning/SKILL.md  patch + compensating control selection
.claude/agents/
  secops-autopilot.md            orchestrator subagent
playbooks/
  vuln-to-verified-fix.md        end-to-end chained workflow
examples/                        owner and control inventory CSV schemas
docs/                            integration, KRI model, safety, demo script
submission/                      CyberAgents Exchange listing draft
tests/                           unit + end-to-end tests with a fake Tenable source
```

## Commands

```bash
secops doctor                         # Tenable auth, scope, User-Agent
secops inventory                      # tenant asset/vulnerability overview
secops run --cve CVE-2017-0144        # read-only pipeline; stops before state change
secops approve --run <id> --gate ticket|remediation|containment|restore --approver "<name>"
secops verify --run <id>              # fresh Tenable re-query
secops report --run <id> --format html --verify
secops evidence --run <id> --verify-only
python3 -m unittest discover -s tests -v
```

## Conventions

- **Read-only by default.** Any state-changing action (ticket creation, NAC quarantine, patch push) requires an explicit approval step. Never auto-execute containment. `secops run` must not create tickets or call the NAC.
- **Evidence first.** Every stage writes a structured record under `runs/<run-id>/`. If it is not recorded, it did not happen.
- **No invented facts.** If a controller, feed version, or asset owner is unknown, record it as `unknown` — do not guess. The value of this system is that a human can trust the output.
- **Connectors are pluggable.** Each external system sits behind the interfaces in `secops_autopilot/connectors/base.py`, so the pipeline runs against simulated backends in tests.
- **Secrets stay local.** Credentials live in `.env` (mode 0600, git-ignored) or the environment. Never commit `.env`, `runs/`, or `.state/`. Every artifact write is redacted.
- **Simulation is labelled.** ITSM, NAC, EDR, and SIEM are file-backed unless a live connector is configured; reports and run records must say which.

## Source of truth

- Tenable filters: `plugin.attributes.cve.raw` on `/workbenches/vulnerabilities`; export filters use a `filters` object (`{"plugin_id":[...]}`).
- Agent inventory may be out of API scope; record the 403 reason instead of inferring a version.
- Approval binds to the remediation plan SHA-256; modifying the plan invalidates it.
- Verification is a fresh read. A missing finding after a rescan is evidence; a stale scan is not.

## Status

Implemented and live-tested against Tenable Vulnerability Management. Tenable Security Center and Cisco ISE adapters follow documented APIs but are marked not live-validated in this environment. Default ITSM/EDR/SIEM backends are simulated. See `README.md` for the full status and limitations.
