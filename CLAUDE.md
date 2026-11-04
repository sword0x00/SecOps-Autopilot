# SecOps Autopilot

Carries a vulnerability from detection to a verified, evidenced fix across the tools a SecOps team already runs.

## What this repo is

An orchestration layer, not another scanner. It takes an already-identified vulnerability (CVE, vendor advisory, zero-day report, scanner export) and drives it through:

1. **Intake** — normalize the vulnerability into one record
2. **Exposure** — find which endpoints and servers are actually affected
3. **Control check** — confirm agent/EDR/AV presence, versions, feeds, and modes
4. **KRI register + scoring** — detect the eight-indicator KRI register per asset, then rank by real risk, not raw CVSS
5. **Remediation** — patch path plus compensating controls (IPS/WAF/firewall)
6. **Ticket** — ticketing-system ticket with owner, evidence, and infosec approval gate
7. **Containment** — NAC (Cisco ISE) isolates non-compliant devices to a remediation VLAN
8. **Remediation execution** — approved patch jobs submitted to the patch-management connector
9. **Verification & recovery** — fresh re-check after patch; restore only verified devices after approval; EDR status is baseline evidence
10. **Evidence** — audit-ready record of every decision and action

## Layout

```
CLAUDE.md                        you are here
README.md                        quickstart, architecture, limitations
SKILL.md                         entry point for the /secops-autopilot skill
pyproject.toml                   package + `secops` console script
secops_autopilot/
  cli.py                         doctor, inventory, run, approve, verify, report, evidence
  pipeline.py                    thin orchestrator and approval facade
  stages/                        explicit stage contracts and stage modules
  intake.py  scoring.py          stage 1 and stage 4 risk-score logic
  advisory.py                    advisory schema, version ranges, provenance
  kri.py  kri_catalog.json       KRI-01 … KRI-06, KRI-08, KRI-09 register and thresholds
  remediation.py                 stage 5 patch/control planning
  controlcheck.py                stage 3 posture and unknowns
  store.py  report.py            evidence store, Markdown/HTML reports
  connectors/
    tenable_vm.py                live Tenable Vulnerability Management
    tenable_sc.py                Tenable Security Center adapter (not live-validated)
    ticketing.py  nac.py  edr.py simulated by default; ISE ERS adapter included
    patch.py                     patch jobs; simulated by default
    http.py                      shared HTTP transport
skills/
  vuln-intake/SKILL.md           vulnerability normalization
  remediation-planning/SKILL.md  patch + compensating control selection
.claude/agents/
  secops-autopilot.md            orchestrator subagent
playbooks/
  vuln-to-verified-fix.md        structured end-to-end workflow
reports/                         live management summaries and evidence reports
examples/                        owner and control inventory CSV schemas
docs/                            architecture, roadmap, KRI, safety
submission/                      CyberAgents Exchange listing draft
tests/                           unit + end-to-end tests with a fake Tenable source
```

## Commands

```bash
secops doctor                         # Tenable auth, scope, User-Agent
secops inventory                      # tenant asset/vulnerability overview
secops stages                         # stage contracts, gates, read-only status
secops run --cve CVE-2017-0144        # read-only pipeline; stops before state change
secops run --cve CVE-2026-109618 --advisory advisory.json
secops approve --run <id> --gate ticket|remediation|containment|patch|restore --approver "<name>"
secops verify --run <id>              # fresh Tenable re-query
secops report --run <id> --format html --verify
secops evidence --run <id> --verify-only
python3 -m unittest discover -s tests -v
```

## Conventions

- **Read-only by default.** Any state-changing action (ticket creation, NAC quarantine, patch submission, restore) requires an explicit approval step. Never auto-execute containment. `secops run` must not create tickets, call the NAC, or submit patch jobs.
- **Stage contracts are runtime data.** Every stage declares inputs, outputs, kind, gate, and idempotency; the record carries the contract. Do not add a state-changing stage without a gate.
- **A patch job is not a fix.** Patch submission is an execution record. Verification is a fresh scanner read plus an EDR check; a stale scan or queued job is not evidence.
- **Evidence first.** Every stage writes a structured record under `runs/<run-id>/`; finalization also writes `executive-summary.md`, `report.md`, `report.html`, and the manifest. If it is not recorded, it did not happen.
- **No invented facts.** If a controller, feed version, runtime version, fixed version, patch target, or asset owner is unknown, record it as `unknown` — do not guess. The value of this system is that a human can trust the output.
- **Advisory metadata is input with provenance.** A `verified` advisory must carry a source URL and retrieval time; conflicts with scanner facts are preserved.
- **Connectors are pluggable.** Each external system sits behind the interfaces in `secops_autopilot/connectors/base.py` (and `patch.py`), so the pipeline runs against simulated backends in tests.
- **Secrets stay local.** Credentials live in `.env` (mode 0600, git-ignored) or the environment. Never commit `.env`, `runs/`, or `.state/`. Every artifact write is redacted.
- **Simulation is labelled.** Ticketing, NAC, EDR, and patch are file-backed unless a live connector is configured; reports and run records must say which.

## Source of truth

- Tenable filters: `plugin.attributes.cve.raw` on `/workbenches/vulnerabilities`; export filters use a `filters` object (`{"plugin_id":[...]}`).
- Agent inventory may be out of API scope; record the 403 reason instead of inferring a version.
- The KRI register is data-driven from `secops_autopilot/kri_catalog.json`; `unknown` is not `not_detected`. KRI-05 is target-CVE generic. KRI-08 reads runtime product/version from CPE; KRI-09 uses web port/service or AES. KRI-06 routes to containment. EDR is a baseline control like AV: presence, version, feed, and mode feed KRI-01 … KRI-04, and EDR status is evidence only.
- Advisory metadata: a `verified` claim requires `provenance.source_url` and `retrieved_at`. The engine does not fetch advisories itself.
- Approval binds to the remediation plan SHA-256; modifying the plan invalidates it.
- Verification is a fresh read. A missing finding after a rescan is evidence only when `last_scan` is within `SECOPS_VERIFICATION_MAX_SCAN_AGE_HOURS` (default 72h); a stale scan is `unknown`, records a `verification_scan_stale` event, and keeps the run open.

## Status

Implemented and live-tested against Tenable Vulnerability Management. Tenable Security Center and Cisco ISE adapters follow documented APIs but are marked not live-validated in this environment. Default ticketing/EDR/patch backends are simulated. See `README.md` and `docs/architecture.md` for the full status and limitations.
