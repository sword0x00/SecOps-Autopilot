# KRI catalog and detection rules

The KRI register is the auditable "which of our named KRIs is present on this
asset?" layer. It is separate from the numeric KRI risk score:

- **KRI register** — seven named indicators, each `detected`, `not_detected`
  (clear), `unknown`, or `not_applicable`, with evidence and an action.
- **KRI risk score** — a 0–100 weighted score used to rank assets for the work
  queue. See [kri-model.md](kri-model.md).

The catalog is data, not hard-coded prose:

```text
secops_autopilot/kri_catalog.json
```

Use `--kri-catalog path/to/catalog.json` to run against a customized copy.

## Status semantics

| Status | Meaning |
|---|---|
| `detected` | The evidence satisfies the detection rule. This is an affirmative finding. |
| `not_detected` | The required evidence was available and the rule did not fire. This is "clear", not "safe forever". |
| `unknown` | The evidence required to decide was missing. The reason is recorded. |
| `not_applicable` | The KRI does not apply to this run, for example KRI-05 on a non-MS17-010 CVE, or a feed KRI on a host with no AV/EDR. |

`unknown` is never collapsed into `not_detected`. A missing EDR signal is not a
clean host.

## The register

| ID | Name | Severity | Detector | Primary inputs |
|---|---|---|---|---|
| KRI-01 | Missing security agent | high | `missing_security_agent` | Tenable `has_agent`; EDR/AV presence |
| KRI-02 | Stale control version | medium | `stale_control_version` | installed vs approved baseline version |
| KRI-03 | Stale threat feeds | high | `stale_threat_feed` | AV signature age; EDR feed age; 24h SLA |
| KRI-04 | Detect-only mode | high | `detect_only_mode` | AV/EDR mode; application-control mode |
| KRI-05 | Unpatched exploitable host | critical | `unpatched_exploitable` | Tenable MS17-010/CVE-2017-0144 finding; SMB service/port |
| KRI-06 | NAC non-compliant posture | high | `nac_noncompliant` | ISE/control-inventory `nac_compliant`; policy |
| KRI-07 | Active compromise | critical | `active_compromise` | EDR infection status; behavioral matches |

## Detection rules

### KRI-01 — Missing security agent

**Rule:** all three signals are `false`: Tenable agent, EDR, and AV.

- Any signal `true` → `not_detected` (the asset has a security control).
- All three `false` → `detected`.
- Some `false`, some unknown, none `true` → `unknown`.

The Tenable `agent_uuid` field is not treated as proof of an endpoint agent; the
`has_agent` flag and source type are authoritative.

### KRI-02 — Stale control version

**Rule:** compare `av_version`/`av_baseline_version` and
`edr_version`/`edr_baseline_version`.

- Any installed version lower than its baseline → `detected`.
- All comparable pairs at/above baseline → `not_detected`.
- A control is present but its version or baseline is missing → `unknown`.
- No AV/EDR present → `not_applicable`.

Version comparison is numeric and tolerant of `7.2` vs `7.2.0`.

### KRI-03 — Stale threat feeds

**Rule:** AV signature age or EDR feed age greater than the `feed_sla_hours`
(default 24) → `detected`.

- Known age over SLA → `detected`.
- All present feeds known and within SLA → `not_detected`.
- A present feed has no age → `unknown`.
- No AV/EDR present → `not_applicable`.

### KRI-04 — Detect-only mode

**Rule:** a known mode in the monitor vocabulary (`monitor`, `audit`, `detect`,
`detect-only`, `alert`, `report`) → `detected`.

- Any known mode in the prevent vocabulary (`prevent`, `block`, `enforce`,
  `active`, `protect`) is clear for that control.
- Unknown mode or a mode outside the vocabulary → `unknown`.
- No control mode available → `not_applicable`.

Application-control mode is included when supplied.

### KRI-05 — Unpatched exploitable host

**Rule:** the run target is in the catalog CVE scope
(`CVE-2017-0144`) or a finding matches the name markers (`MS17-010`,
`ETERNALBLUE`).

- Matching Tenable finding → `detected`.
- Target is in scope but no matching finding for this asset → `not_detected`.
- Run target is outside the scope → `not_applicable`.

Evidence records the plugin ID/name, port/service, and explicitly states that
SMBv1 state requires host confirmation while the missing patch is confirmed by
the finding.

### KRI-06 — NAC non-compliant posture

**Rule:** `nac_compliant` is `false` → `detected`; `true` → `not_detected`;
missing → `unknown`.

The control inventory accepts `nac_compliant` or `nac_posture` with
true/false, `compliant`/`noncompliant`, `pass`/`fail`, or `permit`/`deny`.
`nac_policy` is recorded in the evidence.

### KRI-07 — Active compromise

**Rule:** EDR `infection_status` is `infected`, `malicious`, or `compromised`,
or `behavioral_matches` is non-empty → `detected`.

- Status `clean`, `none_reported`, `not_infected`, or `clear` with no matches →
  `not_detected`.
- Unknown status with no behavioral data → `unknown`.

A missing EDR signal is `unknown`, never `clean`. A KRI-07 detection forces the
remediation path to `isolate`, emits a critical alert, and blocks restore.

## How detections route

| Detection | Routing |
|---|---|
| KRI-01/02/03/04 | Control-gap evidence; ticket to the endpoint/control owner; compensating controls; score input |
| KRI-05 | Patch path + SMB controls; containment candidate at/above threshold |
| KRI-06 | Containment candidate regardless of score; ISE/NAC approval gates still apply |
| KRI-07 | Force `isolate`; critical alert; SOC handoff; restore refused |

KRI-06 and KRI-07 can propose containment even when the numeric risk score is
below the default threshold. The human approval gates still apply.

## Mapping your example

| Asset | Expected detections |
|---|---|
| DC01 | KRI-01 (no EDR/AV), KRI-06 (ISE policy fail) |
| WS-FIN-042 | KRI-02 (AV behind baseline), KRI-03 (feed 11 days > 24h), KRI-04 (monitor mode), KRI-06 (ISE fail) |
| Two Windows hosts | KRI-05 (SMBv1 + missing MS17-010) |
| WS-MKT-011 | KRI-07 (EDR behavioral match) |

The example inventories in `examples/` include these hostnames so the register
can be demonstrated without touching a real control plane.

## Running it

```bash
secops run --cve CVE-2017-0144 \
  --owners examples/owners.example.csv \
  --controls examples/controls.example.csv \
  --kri-catalog secops_autopilot/kri_catalog.json
```

The CLI prints a compact register summary; `report.html` and `report.md` contain
the full per-asset matrix and evidence.

To see the full register with the example hosts and no tenant:

```bash
python3 scripts/kri_demo.py
```

Expected detections: DC01 KRI-01/KRI-06, WS-FIN-042 KRI-02/03/04/06, WS-MKT-011
KRI-07, and KRI-05 on both synthetic Windows hosts.

## Customizing

- Edit the JSON to change thresholds, add a mode to a vocabulary, or add a CVE
  to KRI-05 scope.
- Add a new detector name only with the matching function in
  `secops_autopilot/kri.py`; the loader rejects unknown detector names.
- Keep one KRI per ID and keep IDs stable — approvals and evidence reference them.

## Limitations

- KRI-02/03/04 need a control inventory or EDR connector; without one they are
  `unknown`, not clear.
- KRI-05 is scoped to MS17-010/CVE-2017-0144 by default. Add CVEs and markers to
  the catalog for other exploit families.
- KRI-06 needs an ISE/NAC export field; the simulated NAC does not report
  pre-containment compliance.
- KRI-07 needs an EDR signal or the explicit `.state/edr_status.json` fixture.
- The catalog severity is a routing label, not a replacement for the risk score.
