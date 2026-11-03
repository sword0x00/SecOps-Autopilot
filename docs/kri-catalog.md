# KRI catalog and detection rules

The KRI register is the auditable "which of our named KRIs is present on this
asset?" layer. It is separate from the numeric KRI risk score:

- **KRI register** — nine named indicators, each `detected`, `not_detected`
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
| `not_applicable` | The KRI does not apply to this asset, for example KRI-05 when the target CVE is not represented on the asset, KRI-08 when no affected runtime product is present in CPE, or a feed KRI on a host with no AV/EDR. |

`unknown` is never collapsed into `not_detected`. A missing EDR signal is not a
clean host.

## The register

| ID | Name | Severity | Detector | Primary inputs |
|---|---|---|---|---|
| KRI-01 | Missing security agent | high | `missing_security_agent` | Tenable `has_agent`; EDR/AV presence |
| KRI-02 | Stale control version | medium | `stale_control_version` | installed vs approved baseline version |
| KRI-03 | Stale threat feeds | high | `stale_threat_feed` | AV signature age; EDR feed age; 24h SLA |
| KRI-04 | Detect-only mode | high | `detect_only_mode` | AV/EDR mode; application-control mode |
| KRI-05 | Unresolved exploitable vulnerability | critical | `unpatched_exploitable` | target CVE finding; finding state; exploit signals; patch availability; SMB service/port for MS17-010 |
| KRI-06 | NAC non-compliant posture | high | `nac_noncompliant` | NAC solution/control-inventory `nac_compliant`; policy |
| KRI-07 | Active compromise | critical | `active_compromise` | EDR infection status; behavioral matches |
| KRI-08 | Vulnerable runtime version | critical | `vulnerable_runtime_version` | finding CPE product/version; advisory affected range/fixed version/support |
| KRI-09 | Externally exposed vulnerable service | high | `external_exposure` | finding port/service; asset exposure score (AES) |

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

### KRI-05 — Unresolved exploitable vulnerability

**Rule:** the target CVE is represented by an open finding on the asset, or a
legacy marker (`MS17-010`, `ETERNALBLUE`) matches.

- Open matching finding → `detected`.
- All matching findings are closed/fixed in the export → `not_detected`.
- The target is not represented on that asset → `not_applicable`.
- A detector error → `unknown` for that asset (the register never turns an error
  into a clear result).

Evidence records the plugin ID/name, finding state, exploit signals, patch
availability, and — when present — SMB service/port evidence. For MS17-010 the
report still states that SMBv1 state requires host confirmation while the missing
patch is confirmed by the finding.

The parameters are:

- `legacy_cves`: extra CVEs that should be treated as part of the same family.
- `name_markers`: text markers for legacy evidence enrichment.
- `service_markers`: service evidence markers for the SMB narrative.

The target CVE is always matched first; `legacy_cves` is not a scope restriction.

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
remediation path to `isolate` and marks the asset for containment; restore still
requires verified remediation and Human Approval.

### KRI-08 — Vulnerable runtime version

**Rule:** parse the runtime product and version from the finding's CPE and
evaluate the advisory's affected ranges.

- Version inside an affected range with a fixed version → `detected`; evidence
  names the installed version, range, fixed version, branch, and support status.
- Version inside an affected range with `fixed: null` (unsupported branch) →
  `detected`; evidence says no vendor fixed version is recorded.
- Version outside all affected ranges for the product → `not_detected`.
- Product matches but CPE has no version → `unknown`.
- No advisory attached → `unknown` (the engine cannot assess runtime currency).
- No affected product in the finding's CPE → `not_applicable`.

The version is read only from CPE. The engine does not infer a PHP or Node.js
version from a plugin name or banner text.

### KRI-09 — Externally exposed vulnerable service

**Rule:** a web port/service on the finding, or an asset exposure score (AES)
at/above the threshold (default 700), makes the vulnerable service externally
exposed.

- Web listener (ports 80/443/8080/8443/3000/8000, or HTTP/HTTPS service) →
  `detected`.
- No web listener but AES at/above threshold → `detected`.
- No web listener and AES below threshold, with port/service data → `not_detected`.
- No port, service, or AES data → `unknown`; silence is not "internal".

## How detections route

| Detection | Routing |
|---|---|
| KRI-01/02/03/04 | Control-gap evidence; ticket to the endpoint/control owner; compensating controls; score input |
| KRI-05 | Patch path plus mechanism-matched controls; containment candidate at/above threshold |
| KRI-06 | Containment candidate regardless of score; NAC solution Human Approval conditions still apply |
| KRI-07 | Force `isolate`; containment required; restore only after verified remediation and Human Approval |
| KRI-08 | Exact target version; `compensate`/migration when the branch has no vendor fix |
| KRI-09 | WAF/IPS/firewall priority; containment candidate when combined with high risk |

KRI-06 and KRI-07 can propose containment even when the numeric risk score is
below the default threshold. The human approval gates still apply.

## Mapping your example

| Asset | Expected detections |
|---|---|
| DC01 | KRI-01 (no EDR/AV), KRI-06 (NAC policy fail) |
| WS-FIN-042 | KRI-02 (AV behind baseline), KRI-03 (feed 11 days > 24h), KRI-04 (monitor mode), KRI-06 (NAC policy fail) |
| Two Windows hosts | KRI-05 (SMBv1 + missing MS17-010) |
| WS-MKT-011 | KRI-07 (EDR behavioral match) |
| PHP 8.4.26 web host | KRI-05, KRI-08 (fixed 8.4.27), KRI-09 (TCP/443) |
| Node.js 24.22.0 internal API | KRI-05, KRI-08 (fixed 24.22.1), KRI-09 `not_detected` if no web listener and AES below threshold |

The example inventories in `examples/` include the original hostnames so the
register can be demonstrated without touching a real control plane. The PHP and
Node.js examples are exercised by the live batch and the unit/integration suite.

## Running it

```bash
secops run --cve CVE-2017-0144 \
  --owners examples/owners.example.csv \
  --controls examples/controls.example.csv \
  --kri-catalog secops_autopilot/kri_catalog.json
```

The CLI prints a compact register summary; `report.html` and `report.md` contain
the full per-asset matrix and evidence.

The example inventories are exercised by `tests/test_kri_examples.py`, which
asserts the expected detections: DC01 KRI-01/KRI-06, WS-FIN-042
KRI-02/03/04/06, WS-MKT-011 KRI-07, and KRI-05 on both synthetic Windows hosts.

## Customizing

- Edit the JSON to change thresholds, add a mode to a vocabulary, or add a CVE
  to KRI-05 scope.
- Add a new detector name only with the matching function in
  `secops_autopilot/kri.py`; the loader rejects unknown detector names.
- Keep one KRI per ID and keep IDs stable — approvals and evidence reference them.

## Limitations

- KRI-02/03/04 need a control inventory or EDR connector; without one they are
  `unknown`, not clear.
- KRI-05 matches the target CVE; `legacy_cves`/markers enrich the MS17-010
  evidence but are not a security scope restriction.
- KRI-06 needs a NAC solution export field; the simulated NAC does not report
  pre-containment compliance.
- KRI-07 needs an EDR signal or the explicit `.state/edr_status.json` fixture.
- KRI-08 needs both a versioned CPE and an advisory. Without either it is
  `unknown`, not clear. It does not infer versions from plugin names.
- KRI-09 uses finding port/service or AES; with neither it is `unknown`.
- The catalog severity is a routing label, not a replacement for the risk score.
