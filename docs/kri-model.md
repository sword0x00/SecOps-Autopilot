# KRI model

The score answers a different question than CVSS: *how much does this finding
matter on this asset, with the controls that are actually present?*

> **Two layers, one report.** The *KRI register* (KRI-01 … KRI-09) records named
> control/exploit indicators per asset with a status and evidence. The *KRI risk
> score* is the 0–100 ranking number described below. The register is defined in
> [`kri-catalog.md`](kri-catalog.md); the score uses the control posture and
> findings, including KRI detections, but remains a separate arithmetic record.
> KRI-08 (runtime version/fixed version) and KRI-09 (external exposure) inform
> the plan and priority even when the numeric score is unchanged.

## Formula

```text
KRI = 100 × Σ(weight_i × component_i) / Σ(weight_i)
```

Only components with a known value are included. The denominator is the sum of
the weights actually used, so unknown values are excluded rather than treated as
zero. Every score carries `unknown_components`, `confidence`, and its component
breakdown.

| Component | Weight | Source | Unknown when |
|---|---|---|---|
| Severity | 0.35 | Highest CVSS v3, else CVSS v2, else Tenable severity band | No severity data |
| Exploitability | 0.25 | Tenable VPR; otherwise the strongest exploit signal (CISA KEV 9.8, exploited by malware 9.5, weaponized 8.5, public exploit 8.0) | No VPR and no exploit flags |
| Exposure | 0.15 | Tenable AES; normalized from 0–1000 or 0–100 | Asset detail unavailable |
| Control gap | 0.20 | Agent absence, agent health unknowns, EDR/AV absence or unknowns, signature age, application-control mode, patch agent | Never; it is always computed |
| Criticality | 0.05 | Tenable ACR (0–10) | ACR absent or zero |

## Control-gap scoring

| Condition | Points |
|---|---|
| No endpoint agent (`has_agent=false`) | +4.0 |
| Agent presence unknown | +2.5 |
| Agent present, version unknown | +0.75 |
| Agent present, feed age unknown | +0.75 |
| EDR absent / unknown | +3.0 / +1.25 |
| AV absent / unknown | +2.5 / +1.0 |
| AV signature age > 168h / > 24h | +2.0 / +1.0 |
| EDR feed age > 168h | +1.0 |
| Application-control mode unknown | +0.5 |
| Patch-agent presence unknown | +0.5 |

The total is capped at 10. Unknown EDR/AV states are treated as a control gap,
not as absence and not as a clean bill of health.

## Tiers and containment

| Tier | Score |
|---|---|
| critical | ≥ 80 |
| high | 65–79.9 |
| medium | 45–64.9 |
| low | < 45 |

A containment candidate is an asset with **KRI ≥ the isolate threshold (default
80)** and at least one of:

- the endpoint agent is absent,
- the control gap is ≥ 4.0/10,
- the remediation path is not a plain patch.

The candidate is only a proposal. Containment requires an infosec approval and a
separate execution approval. Containment and patch execution are both authorized
by the remediation approval, then recorded under their own gates.

KRI-08/09 do not alter the arithmetic directly. They change the *decision*:
KRI-08 supplies the exact target version (or the absence of a vendor fix), and
KRI-09 raises the priority of externally reachable assets. Both remain visible in
the KRI matrix and the plan.

## Worked example

From the live lab run for `CVE-2017-0144` (MS17-010 / EternalBlue):

| Asset | Severity | Exploit | Exposure | Control gap | Criticality | KRI |
|---|---|---|---|---|---|---|
| Windows server A | 8.8 | 9.9 (VPR) | 8.49 | 7.25 | 8.0 | 86.8 |
| Windows server B | 8.8 | 9.9 (VPR) | 7.07 | 7.25 | 5.0 | 83.2 |

Both rank critical despite a CVSS of 8.8, because the exploit is weaponized, VPR
is 9.9, and the control posture is unknown or absent. That is the intended
behavior: raw CVSS alone would put a high-severity, internet-adjacent SMB
exposure below many lower-impact findings.

## Why not just CVSS or VPR?

- CVSS does not know whether the host is reachable or whether the agent is
  present.
- VPR is Tenable's prediction of exploitation likelihood; it does not know the
  asset's control state.
- ACR and AES know the asset, but not the vulnerability mechanism.
- The KRI combines them and exposes the arithmetic.

## Unknowns are first-class

If the scanner cannot tell us the agent version, the report says `unknown` and
names the API scope that blocked it. A guessed value would make the audit trail
worse than a gap. The score renormalizes rather than silently assigning a
middle value. A reader can see exactly which components were excluded.

## Limitations

- The export's `agent_uuid` field is present on scanner-only assets in the lab
  tenant, so it is not treated as proof of an endpoint agent. The `has_agent`
  flag and the asset's source type are authoritative; a conflict is recorded
  only when the source indicates an agent and `has_agent=false`.
- AES/ACR values are Tenable scores, not the organization's own business
  criticality. A asset inventory criticality field can be added to `ControlInventory` or a
  separate scoring input.
- Control gap treats unknowns as risk. This is conservative; the report makes
  the assumption visible.
- The named KRI register is independent of the numeric weights. A KRI can be
  `detected` without crossing the containment score threshold; KRI-06 and KRI-07
  explicitly route to containment regardless of the numeric score.
- The weights are defaults, not a universal truth. Tune them in
  `secops_autopilot/scoring.py` and keep the change in the evidence history.
