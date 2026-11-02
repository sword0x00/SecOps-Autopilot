---
name: remediation-planning
description: "Turn a normalized vulnerability record into a remediation plan — the patch path for assets that can patch now, and verified compensating controls for those that cannot. Use after intake and KRI scoring, before any ticket or containment action."
---

# Remediation Planning

Decide how each affected asset gets fixed, and what protects it in the meantime.

## Inputs

- The normalized vulnerability record from `vuln-intake`
- The ranked asset list from KRI scoring
- Control posture per asset (agent present, current, feeding, enforcing)

## Output

```yaml
remediation_plan:
  vulnerability: CVE-2017-0144
  patch_path:
    available: true
    patch_refs:
      - "KB4012212"
    prerequisites: ["..." ]
    rollback: "..."
    estimated_effort: unknown
  compensating_controls:        # for assets that cannot patch on schedule
    - type: ips_rule
      rationale: "..."
      rule_ref: "..."
      verified: false           # do not claim verified without a test
    - type: siem_rule
      rationale: "..."
      rule_ref: "..."
      verified: false
    - type: waf_rule
      rationale: "..."
      rule_ref: "..."
      verified: false
    - type: firewall_rule
      rationale: "..."
      rule_ref: "..."
      verified: false
  per_asset:
    - asset: "host-01"
      path: patch              # patch | compensate | isolate
      reason: "..."
      owner: "..."
  approval_required: true
```

## Procedure

1. **Establish the patch path first.** A patch that exists and deploys is almost always the better answer. Capture prerequisites, rollback, and the effort estimate.
2. **Identify what makes patching impossible on schedule.** Uptime constraints, unsupported OS, vendor-frozen appliances, no owner. These become compensating-control candidates — not excuses.
3. **Select compensating controls that actually block the exploit path.** Match the control to the vulnerability mechanism: a network IPS signature for network-reachable exploitation, a WAF rule for web, a firewall block for a protocol that should not traverse a boundary (for example, SMB across segments).
4. **Mark controls unverified until tested.** `verified: false` is the default. Only a test in the target environment — or a documented vendor validation — promotes it to `true`.
5. **Assign each asset a path.** `patch`, `compensate`, or `isolate`. Every asset gets one, with a stated reason.
6. **Surface the approval gate.** The plan is a proposal. It goes to a ticket and an infosec approval before anything executes.

## Guardrails

- Never present a compensating control as equivalent to a patch. Say what it does not cover.
- Never mark a control `verified: true` without a test or vendor validation reference.
- If the vulnerability record's confidence is `low` or `unknown`, say so in the plan — it changes how much the plan can be trusted.
