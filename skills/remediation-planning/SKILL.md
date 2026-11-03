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
    fixed_versions:              # from the advisory
      - product: php
        branch: "8.4"
        fixed: "8.4.27"
        support: supported
    target_versions_by_asset:
      host-01: "8.4.27"          # only when the advisory names a fix for that branch
    prerequisites: ["..." ]
    rollback: "..."
    estimated_effort: unknown
  compensating_controls:        # for assets that cannot patch on schedule
    - type: ips_rule
      rationale: "..."
      rule_ref: "..."
      verified: false           # do not claim verified without a test
    - type: detection_rule
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
      runtime_product: php
      runtime_version: "8.4.26"
      target_version: "8.4.27" # null when no vendor fix exists for the branch
      reason: "..."
      owner: "..."
  approval_required: true
```

## Procedure

1. **Establish the patch path first.** A patch that exists and deploys is almost always the better answer. Resolve the runtime product/version from CPE and take the advisory's fixed version for that branch. Capture prerequisites, rollback, and the effort estimate.
2. **Do not invent a patch target.** If the advisory records no fixed version for the asset's branch (for example, an unsupported PHP 8.1 host), set `target_version: null`, choose `compensate`, and explain the migration/compensation path.
3. **Identify what makes patching impossible on schedule.** Uptime constraints, unsupported OS/runtime, vendor-frozen appliances, no owner. These become compensating-control candidates — not excuses.
4. **Select compensating controls that actually block the exploit path.** Match the control to the vulnerability mechanism: a network IPS signature for network-reachable exploitation, a WAF rule for web, a firewall block for a protocol that should not traverse a boundary (for example, SMB across segments). Use vendor mitigations from the advisory when supplied; they remain unverified until tested.
5. **Mark controls unverified until tested.** `verified: false` is the default. Only a test in the target environment — or a documented vendor validation — promotes it to `true`.
6. **Assign each asset a path.** `patch`, `compensate`, or `isolate`. Every asset gets one, with a stated reason.
7. **Surface the Human Approval condition.** The plan is a proposal. It goes to a ticket and an infosec Human Approval before containment or patch submission.
8. **Keep execution separate.** A patch job submitted under the `patch` gate is an execution record, not a fix. Verification is a fresh scanner read; only then is remediation claimed.

## Guardrails

- Never present a compensating control as equivalent to a patch. Say what it does not cover.
- Never mark a control `verified: true` without a test or vendor validation reference.
- Never invent a fixed version or a target version. A missing advisory fix is a compensation/migration decision, not a number to guess.
- Never treat a submitted patch job or a ticket as verified remediation.
- If the vulnerability record's confidence is `low` or `unknown`, say so in the plan — it changes how much the plan can be trusted.
