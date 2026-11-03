---
name: vuln-intake
description: "Normalize a CVE, vendor advisory, zero-day report, or vulnerability scanner export into one structured record that the rest of the SecOps Autopilot pipeline can consume. Use at the start of any vulnerability-to-fix run, when a new advisory needs to become an actionable record, or when several sources disagree about the same vulnerability."
---

# Vulnerability Intake

Turn whatever form the vulnerability arrived in — a CVE ID, a vendor advisory, a scanner finding row, a threat-intel note about a zero-day — into a single record with a stable schema.

Everything downstream reads this record. Get it wrong and the pipeline confidently attacks the wrong assets.

## Inputs

Accept any of:

- CVE identifier (`CVE-2017-0144`)
- Vendor advisory URL or pasted text
- Scanner export (CSV/JSON: Nessus, Qualys, Defender, Tenable, OpenVAS)
- Threat-intel write-up about an unpatched or zero-day issue

## Output

One record. Use `unknown` rather than guessing:

```yaml
vulnerability:
  id: CVE-2017-0144            # CVE, advisory ID, or internal ID
  aliases: []                  # vendor IDs, scanner plugin IDs
  title: "EternalBlue SMBv1 RCE"
  published: 2017-03-14
  severity_cvss: 8.1
  cvss_vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
  exploited_in_wild: true
  sources:                     # every source consulted
    - type: nvd
      ref: https://nvd.nist.gov/vuln/detail/CVE-2017-0144
      retrieved: 2026-11-01T00:00:00Z

affected:
  products:
    - name: Windows SMBv1
      versions: ["all versions with SMBv1 enabled"]
  detection_signature: "..."   # how to recognize it on a host
  cpe: []

remediation:
  patch_available: true
  patch_refs: []
  fixed_versions:              # from the advisory, per branch
    - product: php
      branch: "8.4"
      range: ">=8.4.0 <8.4.27"
      fixed: "8.4.27"
      support: supported
  mitigations: []              # vendor/analyst steps, verified: false by default
  compensating_controls: []    # filled in by remediation-planning
  workarounds: []

provenance:                    # required for any "verified" claim
  status: verified             # verified | provided | unverified
  source_url: "https://..."
  retrieved_at: 2026-11-03T00:00:00Z
  method: "primary advisory page fetched"

confidence: unknown             # high | medium | low | unknown
conflicts: []                   # any disagreement between sources
```

## Procedure

1. **Identify the vulnerability.** Resolve the identifier or extract it from the input. If the input carries several, split into separate records — one vulnerability per run.
2. **Collect sources.** At minimum, consult the authoritative source (NVD or the vendor). Note every source and retrieval time. When a vendor advisory supplies fixed versions, load it with `--advisory` or use the JSON schema in `validation/advisories/`; do not merge sources silently.
3. **Extract affected products and versions.** Be precise about version ranges and required configuration. "Affected: Windows Server 2008/2012" is not precise enough — what makes a host vulnerable is the product *and* the configuration (SMBv1 enabled, port 445 reachable). For runtime products (PHP, Node.js), record the CPE product and version; KRI-08 reads them.
4. **Record the fixed version per branch.** Capture the advisory's fixed release for each supported branch, and explicitly record an unsupported branch with `fixed: null`. Do not convert an unsupported branch into a patch target.
5. **Record exploitation status.** Known-exploited-in-the-wild is the single biggest driver of urgency. If sources disagree, record the disagreement in `conflicts` and lean toward the more cautious reading.
6. **Record the detection signature.** Downstream stages need to know how to recognize the condition on an asset, not just the CVE ID.
7. **Grade confidence and provenance.** `low` or `unknown` confidence should not proceed to containment on its own. A `verified` advisory claim needs a source URL and retrieval time.

## Guardrails

- Do not summarize away a conflict between sources — surface it in `conflicts`.
- Do not infer a patch exists because a vendor mentioned one. Record the reference and mark `patch_available` only when you have one.
- Do not invent a fixed version. If the advisory names no fix for the asset's branch, write `fixed: null` and let remediation choose compensation.
- Do not mark provenance `verified` without a source URL and retrieval time.
- Do not assign severity yourself if a CVSS score exists; record the score and vector as published.
