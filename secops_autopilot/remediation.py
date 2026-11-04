"""Stage 5 — remediation planning.

Patch first. Where patching will lag, select controls matched to the exploit
mechanism and state plainly what they do not cover. Every control is
``verified: false`` until someone tests it in the target environment.
"""

from __future__ import annotations

from typing import Any

from .advisory import runtime_matches
from .models import (
    AssetAssessment,
    AssetPlan,
    CompensatingControl,
    RemediationPlan,
    VulnerabilityRecord,
)
from .util import canonical_json, dedupe, sha256_obj, utc_now

# A high-KRI asset with this much control uncertainty is proposed for isolation.
# The proposal is not an action; containment still requires the human gate.
CONTAINMENT_CONTROL_GAP = 4.0


def _all_findings(assessments: list[AssetAssessment]):
    for assessment in assessments:
        yield from assessment.findings


def _mechanism(assessments: list[AssetAssessment]) -> str:
    findings = list(_all_findings(assessments))
    text = " ".join(
        f"{finding.plugin_name} {finding.synopsis} {finding.description}".lower()
        for finding in findings
    )
    ports = {finding.port for finding in findings if finding.port is not None}
    if (
        "smb" in text
        or "eternalblue" in text
        or "ms17-010" in text
        or 445 in ports
        or any((f.service or "").lower() == "cifs" for f in findings)
    ):
        return "smb"
    if any(port in ports for port in (80, 443, 8080, 8443)) or any(
        token in text
        for token in ("http", "apache", "nginx", "iis", "tomcat", "log4j", "web application")
    ):
        return "http"
    if any(token in text for token in ("ssl", "tls", "openssl", "certificate")):
        return "tls"
    if any(token in text for token in ("bash", "shellshock", "ssh", "shell")):
        return "shell"
    return "network"


def _reference(cve: str, findings: list) -> str:
    links = dedupe(link for finding in findings for link in finding.see_also)
    nvd = f"https://nvd.nist.gov/vuln/detail/{cve}"
    return "; ".join([nvd, *links[:3]])


def _control(
    kind: str,
    rationale: str,
    *,
    cve: str,
    reference: str,
    coverage: str,
    limitations: str,
) -> CompensatingControl:
    return CompensatingControl(
        type=kind,
        rationale=rationale,
        rule_ref=(
            f"recommendation only — {cve} ({kind}); no rule ID was supplied by "
            "the control plane"
        ),
        verified=False,
        verification_method="not tested in the target environment",
        coverage=coverage,
        limitations=limitations,
        reference=reference,
        applies_to="all affected assets until the patch is verified",
    )


def _controls_for(mechanism: str, cve: str, findings: list) -> list[CompensatingControl]:
    reference = _reference(cve, findings)
    ips = _control(
        "ips_rule",
        "Block network exploitation attempts for this CVE at inspection points.",
        cve=cve,
        reference=reference,
        coverage="network-reachable exploit attempts crossing an inspected segment",
        limitations="does not cover encrypted channelling, same-segment traffic, "
        "or endpoint-local exploitation; signature must exist and be enabled",
    )
    detection = _control(
        "detection_rule",
        "Detect exploitation attempts and post-exploitation activity for this CVE.",
        cve=cve,
        reference=reference,
        coverage="detection and escalation; not prevention",
        limitations="log source coverage and tuning must be validated; detection "
        "does not block the exploit",
    )
    if mechanism == "smb":
        return [
            ips,
            _control(
                "firewall_rule",
                "Block SMB (TCP/445) between workstation and server segments except "
                "approved management paths.",
                cve=cve,
                reference=reference,
                coverage="cross-segment SMB exploitation and lateral movement",
                limitations="does not protect same-segment SMB; an overbroad rule can "
                "break file sharing and backup traffic",
            ),
            _control(
                "configuration_change",
                "Disable SMBv1 on affected Windows hosts where the business does not "
                "require it.",
                cve=cve,
                reference=reference,
                coverage="removes the vulnerable protocol from the host",
                limitations="requires reboot/change control and application "
                "compatibility testing; does not patch SMBv2/3",
            ),
            detection,
        ]
    if mechanism == "http":
        return [
            _control(
                "waf_rule",
                "Deploy a virtual patch for the vulnerable request pattern at the WAF.",
                cve=cve,
                reference=reference,
                coverage="HTTP(S) request paths that traverse the WAF",
                limitations="does not cover non-WAF traffic, alternate ports, or "
                "attacks that reach the origin directly; false positives are possible",
            ),
            ips,
            detection,
        ]
    if mechanism == "tls":
        return [
            _control(
                "configuration_change",
                "Disable the vulnerable protocol/version and weak cipher suites on "
                "the exposed service.",
                cve=cve,
                reference=reference,
                coverage="removes the vulnerable protocol negotiation",
                limitations="client compatibility must be tested; does not address "
                "application-layer vulnerabilities",
            ),
            ips,
            detection,
        ]
    if mechanism == "shell":
        return [
            ips,
            _control(
                "waf_rule",
                "Inspect HTTP headers for the crafted function-definition pattern "
                "used by this exploit.",
                cve=cve,
                reference=reference,
                coverage="HTTP requests traversing the WAF",
                limitations="not a substitute for patching the shell; alternate "
                "vectors (SSH, DHCP, CGI) are not covered",
            ),
            _control(
                "firewall_rule",
                "Restrict shell and CGI exposure to required sources only.",
                cve=cve,
                reference=reference,
                coverage="reduces reachable attack surface",
                limitations="does not protect allowed sources or host-local paths",
            ),
            detection,
        ]
    return [
        ips,
        _control(
            "firewall_rule",
            "Restrict the vulnerable service to required sources and segments.",
            cve=cve,
            reference=reference,
            coverage="reduces exposure from untrusted networks",
            limitations="does not protect allowed sources or same-segment traffic",
        ),
        detection,
    ]


def _workarounds(
    mechanism: str,
    cve: str,
    findings: list,
    mitigations: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    reference = _reference(cve, findings)
    common = {
        "source": "engine recommendation (not vendor-verified)",
        "verified": False,
        "reference": reference,
    }
    supplied = [
        {
            "source": str(item.get("source") or "advisory"),
            "verified": bool(item.get("verified", False)),
            "reference": str(item.get("reference") or reference),
            "action": item.get("action"),
            "scope": item.get("scope") or "affected runtime",
            "limitations": item.get("limitations"),
        }
        for item in (mitigations or [])
        if item.get("action")
    ]
    if mechanism == "smb":
        return supplied + [
            {**common, "action": "Disable SMBv1 on affected hosts.", "scope": "Windows hosts exposing TCP/445"},
            {**common, "action": "Block TCP/445 at segment boundaries.", "scope": "network path to affected hosts"},
        ]
    if mechanism == "shell":
        return supplied + [
            {**common, "action": "Disable CGI or shell-backed web handlers that are not required.", "scope": "web servers exposing CGI"},
            {**common, "action": "Reject requests containing crafted Bash function definitions in headers.", "scope": "HTTP ingress"},
        ]
    if mechanism == "http":
        return supplied + [
            {**common, "action": "Apply the vendor's documented mitigation or disable the vulnerable feature until patched.", "scope": "affected application"},
        ]
    if mechanism == "tls":
        return supplied + [
            {**common, "action": "Disable SSLv2/SSLv3 and weak cipher suites.", "scope": "exposed TLS services"},
        ]
    return supplied


def _runtime_target(
    assessment: AssetAssessment, vulnerability: VulnerabilityRecord
) -> tuple[str | None, str | None, str | None, dict[str, Any] | None]:
    """Return (product, installed version, fixed version, match) for one asset.

    The match is taken from CPE data and the advisory's affected ranges. If the
    CPE does not identify a product/version, every field is None and the caller
    falls back to the scanner's patch flag without inventing a target.
    """
    matches = runtime_matches(assessment.findings, vulnerability.advisory)
    if not matches:
        return None, None, None, None
    affected = [item for item in matches if item.get("in_range") is True]
    if not affected:
        # The finding exists, but the CPE version is outside every advisory
        # affected range. Do not borrow a fixed version from an unrelated branch;
        # the finding may be stale and must be verified.
        chosen = matches[0]
        return (
            chosen.get("product"),
            chosen.get("version"),
            None,
            chosen,
        )
    chosen = next(
        (item for item in affected if item.get("fixed")),
        affected[0],
    )
    return (
        chosen.get("product"),
        chosen.get("version"),
        chosen.get("fixed"),
        chosen,
    )


def _package_for(product: str | None) -> str | None:
    if not product:
        return None
    normalized = str(product).lower()
    if normalized == "php":
        return "php"
    if normalized in {"node.js", "nodejs", "node"}:
        return "nodejs"
    return str(product)


def build_plan(
    vulnerability: VulnerabilityRecord,
    assessments: list[AssetAssessment],
    *,
    isolate_threshold: float = 80.0,
) -> RemediationPlan:
    mechanisms = _mechanism(assessments)
    findings = list(_all_findings(assessments))
    patch_flags = [
        assessment.patch_available
        for assessment in assessments
        if assessment.patch_available is not None
    ]
    if any(patch_flags):
        patch_available: bool | None = True
    elif patch_flags and all(flag is False for flag in patch_flags):
        patch_available = False
    else:
        patch_available = None
    patch_refs = dedupe(
        ref
        for assessment in assessments
        for ref in assessment.patch_refs
    )
    controls = _controls_for(mechanisms, vulnerability.id, findings)
    workarounds = _workarounds(
        mechanisms, vulnerability.id, findings, vulnerability.mitigation_steps
    )

    per_asset: list[AssetPlan] = []
    for assessment in assessments:
        kri_ids = set(assessment.kri_ids)
        nac_noncompliant = "KRI-06" in kri_ids
        runtime_product, runtime_version, target_version, runtime_match = (
            _runtime_target(assessment, vulnerability)
        )
        asset_patch_available = assessment.patch_available
        runtime_reason = ""
        if runtime_match is not None:
            if runtime_match.get("in_range") is True and runtime_match.get("fixed"):
                asset_patch_available = True
                runtime_reason = (
                    f"{runtime_product} {runtime_version} is below the advisory "
                    f"fixed version {target_version} for branch "
                    f"{runtime_match.get('branch') or 'unspecified'}."
                )
            elif runtime_match.get("in_range") is True and not runtime_match.get("fixed"):
                asset_patch_available = False
                runtime_reason = (
                    f"{runtime_product} {runtime_version} is in the advisory's "
                    f"affected branch {runtime_match.get('branch') or 'unspecified'}, "
                    "but the advisory records no vendor fixed version for that "
                    "branch; compensating controls and migration are required."
                )
            elif runtime_match.get("in_range") is False:
                runtime_reason = (
                    f"{runtime_product} {runtime_version} is outside the advisory "
                    "affected range; the scanner finding may be stale. Verify before "
                    "changing the runtime."
                )
        if asset_patch_available is True:
            path = "patch"
            reason = runtime_reason or (
                "A patch path is available for this detection."
            )
        elif asset_patch_available is False:
            path = "compensate" if controls else "isolate"
            reason = runtime_reason or (
                "No patch path is available; compensating controls are the interim path."
            )
        else:
            path = "compensate" if controls else "isolate"
            reason = runtime_reason or (
                "Patch availability is unknown in scanner metadata; treat as "
                "unpatchable until the owner confirms a patch path."
            )
        gap = assessment.control.control_gap_score
        triggers = []
        if kri_ids:
            triggers.append("KRI register detected: " + ", ".join(sorted(kri_ids)))
        if assessment.risk.score >= isolate_threshold:
            triggers.append(
                f"KRI risk score {assessment.risk.score:.1f} >= threshold {isolate_threshold:.1f}"
            )
        if assessment.control.agent_present is False:
            triggers.append("Scanner reports no endpoint agent")
        if gap >= CONTAINMENT_CONTROL_GAP:
            triggers.append(f"control gap {gap:.1f}/10")
        if nac_noncompliant:
            triggers.append("KRI-06 NAC non-compliance")
        if path != "patch":
            triggers.append(f"remediation path is {path}")
        containment = (
            path == "isolate"
            or nac_noncompliant
            or (
                assessment.risk.score >= isolate_threshold
                and (
                    assessment.control.agent_present is False
                    or gap >= CONTAINMENT_CONTROL_GAP
                    or path != "patch"
                )
            )
        )
        containment_reason = (
            "; ".join(triggers)
            if triggers
            else f"below containment threshold (KRI risk score {assessment.risk.score:.1f})"
        )
        per_asset.append(
            AssetPlan(
                asset_uuid=assessment.asset.uuid,
                hostname=assessment.asset.display_name,
                path=path,
                reason=reason,
                patch_refs=assessment.patch_refs,
                containment_recommended=containment,
                containment_reason=containment_reason,
                owner=assessment.owner.owner,
                owner_team=assessment.owner.team,
                kri_score=assessment.risk.score,
                kri_tier=assessment.risk.tier,
                kri_ids=sorted(kri_ids),
                runtime_product=runtime_product,
                runtime_version=runtime_version,
                target_version=target_version if path == "patch" else None,
                package=_package_for(runtime_product),
            )
        )

    notes = [
        "Patch prerequisites, rollback steps, and effort are not present in Tenable "
        "plugin metadata or advisory fixed-version data; they are recorded as unknown "
        "rather than guessed.",
        "Compensating controls are not equivalent to a patch and remain unverified "
        "until tested in the target environment.",
    ]
    if vulnerability.advisory:
        provenance = (vulnerability.advisory or {}).get("provenance") or {}
        notes.append(
            f"Advisory metadata: {vulnerability.advisory.get('source')} "
            f"[{provenance.get('status', 'provided')}]. Target versions are taken "
            "only from the advisory's affected ranges for the asset's runtime branch."
        )
        if provenance.get("status") != "verified":
            notes.append(
                "Advisory provenance is not marked verified; treat fixed-version "
                "claims as unverified input until confirmed by the owner."
            )
    if patch_available is None:
        notes.append("Patch availability is unknown; confirm with the asset owner/vendor.")
    notes.append(
        "Containment is proposed when the KRI risk score is at/above the threshold "
        f"and the control gap is at least {CONTAINMENT_CONTROL_GAP}/10, the agent is "
        "absent, the patch path is not available, or KRI-06 is detected. KRI-06 "
        "always makes the asset a containment candidate. It remains a proposal until "
        "approval."
    )
    if mechanisms == "smb":
        notes.append(
            "SMB exposure: verify port 445 reachability and SMBv1 state on each host "
            "before relying on a network control. KRI-05 covers the missing MS17-010 "
            "patch; SMBv1 state still requires host confirmation."
        )

    plan = RemediationPlan(
        vulnerability_id=vulnerability.id,
        patch_path={
            "available": patch_available,
            "patch_refs": patch_refs,
            "fixed_versions": vulnerability.fixed_versions,
            "target_versions_by_asset": {
                item.asset_uuid: item.target_version
                for item in per_asset
                if item.target_version
            },
            "prerequisites": [],
            "prerequisites_note": (
                "unknown — not provided by scanner plugin metadata or advisory "
                "fixed-version data"
            ),
            "rollback": "unknown — not provided by scanner plugin metadata",
            "estimated_effort": "unknown",
            "evidence": (
                "Scanner has_patch flag plus solution text plus verified advisory "
                "fixed versions and affected ranges"
            ),
        },
        compensating_controls=controls,
        workarounds=workarounds,
        per_asset=per_asset,
        approval_required=True,
        generated_at=utc_now(),
        notes=notes,
    )
    plan.plan_sha256 = plan_digest(plan.to_dict())
    return plan


def plan_digest(plan_dict: dict[str, Any]) -> str:
    material = dict(plan_dict)
    material["plan_sha256"] = ""
    return sha256_obj(material)


__all__ = ["build_plan", "plan_digest", "_mechanism", "canonical_json"]
