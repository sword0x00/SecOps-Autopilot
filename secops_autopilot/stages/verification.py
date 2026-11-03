"""Stage 9 — verification (merged with stage 10 recovery).

Verification is a fresh read, not a status-change confirmation. The engine
re-queries the scanner for the target CVE, matches assets on every identity key
it has, and records ``remediated`` only when the finding is absent *and* the scan
is fresh. EDR infection is re-checked; an infection signal escalates and blocks
recovery. Recovery is a separate approval-gated stage in ``recovery.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..errors import ConnectorError, StateError
from ..models import (
    STATUS_AWAITING_VERIFICATION,
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_CONTAINMENT_EXECUTED,
    STATUS_ESCALATED,
    STATUS_RESTORED,
    STATUS_VERIFICATION_OPEN,
    STATUS_VERIFIED,
    AssetRef,
    Finding,
    VerificationAsset,
    VerificationResult,
)
from ..util import dedupe, normalize_mac, parse_iso, utc_now
from .context import StageContext

ELIGIBLE_FOR_VERIFICATION = {
    STATUS_APPROVED_FOR_CONTAINMENT,
    STATUS_CONTAINMENT_EXECUTED,
    STATUS_AWAITING_VERIFICATION,
    STATUS_VERIFIED,
    STATUS_VERIFICATION_OPEN,
    STATUS_RESTORED,
}


def execute_verification(ctx: StageContext):
    run = ctx.workflow.run
    if run.status not in ELIGIBLE_FOR_VERIFICATION:
        raise StateError(
            f"verification requires remediation approval (status: {run.status})"
        )
    vulnerability = run.vulnerability or {}
    cve = vulnerability.get("id")
    date_range = int(
        (run.options or {}).get("date_range") or ctx.settings.date_range
    )
    started = utc_now()
    try:
        hits = ctx.source.cve_plugin_hits(cve, date_range)
        ids = [hit.plugin_id for hit in hits if hit.plugin_id]
        findings = ctx.source.findings_for_plugins(ids, date_range) if ids else []
    except ConnectorError as exc:
        result = VerificationResult(
            started_at=started,
            finished_at=utc_now(),
            method=f"{ctx.source.name}: CVE -> plugin -> per-asset findings",
            date_range=date_range,
            assets=[
                VerificationAsset(
                    asset_uuid=(asset.get("asset") or {}).get("uuid", ""),
                    hostname=(asset.get("asset") or {}).get("hostname")
                    or (asset.get("asset") or {}).get("uuid", ""),
                    before_affected=True,
                    after_affected=None,
                    status="unknown",
                    last_scan=asset.get("last_scan"),
                    last_found=None,
                    evidence={"error": str(exc)},
                    infection_status="unknown",
                    contained=any(
                        event.get("asset_uuid")
                        == (asset.get("asset") or {}).get("uuid")
                        and event.get("status") == "isolated"
                        for event in run.containment or []
                    ),
                )
                for asset in run.exposure or []
            ],
            new_affected_assets=[],
            remediated_count=0,
            still_affected_count=0,
            unknown_count=len(run.exposure or []),
            infection_status="unknown",
            notes=[
                "Verification query failed. No remediation claim is made.",
                str(exc),
            ],
        )
        run.verification = result.to_dict()
        run.status = STATUS_VERIFICATION_OPEN
        run.next_actions = [f"Resolve scanner access and rerun verification: {exc}"]
        ctx.emit(
            "verification",
            result.to_dict(),
            summary="Verification could not query the scanner; result recorded as unknown.",
            status="error",
            started_at=started,
            errors=[str(exc)],
        )
        raise

    target_findings = [
        finding
        for finding in findings
        if not finding.cve or cve in {item.upper() for item in finding.cve}
    ]
    current_by_identity: dict[str, Finding] = {}
    current_assets: dict[str, AssetRef] = {}
    for finding in target_findings:
        for key in _identity_keys(finding.asset):
            current_by_identity[key] = finding
        current_assets[finding.asset.uuid] = finding.asset

    before_uuids = {
        (asset.get("asset") or {}).get("uuid") for asset in run.exposure or []
    }
    verification_assets: list[VerificationAsset] = []
    for asset in run.exposure or []:
        ref = AssetRef(
            **{
                key: value
                for key, value in (asset.get("asset") or {}).items()
                if key
                in {
                    "uuid",
                    "hostname",
                    "fqdn",
                    "netbios",
                    "ipv4",
                    "mac",
                    "os",
                    "agent_uuid",
                    "last_seen",
                    "network_id",
                }
            }
        )
        keys = _identity_keys(ref)
        matches: list[Finding] = []
        for key in keys:
            candidate = current_by_identity.get(key)
            if candidate is not None and not any(candidate is item for item in matches):
                matches.append(candidate)
        matched = (
            max(matches, key=lambda item: item.last_found or "") if matches else None
        )
        after_affected = matched is not None
        last_found = matched.last_found if matched else None
        detail, _ = ctx.asset_detail(ref.uuid)
        last_scan = detail.get("last_scan") if detail else asset.get("last_scan")
        parsed_scan = parse_iso(last_scan)
        scan_age_hours: float | None = None
        scan_fresh: bool | None = None
        if parsed_scan is not None:
            scan_age_hours = round(
                (
                    datetime.now(timezone.utc) - parsed_scan
                ).total_seconds()
                / 3600,
                1,
            )
            scan_fresh = scan_age_hours <= float(
                ctx.settings.verification_max_scan_age_hours
            )
        edr_status = ctx.edr.status(ref.uuid, ref.display_name)
        infection = str(edr_status.get("infection_status") or "unknown")
        contained = any(
            event.get("asset_uuid") == ref.uuid
            and event.get("action") == "quarantine"
            and event.get("status") == "isolated"
            for event in run.containment or []
        )
        if infection == "infected":
            run.add_event(
                "edr_infection",
                f"EDR reports infection on {ref.display_name}; restore is blocked.",
            )
        if after_affected:
            status = "not_remediated"
        elif scan_fresh is True:
            status = "remediated"
        else:
            # A finding can be absent because the scan is stale or because no
            # scan timestamp is available. Neither is evidence of a fix.
            status = "unknown"
            run.add_event(
                "verification_scan_stale",
                (
                    f"{ref.display_name}: finding absent, but the scan is "
                    f"{'stale' if scan_fresh is False else 'of unknown freshness'} "
                    f"(last_scan={last_scan or 'unknown'}); not claimed remediated."
                ),
            )
        verification_assets.append(
            VerificationAsset(
                asset_uuid=ref.uuid,
                hostname=ref.display_name,
                before_affected=True,
                after_affected=after_affected,
                status=status,
                last_scan=last_scan,
                last_found=last_found,
                evidence={
                    "matched_plugin_ids": sorted(
                        {finding.plugin_id for finding in matches}
                    ),
                    "last_found": last_found,
                    "last_scan": last_scan,
                    "scan_age_hours": scan_age_hours,
                    "scan_fresh": scan_fresh,
                    "max_scan_age_hours": ctx.settings.verification_max_scan_age_hours,
                    "identity_keys_checked": len(keys),
                },
                infection_status=infection,
                contained=contained,
            )
        )

    new_assets = [
        {
            "asset_uuid": asset.uuid,
            "hostname": asset.display_name,
            "ipv4": asset.ipv4,
            "mac": asset.mac,
        }
        for asset_uuid, asset in current_assets.items()
        if asset_uuid not in before_uuids
    ]
    remediated_count = sum(
        1 for item in verification_assets if item.status == "remediated"
    )
    still_affected = sum(
        1 for item in verification_assets if item.status == "not_remediated"
    )
    unknown_count = sum(1 for item in verification_assets if item.status == "unknown")
    infection_status = (
        "infected"
        if any(item.infection_status == "infected" for item in verification_assets)
        else "unknown"
        if any(item.infection_status == "unknown" for item in verification_assets)
        else "none_reported"
    )
    notes = [
        "Verification re-queries the scanner for the CVE's plugin set. A finding that "
        "disappears after a rescan is the remediation evidence; absence from a stale "
        "scan is not.",
        "No EDR signal means infection status remains unknown; it is never reported as clean.",
        (
            "Scan freshness: a finding is treated as remediated only when the asset's "
            f"last_scan is within {ctx.settings.verification_max_scan_age_hours:g} hours "
            "of verification. A stale or missing timestamp is recorded as unknown."
        ),
    ]
    if new_assets:
        notes.append(
            f"{len(new_assets)} asset(s) appeared during verification and were not in "
            "the original exposure set."
        )
    result = VerificationResult(
        started_at=started,
        finished_at=utc_now(),
        method=f"{ctx.source.name}: CVE -> plugin -> per-asset findings",
        date_range=date_range,
        assets=verification_assets,
        new_affected_assets=new_assets,
        remediated_count=remediated_count,
        still_affected_count=still_affected,
        unknown_count=unknown_count,
        infection_status=infection_status,
        notes=notes,
    )
    run.verification = result.to_dict()
    for item in verification_assets:
        if item.status == "not_remediated":
            run.add_event(
                "verification_failed",
                f"{cve} is still present on {item.hostname}; remediation not confirmed.",
            )
    for asset in new_assets:
        run.add_event(
            "new_exposure_during_verification",
            f"New affected asset during verification: {asset.get('hostname')} "
            f"({asset.get('ipv4')})",
        )

    if infection_status == "infected":
        run.status = STATUS_ESCALATED
    elif (
        remediated_count == len(verification_assets)
        and unknown_count == 0
        and not new_assets
    ):
        run.status = STATUS_VERIFIED
    else:
        run.status = STATUS_VERIFICATION_OPEN

    if run.status == STATUS_VERIFIED:
        run.next_actions = [
            f"Restore contained assets: secops approve --run {run.run_id} "
            f'--gate restore --approver "<name>"',
        ]
        ctx.update_ticket(
            run,
            {
                "status": "RESOLVED",
                "note": "Scanner re-query no longer reports the CVE on the affected assets.",
            },
        )
    else:
        run.next_actions = [
            "Escalate the still-affected assets to their owners; keep NAC isolation "
            "in place until a fresh scanner query clears them."
        ]
        if new_assets:
            run.next_actions.append(
                "New affected assets appeared during verification; scope and "
                "remediate them before closing the ticket."
            )
        ctx.update_ticket(
            run,
            {
                "status": "IN_PROGRESS",
                "note": (
                    f"Verification: {remediated_count} remediated, "
                    f"{still_affected} still affected, {unknown_count} unknown, "
                    f"{len(new_assets)} new."
                ),
            },
        )
    ctx.emit(
        "verification",
        result.to_dict(),
        summary=(
            f"Verification: {remediated_count} remediated, {still_affected} still "
            f"affected, {unknown_count} unknown; infection {infection_status}."
        ),
        started_at=started,
    )
    return run


def _identity_keys(asset: AssetRef) -> list[str]:
    keys = []
    for value in (
        asset.uuid,
        normalize_mac(asset.mac),
        asset.ipv4,
        asset.hostname,
        asset.fqdn,
        asset.netbios,
    ):
        if value:
            keys.append(str(value).strip().lower())
    return dedupe(keys)


__all__ = ["execute_verification", "ELIGIBLE_FOR_VERIFICATION"]
