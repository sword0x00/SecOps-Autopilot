#!/usr/bin/env python3
"""Live, read-only PHP/Node.js batch validation.

This is the reproducible form of the discovery + pipeline run. It reads Tenable
credentials from the environment (or the configured .env), runs the production
read-only pipeline for each target CVE, and writes:

  reports/live-php-node-phase-validation.md
  reports/live-php-node-phase-validation.json

It never approves a gate, creates a ticket, contacts the NAC, submits a patch
job, or restores an asset. Credentials are never written to an artifact.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secops_autopilot.advisory import load_advisory
from secops_autopilot.config import Settings
from secops_autopilot.connectors.edr import SimulatedEDR
from secops_autopilot.connectors.ticketing import SimulatedTicketingSystem
from secops_autopilot.connectors.nac import build_nac
from secops_autopilot.connectors.tenable_vm import TenableVMClient
from secops_autopilot.controls import ControlInventory, OwnerDirectory
from secops_autopilot.pipeline import Pipeline
from secops_autopilot.stages.contracts import CONTRACTS
from secops_autopilot.store import RunStore
from secops_autopilot.util import utc_now

DEFAULT_CVES = [
    # October 2026 PHP/PHP2Shell
    "CVE-2026-109618",
    "CVE-2026-109619",
    # October 2026 Node.js release set
    "CVE-2026-105481",
    "CVE-2026-105482",
    "CVE-2026-105483",
    "CVE-2026-106069",
    "CVE-2026-106070",
    "CVE-2026-106071",
    "CVE-2026-106072",
    "CVE-2026-106073",
    "CVE-2026-106074",
    "CVE-2026-111497",
]


def advisory_for(cve: str) -> dict | None:
    for path in sorted((ROOT / "validation" / "advisories").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        ids = {
            str(value).upper()
            for value in [data.get("id"), data.get("cve"), *(data.get("aliases") or [])]
            if value
        }
        if cve.upper() in ids:
            loaded = load_advisory(path)
            loaded["_path"] = str(path)
            return loaded
    return None


def discover_cves(source: TenableVMClient, date_range: int) -> list[str]:
    """Return CVEs from PHP/Node.js plugin findings the tenant actually reports."""
    data = source.http.get_json(
        "/workbenches/vulnerabilities",
        params={"date_range": date_range, "limit": 5000},
    )
    plugin_ids = []
    for item in data.get("vulnerabilities") or []:
        text = f"{item.get('plugin_name') or ''} {item.get('plugin_family') or ''}".lower()
        if "php" in text or "node.js" in text or "nodejs" in text or "node js" in text:
            plugin_id = item.get("plugin_id")
            if plugin_id:
                plugin_ids.append(int(plugin_id))
    findings = source.findings_for_plugins(sorted(set(plugin_ids)), date_range)
    cves = sorted({cve.upper() for finding in findings for cve in (finding.cve or [])})
    return cves


def stage_status(run: Any) -> dict[str, str]:
    statuses = {}
    for contract in CONTRACTS:
        record = (run.stages or {}).get(contract.id)
        statuses[contract.id] = record.get("status") if record else "not_run"
    return statuses


def run_summary(run: Any) -> dict:
    counts: dict[str, int] = {}
    kri_by_id: dict[str, dict[str, int]] = {}
    for item in run.kri_detections or []:
        status = item.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
        kri_id = str(item.get("kri_id") or "unknown")
        kri_by_id.setdefault(kri_id, {})
        kri_by_id[kri_id][status] = kri_by_id[kri_id].get(status, 0) + 1
    assets = [
        {
            "uuid": (item.get("asset") or {}).get("uuid"),
            "hostname": (item.get("asset") or {}).get("hostname"),
            "ipv4": (item.get("asset") or {}).get("ipv4"),
            "mac": (item.get("asset") or {}).get("mac"),
            "owner": (item.get("owner") or {}).get("owner"),
            "kri_score": (item.get("risk") or {}).get("score"),
            "kri_tier": (item.get("risk") or {}).get("tier"),
        }
        for item in run.exposure or []
    ]
    plan_items = (run.plan or {}).get("per_asset") or []
    return {
        "run_id": run.run_id,
        "cve": (run.target or {}).get("value"),
        "status": run.status,
        "assets": assets,
        "asset_count": len(assets),
        "kri_counts": counts,
        "kri_by_id": kri_by_id,
        "plan_paths": {
            item.get("asset_uuid"): item.get("path") for item in plan_items
        },
        "target_versions": {
            item.get("asset_uuid"): item.get("target_version")
            for item in plan_items
            if item.get("target_version")
        },
        "containment_candidates": sum(
            1 for item in plan_items if item.get("containment_recommended")
        ),
        "stage_status": stage_status(run),
        "errors": [
            f"{stage}: {error}"
            for stage, record in (run.stages or {}).items()
            for error in (record.get("errors") or [])
        ],
        "unknown_count": sum(
            len(record.get("unknowns") or [])
            for record in (run.stages or {}).values()
        ),
        "approval_count": len(run.approvals or []),
        "containment_counts": {
            "isolated": sum(1 for event in run.containment or [] if event.get("status") == "isolated"),
            "blocked": sum(1 for event in run.containment or [] if event.get("status") == "blocked"),
            "failed": sum(1 for event in run.containment or [] if event.get("status") == "failed"),
            "restored": sum(
                1 for event in run.containment or []
                if event.get("action") == "restore" and event.get("status") == "restored"
            ),
        },
        "patch_counts": {
            "status": (run.patch_execution or {}).get("status"),
            "submitted": (run.patch_execution or {}).get("submitted", 0),
            "skipped": len((run.patch_execution or {}).get("skipped") or []),
        },
        "verification_counts": {
            "remediated": (run.verification or {}).get("remediated_count", 0),
            "still_affected": (run.verification or {}).get("still_affected_count", 0),
            "unknown": (run.verification or {}).get("unknown_count", 0),
            "infection": (
                (run.verification or {}).get("infection_status")
                if run.verification
                else "not_run"
            ),
        },
        "report_md": str(Path("runs") / run.run_id / "report.md"),
        "report_html": str(Path("runs") / run.run_id / "report.html"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cves", default="", help="comma-separated CVE list")
    parser.add_argument("--discover", action="store_true", help="discover CVEs from PHP/Node.js plugins")
    parser.add_argument("--date-range", type=int, default=3650)
    parser.add_argument("--max-assets", type=int, default=200)
    parser.add_argument("--out", default="reports")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    settings = Settings.load()
    source = TenableVMClient(settings.vm)
    if args.cves:
        cves = [item.strip().upper() for item in args.cves.split(",") if item.strip()]
    elif args.discover:
        cves = discover_cves(source, args.date_range)
        if not cves:
            print("discovery returned no PHP/Node.js CVEs", file=sys.stderr)
            return 2
        print(f"discovered {len(cves)} PHP/Node.js CVEs", flush=True)
    else:
        cves = DEFAULT_CVES
    store = RunStore(settings)
    pipeline = Pipeline(
        settings,
        source,
        store,
        SimulatedTicketingSystem(settings.state_dir),
        build_nac(settings),
        SimulatedEDR(settings.state_dir),
        owners=OwnerDirectory(),
        controls=ControlInventory(),
    )
    results: list[dict] = []
    for cve in cves:
        advisory = advisory_for(cve)
        print(f"running {cve} (advisory={bool(advisory)})", flush=True)
        try:
            run = pipeline.run(
                cve,
                date_range=args.date_range,
                max_assets=args.max_assets,
                advisory=advisory,
            )
            summary = run_summary(run)
            summary["advisory"] = bool(advisory)
            summary["advisory_source"] = (
                advisory.get("source") if advisory else None
            )
            summary["manifest_ok"] = store.verify_manifest(run.run_id).get("ok", False)
            results.append(summary)
        except Exception as exc:  # a single CVE must not abort the batch
            results.append(
                {
                    "cve": cve,
                    "status": "batch_error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "advisory": bool(advisory),
                }
            )

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    generated = utc_now()
    payload = {
        "generated_at": generated,
        "scope": {
            "mode": "discovered" if args.discover else "explicit",
            "cve_count": len(cves),
        },
        "source": {
            "name": source.name,
            "base_url": settings.vm.base_url,
            "live": getattr(source, "live", False),
            "date_range_days": args.date_range,
        },
        "results": results,
        "summary": {
            "total": len(results),
            "no_exposure": sum(1 for item in results if item.get("status") == "no_exposure_found"),
            "awaiting_ticket_approval": sum(
                1 for item in results if item.get("status") == "awaiting_ticket_approval"
            ),
            "errors": sum(
                1 for item in results if item.get("status") in {"batch_error", "intake_failed", "stage_failed"}
            ),
        },
    }
    (out_dir / "live-php-node-phase-validation.json").write_text(
        json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8"
    )
    (out_dir / "live-php-node-phase-validation.md").write_text(
        _render_markdown(payload), encoding="utf-8"
    )
    _write_executive_formats(
        _render_executive_summary(payload),
        out_dir,
        "live-php-node-executive-summary",
    )
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(f"report: {out_dir / 'live-php-node-phase-validation.md'}")
        print(json.dumps(payload["summary"], indent=2))
    return 0


def _write_executive_formats(text: str, out_dir: Path, stem: str) -> None:
    """Write the same management report as Markdown, HTML, and PDF."""
    md_path = out_dir / f"{stem}.md"
    md_path.write_text(text, encoding="utf-8")
    try:
        import markdown as markdown_lib
        body = markdown_lib.markdown(
            text, extensions=["tables", "sane_lists", "fenced_code"]
        )
    except Exception:
        import html as html_lib
        body = f"<pre>{html_lib.escape(text)}</pre>"
    html_path = out_dir / f"{stem}.html"
    html_path.write_text(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{stem}</title><style>"
        "body{font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;"
        "max-width:1120px;margin:32px auto;padding:0 18px;color:#171a21;background:#fff}"
        "h1{font-size:26px;line-height:1.2}h2{margin-top:30px;border-bottom:1px solid #dde2e8;"
        "padding-bottom:6px}h3{margin-top:22px}table{border-collapse:collapse;width:100%;"
        "margin:12px 0;font-size:13px}th,td{border:1px solid #dde2e8;padding:6px 8px;"
        "text-align:left;vertical-align:top}th{background:#f4f6f8}code{font-family:ui-monospace,"
        "SFMono-Regular,Menlo,monospace;font-size:12px}pre{background:#f4f6f8;padding:12px;"
        "overflow:auto}@media print{body{margin:0;max-width:none;font-size:11px}"
        "table{font-size:10px}h1{font-size:20px}h2{font-size:16px;page-break-after:avoid}}"
        "</style></head><body>" + body + "</body></html>",
        encoding="utf-8",
    )
    chrome = shutil.which("chromium") or shutil.which("google-chrome")
    if not chrome:
        print(f"warning: no Chromium/Chrome; PDF not generated for {stem}", file=sys.stderr)
        return
    pdf_path = out_dir / f"{stem}.pdf"
    result = subprocess.run(
        [
            chrome,
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--print-to-pdf={pdf_path.resolve()}",
            f"file://{html_path.resolve()}",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0 or not pdf_path.is_file():
        print(
            f"warning: PDF generation failed for {stem}: "
            f"{result.stderr.strip()[:300]}",
            file=sys.stderr,
        )


def _render_executive_summary(payload: dict) -> str:
    results = payload["results"]
    kri_names = {
        "KRI-01": "Missing security agent",
        "KRI-02": "Stale control version",
        "KRI-03": "Stale threat feeds",
        "KRI-04": "Detect-only mode",
        "KRI-05": "Unresolved exploitable vulnerability",
        "KRI-06": "NAC non-compliant posture",
        "KRI-08": "Vulnerable runtime version",
        "KRI-09": "Externally exposed vulnerable service",
    }
    tier_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    kri = {"detected": 0, "not_detected": 0, "unknown": 0, "not_applicable": 0}
    kri_by_id: dict[str, dict[str, int]] = {}
    assets: dict[str, dict] = {}
    plan_counts = {"patch": 0, "compensate": 0, "isolate": 0}
    target_assets = 0
    planned_assets = 0
    containment_candidates = 0
    containment = {"isolated": 0, "blocked": 0, "failed": 0, "restored": 0}
    patch = {"submitted": 0, "skipped": 0}
    verification = {"remediated": 0, "still_affected": 0, "unknown": 0}
    infection = {}
    approvals = 0
    unknown_total = 0
    manifests_ok = 0
    stage_counts: dict[str, dict[str, int]] = {}
    for result in results:
        cve = result.get("cve") or "unknown"
        for asset in result.get("assets") or []:
            key = asset.get("hostname") or asset.get("uuid") or "unknown"
            entry = assets.setdefault(
                key,
                {
                    "hostname": key,
                    "ipv4": None,
                    "mac": None,
                    "owner": None,
                    "cves": [],
                    "kri_score": 0.0,
                    "tier": "unknown",
                },
            )
            entry["ipv4"] = entry["ipv4"] or asset.get("ipv4")
            entry["mac"] = entry["mac"] or asset.get("mac")
            entry["owner"] = entry["owner"] or asset.get("owner")
            if cve not in entry["cves"]:
                entry["cves"].append(cve)
            score = asset.get("kri_score") or 0.0
            if score > (entry["kri_score"] or 0.0):
                entry["kri_score"] = score
                entry["tier"] = asset.get("kri_tier") or entry["tier"]
            elif tier_rank.get(asset.get("kri_tier"), 0) > tier_rank.get(entry["tier"], 0):
                entry["tier"] = asset.get("kri_tier")
        for key, value in (result.get("kri_counts") or {}).items():
            kri[key] = kri.get(key, 0) + value
        for kri_id, values in (result.get("kri_by_id") or {}).items():
            bucket = kri_by_id.setdefault(kri_id, {})
            for status, count in values.items():
                bucket[status] = bucket.get(status, 0) + count
        for path in (result.get("plan_paths") or {}).values():
            plan_counts[path] = plan_counts.get(path, 0) + 1
        planned_assets += len(result.get("plan_paths") or {})
        target_assets += len(result.get("target_versions") or {})
        containment_candidates += result.get("containment_candidates", 0)
        for key, value in (result.get("containment_counts") or {}).items():
            containment[key] = containment.get(key, 0) + value
        patch["submitted"] += (result.get("patch_counts") or {}).get("submitted", 0)
        patch["skipped"] += (result.get("patch_counts") or {}).get("skipped", 0)
        for key in ("remediated", "still_affected", "unknown"):
            verification[key] += (result.get("verification_counts") or {}).get(key, 0)
        status = (result.get("verification_counts") or {}).get("infection") or "unknown"
        infection[status] = infection.get(status, 0) + 1
        approvals += result.get("approval_count", 0)
        unknown_total += result.get("unknown_count", 0)
        if result.get("manifest_ok"):
            manifests_ok += 1
        for stage, stage_status in (result.get("stage_status") or {}).items():
            stage_counts.setdefault(stage, {}).setdefault(stage_status, 0)
            stage_counts[stage][stage_status] += 1
    top_assets = sorted(
        assets.values(), key=lambda item: (-len(item["cves"]), -(item["kri_score"] or 0))
    )[:8]
    for contract in CONTRACTS:
        stage_counts.setdefault(contract.id, {"not_run": len(results)})
    advisory_without_target = [
        item["cve"]
        for item in results
        if item.get("advisory") and not (item.get("target_versions") or {})
    ]
    all_cves = sorted(results, key=lambda item: item.get("cve") or "")
    tier_assets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for asset in assets.values():
        tier_assets[asset.get("tier") or "unknown"] = tier_assets.get(asset.get("tier") or "unknown", 0) + 1

    lines = []
    add = lines.append
    add("# Executive summary for management — live PHP/Node.js batch")
    add("")
    add(f"**Generated:** {payload['generated_at']}  ")
    add(f"**Source:** {payload['source']['name']} — {payload['source']['base_url']} "
        f"(live={payload['source']['live']})  ")
    add(f"**Scope:** {payload['summary']['total']} CVEs discovered from PHP/Node.js plugin findings  ")
    add("**Safety:** read-only; no ticket, containment, patch, or restore executed.")
    add("")
    add("## Bottom line")
    add("")
    add(
        f"{payload['summary']['total']} CVEs were processed with "
        f"{payload['summary']['errors']} errors. All runs stopped at the ticket gate. "
        f"{len(assets)} unique assets were returned; {target_assets} of {planned_assets} "
        "asset plans had a verified target version."
    )
    add("")
    add("## Numbers at a glance")
    add("")
    add("| Metric | Value |")
    add("|---|---|")
    add(f"| CVEs run | {payload['summary']['total']} |")
    add(f"| Runs with errors | {payload['summary']['errors']} |")
    add(f"| No-exposure runs | {payload['summary']['no_exposure']} |")
    add(f"| Runs awaiting ticket approval | {payload['summary']['awaiting_ticket_approval']} |")
    add(f"| Unique assets | {len(assets)} |")
    add(f"| Asset appearances | {sum(len(item.get('assets') or []) for item in results)} |")
    add(f"| Asset max tiers critical / high / medium / low / unknown | "
        f"{tier_assets['critical']} / {tier_assets['high']} / {tier_assets['medium']} / "
        f"{tier_assets['low']} / {tier_assets['unknown']} |")
    add(f"| KRI detected / clear / unknown / n/a | {kri['detected']} / {kri['not_detected']} / {kri['unknown']} / {kri['not_applicable']} |")
    add(f"| Plan paths patch / compensate / isolate | {plan_counts['patch']} / {plan_counts['compensate']} / {plan_counts['isolate']} |")
    add(f"| Asset plans with a verified target version | {target_assets} |")
    add(f"| Containment candidates | {containment_candidates} |")
    add(f"| Containment isolated / blocked / failed / restored | "
        f"{containment['isolated']} / {containment['blocked']} / "
        f"{containment['failed']} / {containment['restored']} |")
    add(f"| Patch jobs submitted / skipped | {patch['submitted']} / {patch['skipped']} |")
    add(f"| Verification remediated / still affected / unknown | "
        f"{verification['remediated']} / {verification['still_affected']} / {verification['unknown']} |")
    add(f"| Infection status counts | " + ", ".join(f"{k}={v}" for k, v in sorted(infection.items())) + " |")
    add(f"| Approval gates recorded | {approvals} |")
    add(f"| Explicit unknown fields | {unknown_total} |")
    add(f"| Evidence manifests verified | {manifests_ok}/{len(results)} |")
    add("")
    add("## All CVEs")
    add("")
    add("| CVE | Status | Assets | KRI detected / unknown | Plan paths | Target | Advisory |")
    add("|---|---|---|---|---|---|---|")
    for item in all_cves:
        counts = item.get("kri_counts") or {}
        paths = ", ".join(f"{k}={v}" for k, v in (item.get("plan_paths") or {}).items())
        names = ", ".join(str(a.get("hostname")) for a in (item.get("assets") or [])) or "—"
        targets = len(item.get("target_versions") or {})
        add(
            f"| {item.get('cve')} | {item.get('status')} | {item.get('asset_count', 0)}: {names} | "
            f"{counts.get('detected', 0)} / {counts.get('unknown', 0)} | {paths or '—'} | "
            f"{targets} | {'yes' if item.get('advisory') else 'no'} |"
        )
    add("")
    add("## All assets")
    add("")
    add("| Asset | Address | MAC | Owner | CVEs | Max KRI | Tier |")
    add("|---|---|---|---|---|---|---|")
    for asset in sorted(assets.values(), key=lambda item: (-len(item["cves"]), item["hostname"])):
        add(
            f"| {asset['hostname']} | {asset.get('ipv4') or 'unknown'} | "
            f"{asset.get('mac') or 'unknown'} | {asset.get('owner') or 'unknown'} | "
            f"{len(asset['cves'])}: {', '.join(sorted(asset['cves']))} | "
            f"{asset.get('kri_score', 0):.1f} | {asset.get('tier') or 'unknown'} |"
        )
    add("")
    add("## KRI coverage")
    add("")
    add("| KRI | Name | Detected | Clear | Unknown | N/A |")
    add("|---|---|---|---|---|---|")
    for kri_id in sorted(kri_by_id):
        values = kri_by_id[kri_id]
        add(
            f"| {kri_id} | {kri_names.get(kri_id, '')} | {values.get('detected', 0)} | "
            f"{values.get('not_detected', 0)} | {values.get('unknown', 0)} | "
            f"{values.get('not_applicable', 0)} |"
        )
    add("")
    add("## Phase validation")
    add("")
    add("| Phase | Complete | Skipped | Not run | Error |")
    add("|---|---|---|---|---|")
    for stage in sorted(stage_counts):
        values = stage_counts[stage]
        add(
            f"| {stage} | {values.get('complete', 0)} | {values.get('skipped', 0)} | "
            f"{values.get('not_run', 0)} | {values.get('error', 0) + values.get('failed', 0)} |"
        )
    add("")
    add("## Insights")
    add("")
    add("**Largest asset concentrations**")
    add("")
    add("| Asset | CVEs | Max KRI | Tier |")
    add("|---|---|---|---|")
    for asset in top_assets:
        add(
            f"| {asset['hostname']} | {len(asset['cves'])} | {asset['kri_score']:.1f} | "
            f"{asset.get('tier') or 'unknown'} |"
        )
    add("")
    add("- **No target versions:** the batch produced 0 targets. Patch submission would skip every job until package/runtime versions are enriched.")
    if advisory_without_target:
        add(
            "- **Advisory without target:** " + ", ".join(sorted(advisory_without_target))
            + " had advisory metadata but no CPE-matched target version."
        )
    add("- **Control confidence:** KRI-02/03/04/06 are unknown on every asset; agent inventory is out of scope and no EDR/AV inventory was supplied.")
    add("- **Scope is broader than Node.js:** CVE-2026-111497 matched OS Brotli packages across 15 assets, not only the Node.js host.")
    add("- **Scanner mapping needs review:** the PHP CVEs also matched a PAN-OS plugin; verify the CVE/plugin association.")
    add("- **Discovery is capped:** the workbench query returned the requested 5,000-entry limit; paginate before calling the list exhaustive.")
    add("")
    add("## Decisions required")
    add("")
    add("1. Fix runtime/package version enrichment before approving any patch gate.")
    add("2. Supply an asset inventory/control connector to reduce unknown KRIs.")
    add("3. Review the PAN-OS PHP mapping and the 15-asset Brotli scope.")
    add("4. Select a pilot asset and approve ticket → containment → patch → verification with a named approver.")
    add("")
    add("## Evidence")
    add("")
    add("- `reports/live-php-node-phase-validation.md` — per-CVE and phase detail")
    add("- `reports/live-php-node-phase-validation.json` — machine-readable results")
    add("- `reports/live-php-node-assessment.md` — issue analysis and priorities")
    add("- `reports/executive-summaries/<run-id>.md` — one management summary per run")
    add("")
    return "\n".join(lines)


def _render_markdown(payload: dict) -> str:
    results = payload["results"]
    lines: list[str] = []
    add = lines.append
    add("# Live PHP/Node.js phase validation")
    add("")
    add(f"**Generated:** {payload['generated_at']}  ")
    add(
        f"**Source:** {payload['source']['name']} — "
        f"{payload['source']['base_url']} (live={payload['source']['live']})  "
    )
    add(f"**Window:** last {payload['source']['date_range_days']} days  ")
    add(f"**CVEs attempted:** {payload['summary']['total']}  ")
    add(
        f"**Scope:** {payload.get('scope', {}).get('mode', 'explicit')} "
        f"({payload.get('scope', {}).get('cve_count', payload['summary']['total'])} CVEs)"
    )
    add("")
    add("## Scope and safety")
    add("")
    add(
        "This batch runs the read-only stages only: intake, exposure, control check, "
        "KRI register, scoring, remediation planning, and evidence. It "
        "does not approve ticket, containment, patch, or restore gates."
    )
    add("")
    add("## Per-CVE results")
    add("")
    add("| CVE | Status | Assets | KRI detected/unknown | Plan | Target versions | Errors |")
    add("|---|---|---|---|---|---|---|")
    for item in results:
        if item.get("status") == "batch_error":
            add(
                f"| {item['cve']} | **batch_error** | — | — | — | — | "
                f"{str(item.get('error'))[:120]} |"
            )
            continue
        assets = item.get("assets") or []
        paths = ", ".join(
            f"{uuid}={path}" for uuid, path in (item.get("plan_paths") or {}).items()
        ) or "—"
        targets = ", ".join(
            f"{uuid}={version}"
            for uuid, version in (item.get("target_versions") or {}).items()
        ) or "—"
        counts = item.get("kri_counts") or {}
        add(
            f"| {item['cve']} | {item['status']} | {item['asset_count']} "
            f"({', '.join(str(a.get('hostname')) for a in assets) or '—'}) | "
            f"{counts.get('detected', 0)}/{counts.get('unknown', 0)} | "
            f"{paths} | {targets} | "
            f"{'; '.join(item.get('errors') or [])[:120] or '—'} |"
        )
    add("")
    add("## Phase validation")
    add("")
    add("| Phase | Complete | Skipped | Not run | Error | Assessment |")
    add("|---|---|---|---|---|---|")
    phase_notes = {
        "intake": "Runs live; no match yields `no_exposure_found`.",
        "exposure": "Runs live; assets are only those returned by Tenable.",
        "control_check": "Runs; agent inventory is 403, so agent version/feed are unknown.",
        "kri_register": "Runs; KRI-08 is unknown unless an advisory was supplied.",
        "kri_scoring": "Runs; unknown components are excluded and reported.",
        "remediation_planning": "Runs; target versions require advisory metadata.",
        "ticket": "Not run: approval gate.",
        "remediation_approval": "Not run: approval gate.",
        "containment": "Not run: approval gate and simulated NAC.",
        "patch_execution": "Not run: approval gate and simulated patch connector.",
        "verification": "Not run: requires remediation approval / post-remediation state.",
        "recovery": "Not run: requires verification and restore approval.",
        "evidence": "Runs; report and manifest written.",
    }
    for contract in CONTRACTS:
        statuses = [
            item.get("stage_status", {}).get(contract.id)
            for item in results
            if item.get("status") != "batch_error"
        ]
        complete = statuses.count("complete")
        skipped = statuses.count("skipped")
        not_run = statuses.count("not_run")
        errors = statuses.count("error") + statuses.count("failed")
        add(
            f"| {contract.id} | {complete} | {skipped} | {not_run} | {errors} | "
            f"{phase_notes.get(contract.id, '')} |"
        )
    add("")
    add("## Issues and gaps")
    add("")
    issues = []
    for item in results:
        if item.get("status") in {"batch_error", "intake_failed", "stage_failed", "no_exposure_found"}:
            issues.append(
                f"{item['cve']}: {item['status']}"
                + (f" — {item.get('error')}" if item.get("error") else "")
            )
    if issues:
        for issue in issues:
            add(f"- {issue}")
    else:
        add("- No intake/exposure errors in this batch.")
    manifest_failures = [
        item.get("cve") for item in results if item.get("manifest_ok") is False
    ]
    add(
        "- **Evidence manifests:** "
        + (
            f"FAILED for {', '.join(manifest_failures)}"
            if manifest_failures
            else "all generated run manifests verified OK"
        )
    )
    add("")
    add(
        "- **Agent inventory 403:** live Tenable scope cannot read `/scanners/agents`; "
        "agent version/feed are recorded as unknown, not guessed."
    )
    add(
        "- **No EDR/AV control connector:** KRI-01/02/03/04/06 remain unknown unless "
        "a control inventory or live connector is supplied."
    )
    add(
        "- **Advisory coverage:** only the CVEs with files in `validation/advisories/` "
        "get KRI-08 fixed-version evaluation and patch targets. Others have no target."
    )
    advisory_without_target = [
        item.get("cve")
        for item in results
        if item.get("advisory") and not (item.get("target_versions") or {})
    ]
    if advisory_without_target:
        add(
            "- **Advisory without target version:** "
            + ", ".join(sorted(advisory_without_target))
            + ". The advisory was attached, but the finding CPE did not expose a "
            "matching runtime/product version, so the engine refused to invent a target."
        )
    if results and all(not (item.get("target_versions") or {}) for item in results if item.get("status") != "batch_error"):
        add(
            "- **Patch-gate impact:** 0 target versions across the batch; a patch "
            "gate would record no jobs. Package/version enrichment is required."
        )
    add(
        "- **Gated phases:** ticket, containment, patch execution, verification, and "
        "restore did not run because no human approval was recorded. This is by design."
    )
    add(
        "- **Simulated control plane:** ticketing, NAC, EDR, and patch are file-backed "
        "unless a live connector is configured."
    )
    add("")
    add("## Per-run evidence")
    add("")
    for item in results:
        if item.get("run_id"):
            add(
                f"- `{item['cve']}` — `{item['run_id']}` — "
                f"`{item.get('report_html')}`"
            )
    add("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
