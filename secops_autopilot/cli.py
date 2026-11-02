"""Command-line interface for SecOps Autopilot."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import Settings
from .connectors.base import VulnerabilitySource
from .connectors.edr import SimulatedEDR
from .connectors.itsm import SimulatedITSM
from .connectors.nac import build_nac
from .connectors.siem import SimulatedSIEM
from .connectors.tenable_sc import TenableSCClient
from .connectors.tenable_vm import TenableVMClient
from .controls import ControlInventory, OwnerDirectory
from .errors import ConnectorError, SecOpsError
from .models import (
    GATE_CONTAINMENT,
    GATE_REMEDIATION,
    GATE_RESTORE,
    GATE_TICKET,
)
from .pipeline import Pipeline
from .store import RunStore
from .util import utc_now

GATES = [GATE_TICKET, GATE_REMEDIATION, GATE_CONTAINMENT, GATE_RESTORE]


# -- terminal helpers ---------------------------------------------------


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _paint(text: str, code: str) -> str:
    if not _color_enabled():
        return text
    return f"\033[{code}m{text}\033[0m"


def _tier(text: str) -> str:
    colors = {"critical": "31", "high": "33", "medium": "33", "low": "32"}
    return _paint(str(text), colors.get(str(text).lower(), "0"))


def _status(text: str) -> str:
    if text in {"verified_remediated", "restored", "complete"}:
        return _paint(text, "32")
    if text in {"escalated_to_soc", "remediation_rejected", "intake_failed"}:
        return _paint(text, "31")
    if text.startswith("awaiting"):
        return _paint(text, "33")
    return text


def _fmt(value: Any, width: int = 32) -> str:
    if value is None or value == "":
        text = "unknown"
    elif isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, float):
        text = f"{value:.1f}"
    else:
        text = str(value)
    text = text.replace("\n", " ")
    if len(text) > width:
        text = text[: width - 1] + "…"
    return text


def _table(headers: list[str], rows: list[list[Any]], width: int = 32) -> str:
    cells = [[_fmt(cell, width) for cell in row] for row in rows]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in cells))
        if cells
        else len(headers[index])
        for index in range(len(headers))
    ]
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        "  ".join("-" * widths[index] for index in range(len(headers))),
    ]
    for row in cells:
        lines.append(
            "  ".join(row[index].ljust(widths[index]) for index in range(len(headers)))
        )
    return "\n".join(lines)


# -- source / pipeline construction ------------------------------------


class _NoopSource:
    """Used by commands that operate only on a recorded run."""

    name = "not-used"
    live = False

    def _raise(self, *_: Any, **__: Any) -> Any:
        raise ConnectorError("Tenable is not needed for this command")

    def health(self) -> dict[str, Any]:
        return self._raise()

    def cve_plugin_hits(self, *args: Any, **kwargs: Any) -> Any:
        return self._raise()

    def findings_for_plugins(self, *args: Any, **kwargs: Any) -> Any:
        return self._raise()

    def asset_detail(self, *args: Any, **kwargs: Any) -> Any:
        return self._raise()

    def agent_inventory(self, *args: Any, **kwargs: Any) -> Any:
        return self._raise()

    def public_snapshot(self) -> dict[str, Any]:
        return {"name": self.name, "live": False, "note": "not used by this command"}


def _settings(args: argparse.Namespace) -> Settings:
    env_files = [Path(args.env_file)] if getattr(args, "env_file", None) else None
    return Settings.load(
        profile=getattr(args, "profile", "default"),
        source=getattr(args, "source", "auto"),
        env_files=env_files,
        runs_dir=getattr(args, "runs_dir", None),
    )


def _source(settings: Settings) -> VulnerabilitySource:
    choice = settings.resolve_source()
    if choice == "vm":
        return TenableVMClient(settings.vm)
    return TenableSCClient(settings.sc)


def _pipeline(
    settings: Settings,
    *,
    with_source: bool,
    owners_path: str | None = None,
    controls_path: str | None = None,
    kri_catalog_path: str | None = None,
) -> Pipeline:
    source = _source(settings) if with_source else _NoopSource()
    store = RunStore(settings)
    return Pipeline(
        settings,
        source,
        store,
        SimulatedITSM(settings.state_dir),
        build_nac(settings),
        SimulatedEDR(settings.state_dir),
        SimulatedSIEM(settings.state_dir),
        owners=OwnerDirectory(owners_path),
        controls=ControlInventory(controls_path),
        kri_catalog_path=kri_catalog_path,
    )


# -- commands -----------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    settings = _settings(args)
    payload: dict[str, Any] = {
        "version": __version__,
        "profile": args.profile,
        "source_preference": args.source,
        "retrieved": utc_now(),
        "tenable_vm": settings.vm.public_snapshot(),
        "tenable_sc": settings.sc.public_snapshot(),
        "ise": settings.ise.public_snapshot(),
    }
    try:
        source = _source(settings)
        health = source.health()
        payload["health"] = health
        payload["ok"] = bool(health.get("ok"))
        payload["degraded"] = health.get("workbench_read") is False
    except SecOpsError as exc:
        payload["health"] = {"ok": False, "error": str(exc)}
        payload["ok"] = False
        payload["degraded"] = True
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(f"SecOps Autopilot {__version__} — Tenable connectivity\n")
        print(f"Profile:        {args.profile}")
        print(f"Source choice:  {args.source}")
        print(f"VM configured:  {settings.vm.configured}")
        print(f"SC configured:  {settings.sc.configured}")
        print(f"ISE configured: {settings.ise.configured}")
        health = payload.get("health") or {}
        if health.get("ok"):
            print(f"\nProduct:        {health.get('product')}")
            print(f"Base URL:       {health.get('base_url')}")
            print(f"Account:        {health.get('account')}")
            print(f"User-Agent:     {health.get('user_agent')}")
            print(f"Workbench read: {health.get('workbench_read')}")
            print(f"Agent inventory:{health.get('agent_inventory')}")
            if health.get("agent_inventory_reason"):
                print(f"  reason:       {health.get('agent_inventory_reason')}")
            if health.get("adapter_validation"):
                print(f"Adapter note:   {health.get('adapter_validation')}")
            print(f"Latency:        {health.get('latency_ms')} ms")
        else:
            print(f"\nHealth check failed: {health.get('error')}")
        print("\nCredential safety: keys are read from .env / environment and are never "
              "written to run artifacts.")
    if not payload.get("ok"):
        return 2
    if payload.get("degraded"):
        return 1
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    settings = _settings(args)
    source = _source(settings)
    if not hasattr(source, "tenant_summary"):
        print("Inventory summary is implemented for Tenable Vulnerability Management; "
              "the Security Center adapter supports run/verify commands.")
        return 0
    summary = source.tenant_summary(date_range=args.date_range, limit=args.limit)
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return 0
    print(f"Tenable tenant overview — last {summary['date_range_days']} days")
    print(f"Base URL: {summary['base_url']}")
    print(f"Assets returned: {summary['assets_returned']} "
          f"(agent flag true: {summary['assets_with_agent_flag']})")
    print(f"Plugin vulnerabilities returned: {summary['vulnerabilities_returned']}")
    print("Severity distribution: " + ", ".join(
        f"{key}={value}" for key, value in sorted(summary["severity_distribution"].items())
    ))
    print(f"Agent inventory: {'available' if summary['agent_inventory_available'] else 'unknown'}")
    if summary.get("agent_inventory_reason"):
        print(f"  reason: {summary['agent_inventory_reason']}")
    print("\nTop plugins by severity / asset count:")
    print(_table(
        ["Plugin", "Name", "Severity", "Assets", "CVSS3", "VPR"],
        [
            [
                item.get("plugin_id"),
                item.get("name"),
                item.get("severity"),
                item.get("asset_count"),
                item.get("cvss3"),
                item.get("vpr"),
            ]
            for item in summary.get("top_plugins") or []
        ],
        width=46,
    ))
    print("\nNote: the workbench list is capped by the API limit; use a CVE run for "
          "per-asset evidence.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    settings = _settings(args)
    pipeline = _pipeline(
        settings,
        with_source=True,
        owners_path=args.owners,
        controls_path=args.controls,
        kri_catalog_path=args.kri_catalog,
    )
    run = pipeline.run(args.cve, date_range=args.date_range, max_assets=args.max_assets)
    if args.json:
        print(json.dumps(_run_summary(run), indent=2, default=str))
        return 0
    _print_run(run)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = RunStore(settings)
    run = store.load(args.run)
    if args.json:
        print(json.dumps(_run_summary(run), indent=2, default=str))
        return 0
    _print_run(run, detail=True)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    settings = _settings(args)
    pipeline = _pipeline(settings, with_source=False)
    run = pipeline.approve(
        args.run,
        args.gate,
        args.approver,
        args.note or "",
        reject=args.reject,
    )
    if args.json:
        print(json.dumps(_run_summary(run), indent=2, default=str))
        return 0
    print(f"Approval recorded: gate={args.gate} "
          f"decision={'reject' if args.reject else 'approve'} by {args.approver}")
    print(f"Run status: {_status(run.status)}")
    if run.ticket:
        ticket = run.ticket
        print(f"Ticket: {ticket.get('ticket_id')} — {ticket.get('status')}")
    if args.gate == GATE_CONTAINMENT and run.containment:
        print("\nContainment events:")
        print(_table(
            ["Event", "Asset", "MAC", "Status", "VLAN", "Reason"],
            [
                [
                    event.get("event_id"),
                    event.get("hostname"),
                    event.get("mac"),
                    event.get("status"),
                    event.get("vlan"),
                    event.get("reason"),
                ]
                for event in run.containment
            ],
            width=40,
        ))
    if args.gate == GATE_RESTORE and run.containment:
        print("\nRestore events:")
        print(_table(
            ["Event", "Asset", "MAC", "Status", "Reason"],
            [
                [
                    event.get("event_id"),
                    event.get("hostname"),
                    event.get("mac"),
                    event.get("status"),
                    event.get("reason"),
                ]
                for event in run.containment
                if event.get("action") == "restore"
            ],
            width=40,
        ))
    if run.next_actions:
        print("\nNext:")
        for action in run.next_actions:
            print(f"  - {action}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    settings = _settings(args)
    pipeline = _pipeline(settings, with_source=True)
    run = pipeline.verify(args.run)
    verification = run.verification or {}
    if args.json:
        print(json.dumps(_run_summary(run), indent=2, default=str))
    else:
        print(f"Verification complete: {_status(run.status)}")
        print(
            f"Remediated: {verification.get('remediated_count')} · "
            f"still affected: {verification.get('still_affected_count')} · "
            f"unknown: {verification.get('unknown_count')} · "
            f"infection: {verification.get('infection_status')}"
        )
        print("\n" + _table(
            ["Asset", "Before", "After", "Status", "Infection", "Contained"],
            [
                [
                    item.get("hostname"),
                    item.get("before_affected"),
                    item.get("after_affected"),
                    item.get("status"),
                    item.get("infection_status"),
                    item.get("contained"),
                ]
                for item in verification.get("assets") or []
            ],
            width=34,
        ))
        if verification.get("new_affected_assets"):
            print("\nNew affected assets during verification:")
            for asset in verification["new_affected_assets"]:
                print(f"  - {asset.get('hostname')} ({asset.get('ipv4')})")
        if run.next_actions:
            print("\nNext:")
            for action in run.next_actions:
                print(f"  - {action}")
    if args.fail_on_open and run.status not in {
        "verified_remediated",
        "restored",
        "complete",
    }:
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = RunStore(settings)
    run = store.load(args.run)
    store.finalize(run)
    directory = store.run_dir(run.run_id)
    if args.format == "json":
        print(json.dumps(_run_summary(run), indent=2, default=str))
        return 0
    path = directory / ("report.html" if args.format == "html" else "report.md")
    print(f"Report: {path}")
    print(f"Run record: {directory / 'run.json'}")
    print(f"Manifest: {directory / 'manifest.json'}")
    if args.verify:
        verification = store.verify_manifest(run.run_id)
        print(f"Integrity: {'OK' if verification['ok'] else 'FAILED'}")
        if not verification["ok"]:
            for item in verification["checked"]:
                if item["status"] != "ok":
                    print(f"  {item['file']}: {item['status']}")
            return 1
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = RunStore(settings)
    run = store.load(args.run)
    if not args.verify_only:
        store.finalize(run)
    verification = store.verify_manifest(run.run_id)
    print(f"Evidence: {store.run_dir(run.run_id)}")
    print(f"Manifest: {store.run_dir(run.run_id) / 'manifest.json'}")
    print(f"Integrity: {'OK' if verification['ok'] else 'FAILED'}")
    if verification.get("unlisted_files"):
        print("Unlisted files present: " + ", ".join(verification["unlisted_files"]))
    if not verification["ok"]:
        for item in verification["checked"]:
            if item["status"] != "ok":
                print(f"  {item['file']}: {item['status']}")
        return 1
    return 0


def cmd_runs(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = RunStore(settings)
    runs = store.list_runs()
    if args.json:
        print(json.dumps(runs, indent=2, default=str))
        return 0
    if not runs:
        print(f"No runs under {settings.runs_dir}")
        return 0
    print(_table(
        ["Run", "Created", "Status", "Target", "Assets"],
        [
            [
                item.get("run_id"),
                item.get("created_at"),
                item.get("status"),
                item.get("target"),
                item.get("assets"),
            ]
            for item in runs
        ],
        width=52,
    ))
    return 0


def _print_kri_register(run: Any) -> None:
    detections = run.kri_detections or []
    kri_ids = sorted(
        {str(item.get("kri_id")) for item in detections if item.get("kri_id")}
    )
    if not kri_ids:
        return
    print("\nKRI register:")
    for kri_id in kri_ids:
        items = [item for item in detections if item.get("kri_id") == kri_id]
        detected = [item for item in items if item.get("status") == "detected"]
        unknown = [item for item in items if item.get("status") == "unknown"]
        name = items[0].get("name", "") if items else ""
        print(
            f"  {kri_id} {name}: {len(detected)} detected, "
            f"{len(unknown)} unknown"
        )
        for item in detected[:5]:
            evidence = "; ".join(item.get("evidence") or [])
            print(f"    - {item.get('hostname')}: {_fmt(evidence, 110)}")
    print("  Full per-asset matrix: `secops report --run <id> --format html`")


# -- rendering ----------------------------------------------------------


def _run_summary(run: Any) -> dict[str, Any]:
    vulnerability = run.vulnerability or {}
    plan = run.plan or {}
    ticket = run.ticket or {}
    verification = run.verification or {}
    return {
        "run_id": run.run_id,
        "created_at": run.created_at,
        "status": run.status,
        "target": run.target,
        "source": run.source,
        "vulnerability": {
            "id": vulnerability.get("id"),
            "title": vulnerability.get("title"),
            "confidence": vulnerability.get("confidence"),
            "affected_assets": vulnerability.get("affected_asset_count"),
            "exploited_in_wild": vulnerability.get("exploited_in_wild"),
            "patch_available": vulnerability.get("patch_available"),
        },
        "assets": [
            {
                "asset_uuid": (asset.get("asset") or {}).get("uuid"),
                "hostname": (asset.get("asset") or {}).get("hostname"),
                "ipv4": (asset.get("asset") or {}).get("ipv4"),
                "mac": (asset.get("asset") or {}).get("mac"),
                "kri": (asset.get("risk") or {}).get("score"),
                "tier": (asset.get("risk") or {}).get("tier"),
                "agent_present": (asset.get("control") or {}).get("agent_present"),
                "owner": (asset.get("owner") or {}).get("owner"),
            }
            for asset in run.exposure or []
        ],
        "plan": {
            "sha256": plan.get("plan_sha256"),
            "patch_available": (plan.get("patch_path") or {}).get("available"),
            "patch_refs": (plan.get("patch_path") or {}).get("patch_refs"),
            "compensating_controls": len(plan.get("compensating_controls") or []),
            "containment_candidates": sum(
                1 for item in plan.get("per_asset") or [] if item.get("containment_recommended")
            ),
        },
        "ticket": ticket or None,
        "approvals": run.approvals,
        "containment": run.containment,
        "verification": {
            "remediated": verification.get("remediated_count"),
            "still_affected": verification.get("still_affected_count"),
            "unknown": verification.get("unknown_count"),
            "infection_status": verification.get("infection_status"),
        }
        if verification
        else None,
        "kri_register": {
            "catalog": (run.options or {}).get("kri_catalog"),
            "counts": {
                status: sum(
                    1
                    for item in (run.kri_detections or [])
                    if item.get("status") == status
                )
                for status in ("detected", "not_detected", "unknown", "not_applicable")
            },
            "detected": [
                {
                    "kri_id": item.get("kri_id"),
                    "name": item.get("name"),
                    "asset_uuid": item.get("asset_uuid"),
                    "hostname": item.get("hostname"),
                    "evidence": item.get("evidence"),
                }
                for item in (run.kri_detections or [])
                if item.get("status") == "detected"
            ],
        },
        "alerts": len(run.alerts or []),
        "unknowns": len(
            [
                unknown
                for stage in (run.stages or {}).values()
                for unknown in stage.get("unknowns") or []
            ]
        ),
        "next_actions": run.next_actions,
        "artifacts": run.artifacts,
    }


def _print_run(run: Any, *, detail: bool = False) -> None:
    vulnerability = run.vulnerability or {}
    plan = run.plan or {}
    print(f"Run:    {run.run_id}")
    print(f"Status: {_status(run.status)}")
    print(f"Target: {run.target.get('value')}")
    print(f"Source: {(run.source or {}).get('product')} ({(run.source or {}).get('name')})")
    if vulnerability:
        print(
            f"\n{vulnerability.get('id')} — {vulnerability.get('title')}\n"
            f"CVSS {_fmt(vulnerability.get('severity_cvss'))} · "
            f"exploited in wild: {_fmt(vulnerability.get('exploited_in_wild'))} · "
            f"patch: {_fmt(vulnerability.get('patch_available'))} · "
            f"confidence: {vulnerability.get('confidence')}"
        )
    if run.exposure:
        print(f"\nAffected assets: {len(run.exposure)}")
        plan_by_uuid = {
            item.get("asset_uuid"): item for item in plan.get("per_asset") or []
        }
        print(_table(
            ["Asset", "Address", "MAC", "Agent", "KRI", "Tier", "Path", "Contain"],
            [
                [
                    (asset.get("asset") or {}).get("hostname"),
                    (asset.get("asset") or {}).get("ipv4"),
                    (asset.get("asset") or {}).get("mac"),
                    (asset.get("control") or {}).get("agent_present"),
                    (asset.get("risk") or {}).get("score"),
                    (asset.get("risk") or {}).get("tier"),
                    (plan_by_uuid.get((asset.get("asset") or {}).get("uuid")) or {}).get("path"),
                    (plan_by_uuid.get((asset.get("asset") or {}).get("uuid")) or {}).get("containment_recommended"),
                ]
                for asset in run.exposure
            ],
            width=28,
        ))
    if run.kri_detections:
        _print_kri_register(run)
    if plan:
        patch = plan.get("patch_path") or {}
        print(
            f"\nPlan: patch {_fmt(patch.get('available'))} · "
            f"{len(plan.get('compensating_controls') or [])} control(s) · "
            f"sha256 {str(plan.get('plan_sha256'))[:16]}…"
        )
    if run.ticket:
        print(f"Ticket: {run.ticket.get('ticket_id')} — {run.ticket.get('status')}")
    if detail and run.approvals:
        print("\nApprovals:")
        print(_table(
            ["Gate", "Decision", "Approver", "At"],
            [
                [
                    item.get("gate"),
                    item.get("decision"),
                    item.get("approver"),
                    item.get("recorded_at"),
                ]
                for item in run.approvals
            ],
            width=40,
        ))
    if detail and run.containment:
        print("\nContainment:")
        print(_table(
            ["Event", "Asset", "MAC", "Action", "Status"],
            [
                [
                    item.get("event_id"),
                    item.get("hostname"),
                    item.get("mac"),
                    item.get("action"),
                    item.get("status"),
                ]
                for item in run.containment
            ],
            width=34,
        ))
    if detail and run.verification:
        verification = run.verification
        print(
            f"\nVerification: {verification.get('remediated_count')} remediated · "
            f"{verification.get('still_affected_count')} still affected · "
            f"{verification.get('unknown_count')} unknown · "
            f"infection {verification.get('infection_status')}"
        )
    if run.next_actions:
        print("\nNext:")
        for action in run.next_actions:
            print(f"  - {action}")


# -- parser -------------------------------------------------------------


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default="default", choices=["default", "alt"])
    parser.add_argument("--source", default="auto", choices=["auto", "vm", "sc"])
    parser.add_argument("--runs-dir", default=None)
    parser.add_argument("--env-file", default=None)
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secops",
        description=(
            "SecOps Autopilot — carry a vulnerability from Tenable finding to a "
            "verified, evidenced fix. Read-only until an approval gate is passed."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check Tenable connectivity and scope")
    _common(doctor)
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    inventory = sub.add_parser("inventory", help="Show tenant asset/vulnerability summary")
    _common(inventory)
    inventory.add_argument("--date-range", type=int, default=90)
    inventory.add_argument("--limit", type=int, default=5000)
    inventory.add_argument("--json", action="store_true")
    inventory.set_defaults(func=cmd_inventory)

    run = sub.add_parser("run", help="Run the read-only pipeline for a CVE")
    _common(run)
    run.add_argument("--cve", required=True)
    run.add_argument("--date-range", type=int, default=None)
    run.add_argument("--max-assets", type=int, default=200)
    run.add_argument("--owners", default=None, help="CSV mapping assets to owners")
    run.add_argument("--controls", default=None, help="CSV with EDR/AV/control posture")
    run.add_argument(
        "--kri-catalog",
        default=None,
        help="Path to a KRI catalog JSON (default: packaged kri_catalog.json)",
    )
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=cmd_run)

    status = sub.add_parser("status", help="Show a recorded run")
    _common(status)
    status.add_argument("--run", required=True)
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    approve = sub.add_parser("approve", help="Pass an approval gate (state-changing)")
    _common(approve)
    approve.add_argument("--run", required=True)
    approve.add_argument("--gate", required=True, choices=GATES)
    approve.add_argument("--approver", required=True)
    approve.add_argument("--note", default="")
    approve.add_argument("--reject", action="store_true", help="Reject (remediation gate only)")
    approve.add_argument("--json", action="store_true")
    approve.set_defaults(func=cmd_approve)

    verify = sub.add_parser("verify", help="Re-query Tenable and compare to the exposure set")
    _common(verify)
    verify.add_argument("--run", required=True)
    verify.add_argument("--fail-on-open", action="store_true")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_verify)

    report = sub.add_parser("report", help="Finalize and locate report artifacts")
    _common(report)
    report.add_argument("--run", required=True)
    report.add_argument("--format", choices=["markdown", "html", "json"], default="html")
    report.add_argument("--verify", action="store_true")
    report.set_defaults(func=cmd_report)

    evidence = sub.add_parser("evidence", help="Regenerate and verify the evidence manifest")
    _common(evidence)
    evidence.add_argument("--run", required=True)
    evidence.add_argument("--verify-only", action="store_true")
    evidence.set_defaults(func=cmd_evidence)

    runs = sub.add_parser("runs", help="List recorded runs")
    _common(runs)
    runs.add_argument("--json", action="store_true")
    runs.set_defaults(func=cmd_runs)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        return int(args.func(args) or 0)
    except SecOpsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
