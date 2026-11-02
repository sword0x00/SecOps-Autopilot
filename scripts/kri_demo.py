#!/usr/bin/env python3
"""Deterministic KRI-01 … KRI-07 demonstration.

Uses the example control inventory, the example EDR status fixture, and five
synthetic assets. No Tenable credentials, no control-plane calls, no state
changes. This is the fastest way to see the full register:

    python3 scripts/kri_demo.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secops_autopilot.connectors.edr import SimulatedEDR  # noqa: E402
from secops_autopilot.controlcheck import build_control_posture  # noqa: E402
from secops_autopilot.controls import ControlInventory  # noqa: E402
from secops_autopilot.kri import (  # noqa: E402
    DETECTED,
    evaluate_kri_register,
    load_catalog,
)
from secops_autopilot.models import (  # noqa: E402
    AssetRef,
    Finding,
    VulnerabilityRecord,
)

EXAMPLES = ROOT / "examples"
STATUS_LABELS = {
    "detected": "DETECTED",
    "not_detected": "clear",
    "unknown": "unknown",
    "not_applicable": "n/a",
}


def ms17_finding(uuid: str, hostname: str) -> Finding:
    return Finding(
        plugin_id=97833,
        plugin_name=(
            "MS17-010: Security Update for Microsoft Windows SMB Server "
            "(4013389) (ETERNALBLUE) (WannaCry)"
        ),
        family="Windows",
        severity=4,
        asset=AssetRef(
            uuid=uuid,
            hostname=hostname,
            ipv4="10.0.0.20",
            os=["Microsoft Windows Server 2016"],
        ),
        source="kri-demo",
        cvss3_base=8.8,
        vpr=9.9,
        cve=["CVE-2017-0144"],
        exploit_available=True,
        exploited_by_malware=True,
        has_patch=True,
        solution="Apply KB4013389.",
        synopsis="The remote SMB server is missing MS17-010.",
        port=445,
        protocol="TCP",
        service="cifs",
        output="The remote host is missing MS17-010.",
        state="OPEN",
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "state"
        state.mkdir()
        shutil.copy(EXAMPLES / "edr_status.example.json", state / "edr_status.json")
        inventory = ControlInventory(EXAMPLES / "controls.example.csv")
        edr = SimulatedEDR(state)

        assets = [
            ("dc01", "DC01", []),
            ("ws-fin-042", "WS-FIN-042", []),
            ("ws-mkt-011", "WS-MKT-011", []),
            ("win-01", "WIN-01", [ms17_finding("win-01", "WIN-01")]),
            ("win-02", "WIN-02", [ms17_finding("win-02", "WIN-02")]),
        ]
        contexts = []
        for uuid, hostname, findings in assets:
            asset = AssetRef(uuid=uuid, hostname=hostname, ipv4="10.0.0.20")
            detail = {
                "asset_uuid": uuid,
                "hostname": hostname,
                "has_agent": False,
                "sources": ["NESSUS_SCAN"],
            }
            control_entry = inventory.lookup(asset)
            edr_status = edr.status(uuid, hostname)
            contexts.append(
                {
                    "asset": asset,
                    "findings": findings,
                    "control": build_control_posture(
                        asset,
                        detail,
                        agent_inventory=None,
                        agent_inventory_reason="demo: no agent inventory",
                        control_entry=control_entry,
                        edr_status=edr_status,
                    ),
                    "edr_status": edr_status,
                    "control_entry": control_entry,
                }
            )

        vulnerability = VulnerabilityRecord(
            id="CVE-2017-0144",
            title="MS17-010 / EternalBlue",
            title_source="demo",
        )
        detections = evaluate_kri_register(
            contexts, vulnerability, load_catalog()
        )

        kri_ids = sorted({item.kri_id for item in detections})
        matrix: dict[str, dict[str, str]] = {}
        for item in detections:
            matrix.setdefault(item.hostname, {})[item.kri_id] = item.status

        print("KRI register demo — example inventories, synthetic findings")
        print("No Tenable tenant, no control-plane action.\n")
        print(f"{'Asset':<14}" + "".join(f"{kri:<10}" for kri in kri_ids))
        print("-" * (14 + 10 * len(kri_ids)))
        for hostname, row in matrix.items():
            cells = "".join(
                f"{STATUS_LABELS.get(row[kri], row[kri]):<10}" for kri in kri_ids
            )
            print(f"{hostname:<14}{cells}")

        detected = [item for item in detections if item.status == DETECTED]
        print(f"\nDetected: {len(detected)}")
        for item in detected:
            print(f"  {item.kri_id} {item.name} on {item.hostname}: {'; '.join(item.evidence)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
