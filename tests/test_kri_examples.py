from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from secops_autopilot.connectors.edr import SimulatedEDR
from secops_autopilot.controlcheck import build_control_posture
from secops_autopilot.controls import ControlInventory
from secops_autopilot.kri import DETECTED, evaluate_kri_register, load_catalog
from secops_autopilot.models import AssetRef, VulnerabilityRecord

from tests.helpers import make_finding

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class KRIExampleMappingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.state.mkdir(parents=True)
        shutil.copy(
            EXAMPLES / "edr_status.example.json",
            self.state / "edr_status.json",
        )
        self.inventory = ControlInventory(EXAMPLES / "controls.example.csv")
        self.edr = SimulatedEDR(self.state)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _context(self, uuid: str, hostname: str, findings=None):
        asset = AssetRef(uuid=uuid, hostname=hostname, ipv4="10.0.0.20")
        detail = {
            "asset_uuid": uuid,
            "hostname": hostname,
            "has_agent": False,
            "sources": ["NESSUS_SCAN"],
            "last_scan": "2026-11-02T00:00:00Z",
        }
        control_entry = self.inventory.lookup(asset)
        edr_status = self.edr.status(uuid, hostname)
        control = build_control_posture(
            asset,
            detail,
            agent_inventory=None,
            agent_inventory_reason="test",
            control_entry=control_entry,
            edr_status=edr_status,
        )
        return {
            "asset": asset,
            "control": control,
            "findings": findings or [],
            "edr_status": edr_status,
            "control_entry": control_entry,
        }

    def test_example_assets_produce_the_expected_kris(self):
        contexts = [
            self._context("dc01", "DC01"),
            self._context("ws-fin-042", "WS-FIN-042"),
            self._context("ws-mkt-011", "WS-MKT-011"),
            self._context(
                "win-01",
                "WIN-01",
                [make_finding(asset_uuid="win-01", hostname="WIN-01")],
            ),
            self._context(
                "win-02",
                "WIN-02",
                [make_finding(asset_uuid="win-02", hostname="WIN-02")],
            ),
        ]
        vulnerability = VulnerabilityRecord(
            id="CVE-2017-0144",
            title="MS17-010",
            title_source="test",
        )
        results = evaluate_kri_register(contexts, vulnerability, load_catalog())
        matrix = {
            (item.hostname, item.kri_id): item.status for item in results
        }

        self.assertEqual(matrix[("DC01", "KRI-01")], DETECTED)
        self.assertEqual(matrix[("DC01", "KRI-06")], DETECTED)

        self.assertEqual(matrix[("WS-FIN-042", "KRI-02")], DETECTED)
        self.assertEqual(matrix[("WS-FIN-042", "KRI-03")], DETECTED)
        self.assertEqual(matrix[("WS-FIN-042", "KRI-04")], DETECTED)
        self.assertEqual(matrix[("WS-FIN-042", "KRI-06")], DETECTED)

        self.assertEqual(matrix[("WS-MKT-011", "KRI-07")], DETECTED)
        self.assertEqual(matrix[("WIN-01", "KRI-05")], DETECTED)
        self.assertEqual(matrix[("WIN-02", "KRI-05")], DETECTED)

        # A control that exists and is healthy is not KRI-01.
        self.assertEqual(matrix[("WS-MKT-011", "KRI-01")], "not_detected")
        # Unknown control data must not be reported as clear.
        self.assertEqual(matrix[("DC01", "KRI-03")], "not_applicable")


if __name__ == "__main__":
    unittest.main()
