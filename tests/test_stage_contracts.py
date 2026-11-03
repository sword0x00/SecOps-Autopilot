from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secops_autopilot.controls import ControlInventory
from secops_autopilot.errors import StateError
from secops_autopilot.models import (
    GATE_PATCH,
    GATE_REMEDIATION,
    GATE_TICKET,
    AssetRef,
)
from secops_autopilot.stages.contracts import CONTRACTS, contract_for

from tests.helpers import CVE, FakeSource, make_pipeline, make_settings, sample_findings


class StageContractTest(unittest.TestCase):
    def test_contracts_are_ordered_and_unique(self):
        ids = [contract.id for contract in CONTRACTS]
        self.assertEqual(len(ids), len(set(ids)))
        orders = [contract.order for contract in CONTRACTS]
        self.assertEqual(orders, sorted(orders))
        self.assertEqual(
            {contract.methodology_stage for contract in CONTRACTS},
            set(range(1, 11)),
        )

    def test_patch_contract_is_gated_and_state_changing(self):
        contract = contract_for("patch_execution")
        self.assertEqual(contract.approval_gate, GATE_PATCH)
        self.assertFalse(contract.read_only)
        self.assertIn("plan", contract.requires)
        self.assertIn("simulated", contract.description.lower())
        self.assertTrue(contract_for("verification").read_only)
        self.assertIn(
            "evidence_files", contract_for("evidence").side_effects
        )

    def test_read_only_stages_are_all_before_the_first_gate(self):
        first_gate = next(
            contract.order for contract in CONTRACTS if contract.approval_gate
        )
        for contract in CONTRACTS:
            if contract.kind == "read" and contract.id not in {"verification"}:
                self.assertLess(contract.order, first_gate)

    def test_control_inventory_preserves_false_nac_posture(self):
        inventory = ControlInventory(
            rows=[{"match": "asset-1", "nac_compliant": False, "edr_present": True}]
        )
        entry = inventory.lookup(AssetRef(uuid="asset-1"))
        self.assertIs(entry["nac_compliant"], False)
        self.assertIs(entry["edr_present"], True)


class StageRecordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = make_settings(self.root)
        self.pipeline = make_pipeline(self.settings, FakeSource(sample_findings()))

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_stage_record_carries_its_contract(self):
        run = self.pipeline.run(CVE)
        for stage, record in run.stages.items():
            contract = record.get("contract") or {}
            self.assertEqual(contract.get("id"), stage, stage)
            self.assertIn("order", contract)
            self.assertIn("read_only", contract)
            self.assertIsNotNone(record.get("duration_ms"))
        self.assertTrue(run.stages["intake"]["contract"]["read_only"])
        self.assertTrue(
            run.stages["remediation_planning"]["contract"]["read_only"]
        )
        self.assertIn("evidence", run.stages)
        self.assertEqual(run.stages["evidence"]["contract"]["kind"], "evidence")
        self.assertIn("remediation_planning", run.stages)

    def test_patch_gate_requires_remediation_approval(self):
        run = self.pipeline.run(CVE)
        run = self.pipeline.approve(run.run_id, GATE_TICKET, "Ticket Approver")
        with self.assertRaises(StateError):
            self.pipeline.approve(run.run_id, GATE_PATCH, "Patch Approver")

    def test_patch_gate_records_no_invented_target_version(self):
        run = self.pipeline.run(CVE)
        run = self.pipeline.approve(run.run_id, GATE_TICKET, "Ticket Approver")
        run = self.pipeline.approve(
            run.run_id, GATE_REMEDIATION, "Infosec Approver"
        )
        run = self.pipeline.approve(run.run_id, GATE_PATCH, "Patch Approver")
        patch = run.patch_execution or {}
        self.assertEqual(patch.get("status"), "not_submitted")
        self.assertEqual(patch.get("submitted"), 0)
        self.assertTrue(patch.get("simulated"))
        self.assertTrue(
            any(approval["gate"] == GATE_PATCH for approval in run.approvals)
        )
        # A retry must not create a second approval or job record.
        approvals = len(run.approvals)
        run = self.pipeline.approve(run.run_id, GATE_PATCH, "Patch Approver")
        self.assertEqual(len(run.approvals), approvals)
        self.assertEqual(len(run.patch_execution.get("jobs") or []), 0)


if __name__ == "__main__":
    unittest.main()
