from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secops_autopilot.errors import ApprovalError, StateError
from secops_autopilot.models import GATE_CONTAINMENT, GATE_REMEDIATION, GATE_RESTORE, GATE_TICKET

from tests.helpers import (
    CVE,
    TEST_ACCESS,
    TEST_SECRET,
    FakeSource,
    make_pipeline,
    make_settings,
    sample_findings,
)


class FlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = make_settings(self.root)
        self.source = FakeSource(sample_findings())
        self.pipeline = make_pipeline(self.settings, self.source)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _advance_to_verification(self):
        run = self.pipeline.run(CVE)
        run = self.pipeline.approve(run.run_id, GATE_TICKET, "Ticket Approver")
        run = self.pipeline.approve(run.run_id, GATE_REMEDIATION, "Infosec Approver")
        run = self.pipeline.approve(run.run_id, GATE_CONTAINMENT, "SecOps Lead")
        return run

    def test_read_only_run_stops_before_first_state_change(self):
        run = self.pipeline.run(CVE)
        self.assertEqual(run.status, "awaiting_ticket_approval")
        self.assertIsNone(run.ticket)
        self.assertEqual(run.containment, [])
        self.assertEqual(len(run.exposure), 2)
        self.assertEqual(run.plan["patch_path"]["available"], True)
        self.assertIn("KB5034444", run.plan["patch_path"]["patch_refs"])
        control_types = {
            control["type"] for control in run.plan["compensating_controls"]
        }
        self.assertTrue({"ips_rule", "firewall_rule", "configuration_change", "detection_rule"} <= control_types)
        self.assertTrue(all(not control["verified"] for control in run.plan["compensating_controls"]))
        self.assertTrue(run.plan["workarounds"])
        self.assertEqual(len(run.kri_detections), 16)
        self.assertIn("kri_register", run.stages)
        detected = {
            (item["kri_id"], item["asset_uuid"])
            for item in run.kri_detections
            if item["status"] == "detected"
        }
        self.assertTrue(any(kri_id == "KRI-05" for kri_id, _ in detected))
        self.assertTrue(
            all("KRI-05" in item["kri_ids"] for item in run.plan["per_asset"])
        )
        directory = self.pipeline.store.run_dir(run.run_id)
        self.assertTrue((directory / "report.md").is_file())
        self.assertTrue((directory / "report.html").is_file())
        self.assertTrue((directory / "executive-summary.md").is_file())
        self.assertTrue((directory / "manifest.json").is_file())
        executive = (directory / "executive-summary.md").read_text(encoding="utf-8")
        self.assertIn(CVE, executive)
        self.assertIn("Numbers at a glance", executive)
        self.assertIn("What this report does not prove", executive)
        report = (directory / "report.md").read_text(encoding="utf-8")
        self.assertIn(CVE, report)
        self.assertIn("Read this first", report)
        self.assertIn("KRI register", report)
        self.assertIn("KRI-05", report)

    def test_approval_chain_isolates_only_assets_with_a_mac(self):
        run = self._advance_to_verification()
        self.assertEqual(run.status, "awaiting_verification")
        isolated = [event for event in run.containment if event["status"] == "isolated"]
        blocked = [event for event in run.containment if event["status"] == "blocked"]
        self.assertEqual(len(isolated), 1)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(isolated[0]["mac"], "00:11:22:33:44:55")
        self.assertIn("No MAC", blocked[0]["reason"])
        self.assertEqual(run.ticket["status"], "IN_PROGRESS")
        self.assertEqual(len(run.approvals), 3)
        for approval in run.approvals:
            self.assertEqual(approval["plan_sha256"], run.plan["plan_sha256"])

    def test_verification_does_not_claim_a_fix_when_findings_remain(self):
        run = self._advance_to_verification()
        run = self.pipeline.verify(run.run_id)
        self.assertEqual(run.status, "verification_open")
        verification = run.verification
        self.assertEqual(verification["still_affected_count"], 2)
        self.assertEqual(verification["remediated_count"], 0)
        self.assertEqual(verification["infection_status"], "unknown")
        with self.assertRaises(StateError):
            self.pipeline.approve(run.run_id, GATE_RESTORE, "SecOps Lead")

    def test_verified_branch_restores_after_explicit_approval(self):
        self.source.after = []
        run = self._advance_to_verification()
        run = self.pipeline.verify(run.run_id)
        self.assertEqual(run.status, "verified_remediated")
        self.assertEqual(run.verification["remediated_count"], 2)
        run = self.pipeline.approve(run.run_id, GATE_RESTORE, "SecOps Lead")
        self.assertEqual(run.status, "restored")
        restores = [event for event in run.containment if event["action"] == "restore"]
        self.assertEqual(len(restores), 1)
        self.assertEqual(restores[0]["status"], "restored")

    def test_stale_scan_is_unknown_not_remediated(self):
        self.settings.verification_max_scan_age_hours = 1.0
        self.source.after = []
        run = self._advance_to_verification()
        run = self.pipeline.verify(run.run_id)
        self.assertEqual(run.status, "verification_open")
        self.assertEqual(run.verification["remediated_count"], 0)
        self.assertEqual(run.verification["unknown_count"], 2)
        self.assertTrue(
            any(
                event["kind"] == "verification_scan_stale"
                for event in run.events
            )
        )
        with self.assertRaises(StateError):
            self.pipeline.approve(run.run_id, GATE_RESTORE, "SecOps Lead")

    def test_edr_status_is_baseline_evidence_and_does_not_block_restore(self):
        self.source.after = []
        run = self._advance_to_verification()
        status_file = self.settings.state_dir / "edr_status.json"
        status_file.parent.mkdir(parents=True, exist_ok=True)
        status_file.write_text(
            json.dumps(
                {
                    "assets": {
                        "asset-1": {
                            "present": True,
                            "vendor": "ExampleEDR",
                            "version": "7.2",
                            "feed_age_hours": 6,
                            "infection_status": "infected",
                            "detail": "Synthetic EDR status for the test suite.",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        run = self.pipeline.verify(run.run_id)
        self.assertEqual(run.status, "verified_remediated")
        self.assertEqual(run.verification["infection_status"], "infected")
        self.assertFalse(
            any(event["kind"] == "edr_infection" for event in run.events)
        )
        run = self.pipeline.approve(run.run_id, GATE_RESTORE, "SecOps Lead")
        self.assertEqual(run.status, "restored")

    def test_new_asset_during_verification_keeps_the_run_open(self):
        from tests.helpers import make_finding

        self.source.after = [
            make_finding(
                asset_uuid="asset-3",
                hostname="new-01",
                ipv4="10.0.0.12",
                mac="00:11:22:33:44:66",
            )
        ]
        run = self._advance_to_verification()
        run = self.pipeline.verify(run.run_id)
        self.assertEqual(run.status, "verification_open")
        self.assertEqual(len(run.verification["new_affected_assets"]), 1)
        self.assertTrue(
            any("New affected assets" in action for action in run.next_actions)
        )

    def test_rejected_remediation_blocks_containment(self):
        run = self.pipeline.run(CVE)
        run = self.pipeline.approve(run.run_id, GATE_TICKET, "Ticket Approver")
        run = self.pipeline.approve(
            run.run_id,
            GATE_REMEDIATION,
            "Infosec Approver",
            "Not acceptable; revise the plan",
            reject=True,
        )
        self.assertEqual(run.status, "remediation_rejected")
        self.assertEqual(run.ticket["status"], "REJECTED")
        self.assertEqual(run.containment, [])
        with self.assertRaises(StateError):
            self.pipeline.approve(run.run_id, GATE_CONTAINMENT, "SecOps Lead")

    def test_no_findings_produces_no_exposure_and_no_plan(self):
        source = FakeSource([])
        pipeline = make_pipeline(self.settings, source)
        run = pipeline.run(CVE)
        self.assertEqual(run.status, "no_exposure_found")
        self.assertIsNone(run.plan)
        self.assertEqual(run.exposure, [])

    def test_plan_tampering_is_rejected(self):
        run = self.pipeline.run(CVE)
        run.plan["patch_path"]["available"] = False
        self.pipeline.store.save(run)
        with self.assertRaises(ApprovalError):
            self.pipeline.approve(run.run_id, GATE_TICKET, "Ticket Approver")

    def test_manifest_detects_modified_stage(self):
        run = self.pipeline.run(CVE)
        store = self.pipeline.store
        verified = store.verify_manifest(run.run_id)
        self.assertTrue(verified["ok"])
        stage = store.run_dir(run.run_id) / "stages" / "01-intake.json"
        stage.write_text(stage.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        verified = store.verify_manifest(run.run_id)
        self.assertFalse(verified["ok"])
        self.assertTrue(any(item["status"] == "mismatch" for item in verified["checked"]))

    def test_credentials_are_never_written_to_artifacts(self):
        run = self.pipeline.run(CVE)
        for path in self.pipeline.store.run_dir(run.run_id).rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn(TEST_ACCESS, text, str(path))
            self.assertNotIn(TEST_SECRET, text, str(path))
            self.assertNotIn("X-ApiKeys", text, str(path))

    def test_owner_and_control_inventory_are_applied_without_guessing(self):
        owners = self.root / "owners.csv"
        owners.write_text(
            "match,owner,team,email\n"
            "10.0.0.10,Alice Example,Server Engineering,alice@example.invalid\n",
            encoding="utf-8",
        )
        controls = self.root / "controls.csv"
        controls.write_text(
            "match,edr_present,edr_vendor,av_present,av_signature_age_hours,"
            "app_control_mode,patch_agent_present,source,updated_at\n"
            "10.0.0.10,true,ExampleEDR,true,12,enforce,true,test-inventory,2026-11-02T00:00:00Z\n",
            encoding="utf-8",
        )
        source = FakeSource(
            sample_findings(),
            agents=[
                {
                    "id": "agent-1",
                    "name": "srv-01",
                    "version": "10.0.0",
                    "status": "on",
                    "last_connect": "2026-11-02T09:00:00Z",
                }
            ],
        )
        pipeline = make_pipeline(self.settings, source, owners=owners, controls=controls)
        run = pipeline.run(CVE)
        by_host = {
            asset["asset"]["hostname"]: asset for asset in run.exposure
        }
        srv = by_host["srv-01"]
        self.assertEqual(srv["owner"]["owner"], "Alice Example")
        self.assertEqual(srv["owner"]["team"], "Server Engineering")
        self.assertEqual(srv["control"]["edr_present"], True)
        self.assertEqual(srv["control"]["av_signature_age_hours"], 12.0)
        self.assertEqual(srv["control"]["app_control_mode"], "enforce")
        self.assertEqual(srv["control"]["agent_version"], "10.0.0")
        app = by_host["app-01"]
        self.assertEqual(app["owner"]["owner"], "unknown")
        self.assertLess(
            srv["control"]["control_gap_score"],
            app["control"]["control_gap_score"],
        )


if __name__ == "__main__":
    unittest.main()
