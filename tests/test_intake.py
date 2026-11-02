from __future__ import annotations

import unittest

from secops_autopilot.errors import IntakeError
from secops_autopilot.intake import build_vulnerability, normalize_cve
from secops_autopilot.models import PluginHit

from tests.helpers import CVE, PLUGIN_ID, PLUGIN_NAME, make_finding


class IntakeTest(unittest.TestCase):
    def test_normalize_cve(self):
        self.assertEqual(normalize_cve("cve-2024-0001"), CVE)
        with self.assertRaises(IntakeError):
            normalize_cve("not-a-cve")
        with self.assertRaises(IntakeError):
            normalize_cve("CVE-24-1")

    def test_builds_record_from_tenable_data(self):
        findings = [
            make_finding(asset_uuid="asset-1"),
            make_finding(asset_uuid="asset-2", hostname="app-01", mac=None),
        ]
        hits = [
            PluginHit(
                plugin_id=PLUGIN_ID,
                plugin_name=PLUGIN_NAME,
                family="Windows",
                severity=4,
                asset_count=2,
                cvss3_base=9.8,
                vpr=9.5,
            )
        ]
        record = build_vulnerability(CVE, hits, findings, [], date_range=90)
        self.assertEqual(record.id, CVE)
        self.assertEqual(record.title, PLUGIN_NAME)
        self.assertEqual(record.severity_cvss, 9.8)
        self.assertEqual(record.severity_source, "tenable:cvss3_base_score")
        self.assertTrue(record.exploited_in_wild)
        self.assertTrue(record.patch_available)
        self.assertIn("KB5034444", record.patch_refs)
        self.assertIn("MS17-010", record.aliases)
        self.assertEqual(record.affected_asset_count, 2)
        self.assertEqual(record.affected_finding_count, 2)
        self.assertEqual(record.confidence, "high")

    def test_findings_for_other_cves_are_excluded(self):
        findings = [
            make_finding(asset_uuid="asset-1"),
            make_finding(asset_uuid="asset-2", cve="CVE-2024-9999"),
        ]
        hits = [
            PluginHit(
                plugin_id=PLUGIN_ID,
                plugin_name=PLUGIN_NAME,
                family="Windows",
                severity=4,
                asset_count=2,
            )
        ]
        record = build_vulnerability(CVE, hits, findings, [], date_range=90)
        self.assertEqual(record.affected_asset_count, 1)
        self.assertTrue(any("excluded" in note for note in record.notes))

    def test_no_tenable_match_is_low_confidence(self):
        record = build_vulnerability(CVE, [], [], [], date_range=90)
        self.assertEqual(record.confidence, "low")
        self.assertEqual(record.affected_asset_count, 0)
        self.assertIsNone(record.patch_available)


if __name__ == "__main__":
    unittest.main()
