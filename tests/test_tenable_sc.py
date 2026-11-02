from __future__ import annotations

import unittest
from typing import Any

from secops_autopilot.config import TenableSCSettings
from secops_autopilot.connectors.tenable_sc import TenableSCClient

SC_ROW = {
    "ip": "10.0.0.10",
    "dnsName": "srv-01.example.invalid",
    "netbiosName": "srv-01",
    "macAddress": "00:11:22:33:44:55",
    "os": "Microsoft Windows Server 2016",
    "assetID": "sc-asset-1",
    "pluginID": "900001",
    "pluginName": "MS17-010 Example SMB RCE (CVE-2024-0001)",
    "pluginFamily": "Windows",
    "severity": {"id": "4", "name": "Critical"},
    "cve": "CVE-2024-0001",
    "cvssV3BaseScore": "9.8",
    "cvssV3Vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "vprScore": "9.5",
    "exploitAvailable": "true",
    "exploitedByMalware": "true",
    "patchAvailable": "true",
    "solution": "Apply KB5034444.",
    "synopsis": "An example SMB remote code execution issue.",
    "description": "Synthetic Security Center row.",
    "port": "445",
    "protocol": "TCP",
    "pluginText": "The remote host is missing rollup KBs: - 5034444",
    "firstSeen": "2026-10-01T00:00:00Z",
    "lastSeen": "2026-11-01T10:00:00Z",
}


class FakeSCHTTP:
    def __init__(self) -> None:
        self.post_calls: list[tuple[str, dict[str, Any]]] = []

    def post_json(self, path: str, body: dict[str, Any], **_: Any) -> Any:
        self.post_calls.append((path, body))
        return {"response": {"results": [SC_ROW], "totalRecords": 1}}

    def get_json(self, path: str, **_: Any) -> Any:
        if path == "/rest/currentUser":
            return {"response": {"username": "sc-user"}}
        raise AssertionError(f"unexpected GET {path}")


class SecurityCenterAdapterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = TenableSCSettings(
            profile="sc",
            base_url="https://sc.example.invalid",
            access_key="ACCESS-123456",
            secret_key="SECRET-123456",
            user_agent="SecOps-Autopilot/test (test@example.invalid)",
        )
        self.client = TenableSCClient(self.settings)
        self.fake = FakeSCHTTP()
        self.client.http = self.fake  # type: ignore[assignment]

    def test_health(self):
        health = self.client.health()
        self.assertTrue(health["ok"])
        self.assertEqual(health["account"], "sc-user")
        self.assertIn("not live-tested", health["adapter_validation"])

    def test_cve_query_and_payload_shape(self):
        hits = self.client.cve_plugin_hits("CVE-2024-0001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].plugin_id, 900001)
        self.assertEqual(hits[0].asset_count, 1)
        path, body = self.fake.post_calls[0]
        self.assertEqual(path, "/rest/analysis")
        self.assertEqual(body["type"], "vuln")
        self.assertEqual(body["query"]["tool"], "vulndetails")
        self.assertEqual(body["query"]["filters"][0]["filterName"], "cveID")
        self.assertEqual(body["query"]["filters"][0]["value"], "CVE-2024-0001")

    def test_finding_normalisation(self):
        findings = self.client.findings_for_plugins([900001])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.asset.uuid, "sc-asset-1")
        self.assertEqual(finding.asset.mac, "00:11:22:33:44:55")
        self.assertEqual(finding.severity, 4)
        self.assertEqual(finding.cve, ["CVE-2024-0001"])
        self.assertEqual(finding.vpr, 9.5)
        self.assertTrue(finding.has_patch)
        self.assertTrue(finding.exploited_by_malware)


if __name__ == "__main__":
    unittest.main()
