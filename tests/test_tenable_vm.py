from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from secops_autopilot.config import TenableVMSettings
from secops_autopilot.connectors.http import TenableHTTP
from secops_autopilot.connectors.tenable_vm import TenableVMClient, finding_from_export

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeVMHTTP:
    def __init__(self) -> None:
        self.get_calls: list[tuple[str, dict[str, Any] | None]] = []
        self.post_calls: list[tuple[str, dict[str, Any]]] = []

    def get_json(self, path: str, params: dict[str, Any] | None = None, **_: Any) -> Any:
        self.get_calls.append((path, params))
        if path == "/workbenches/vulnerabilities":
            return fixture("workbench_cve.json")
        if path == "/assets/asset-1":
            return fixture("asset_detail.json")
        if path.endswith("/status"):
            return {"status": "FINISHED", "chunks_available": [1], "total_chunks": 1}
        if path.endswith("/chunks/1"):
            return [fixture("export_record.json")]
        raise AssertionError(f"unexpected GET {path}")

    def post_json(self, path: str, body: dict[str, Any], **_: Any) -> Any:
        self.post_calls.append((path, body))
        if path == "/vulns/export":
            return {"export_uuid": "export-1"}
        raise AssertionError(f"unexpected POST {path}")


class TenableVMMappingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = TenableVMSettings(
            profile="test",
            base_url="https://tenable.example.invalid",
            access_key="ACCESS-123456",
            secret_key="SECRET-123456",
            user_agent="SecOps-Autopilot/test (test@example.invalid)",
        )
        self.client = TenableVMClient(self.settings, sleep=lambda _: None)
        self.fake = FakeVMHTTP()
        self.client.http = self.fake  # type: ignore[assignment]

    def test_http_transport_sets_required_headers(self):
        http = TenableHTTP(
            base_url="https://tenable.example.invalid",
            access_key="ACCESS-123456",
            secret_key="SECRET-123456",
            user_agent="SecOps-Autopilot/test (test@example.invalid)",
        )
        self.assertEqual(
            http.session.headers["User-Agent"],
            "SecOps-Autopilot/test (test@example.invalid)",
        )
        self.assertEqual(
            http.session.headers["X-ApiKeys"],
            "accessKey=ACCESS-123456; secretKey=SECRET-123456;",
        )

    def test_export_record_normalisation(self):
        finding = finding_from_export(fixture("export_record.json"))
        self.assertEqual(finding.plugin_id, 900001)
        self.assertEqual(finding.cve, ["CVE-2024-0001"])
        self.assertEqual(finding.vpr, 9.5)
        self.assertEqual(finding.cvss3_base, 9.8)
        self.assertTrue(finding.has_patch)
        self.assertTrue(finding.exploit_framework_metasploit)
        self.assertEqual(finding.asset.mac, "00:11:22:33:44:55")
        self.assertEqual(finding.port, 445)
        self.assertEqual(finding.service, "cifs")

    def test_cve_query_uses_tenable_filter_name(self):
        hits = self.client.cve_plugin_hits("CVE-2024-0001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].plugin_id, 900001)
        path, params = self.fake.get_calls[0]
        self.assertEqual(path, "/workbenches/vulnerabilities")
        self.assertEqual(params["filter.0.filter"], "plugin.attributes.cve.raw")
        self.assertEqual(params["filter.0.value"], "CVE-2024-0001")

    def test_export_polling_and_finding_normalisation(self):
        findings = self.client.findings_for_plugins([900001])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].asset.hostname, "srv-01")
        self.assertEqual(self.fake.post_calls[0][0], "/vulns/export")
        self.assertEqual(
            self.fake.post_calls[0][1]["filters"]["plugin_id"], [900001]
        )
        self.assertEqual(self.client.last_exports[0]["export_uuid"], "export-1")

    def test_asset_detail_normalisation(self):
        detail = self.client.asset_detail("asset-1")
        self.assertEqual(detail["hostname"], "srv-01")
        self.assertTrue(detail["has_agent"])
        self.assertEqual(detail["mac"], "00:11:22:33:44:55")
        self.assertEqual(detail["acr_score"], 8.0)
        self.assertEqual(detail["aes_score"], 850.0)
        self.assertEqual(detail["last_scan"], "2026-11-01T09:00:00Z")


if __name__ == "__main__":
    unittest.main()
