from __future__ import annotations

import unittest
from types import SimpleNamespace

from secops_autopilot.advisory import (
    advisory_summary,
    compare_versions,
    merge_advisory,
    parse_cpe,
    runtime_matches,
    validate_advisory,
    version_in_range,
)
from secops_autopilot.errors import ConfigError
from secops_autopilot.kri import DETECTED, NOT_APPLICABLE, NOT_DETECTED, UNKNOWN, evaluate_kri_register, load_catalog
from secops_autopilot.models import AssetRef, ControlPosture, Finding, VulnerabilityRecord
from secops_autopilot.remediation import _runtime_target

PHP_ADVISORY = {
    "id": "CVE-2026-109618",
    "cve": "CVE-2026-109618",
    "title": "PHP OOM RCE",
    "source": "Test advisory",
    "url": "https://example.invalid/advisory",
    "affected": [
        {
            "product": "php",
            "vendor": "php",
            "cpe_product": "php",
            "range": ">=8.4.0 <8.4.27",
            "fixed": "8.4.27",
            "branch": "8.4",
            "support": "supported",
        },
        {
            "product": "php",
            "vendor": "php",
            "cpe_product": "php",
            "range": ">=8.1.0 <8.2.0",
            "fixed": None,
            "branch": "8.1",
            "support": "unsupported",
        },
    ],
    "mitigations": [
        {"action": "Upgrade PHP.", "source": "Test advisory", "verified": False}
    ],
    "provenance": {
        "status": "verified",
        "source_url": "https://example.invalid/advisory",
        "retrieved_at": "2026-11-03T00:00:00Z",
    },
}


def php_finding(version: str = "8.4.26") -> Finding:
    return Finding(
        plugin_id=990061,
        plugin_name="PHP Remote Code Execution (CVE-2026-109618)",
        family="Web Servers",
        severity=4,
        asset=AssetRef(
            uuid="asset-php-01",
            hostname="php-web-01",
            ipv4="10.20.1.11",
            mac="00:11:22:33:44:55",
        ),
        source="test",
        cvss3_base=9.2,
        cve=["CVE-2026-109618"],
        cpe=[f"cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"],
        has_patch=True,
        solution="Upgrade PHP.",
        port=443,
        service="https",
        state="OPEN",
    )


def evaluate(advisory: dict | None, finding: Finding | None = None, *, aes: float = 850.0):
    record = VulnerabilityRecord(
        id="CVE-2026-109618",
        title="PHP OOM RCE",
        title_source="test",
    )
    if advisory:
        record = merge_advisory(record, advisory)
    context = {
        "asset": AssetRef(uuid="asset-php-01", hostname="php-web-01"),
        "control": ControlPosture(
            asset_uuid="asset-php-01",
            agent_present=True,
            edr_present=True,
            av_present=True,
            edr_version="7.2.1",
            edr_baseline_version="7.2.1",
            av_version="12.4",
            av_baseline_version="12.4",
            av_signature_age_hours=6,
            edr_feed_age_hours=6,
            av_mode="prevent",
            edr_mode="prevent",
            app_control_mode="enforce",
            nac_compliant=True,
        ),
        "findings": [finding or php_finding()],
        "edr_status": {"infection_status": "none_reported", "behavioral_matches": []},
        "detail": {"aes_score": aes},
    }
    return {
        item.kri_id: item
        for item in evaluate_kri_register([context], record, load_catalog())
    }


class AdvisoryTest(unittest.TestCase):
    def test_cpe_and_version_range(self):
        parsed = parse_cpe("cpe:2.3:a:php:php:8.4.26:*:*:*:*:*:*:*")
        self.assertEqual(parsed["product"], "php")
        self.assertEqual(parsed["version"], "8.4.26")
        self.assertTrue(version_in_range("8.4.26", ">=8.4.0 <8.4.27"))
        self.assertFalse(version_in_range("8.4.27", ">=8.4.0 <8.4.27"))
        self.assertTrue(version_in_range("22.22.0", ">=22.0.0 <22.23.4"))
        self.assertEqual(compare_versions("8.4.27", "8.4.26"), 1)
        self.assertIsNone(version_in_range("unknown", ">=8.4.0"))

    def test_merge_sets_fixed_versions_and_provenance(self):
        advisory = validate_advisory(PHP_ADVISORY)
        record = merge_advisory(
            VulnerabilityRecord(
                id="CVE-2026-109618", title="PHP", title_source="test"
            ),
            advisory,
        )
        self.assertTrue(record.patch_available)
        self.assertEqual(record.fixed_versions[0]["fixed"], "8.4.27")
        self.assertEqual(record.provenance[0]["status"], "verified")
        self.assertIn("8.4.27", " ".join(record.patch_refs))
        self.assertEqual(record.mitigation_steps[0]["action"], "Upgrade PHP.")

    def test_merge_rejects_wrong_cve(self):
        advisory = validate_advisory(PHP_ADVISORY)
        with self.assertRaises(ConfigError):
            merge_advisory(
                VulnerabilityRecord(
                    id="CVE-2026-999999", title="Wrong", title_source="test"
                ),
                advisory,
            )

    def test_verified_provenance_requires_source(self):
        bad = dict(PHP_ADVISORY)
        bad["provenance"] = {"status": "verified"}
        with self.assertRaises(ConfigError):
            validate_advisory(bad)

    def test_runtime_match_and_fixed_version(self):
        advisory = validate_advisory(PHP_ADVISORY)
        matches = runtime_matches([php_finding()], advisory)
        self.assertTrue(matches)
        self.assertTrue(matches[0]["in_range"])
        self.assertEqual(matches[0]["fixed"], "8.4.27")

    def test_fixed_runtime_does_not_borrow_another_branch_target(self):
        record = merge_advisory(
            VulnerabilityRecord(
                id="CVE-2026-109618", title="PHP", title_source="test"
            ),
            validate_advisory(PHP_ADVISORY),
        )
        product, version, target, match = _runtime_target(
            SimpleNamespace(findings=[php_finding("8.4.27")]), record
        )
        self.assertEqual(product, "php")
        self.assertEqual(version, "8.4.27")
        self.assertIsNone(target)
        self.assertFalse(match["in_range"])

    def test_kri_08_detects_affected_runtime(self):
        results = evaluate(validate_advisory(PHP_ADVISORY))
        self.assertEqual(results["KRI-08"].status, DETECTED)
        evidence = " ".join(results["KRI-08"].evidence)
        self.assertIn("8.4.26", evidence)
        self.assertIn("8.4.27", evidence)

    def test_kri_08_clear_on_fixed_runtime(self):
        results = evaluate(
            validate_advisory(PHP_ADVISORY), php_finding("8.4.27")
        )
        self.assertEqual(results["KRI-08"].status, NOT_DETECTED)

    def test_kri_08_unknown_without_advisory(self):
        results = evaluate(None)
        self.assertEqual(results["KRI-08"].status, UNKNOWN)

    def test_kri_08_unsupported_branch_has_no_fixed_version(self):
        results = evaluate(
            validate_advisory(PHP_ADVISORY), php_finding("8.1.31")
        )
        self.assertEqual(results["KRI-08"].status, DETECTED)
        evidence = " ".join(results["KRI-08"].evidence)
        self.assertIn("no vendor fixed version", evidence)
        self.assertIn("unsupported", evidence)

    def test_kri_08_not_applicable_for_other_product(self):
        finding = php_finding()
        finding.cpe = ["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"]
        results = evaluate(validate_advisory(PHP_ADVISORY), finding)
        self.assertEqual(results["KRI-08"].status, NOT_APPLICABLE)

    def test_kri_05_generic_detects_target_cve(self):
        results = evaluate(validate_advisory(PHP_ADVISORY))
        self.assertEqual(results["KRI-05"].status, DETECTED)
        self.assertIn("990061", " ".join(results["KRI-05"].evidence))

    def test_kri_09_exposure_distinguishes_web_and_internal(self):
        results = evaluate(validate_advisory(PHP_ADVISORY))
        self.assertEqual(results["KRI-09"].status, DETECTED)
        internal = php_finding()
        internal.port = 5432
        internal.service = "postgresql"
        results = evaluate(validate_advisory(PHP_ADVISORY), internal, aes=300.0)
        self.assertEqual(results["KRI-09"].status, NOT_DETECTED)

    def test_advisory_summary(self):
        summary = advisory_summary(validate_advisory(PHP_ADVISORY))
        self.assertEqual(summary["id"], "CVE-2026-109618")
        self.assertEqual(summary["fixed_versions"], ["8.4.27"])


if __name__ == "__main__":
    unittest.main()
