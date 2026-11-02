from __future__ import annotations

import unittest

from secops_autopilot.kri import (
    DETECTED,
    NOT_APPLICABLE,
    NOT_DETECTED,
    UNKNOWN,
    detection_counts,
    evaluate_kri_register,
    load_catalog,
)
from secops_autopilot.models import AssetRef, ControlPosture, VulnerabilityRecord

from tests.helpers import make_finding


def vulnerability(cve: str = "CVE-2017-0144") -> VulnerabilityRecord:
    return VulnerabilityRecord(
        id=cve,
        title="Example vulnerability",
        title_source="test",
    )


def evaluate(
    control: ControlPosture,
    *,
    findings=None,
    edr_status=None,
    cve: str = "CVE-2017-0144",
):
    ctx = {
        "asset": AssetRef(uuid="asset-1", hostname="srv-01"),
        "control": control,
        "findings": findings or [],
        "edr_status": edr_status
        or {
            "infection_status": "unknown",
            "behavioral_matches": [],
            "present": None,
            "source": "test",
        },
        "control_entry": {},
    }
    results = evaluate_kri_register([ctx], vulnerability(cve), load_catalog())
    return {item.kri_id: item for item in results}


class KRIRegisterTest(unittest.TestCase):
    def test_catalog_loads_all_seven(self):
        catalog = load_catalog()
        self.assertEqual(
            [item["id"] for item in catalog["kris"]],
            [f"KRI-0{index}" for index in range(1, 8)],
        )

    def test_kri_01_missing_security_agent(self):
        detected = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                agent_present=False,
                edr_present=False,
                av_present=False,
            )
        )["KRI-01"]
        self.assertEqual(detected.status, DETECTED)
        clear = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                agent_present=False,
                edr_present=True,
                av_present=False,
            )
        )["KRI-01"]
        self.assertEqual(clear.status, NOT_DETECTED)
        unknown = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                agent_present=False,
                edr_present=None,
                av_present=False,
            )
        )["KRI-01"]
        self.assertEqual(unknown.status, UNKNOWN)

    def test_kri_02_stale_control_version(self):
        detected = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                av_version="6.5.0",
                av_baseline_version="7.0.0",
            )
        )["KRI-02"]
        self.assertEqual(detected.status, DETECTED)
        self.assertTrue(any("6.5.0" in item for item in detected.evidence))
        clear = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                av_version="7.0.0",
                av_baseline_version="7.0",
                edr_present=False,
            )
        )["KRI-02"]
        self.assertEqual(clear.status, NOT_DETECTED)
        unknown = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                edr_present=False,
            )
        )["KRI-02"]
        self.assertEqual(unknown.status, UNKNOWN)

    def test_kri_03_stale_threat_feed(self):
        detected = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                av_signature_age_hours=264,
            )
        )["KRI-03"]
        self.assertEqual(detected.status, DETECTED)
        self.assertIn("24", " ".join(detected.evidence))
        clear = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                av_signature_age_hours=12,
                edr_present=False,
            )
        )["KRI-03"]
        self.assertEqual(clear.status, NOT_DETECTED)
        unknown = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                edr_present=False,
            )
        )["KRI-03"]
        self.assertEqual(unknown.status, UNKNOWN)

    def test_kri_04_detect_only_mode(self):
        detected = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                av_mode="monitor",
            )
        )["KRI-04"]
        self.assertEqual(detected.status, DETECTED)
        clear = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                av_mode="prevent",
                edr_present=False,
            )
        )["KRI-04"]
        self.assertEqual(clear.status, NOT_DETECTED)
        unknown = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                av_present=True,
                edr_present=False,
            )
        )["KRI-04"]
        self.assertEqual(unknown.status, UNKNOWN)

    def test_kri_05_unpatched_exploitable_and_scope(self):
        detected = evaluate(
            ControlPosture(asset_uuid="asset-1"),
            findings=[make_finding()],
        )["KRI-05"]
        self.assertEqual(detected.status, DETECTED)
        self.assertTrue(any("MS17-010" in item for item in detected.evidence))
        not_applicable = evaluate(
            ControlPosture(asset_uuid="asset-1"),
            findings=[
                make_finding(
                    plugin_name="Unrelated example finding",
                    cve="CVE-2024-9998",
                )
            ],
            cve="CVE-2024-9999",
        )["KRI-05"]
        self.assertEqual(not_applicable.status, NOT_APPLICABLE)

    def test_kri_06_nac_noncompliant(self):
        detected = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                nac_compliant=False,
                nac_policy="SECOPS-QUARANTINE",
            )
        )["KRI-06"]
        self.assertEqual(detected.status, DETECTED)
        clear = evaluate(
            ControlPosture(asset_uuid="asset-1", nac_compliant=True)
        )["KRI-06"]
        self.assertEqual(clear.status, NOT_DETECTED)
        unknown = evaluate(ControlPosture(asset_uuid="asset-1"))["KRI-06"]
        self.assertEqual(unknown.status, UNKNOWN)

    def test_kri_07_active_compromise(self):
        infected = evaluate(
            ControlPosture(asset_uuid="asset-1"),
            edr_status={"infection_status": "infected", "behavioral_matches": []},
        )["KRI-07"]
        self.assertEqual(infected.status, DETECTED)
        behavior = evaluate(
            ControlPosture(asset_uuid="asset-1"),
            edr_status={
                "infection_status": "unknown",
                "behavioral_matches": ["Suspicious PowerShell beacon"],
            },
        )["KRI-07"]
        self.assertEqual(behavior.status, DETECTED)
        clean = evaluate(
            ControlPosture(asset_uuid="asset-1"),
            edr_status={"infection_status": "clean", "behavioral_matches": []},
        )["KRI-07"]
        self.assertEqual(clean.status, NOT_DETECTED)
        unknown = evaluate(ControlPosture(asset_uuid="asset-1"))["KRI-07"]
        self.assertEqual(unknown.status, UNKNOWN)

    def test_detection_counts(self):
        results = evaluate(
            ControlPosture(
                asset_uuid="asset-1",
                agent_present=False,
                edr_present=False,
                av_present=False,
            )
        )
        counts = detection_counts(list(results.values()))
        self.assertEqual(sum(counts.values()), 7)
        self.assertEqual(counts[DETECTED], 1)
        self.assertEqual(counts[NOT_DETECTED], 1)
        self.assertEqual(counts[UNKNOWN], 2)
        self.assertEqual(counts[NOT_APPLICABLE], 3)


if __name__ == "__main__":
    unittest.main()
