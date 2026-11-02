from __future__ import annotations

import unittest

from secops_autopilot.models import ControlPosture
from secops_autopilot.scoring import (
    control_gap_score,
    exploit_component,
    normalise_exposure,
    score_asset,
    tier_for,
)

from tests.helpers import make_finding


class ScoringTest(unittest.TestCase):
    def test_exposure_normalisation_handles_both_tenable_scales(self):
        self.assertEqual(normalise_exposure(850), 8.5)
        self.assertEqual(normalise_exposure(85), 8.5)
        self.assertIsNone(normalise_exposure(None))
        self.assertIsNone(normalise_exposure(0))

    def test_stronger_exploit_signal_wins_over_lower_vpr(self):
        finding = make_finding(vpr=5.0)
        score, source, signals = exploit_component([finding])
        self.assertEqual(score, 9.5)
        self.assertIn("signals", source)
        self.assertIn("exploited_by_malware", signals)

    def test_control_gap_counts_absence_and_unknowns(self):
        posture = ControlPosture(
            asset_uuid="asset-1",
            agent_present=True,
            agent_version=None,
            edr_present=None,
            av_present=None,
            app_control_mode=None,
            patch_agent_present=None,
        )
        self.assertEqual(control_gap_score(posture), 4.75)
        absent = ControlPosture(
            asset_uuid="asset-2",
            agent_present=False,
            edr_present=False,
            av_present=False,
            app_control_mode="enforce",
            patch_agent_present=True,
        )
        self.assertEqual(control_gap_score(absent), 9.5)

    def test_unknown_components_are_excluded_and_weights_renormalized(self):
        finding = make_finding()
        posture = ControlPosture(
            asset_uuid="asset-1",
            agent_present=True,
            agent_version="10.0.0",
            edr_present=True,
            av_present=True,
            app_control_mode="enforce",
            patch_agent_present=True,
        )
        risk = score_asset(
            "asset-1",
            [finding],
            posture,
            aes_raw=None,
            acr_raw=None,
        )
        self.assertIn("exposure", risk.unknown_components)
        self.assertIn("criticality", risk.unknown_components)
        self.assertNotIn("exposure", risk.effective_weights)
        self.assertAlmostEqual(sum(risk.effective_weights.values()), 0.8)
        self.assertEqual(risk.confidence, "medium")
        self.assertGreater(risk.score, 70)

    def test_tier_boundaries(self):
        self.assertEqual(tier_for(80), "critical")
        self.assertEqual(tier_for(79.9), "high")
        self.assertEqual(tier_for(65), "high")
        self.assertEqual(tier_for(45), "medium")
        self.assertEqual(tier_for(44.9), "low")


if __name__ == "__main__":
    unittest.main()
