"""Alerting connector.

Alerts are first-class records in the run. The default sink is a local JSON
file so a demonstration does not ship security telemetry to an unconfigured
SIEM. A production adapter would implement ``send`` against the team's SIEM.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..util import utc_now
from .state import JsonState


class SimulatedSIEM:
    name = "simulated_siem"
    live = False
    simulated = True

    def __init__(self, state_dir: Path) -> None:
        self.state = JsonState(state_dir / "siem.json")

    def send(self, alert: dict[str, Any]) -> dict[str, Any]:
        def mutate(data: dict[str, Any]) -> dict[str, Any]:
            next_id = int(data.get("next_id", 1))
            data["next_id"] = next_id + 1
            receipt = {
                "receipt_id": f"SIM-SIEM-{next_id:06d}",
                "received_at": utc_now(),
                "sink": self.name,
                "simulated": True,
            }
            record = {**alert, **receipt}
            data.setdefault("alerts", []).append(record)
            return record

        return self.state.update(mutate, {"next_id": 1, "alerts": []})

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "SIEM (simulated)",
            "live": False,
            "simulated": True,
            "note": "Alert records are file-backed in .state/siem.json; no SIEM was contacted.",
        }
