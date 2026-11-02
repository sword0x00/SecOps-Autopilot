"""EDR connector used for the infection branch and SOC handoff.

No EDR tenant was provided. The simulator therefore returns ``unknown`` unless
an explicit fixture (``.state/edr_status.json``) supplies a status. It never
returns ``clean``: absence of an EDR signal is not evidence of a clean host.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..util import utc_now
from .state import JsonState


class SimulatedEDR:
    name = "simulated_edr"
    live = False
    simulated = True

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.cases = JsonState(state_dir / "edr_cases.json")
        self.statuses = JsonState(state_dir / "edr_status.json")

    def status(self, asset_uuid: str, hostname: str) -> dict[str, Any]:
        data = self.statuses.read({"assets": {}})
        assets = {
            str(key).strip().lower(): value
            for key, value in (data.get("assets") or {}).items()
        }
        keys = [key for key in (asset_uuid, hostname) if key]
        for key in keys:
            entry = assets.get(str(key).strip().lower())
            if isinstance(entry, dict):
                return {
                    "present": entry.get("present"),
                    "vendor": entry.get("vendor"),
                    "version": entry.get("version"),
                    "feed_age_hours": entry.get("feed_age_hours"),
                    "infection_status": entry.get("infection_status") or "unknown",
                    "behavioral_matches": [
                        str(item) for item in (entry.get("behavioral_matches") or [])
                    ],
                    "source": "simulated_edr:.state/edr_status.json",
                    "detail": entry.get("detail"),
                }
        return {
            "present": None,
            "vendor": None,
            "version": None,
            "feed_age_hours": None,
            "infection_status": "unknown",
            "behavioral_matches": [],
            "source": "no EDR integration configured",
            "detail": (
                "No EDR tenant or status fixture is configured. The engine cannot "
                "assert that a host is clean; this remains unknown."
            ),
        }

    def handoff(self, asset_uuid: str, hostname: str, evidence: dict[str, Any]) -> dict[str, Any]:
        def mutate(data: dict[str, Any]) -> dict[str, Any]:
            next_id = int(data.get("next_id", 1))
            data["next_id"] = next_id + 1
            case = {
                "case_id": f"SIM-SOC-{next_id:06d}",
                "asset_uuid": asset_uuid,
                "hostname": hostname,
                "status": "queued",
                "created_at": utc_now(),
                "simulated": True,
                "evidence": evidence,
            }
            data.setdefault("cases", []).append(case)
            return case

        return self.cases.update(mutate, {"next_id": 1, "cases": []})

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "EDR (simulated)",
            "live": False,
            "simulated": True,
            "note": (
                "No EDR tenant is configured. Infection status is unknown unless "
                ".state/edr_status.json is supplied. SOC handoffs are file-backed."
            ),
        }
