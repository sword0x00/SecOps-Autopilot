"""Patch-management connector.

The engine had no stage-8 execution connector: it could plan a patch but could
not record that an approved patch job was submitted. This connector closes that
gap without pretending to patch anything. The default implementation is
file-backed and labels every job ``simulated``; a real adapter (SCCM, Intune,
Satellite, Ansible AWX, Tanium) implements the same small interface.

The simulator never reports ``patched`` unless a scenario explicitly supplies an
outcome. Production verification must still come from a fresh scanner read:
submitting a job is not evidence that a host changed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from ..util import utc_now
from .state import JsonState


class PatchConnector(Protocol):
    name: str
    live: bool
    simulated: bool

    def submit(
        self,
        *,
        run_id: str,
        ticket_id: str,
        jobs: list[dict[str, Any]],
        approver: str,
    ) -> dict[str, Any]:
        ...

    def public_snapshot(self) -> dict[str, Any]:
        ...


class SimulatedPatchManager:
    """File-backed patch job ledger.

    ``outcomes`` lets deterministic validation scenarios model a manager that
    accepts or rejects a job. It defaults to ``simulated_queued``: accepted for
    delivery, but no host was touched and no patch is claimed.
    """

    name = "simulated_patch_manager"
    live = False
    simulated = True

    def __init__(
        self,
        state_dir: Path,
        *,
        outcomes: dict[str, str] | None = None,
    ) -> None:
        self.state = JsonState(state_dir / "patch.json")
        self.outcomes = dict(outcomes or {})

    def submit(
        self,
        *,
        run_id: str,
        ticket_id: str,
        jobs: list[dict[str, Any]],
        approver: str,
    ) -> dict[str, Any]:
        def mutate(data: dict[str, Any]) -> dict[str, Any]:
            existing = {
                (item.get("run_id"), item.get("asset_uuid")): item
                for item in data.get("jobs") or []
            }
            results: list[dict[str, Any]] = []
            for job in jobs:
                key = (run_id, job.get("asset_uuid"))
                if key in existing:
                    item = dict(existing[key])
                    item["idempotent"] = True
                    results.append(item)
                    continue
                next_id = int(data.get("next_id", 1))
                data["next_id"] = next_id + 1
                outcome = self.outcomes.get(str(job.get("asset_uuid")), "queued")
                if outcome not in {"queued", "success", "failed"}:
                    outcome = "queued"
                status = {
                    "queued": "simulated_queued",
                    "success": "simulated_success",
                    "failed": "simulated_failure",
                }[outcome]
                item = {
                    "job_id": f"SIM-PATCH-{next_id:06d}",
                    "run_id": run_id,
                    "ticket_id": ticket_id,
                    "asset_uuid": job.get("asset_uuid"),
                    "hostname": job.get("hostname"),
                    "package": job.get("package"),
                    "current_version": job.get("current_version"),
                    "target_version": job.get("target_version"),
                    "status": status,
                    "simulated": True,
                    "touched_host": False,
                    "submitted_at": utc_now(),
                    "approver": approver,
                    "connector": self.name,
                    "reason": job.get("reason"),
                }
                data.setdefault("jobs", []).append(item)
                results.append(item)
                existing[key] = item
            return {
                "connector": self.name,
                "simulated": True,
                "jobs": results,
                "submitted": sum(
                    1 for item in results if not item.get("idempotent")
                ),
                "idempotent": sum(1 for item in results if item.get("idempotent")),
            }

        return self.state.update(
            mutate, {"next_id": 1, "jobs": []}
        )

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "Patch management (simulated)",
            "live": False,
            "simulated": True,
            "touched_host": False,
            "note": (
                "Patch jobs are recorded in .state/patch.json. No patch was "
                "delivered, no host was rebooted, and no host is reported patched. "
                "Verification requires a fresh scanner read."
            ),
        }


def build_patch(state_dir: Path) -> SimulatedPatchManager:
    """Return the safe default. A live adapter would be selected here."""
    return SimulatedPatchManager(state_dir)


__all__ = ["PatchConnector", "SimulatedPatchManager", "build_patch"]
