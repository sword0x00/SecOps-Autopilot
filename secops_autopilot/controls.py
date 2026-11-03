"""Owner and control inventory from CSV.

Tenable answers "is a Tenable agent flag present?" but not "is the EDR healthy?"
or "who owns this asset?". Those answers belong to the asset inventory and EDR consoles.
This module accepts a small CSV export from either, and records ``unknown`` when
no row matches. It never synthesizes an owner or a control state.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .models import AssetRef, OwnerInfo
from .util import UNKNOWN, as_bool, as_float, normalize_mac


def _load_rows(path: str | Path | None) -> list[dict[str, str]]:
    if not path:
        return []
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise FileNotFoundError(f"inventory file not found: {file_path}")
    with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for raw in reader:
            row = {
                str(key).strip().lower().replace(" ", "_"): (value or "").strip()
                for key, value in raw.items()
                if key is not None
            }
            if any(row.values()):
                rows.append(row)
        return rows


def _asset_keys(asset: AssetRef) -> list[str]:
    keys = [
        asset.uuid,
        asset.hostname,
        asset.fqdn,
        asset.netbios,
        asset.ipv4,
        asset.mac,
    ]
    return [str(key).strip().lower() for key in keys if key]


def _parse_nac(value: str | None) -> bool | None:
    parsed = as_bool(value)
    if parsed is not None:
        return parsed
    text = (value or "").strip().lower()
    if not text:
        return None
    if any(token in text for token in ("noncompliant", "non-compliant", "fail", "deny", "denied")):
        return False
    if any(token in text for token in ("compliant", "pass", "permit", "allow")):
        return True
    return None


def _matches(row: dict[str, str], keys: list[str]) -> bool:
    match = (row.get("match") or "").strip().lower()
    if not match:
        return False
    candidates = {match}
    if normalize_mac(match):
        candidates.add(normalize_mac(match) or "")
    return bool(candidates.intersection(keys))


class OwnerDirectory:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self.path = path
        self.rows = list(rows) if rows is not None else _load_rows(path)
        self._source = (
            f"owners inventory: {self.path}"
            if self.path
            else "in-memory owners fixture"
            if rows is not None
            else "no asset inventory owner mapping configured"
        )

    def lookup(self, asset: AssetRef) -> OwnerInfo:
        keys = _asset_keys(asset)
        for row in self.rows:
            if _matches(row, keys):
                return OwnerInfo(
                    owner=row.get("owner") or UNKNOWN,
                    team=row.get("team") or UNKNOWN,
                    email=row.get("email") or None,
                    source=self._source,
                    match=row.get("match"),
                )
        return OwnerInfo(source=self._source)

    def public_snapshot(self) -> dict[str, Any]:
        return {"path": str(self.path) if self.path else None, "rows": len(self.rows)}


class ControlInventory:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self.path = path
        self.rows = list(rows) if rows is not None else _load_rows(path)
        self._source = (
            f"controls inventory: {self.path}"
            if self.path
            else "in-memory controls fixture"
            if rows is not None
            else "no control inventory configured"
        )

    def lookup(self, asset: AssetRef) -> dict[str, Any]:
        keys = _asset_keys(asset)
        for row in self.rows:
            if not _matches(row, keys):
                continue
            nac_value = row.get("nac_compliant")
            if nac_value is None:
                nac_value = row.get("nac_posture")
            return {
                "matched": True,
                "match": row.get("match"),
                "source": self._source,
                "edr_present": as_bool(row.get("edr_present")),
                "edr_vendor": row.get("edr_vendor") or None,
                "edr_version": row.get("edr_version") or None,
                "edr_baseline_version": row.get("edr_baseline_version") or None,
                "edr_last_seen": row.get("edr_last_seen") or None,
                "edr_feed_age_hours": as_float(row.get("edr_feed_age_hours")),
                "edr_mode": row.get("edr_mode") or None,
                "av_present": as_bool(row.get("av_present")),
                "av_vendor": row.get("av_vendor") or None,
                "av_version": row.get("av_version") or None,
                "av_baseline_version": row.get("av_baseline_version") or None,
                "av_signature_age_hours": as_float(row.get("av_signature_age_hours")),
                "av_mode": row.get("av_mode") or None,
                "app_control_mode": row.get("app_control_mode") or None,
                "nac_compliant": _parse_nac(nac_value),
                "nac_policy": row.get("nac_policy") or None,
                "patch_agent_present": as_bool(row.get("patch_agent_present")),
                "updated_at": row.get("updated_at") or None,
            }
        return {"matched": False, "source": self._source}

    def public_snapshot(self) -> dict[str, Any]:
        return {"path": str(self.path) if self.path else None, "rows": len(self.rows)}
